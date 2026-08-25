import asyncio
import importlib.util
import logging
import sys
import types
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def load_plugin_module():
    core_module = types.ModuleType("core")
    core_module.__path__ = []

    kira_logging = types.ModuleType("core.logging_manager")
    kira_logging._created_by_get_logger = set()

    def get_logger(name, _color):
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        if not logger.handlers:
            logger.addHandler(logging.NullHandler())
        kira_logging._created_by_get_logger.add(name)
        return logger

    kira_logging.get_logger = get_logger

    plugin_module = types.ModuleType("core.plugin")

    class BasePlugin:
        def __init__(self, ctx, cfg):
            self.ctx = ctx
            self.plugin_cfg = cfg

    class Priority:
        LOW = -50

    class On:
        @staticmethod
        def exception(priority=None):
            del priority

            def decorator(func):
                return func

            return decorator

    plugin_module.BasePlugin = BasePlugin
    plugin_module.Priority = Priority
    plugin_module.on = On()

    chat_module = types.ModuleType("core.chat")
    chat_module.__path__ = []
    message_utils = types.ModuleType("core.chat.message_utils")

    class KiraExceptionEvent:
        def __init__(self, name, message, source=None, comp_id=None, stage=None):
            self.name = name
            self.message = message
            self.source = source
            self.comp_id = comp_id
            self.stage = stage

    class MessageChain:
        def __init__(self):
            self.text_value = ""

        def text(self, value):
            self.text_value += value
            return self

    message_utils.KiraExceptionEvent = KiraExceptionEvent
    message_utils.MessageChain = MessageChain

    core_module.logging_manager = kira_logging
    core_module.plugin = plugin_module
    core_module.chat = chat_module

    sys.modules["core"] = core_module
    sys.modules["core.logging_manager"] = kira_logging
    sys.modules["core.plugin"] = plugin_module
    sys.modules["core.chat"] = chat_module
    sys.modules["core.chat.message_utils"] = message_utils

    spec = importlib.util.spec_from_file_location(
        "error_notifier_plugin_under_test", PLUGIN_ROOT / "main.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, kira_logging, KiraExceptionEvent


PLUGIN, KIRA_LOGGING, KiraExceptionEvent = load_plugin_module()


class FakeResult:
    ok = True
    err = ""


class FakeContext:
    def __init__(self):
        self.sent = []

    async def send_message_chain(self, session, chain):
        self.sent.append((session, chain.text_value))
        return FakeResult()


class SanitizeTests(unittest.TestCase):
    def test_redacts_credentials_url_secrets_and_long_ids(self):
        raw = (
            "Authorization=Bearer abc.def token=my-token password:hello "
            "https://example.test/?api_key=visible&x=1 QQ=123456789 "
            "json={\"access_token\": \"json-secret\"}"
        )
        result = PLUGIN.sanitize_text(raw, 1000)

        self.assertNotIn("abc.def", result)
        self.assertNotIn("my-token", result)
        self.assertNotIn("hello", result)
        self.assertNotIn("visible", result)
        self.assertNotIn("json-secret", result)
        self.assertNotIn("123456789", result)
        self.assertIn("[REDACTED]", result)
        self.assertIn("[ID]", result)

    def test_truncates_long_summary(self):
        self.assertEqual(PLUGIN.sanitize_text("abcdef", 5), "abcd…")

    def test_omits_traceback_frames_but_keeps_redacted_exception(self):
        raw = (
            "Traceback (most recent call last):\n"
            "  File \"/srv/app.py\", line 10, in run\n"
            "    raise ValueError()\n"
            "ValueError: failed token=trace-secret"
        )
        result = PLUGIN.summarize_error_text(raw, 1000)

        self.assertIn("Python traceback omitted", result)
        self.assertIn("ValueError", result)
        self.assertNotIn("/srv/app.py", result)
        self.assertNotIn("trace-secret", result)

    def test_fingerprint_ignores_timestamp_uuid_and_retry_counter(self):
        first = PLUGIN.Alert(
            timestamp="ignored",
            source="provider",
            component="openai",
            stage="agent_loop",
            error_type="APIError",
            summary=(
                "failed at 2026-08-26 03:40:00 attempt 1 "
                "request 123e4567-e89b-12d3-a456-426614174000"
            ),
        )
        second = PLUGIN.Alert(
            timestamp="ignored",
            source="provider",
            component="openai",
            stage="agent_loop",
            error_type="APIError",
            summary=(
                "failed at 2026-08-26 03:41:30 attempt 2 "
                "request 987e6543-e21b-12d3-a456-426614174999"
            ),
        )

        self.assertEqual(first.fingerprint, second.fingerprint)


class AlertGateTests(unittest.TestCase):
    def test_deduplicates_and_reports_suppressed_count(self):
        gate = PLUGIN.AlertGate(cooldown_seconds=300, max_alerts_per_hour=10)

        self.assertEqual(gate.check("same", now=0), (True, 0))
        self.assertEqual(gate.check("same", now=10), (False, 0))
        self.assertEqual(gate.check("same", now=301), (True, 1))

    def test_applies_global_hourly_limit(self):
        gate = PLUGIN.AlertGate(cooldown_seconds=0, max_alerts_per_hour=2)

        self.assertEqual(gate.check("one", now=0), (True, 0))
        self.assertEqual(gate.check("two", now=1), (True, 0))
        self.assertEqual(gate.check("three", now=2), (False, 0))
        self.assertEqual(gate.check("three", now=3601), (True, 1))


class PluginAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_on_exception_mode_sends_exact_template_with_redaction(self):
        ctx = FakeContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "qq:dm:1",
                "message_template": "{source}|{component}|{error_type}|{summary}|{repeat_count}",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            event = KiraExceptionEvent(
                name="APIError",
                message="request failed token=super-secret user=123456789",
                source="provider",
                comp_id="openai",
                stage="agent_loop",
            )
            await plugin.handle_exception(None, event)
            await asyncio.wait_for(plugin._queue.join(), timeout=1)

            self.assertEqual(len(ctx.sent), 1)
            self.assertEqual(ctx.sent[0][0], "qq:dm:1")
            self.assertIn("provider|openai|APIError", ctx.sent[0][1])
            self.assertNotIn("super-secret", ctx.sent[0][1])
            self.assertNotIn("123456789", ctx.sent[0][1])
        finally:
            await plugin.terminate()

    async def test_all_error_mode_captures_kira_logger(self):
        ctx = FakeContext()
        logger = logging.getLogger("source_for_all_error_test")
        logger.handlers.clear()
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        KIRA_LOGGING._created_by_get_logger.add(logger.name)

        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "all_error",
                "target_session": "qq:dm:1",
                "message_template": "{component}|{error_type}|{summary}",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            logger.error("database failed password=do-not-send")
            await asyncio.sleep(0)
            await asyncio.wait_for(plugin._queue.join(), timeout=1)

            self.assertEqual(len(ctx.sent), 1)
            self.assertIn("source_for_all_error_test|ERROR", ctx.sent[0][1])
            self.assertNotIn("do-not-send", ctx.sent[0][1])
        finally:
            await plugin.terminate()
            KIRA_LOGGING._created_by_get_logger.discard(logger.name)
            logger.handlers.clear()

    async def test_on_exception_mode_does_not_install_log_handler(self):
        plugin = PLUGIN.ErrorNotifierPlugin(
            FakeContext(),
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "qq:dm:1",
            },
        )
        await plugin.initialize()
        try:
            self.assertIsNone(plugin._log_handler)
            self.assertFalse(plugin._attached_loggers)
        finally:
            await plugin.terminate()

    async def test_all_error_mode_ignores_notifier_own_logger(self):
        ctx = FakeContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "all_error",
                "target_session": "qq:dm:1",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            logging.getLogger(PLUGIN.NOTIFIER_LOGGER_NAME).error("send failed")
            await asyncio.sleep(0)
            self.assertTrue(plugin._queue.empty())
            self.assertEqual(ctx.sent, [])
        finally:
            await plugin.terminate()

    async def test_error_storm_bounds_pending_event_loop_callbacks(self):
        ctx = FakeContext()
        logger = logging.getLogger("source_for_error_storm_test")
        logger.handlers.clear()
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        KIRA_LOGGING._created_by_get_logger.add(logger.name)

        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "all_error",
                "target_session": "qq:dm:1",
                "max_alerts_per_hour": 1,
            },
        )
        await plugin.initialize()
        try:
            for index in range(250):
                logger.error("storm item %s", index)

            self.assertLessEqual(
                plugin._pending_log_callbacks,
                plugin._pending_log_callbacks_limit,
            )
            self.assertGreaterEqual(plugin._dropped_alerts, 150)
            await asyncio.sleep(0)
        finally:
            await plugin.terminate()
            KIRA_LOGGING._created_by_get_logger.discard(logger.name)
            logger.handlers.clear()

    async def test_invalid_target_keeps_plugin_inactive(self):
        plugin = PLUGIN.ErrorNotifierPlugin(
            FakeContext(),
            {
                "enabled": True,
                "monitor_mode": "all_error",
                "target_session": "",
            },
        )
        await plugin.initialize()
        self.assertFalse(plugin._active)
        self.assertIsNone(plugin._log_handler)


if __name__ == "__main__":
    unittest.main()

