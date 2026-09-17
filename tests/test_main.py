import asyncio
import importlib.util
import json
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


def load_plugin_module_same_host(suffix):
    """Load a fresh plugin module while retaining the synthetic KiraAI host."""
    module_name = f"error_notifier_plugin_reload_{suffix}"
    spec = importlib.util.spec_from_file_location(module_name, PLUGIN_ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


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
    def test_authorization_shape_matrix_is_redacted_conservatively(self):
        samples = (
            (
                'Authorization: "Basic SYNTH_INSIDE_DOUBLE SECRET" component=gateway',
                ("SYNTH_INSIDE_DOUBLE", "SECRET"),
            ),
            (
                "Authorization: 'Bearer SYNTH_INSIDE_SINGLE TWO' component=gateway",
                ("SYNTH_INSIDE_SINGLE", "TWO"),
            ),
            (
                'Authorization: Basic "SYNTH_OUTSIDE_DOUBLE SECRET" component=gateway',
                ("SYNTH_OUTSIDE_DOUBLE", "SECRET"),
            ),
            (
                "Authorization: Bearer 'SYNTH_OUTSIDE_SINGLE TWO' component=gateway",
                ("SYNTH_OUTSIDE_SINGLE", "TWO"),
            ),
            (
                'headers={"Authorization": "Basic SYNTH_DICT_DOUBLE SECRET"} component=gateway',
                ("SYNTH_DICT_DOUBLE", "SECRET"),
            ),
            (
                "headers={'Proxy-Authorization': 'Bearer SYNTH_DICT_SINGLE TWO'} component=gateway",
                ("SYNTH_DICT_SINGLE", "TWO"),
            ),
            (
                'Authorization: Basic "SYNTH_MULTI\nLINE SECRET" component=gateway',
                ("SYNTH_MULTI", "LINE SECRET"),
            ),
            (
                'Authorization: Bearer "SYNTH_ESCAPED\\\"QUOTE SECRET" component=gateway',
                ("SYNTH_ESCAPED", "QUOTE SECRET"),
            ),
            (
                'headers={"Authorization": "Basic SYNTH_UNCLOSED\ncomponent=gateway',
                ("SYNTH_UNCLOSED",),
            ),
            (
                "Authorization: Bearer SYNTH_UNQUOTED TWO component=gateway",
                ("SYNTH_UNQUOTED", "TWO"),
            ),
        )

        for raw, secrets in samples:
            with self.subTest(raw=raw):
                result = PLUGIN.sanitize_text(raw, 1000)
                for secret in secrets:
                    self.assertNotIn(secret, result)
                self.assertIn("component=gateway", result)

    def test_redacts_quoted_and_multiline_credential_edge_cases(self):
        samples = (
            (
                'Authorization: "Basic SYNTH_BASIC_SECRET" request failed',
                ("SYNTH_BASIC_SECRET",),
                ("request failed",),
            ),
            (
                'Authorization: "Bearer SYNTH_BEARER TWO_WORDS" code=401',
                ("SYNTH_BEARER", "TWO_WORDS"),
                ("code=401",),
            ),
            (
                'password="SYNTH_MULTILINE_SECRET\nnext=visible',
                ("SYNTH_MULTILINE_SECRET",),
                ("next=visible",),
            ),
            (
                'password="SYNTH_CLOSED\nMULTILINE_SECRET" next=visible',
                ("SYNTH_CLOSED", "MULTILINE_SECRET"),
                ("next=visible",),
            ),
            (
                'password="SYNTH_ESCAPED\\\"QUOTE SECRET" next=visible',
                ("SYNTH_ESCAPED", "QUOTE SECRET"),
                ("next=visible",),
            ),
        )

        for raw, secrets, visible_values in samples:
            with self.subTest(raw=raw):
                result = PLUGIN.sanitize_text(raw, 1000)
                for secret in secrets:
                    self.assertNotIn(secret, result)
                for visible in visible_values:
                    self.assertIn(visible, result)

    def test_synthetic_sensitive_samples_are_redacted_and_readable(self):
        samples_path = PLUGIN_ROOT / "tests" / "fixtures" / "sensitive_alert_samples.json"
        samples = json.loads(samples_path.read_text(encoding="utf-8"))

        for sample in samples:
            with self.subTest(sample=sample["name"]):
                result = PLUGIN.sanitize_text(sample["text"], 1000)
                for secret in sample["secrets"]:
                    self.assertNotIn(secret, result)
                for visible in sample["visible"]:
                    self.assertIn(visible, result)

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
    async def test_authorization_redaction_is_consistent_outbound_and_in_send_log(self):
        class NegativeResultContext:
            def __init__(self):
                self.sent = []

            async def send_message_chain(self, _session, chain):
                self.sent.append(chain.text_value)
                return types.SimpleNamespace(
                    ok=False,
                    err=(
                        'adapter rejected Authorization: Bearer '
                        '"SYNTH_LOG_SECRET TWO" component=qq-adapter'
                    ),
                )

        ctx = NegativeResultContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "message_template": "{component}|{error_type}|{summary}",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            with self.assertLogs(PLUGIN.NOTIFIER_LOGGER_NAME, level="ERROR") as logs:
                await plugin.handle_exception(
                    None,
                    KiraExceptionEvent(
                        name="SyntheticAuthError",
                        message=(
                            'headers={"Authorization": '
                            '"Basic SYNTH_OUTBOUND_SECRET TWO"} detail=failed'
                        ),
                        source="provider",
                        comp_id="provider-gateway",
                        stage="agent_loop",
                    ),
                )
                await asyncio.wait_for(plugin._queue.join(), timeout=0.5)

            outbound = ctx.sent[0]
            log_output = "\n".join(logs.output)
            self.assertNotIn("SYNTH_OUTBOUND_SECRET", outbound)
            self.assertNotIn("TWO", outbound)
            self.assertIn("provider-gateway|SyntheticAuthError", outbound)
            self.assertIn("detail=failed", outbound)
            self.assertNotIn("SYNTH_LOG_SECRET", log_output)
            self.assertNotIn("TWO", log_output)
            self.assertIn("component=qq-adapter", log_output)
        finally:
            await plugin.terminate()

    async def test_process_send_cap_survives_instances_and_module_reload(self):
        class SharedCancellationSwallowingContext:
            def __init__(self):
                self.calls = 0
                self.release = asyncio.Event()

            async def send_message_chain(self, _session, _chain):
                self.calls += 1
                while not self.release.is_set():
                    try:
                        await self.release.wait()
                    except asyncio.CancelledError:
                        continue
                return FakeResult()

        modules = (
            PLUGIN,
            load_plugin_module_same_host("second"),
            load_plugin_module_same_host("third"),
        )
        ctx = SharedCancellationSwallowingContext()
        plugins = [
            module.ErrorNotifierPlugin(
                ctx,
                {
                    "enabled": True,
                    "monitor_mode": "on_exception",
                    "target_session": "synthetic:dm:test-target",
                    "cooldown_seconds": 0,
                    "send_timeout_seconds": 1,
                },
            )
            for module in modules
        ]
        for plugin in plugins:
            plugin.send_timeout_seconds = 0.03
            await plugin.initialize()

        try:
            for plugin_index, plugin in enumerate(plugins):
                for alert_index in range(3):
                    await plugin.handle_exception(
                        None,
                        KiraExceptionEvent(
                            name="APIError",
                            message=f"reload {plugin_index} alert {alert_index}",
                            source="provider",
                            comp_id="provider-gateway",
                            stage="agent_loop",
                        ),
                    )

            await asyncio.wait_for(
                asyncio.gather(*(plugin._queue.join() for plugin in plugins)),
                timeout=0.4,
            )

            self.assertEqual(ctx.calls, 2)
            self.assertEqual(sum(p.delivery_stats.attempted for p in plugins), 9)
            self.assertEqual(sum(p.delivery_stats.failed for p in plugins), 9)
            self.assertEqual(sum(p.delivery_stats.timed_out for p in plugins), 2)
            self.assertEqual(sum(p.delivery_stats.saturated for p in plugins), 7)
            for plugin in plugins:
                self.assertEqual(plugin.process_pending_send_count, 2)

            await asyncio.wait_for(
                asyncio.gather(*(plugin.terminate() for plugin in plugins)),
                timeout=0.1,
            )
            self.assertEqual(plugins[0].process_pending_send_count, 2)
        finally:
            ctx.release.set()
            for _ in range(5):
                await asyncio.sleep(0)
                if all(
                    getattr(plugin, "process_pending_send_count", plugin.pending_send_count)
                    == 0
                    for plugin in plugins
                ):
                    break
            for plugin in plugins:
                if plugin._active:
                    await plugin.terminate()

    async def test_runtime_timeout_matches_integer_schema_boundary(self):
        below_minimum = PLUGIN.ErrorNotifierPlugin(
            FakeContext(),
            {
                "enabled": True,
                "target_session": "synthetic:dm:test-target",
                "send_timeout_seconds": 0.1,
            },
        )
        fractional = PLUGIN.ErrorNotifierPlugin(
            FakeContext(),
            {
                "enabled": True,
                "target_session": "synthetic:dm:test-target",
                "send_timeout_seconds": 1.9,
            },
        )

        self.assertEqual(below_minimum.send_timeout_seconds, 1)
        self.assertEqual(fractional.send_timeout_seconds, 1)

    async def test_non_cooperative_cancellation_is_bounded_and_worker_keeps_draining(self):
        class CancellationSwallowingContext:
            def __init__(self):
                self.calls = 0
                self.release = asyncio.Event()

            async def send_message_chain(self, _session, _chain):
                self.calls += 1
                while not self.release.is_set():
                    try:
                        await self.release.wait()
                    except asyncio.CancelledError:
                        continue
                return FakeResult()

        ctx = CancellationSwallowingContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "cooldown_seconds": 0,
                "send_timeout_seconds": 1,
            },
        )
        plugin.send_timeout_seconds = 0.03
        await plugin.initialize()
        try:
            for index in range(3):
                await plugin.handle_exception(
                    None,
                    KiraExceptionEvent(
                        name="APIError",
                        message=f"synthetic non-cooperative send {index}",
                        source="provider",
                        comp_id="provider-gateway",
                        stage="agent_loop",
                    ),
                )

            await asyncio.wait_for(plugin._queue.join(), timeout=0.3)

            self.assertEqual(ctx.calls, 2)
            self.assertEqual(plugin.delivery_stats.attempted, 3)
            self.assertEqual(plugin.delivery_stats.failed, 3)
            self.assertEqual(plugin.delivery_stats.timed_out, 2)
            self.assertEqual(plugin.delivery_stats.saturated, 1)
            self.assertEqual(plugin.pending_send_count, 2)
            await asyncio.wait_for(plugin.terminate(), timeout=0.1)
            self.assertEqual(plugin.pending_send_count, 2)
            self.assertFalse(plugin._sending_notification)
            self.assertIsNone(plugin._worker_task)
        finally:
            ctx.release.set()
            await asyncio.sleep(0)
            if plugin._active:
                await plugin.terminate()

    async def test_send_timeout_recovers_worker_and_counts_real_outcomes(self):
        class TimeoutThenSuccessContext:
            def __init__(self):
                self.calls = []
                self.first_started = asyncio.Event()
                self.first_cancelled = asyncio.Event()

            async def send_message_chain(self, _session, chain):
                self.calls.append(chain.text_value)
                if len(self.calls) == 1:
                    self.first_started.set()
                    try:
                        await asyncio.Event().wait()
                    finally:
                        self.first_cancelled.set()
                return FakeResult()

        ctx = TimeoutThenSuccessContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "cooldown_seconds": 0,
                "send_timeout_seconds": 1,
            },
        )
        plugin.send_timeout_seconds = 0.03
        await plugin.initialize()
        try:
            for index in range(2):
                await plugin.handle_exception(
                    None,
                    KiraExceptionEvent(
                        name="APIError",
                        message=f"synthetic timeout sequence {index}",
                        source="provider",
                        comp_id="provider-gateway",
                        stage="agent_loop",
                    ),
                )
            await asyncio.wait_for(plugin._queue.join(), timeout=0.5)

            self.assertTrue(ctx.first_cancelled.is_set())
            self.assertEqual(len(ctx.calls), 2)
            self.assertEqual(plugin.delivery_stats.attempted, 2)
            self.assertEqual(plugin.delivery_stats.failed, 1)
            self.assertEqual(plugin.delivery_stats.timed_out, 1)
            self.assertEqual(plugin.delivery_stats.delivered, 1)
        finally:
            await plugin.terminate()

    async def test_exception_and_negative_result_do_not_retry_or_block_next_item(self):
        class FailureSequenceContext:
            def __init__(self):
                self.calls = 0

            async def send_message_chain(self, _session, _chain):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("password=EN02_EXCEPTION_SECRET")
                if self.calls == 2:
                    return types.SimpleNamespace(
                        ok=False,
                        err="Authorization: Bearer EN02_RESULT_SECRET",
                    )
                return FakeResult()

        ctx = FailureSequenceContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            with self.assertLogs(PLUGIN.NOTIFIER_LOGGER_NAME, level="ERROR") as logs:
                for index in range(3):
                    await plugin.handle_exception(
                        None,
                        KiraExceptionEvent(
                            name="APIError",
                            message=f"synthetic failure sequence {index}",
                            source="provider",
                            comp_id="provider-gateway",
                            stage="agent_loop",
                        ),
                    )
                await asyncio.wait_for(plugin._queue.join(), timeout=0.5)

            output = "\n".join(logs.output)
            self.assertNotIn("EN02_EXCEPTION_SECRET", output)
            self.assertNotIn("EN02_RESULT_SECRET", output)
            self.assertEqual(ctx.calls, 3)
            self.assertEqual(plugin.delivery_stats.attempted, 3)
            self.assertEqual(plugin.delivery_stats.failed, 2)
            self.assertEqual(plugin.delivery_stats.delivered, 1)
        finally:
            await plugin.terminate()

    async def test_concurrent_business_error_is_retained_without_send_recursion(self):
        business_logger = logging.getLogger("source_for_concurrent_business_error")
        adapter_logger = logging.getLogger("source_for_synthetic_adapter_error")
        for logger in (business_logger, adapter_logger):
            logger.handlers.clear()
            logger.setLevel(logging.DEBUG)
            logger.propagate = False
            KIRA_LOGGING._created_by_get_logger.add(logger.name)

        class BlockingContext:
            def __init__(self):
                self.calls = []
                self.started = asyncio.Event()

            async def send_message_chain(self, _session, chain):
                self.calls.append(chain.text_value)
                if len(self.calls) == 1:
                    self.started.set()
                    adapter_logger.error(
                        "synthetic adapter send failure password=EN02_RECURSION_SECRET"
                    )
                    await asyncio.Event().wait()
                return FakeResult()

        ctx = BlockingContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "all_error",
                "target_session": "synthetic:dm:test-target",
                "cooldown_seconds": 0,
                "send_timeout_seconds": 1,
            },
        )
        plugin.send_timeout_seconds = 0.03
        await plugin.initialize()
        try:
            business_logger.error("first synthetic business error")
            await asyncio.wait_for(ctx.started.wait(), timeout=0.2)
            business_logger.error("second concurrent business error")
            await asyncio.sleep(0)
            await asyncio.wait_for(plugin._queue.join(), timeout=0.5)

            self.assertEqual(len(ctx.calls), 2)
            self.assertIn("first synthetic business error", ctx.calls[0])
            self.assertIn("second concurrent business error", ctx.calls[1])
            self.assertFalse(any("EN02_RECURSION_SECRET" in call for call in ctx.calls))
            self.assertEqual(plugin._dropped_alerts, 0)
            self.assertEqual(plugin.delivery_stats.attempted, 2)
            self.assertEqual(plugin.delivery_stats.failed, 1)
            self.assertEqual(plugin.delivery_stats.delivered, 1)
        finally:
            await plugin.terminate()
            for logger in (business_logger, adapter_logger):
                KIRA_LOGGING._created_by_get_logger.discard(logger.name)
                logger.handlers.clear()

    async def test_policy_limit_is_not_counted_as_attempt_or_delivery(self):
        ctx = FakeContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "cooldown_seconds": 0,
                "max_alerts_per_hour": 1,
            },
        )
        await plugin.initialize()
        try:
            for index in range(2):
                await plugin.handle_exception(
                    None,
                    KiraExceptionEvent(
                        name="APIError",
                        message=f"synthetic rate limit item {index}",
                        source="provider",
                        comp_id="provider-gateway",
                        stage="agent_loop",
                    ),
                )
            await asyncio.wait_for(plugin._queue.join(), timeout=0.5)

            self.assertEqual(len(ctx.sent), 1)
            self.assertEqual(plugin.delivery_stats.rate_limited, 1)
            self.assertEqual(plugin.delivery_stats.attempted, 1)
            self.assertEqual(plugin.delivery_stats.delivered, 1)
        finally:
            await plugin.terminate()

    async def test_terminate_cancels_inflight_send_and_clears_state(self):
        class BlockingContext:
            def __init__(self):
                self.started = asyncio.Event()
                self.cancelled = asyncio.Event()

            async def send_message_chain(self, _session, _chain):
                self.started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    self.cancelled.set()

        ctx = BlockingContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "cooldown_seconds": 0,
                "send_timeout_seconds": 30,
            },
        )
        await plugin.initialize()
        await plugin.handle_exception(
            None,
            KiraExceptionEvent(
                name="APIError",
                message="synthetic termination item",
                source="provider",
                comp_id="provider-gateway",
                stage="agent_loop",
            ),
        )
        await asyncio.wait_for(ctx.started.wait(), timeout=0.2)
        await plugin.handle_exception(
            None,
            KiraExceptionEvent(
                name="APIError",
                message="synthetic queued termination item",
                source="provider",
                comp_id="provider-gateway",
                stage="agent_loop",
            ),
        )

        await asyncio.wait_for(plugin.terminate(), timeout=0.2)
        await asyncio.wait_for(plugin._queue.join(), timeout=0.2)

        self.assertTrue(ctx.cancelled.is_set())
        self.assertFalse(plugin._active)
        self.assertFalse(plugin._sending_notification)
        self.assertIsNone(plugin._worker_task)
        self.assertIsNone(plugin._scanner_task)
        self.assertEqual(plugin._pending_log_callbacks, 0)
        self.assertTrue(plugin._queue.empty())
        self.assertEqual(plugin._dropped_alerts, 1)

    async def test_outbound_message_redacts_spaced_secret_without_erasing_context(self):
        ctx = FakeContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "message_template": "{component}|{error_type}|{summary}",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            await plugin.handle_exception(
                None,
                KiraExceptionEvent(
                    name="APIError",
                    message=(
                        'request failed password="EN01_OUTBOUND TWO WORDS" '
                        "code=503"
                    ),
                    source="provider",
                    comp_id="provider-gateway",
                    stage="agent_loop",
                ),
            )
            await asyncio.wait_for(plugin._queue.join(), timeout=1)

            content = ctx.sent[0][1]
            self.assertNotIn("EN01_OUTBOUND", content)
            self.assertNotIn("TWO WORDS", content)
            self.assertIn("provider-gateway|APIError|request failed", content)
            self.assertIn("code=503", content)
        finally:
            await plugin.terminate()

    async def test_hidden_summary_keeps_type_and_component_readable(self):
        ctx = FakeContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "synthetic:dm:test-target",
                "message_template": "{component}|{error_type}|{summary}",
                "include_error_summary": False,
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            await plugin.handle_exception(
                None,
                KiraExceptionEvent(
                    name="APIError",
                    message="password=EN01_HIDDEN_SECRET",
                    source="provider",
                    comp_id="provider-gateway",
                    stage="agent_loop",
                ),
            )
            await asyncio.wait_for(plugin._queue.join(), timeout=1)
            self.assertEqual(
                ctx.sent[0][1],
                "provider-gateway|APIError|（已按配置隐藏）",
            )
        finally:
            await plugin.terminate()

    async def test_send_failure_log_redacts_adapter_error(self):
        class FailedContext:
            async def send_message_chain(self, _session, _chain):
                return types.SimpleNamespace(
                    ok=False,
                    err="Authorization: Bearer EN01_LOG_SECRET",
                )

        plugin = PLUGIN.ErrorNotifierPlugin(FailedContext(), {})
        with self.assertLogs(PLUGIN.NOTIFIER_LOGGER_NAME, level="ERROR") as logs:
            await plugin._send_text("safe synthetic message")

        output = "\n".join(logs.output)
        self.assertNotIn("EN01_LOG_SECRET", output)
        self.assertIn("Failed to send error notification", output)

    async def test_blacklisted_exception_is_not_sent(self):
        ctx = FakeContext()
        plugin = PLUGIN.ErrorNotifierPlugin(
            ctx,
            {
                "enabled": True,
                "monitor_mode": "on_exception",
                "target_session": "qq:dm:1",
                "error_blacklist": "temporary upstream failure\nignoredtype",
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            await plugin.handle_exception(
                None,
                KiraExceptionEvent(
                    name="IgnoredType",
                    message="should not be sent",
                    source="provider",
                    comp_id="openai",
                    stage="agent_loop",
                ),
            )
            await plugin.handle_exception(
                None,
                KiraExceptionEvent(
                    name="APIError",
                    message="TEMPORARY upstream failure while retrying",
                    source="provider",
                    comp_id="openai",
                    stage="agent_loop",
                ),
            )
            await asyncio.sleep(0)

            self.assertEqual(ctx.sent, [])
            self.assertTrue(plugin._queue.empty())
        finally:
            await plugin.terminate()

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

    async def test_blacklisted_log_is_not_sent_or_scheduled(self):
        ctx = FakeContext()
        logger = logging.getLogger("source_for_blacklist_test")
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
                "error_blacklist": ["database is read-only"],
                "cooldown_seconds": 0,
            },
        )
        await plugin.initialize()
        try:
            logger.error("DATABASE is read-only during startup")
            await asyncio.sleep(0)
            await asyncio.wait_for(plugin._queue.join(), timeout=1)

            self.assertEqual(ctx.sent, [])
            self.assertEqual(plugin._pending_log_callbacks, 0)
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
