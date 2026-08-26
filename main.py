from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

import core.logging_manager as kira_logging
from core.chat.message_utils import KiraExceptionEvent, MessageChain
from core.logging_manager import get_logger
from core.plugin import BasePlugin, Priority, on


PLUGIN_ID = "kira-ai-plugin-error-notifier"
MODE_ON_EXCEPTION = "on_exception"
MODE_ALL_ERROR = "all_error"
VALID_MODES = {MODE_ON_EXCEPTION, MODE_ALL_ERROR}
NOTIFIER_LOGGER_NAME = "error_notifier"

DEFAULT_MESSAGE_TEMPLATE = """【KiraAI 异常提醒】

时间：{time}
来源：{source}
模块：{component}
阶段：{stage}
异常：{error_type}
摘要：{summary}
相同错误已合并：{repeat_count} 次

KiraAI 当前进程仍在运行。"""

_notifier_logger = get_logger(NOTIFIER_LOGGER_NAME, "red")

_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|secret|password|passkey|access[_-]?token|"
    r"refresh[_-]?token|authorization)\b[\"']?\s*[:=]\s*)[\"']?[^\"',;\s}\]]+"
)
_BEARER_RE = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:api[_-]?key|token|secret|password|passkey|access[_-]?token)=)[^&\s]+"
)
_LONG_ID_RE = re.compile(r"\b\d{8,20}\b")
_TRACEBACK_FILE_RE = re.compile(r'^\s*File "[^"]+", line \d+', re.MULTILINE)
_ISO_TIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_CLOCK_TIME_RE = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b")
_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
_LONG_HEX_RE = re.compile(r"(?i)\b[0-9a-f]{16,}\b")
_RETRY_NUMBER_RE = re.compile(
    r"(?i)\b(attempt|retry|retries|count)\b([\s:=#/-]*)\d+\b"
)
_ZH_RETRY_RE = re.compile(r"第\s*\d+\s*次")


def sanitize_text(value: object, max_chars: int = 400) -> str:
    """Remove common credentials and compact a value for an outbound alert."""
    text = str(value or "")
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _SENSITIVE_VALUE_RE.sub(r"\1[REDACTED]", text)
    text = _URL_SECRET_RE.sub(r"\1[REDACTED]", text)
    text = _LONG_ID_RE.sub("[ID]", text)
    text = " ".join(text.split())
    if not text:
        return "（无错误摘要）"
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def summarize_error_text(value: object, max_chars: int = 400) -> str:
    """Return a redacted one-line summary and omit Python traceback frames."""
    raw = str(value or "")
    if "Traceback (most recent call last):" in raw or _TRACEBACK_FILE_RE.search(raw):
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        final_line = lines[-1] if lines else "Python traceback omitted"
        raw = f"Python traceback omitted; {final_line}"
    return sanitize_text(raw, max_chars)


def normalize_fingerprint_text(value: str) -> str:
    """Remove volatile timestamps, request IDs and retry counters from a fingerprint."""
    text = value.lower()
    text = _ISO_TIME_RE.sub("<time>", text)
    text = _CLOCK_TIME_RE.sub("<time>", text)
    text = _UUID_RE.sub("<id>", text)
    text = _LONG_HEX_RE.sub("<id>", text)
    text = _RETRY_NUMBER_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<n>", text)
    text = _ZH_RETRY_RE.sub("第<n>次", text)
    return text


@dataclass(frozen=True)
class Alert:
    timestamp: str
    source: str
    component: str
    stage: str
    error_type: str
    summary: str

    @property
    def fingerprint(self) -> str:
        raw = "\x1f".join(
            (
                self.source,
                self.component,
                self.stage,
                self.error_type,
                normalize_fingerprint_text(self.summary),
            )
        )
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class _GateEntry:
    last_sent: float = float("-inf")
    last_seen: float = 0.0
    suppressed: int = 0


class AlertGate:
    """Deduplicate alerts and enforce a global hourly send cap."""

    def __init__(self, cooldown_seconds: int, max_alerts_per_hour: int):
        self.cooldown_seconds = max(0, int(cooldown_seconds))
        self.max_alerts_per_hour = max(1, int(max_alerts_per_hour))
        self._entries: dict[str, _GateEntry] = {}
        self._sent_times: deque[float] = deque()

    def check(self, fingerprint: str, now: Optional[float] = None) -> tuple[bool, int]:
        now = time.monotonic() if now is None else now
        hour_ago = now - 3600
        while self._sent_times and self._sent_times[0] <= hour_ago:
            self._sent_times.popleft()

        entry = self._entries.setdefault(fingerprint, _GateEntry())
        entry.last_seen = now

        if now - entry.last_sent < self.cooldown_seconds:
            entry.suppressed += 1
            self._trim_entries()
            return False, 0

        if len(self._sent_times) >= self.max_alerts_per_hour:
            entry.suppressed += 1
            self._trim_entries()
            return False, 0

        repeat_count = entry.suppressed
        entry.suppressed = 0
        entry.last_sent = now
        self._sent_times.append(now)
        self._trim_entries()
        return True, repeat_count

    def _trim_entries(self):
        if len(self._entries) <= 1024:
            return
        oldest = sorted(self._entries.items(), key=lambda item: item[1].last_seen)[:256]
        for fingerprint, _ in oldest:
            self._entries.pop(fingerprint, None)


class AsyncErrorHandler(logging.Handler):
    """Forward ERROR records without blocking or recursively logging from emit()."""

    def __init__(self, callback: Callable[[logging.LogRecord], None]):
        super().__init__(level=logging.ERROR)
        self._callback = callback

    def emit(self, record: logging.LogRecord):
        if record.name == NOTIFIER_LOGGER_NAME:
            return
        try:
            self._callback(record)
        except Exception:
            # Logging handlers must never break the application they observe.
            return


class ErrorNotifierPlugin(BasePlugin):
    def __init__(self, ctx, cfg: dict):
        super().__init__(ctx, cfg)
        self.enabled = bool(cfg.get("enabled", False))
        self.monitor_mode = str(cfg.get("monitor_mode", MODE_ON_EXCEPTION)).strip()
        if self.monitor_mode not in VALID_MODES:
            self.monitor_mode = MODE_ON_EXCEPTION

        self.target_session = str(cfg.get("target_session", "")).strip()
        self.message_template = str(
            cfg.get("message_template", DEFAULT_MESSAGE_TEMPLATE)
            or DEFAULT_MESSAGE_TEMPLATE
        )
        self.include_error_summary = bool(cfg.get("include_error_summary", True))
        self.notify_on_start = bool(cfg.get("notify_on_start", False))
        self.cooldown_seconds = self._as_int(cfg.get("cooldown_seconds", 300), 300, 0, 86400)
        self.max_alerts_per_hour = self._as_int(
            cfg.get("max_alerts_per_hour", 10), 10, 1, 1000
        )
        self.max_summary_chars = self._as_int(
            cfg.get("max_summary_chars", 400), 400, 100, 2000
        )
        self.error_blacklist = self._as_blacklist(cfg.get("error_blacklist", ""))

        self._gate = AlertGate(self.cooldown_seconds, self.max_alerts_per_hour)
        self._queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=100)
        self._worker_task: Optional[asyncio.Task] = None
        self._scanner_task: Optional[asyncio.Task] = None
        self._log_handler: Optional[AsyncErrorHandler] = None
        self._attached_loggers: set[logging.Logger] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._active = False
        self._sending_notification = False
        self._dropped_alerts = 0
        self._pending_log_callbacks = 0
        self._pending_log_callbacks_limit = 100
        self._pending_lock = threading.Lock()

    @staticmethod
    def _as_int(value: object, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return min(max(parsed, minimum), maximum)

    @staticmethod
    def _as_blacklist(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            candidates = value.splitlines()
        elif isinstance(value, (list, tuple, set)):
            candidates = value
        else:
            candidates = ()

        patterns = []
        for candidate in candidates:
            pattern = str(candidate or "").strip().casefold()
            if pattern and pattern not in patterns:
                patterns.append(pattern)
        return tuple(patterns)

    def _is_blacklisted(self, alert: Alert) -> bool:
        if not self.error_blacklist:
            return False
        searchable = "\n".join(
            (
                alert.source,
                alert.component,
                alert.stage,
                alert.error_type,
                alert.summary,
            )
        ).casefold()
        return any(pattern in searchable for pattern in self.error_blacklist)

    async def initialize(self):
        if not self.enabled:
            _notifier_logger.info("Error notifier is disabled")
            return

        if not self._valid_target_session(self.target_session):
            _notifier_logger.warning(
                "Error notifier target_session is empty or invalid; expected adapter:dm|gm:id"
            )
            return

        self._loop = asyncio.get_running_loop()
        self._active = True
        self._worker_task = asyncio.create_task(
            self._alert_worker(), name=f"{PLUGIN_ID}:worker"
        )

        if self.monitor_mode == MODE_ALL_ERROR:
            self._log_handler = AsyncErrorHandler(self._on_log_record)
            self._attach_known_loggers()
            self._scanner_task = asyncio.create_task(
                self._logger_scanner(), name=f"{PLUGIN_ID}:logger-scanner"
            )

        _notifier_logger.info(
            "Error notifier initialized: mode=%s target_configured=yes",
            self.monitor_mode,
        )

        if self.notify_on_start:
            await self._send_text(
                "【KiraAI 恢复提醒】\n错误通知插件已加载，目标适配器当前可用。"
            )

    async def terminate(self):
        self._active = False
        self._detach_log_handler()

        tasks = [task for task in (self._scanner_task, self._worker_task) if task]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._scanner_task = None
        self._worker_task = None
        self._loop = None
        _notifier_logger.info("Error notifier terminated")

    @on.exception(priority=Priority.LOW)
    async def handle_exception(self, _event, exc_event: KiraExceptionEvent):
        if not self._active or self.monitor_mode != MODE_ON_EXCEPTION:
            return

        alert = Alert(
            timestamp=self._now_text(),
            source=sanitize_text(getattr(exc_event, "source", None) or "unknown", 80),
            component=sanitize_text(getattr(exc_event, "comp_id", None) or "unknown", 120),
            stage=sanitize_text(getattr(exc_event, "stage", None) or "unknown", 120),
            error_type=sanitize_text(getattr(exc_event, "name", None) or "Exception", 120),
            summary=summarize_error_text(
                getattr(exc_event, "message", None) or "", self.max_summary_chars
            ),
        )
        self._enqueue_nowait(alert)

    @staticmethod
    def _valid_target_session(value: str) -> bool:
        parts = value.split(":", maxsplit=2)
        return len(parts) == 3 and all(parts) and parts[1] in {"dm", "gm"}

    @staticmethod
    def _now_text() -> str:
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

    def _on_log_record(self, record: logging.LogRecord):
        if (
            not self._active
            or self.monitor_mode != MODE_ALL_ERROR
            or self._sending_notification
            or not self._loop
            or self._loop.is_closed()
        ):
            return

        try:
            summary = record.getMessage()
        except Exception:
            summary = str(record.msg)

        error_type = record.levelname
        if record.exc_info and record.exc_info[0]:
            error_type = record.exc_info[0].__name__

        alert = Alert(
            timestamp=self._now_text(),
            source="log",
            component=sanitize_text(record.name or "unknown", 120),
            stage="logging",
            error_type=sanitize_text(error_type, 120),
            summary=summarize_error_text(summary, self.max_summary_chars),
        )
        if self._is_blacklisted(alert):
            return
        self._schedule_log_alert(alert)

    def _schedule_log_alert(self, alert: Alert):
        loop = self._loop
        if not loop or loop.is_closed():
            return

        with self._pending_lock:
            if self._pending_log_callbacks >= self._pending_log_callbacks_limit:
                self._dropped_alerts += 1
                return
            self._pending_log_callbacks += 1

        try:
            loop.call_soon_threadsafe(self._enqueue_scheduled_log_alert, alert)
        except RuntimeError:
            with self._pending_lock:
                self._pending_log_callbacks = max(0, self._pending_log_callbacks - 1)
                self._dropped_alerts += 1

    def _enqueue_scheduled_log_alert(self, alert: Alert):
        with self._pending_lock:
            self._pending_log_callbacks = max(0, self._pending_log_callbacks - 1)
        self._enqueue_nowait(alert)

    def _enqueue_nowait(self, alert: Alert):
        if not self._active or self._is_blacklisted(alert):
            return
        try:
            self._queue.put_nowait(alert)
        except asyncio.QueueFull:
            with self._pending_lock:
                self._dropped_alerts += 1
                dropped_alerts = self._dropped_alerts
            if dropped_alerts == 1 or dropped_alerts % 100 == 0:
                _notifier_logger.warning(
                    "Error notifier queue is full; dropped alerts=%s",
                    dropped_alerts,
                )

    async def _alert_worker(self):
        while True:
            alert = await self._queue.get()
            try:
                allowed, repeat_count = self._gate.check(alert.fingerprint)
                if allowed:
                    await self._send_text(self._render_message(alert, repeat_count))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _notifier_logger.error("Failed to process error alert: %s", exc)
            finally:
                self._queue.task_done()

    def _render_message(self, alert: Alert, repeat_count: int) -> str:
        summary = alert.summary if self.include_error_summary else "（已按配置隐藏）"
        values = {
            "time": alert.timestamp,
            "source": alert.source,
            "component": alert.component,
            "stage": alert.stage,
            "error_type": alert.error_type,
            "summary": summary,
            "repeat_count": repeat_count,
            "mode": self.monitor_mode,
        }
        try:
            return self.message_template.format_map(values)
        except (KeyError, ValueError) as exc:
            _notifier_logger.warning(
                "Invalid message_template (%s); using the default template", exc
            )
            return DEFAULT_MESSAGE_TEMPLATE.format_map(values)

    async def _send_text(self, content: str):
        self._sending_notification = True
        try:
            result = await self.ctx.send_message_chain(
                self.target_session,
                MessageChain().text(content),
            )
            if not result or not getattr(result, "ok", False):
                error = getattr(result, "err", "no result") if result else "no result"
                _notifier_logger.error("Failed to send error notification: %s", error)
        except Exception as exc:
            _notifier_logger.error("Failed to send error notification: %s", exc)
        finally:
            self._sending_notification = False

    async def _logger_scanner(self):
        while True:
            await asyncio.sleep(3)
            self._attach_known_loggers()

    def _attach_known_loggers(self):
        if not self._log_handler:
            return

        logger_names = set(getattr(kira_logging, "_created_by_get_logger", set()))
        if not logger_names:
            logger_names = {
                name
                for name, value in logging.Logger.manager.loggerDict.items()
                if isinstance(value, logging.Logger) and value.handlers
            }

        for name in logger_names:
            if name == NOTIFIER_LOGGER_NAME:
                continue
            logger = logging.getLogger(name)
            if self._log_handler not in logger.handlers:
                logger.addHandler(self._log_handler)
            self._attached_loggers.add(logger)

    def _detach_log_handler(self):
        if not self._log_handler:
            return
        for logger in tuple(self._attached_loggers):
            try:
                logger.removeHandler(self._log_handler)
            except Exception:
                pass
        self._attached_loggers.clear()
        self._log_handler.close()
        self._log_handler = None
