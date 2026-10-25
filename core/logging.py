"""
统一日志配置模块
RotatingFileHandler + 可选请求关联 ID
"""
import logging
import os
import re
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from core.config import LOG_FILE, LOG_DIR, settings
from core.request_context import get_request_id

LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_ABS = LOG_FILE.resolve() if not LOG_FILE.is_absolute() else LOG_FILE


class RequestIdFilter(logging.Filter):
    _SENSITIVE = re.compile(
        r"(?i)(?P<key>authorization|cookie|set-cookie|access_token|refresh_token|session_key|secret|password|openid|unionid|phone|mobile|appid|reason|contact|account)[\"']?\s*[:=]\s*(?P<value>\"[^\"]*\"|'[^']*'|Bearer\s+[^\s,;&}]+|[^\s,;&}]+)"
    )

    @staticmethod
    def _safe_exception(exc_info) -> str:
        exc_type, exc, tb = exc_info
        parts = []
        seen = set()
        current = exc
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            frames = traceback.extract_tb(current.__traceback__)
            parts.extend(
                f"  File {frame.filename!r}, line {frame.lineno}, in {frame.name}\n"
                for frame in frames
            )
            parts.append(f"{type(current).__name__}: [REDACTED]")
            current = current.__cause__ or current.__context__
        return "\n".join(parts)

    def filter(self, record: logging.LogRecord) -> bool:
        original = record.getMessage()
        redacted = self._SENSITIVE.sub(lambda match: f"{match.group('key')}=[REDACTED]", original)
        if redacted != original:
            record.msg = redacted
            record.args = ()
        if record.exc_info:
            record.exc_text = self._safe_exception(record.exc_info)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self._SENSITIVE.sub(
                lambda match: f"{match.group('key')}=[REDACTED]", record.exc_text
            )
        record.request_id = get_request_id() or "-"
        return True


def setup_logging(
    level: int = logging.INFO,
    log_to_file: bool = True,
    log_to_console: bool = False,
    log_format: str | None = None,
) -> None:
    if log_format is None:
        log_format = (
            "%(asctime)s - %(name)s - %(levelname)s - "
            "[%(request_id)s] %(message)s"
        )

    handlers: list[logging.Handler] = []
    req_filter = RequestIdFilter()

    if log_to_file:
        log_file_path = LOG_FILE.resolve() if not LOG_FILE.is_absolute() else LOG_FILE
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_file_path),
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(log_format))
        file_handler.addFilter(req_filter)
        handlers.append(file_handler)

    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(log_format))
        console_handler.addFilter(req_filter)
        handlers.append(console_handler)

    logging.basicConfig(level=level, format=log_format, handlers=handlers, force=True)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


if os.environ.get("DS_LOG_CONSOLE_ONLY") == "1":
    setup_logging(log_to_file=False, log_to_console=True)
else:
    setup_logging(log_to_file=True, log_to_console=False)
