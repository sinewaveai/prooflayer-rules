"""
Structured JSON Logging
========================

Provides a JSON log formatter for ProofLayer modules.
When config has format=json, all loggers use this formatter.

Log format:
    {"timestamp": "...", "level": "INFO", "module": "engine", "message": "...", "extra": {...}}
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }

        # Collect extra fields set via `logger.info("msg", extra={...})`
        extra = {}
        # Standard LogRecord attributes to exclude
        _standard_attrs = {
            "name", "msg", "args", "created", "relativeCreated",
            "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "pathname", "filename", "module", "thread", "threadName",
            "process", "processName", "levelname", "levelno", "message",
            "msecs", "taskName",
        }
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _standard_attrs:
                continue
            extra[key] = value

        if extra:
            log_entry["extra"] = extra

        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def configure_logging(
    level: str = "INFO",
    log_format: str = "text",
    logger_names: Optional[list] = None,
) -> None:
    """
    Configure ProofLayer logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: "json" for structured JSON, "text" for standard text format
        logger_names: Specific logger names to configure. If None, configures
                      the root 'prooflayer' logger (which propagates to all children).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    if log_format == "json":
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    names = logger_names or ["prooflayer"]

    for name in names:
        lgr = logging.getLogger(name)
        lgr.setLevel(log_level)
        # Avoid duplicate handlers on repeated calls
        lgr.handlers = [handler]
