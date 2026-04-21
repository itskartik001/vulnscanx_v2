"""
VulnScanX - Structured Logger
"""
import logging
import json
import sys
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

COLORS = {
    "DEBUG": "\033[36m", "INFO": "\033[32m", "WARNING": "\033[33m",
    "ERROR": "\033[31m", "CRITICAL": "\033[35m", "RESET": "\033[0m",
}


class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = COLORS.get(record.levelname, COLORS["RESET"])
        reset = COLORS["RESET"]
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        name = record.name.split(".")[-1]
        return f"{color}[{ts}] [{record.levelname:<8}] [{name}]{reset} {record.getMessage()}"


class JSONFileHandler(logging.FileHandler):
    def emit(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        try:
            self.stream.write(json.dumps(log_entry) + "\n")
            self.flush()
        except Exception:
            self.handleError(record)


_loggers = {}


def get_logger(name: str) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]
    logger = logging.getLogger(f"vulnscanx.{name}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(ColorFormatter())
        logger.addHandler(ch)
        log_file = LOG_DIR / f"vulnscanx_{datetime.now().strftime('%Y%m%d')}.jsonl"
        fh = JSONFileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    _loggers[name] = logger
    return logger
