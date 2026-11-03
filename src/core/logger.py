import logging
import os

from concurrent_log_handler import ConcurrentRotatingFileHandler

from src.core.config.environment import LOG_LEVEL, LOG_DIR


_LOG_FORMAT = "[%(asctime)s][%(levelname)s][PID %(process)d]::%(message)s"
_DATE_FORMAT = "%m/%d/%Y %I:%M:%S %p"


def _resolve_level(value) -> int:
    """Accept a numeric level ("20"/20) or a name ("INFO"); default INFO."""
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    return getattr(logging, text.upper(), logging.INFO)


def setup_logging():
    """Configure application logging.

    Logs to stdout/stderr by default (the container captures it via `docker
    logs`). File logging is opt-in: set LOG_DIR to a writable directory to also
    write a rotating log file there. Level is controlled by LOG_LEVEL
    (name or number), defaulting to INFO.
    """
    level = _resolve_level(LOG_LEVEL)

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.handlers = []

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # Optional rotating file handler. Only enabled when LOG_DIR is set, and
    # guarded so a file-logging problem can never crash the app or flood the
    # console with a per-record traceback (the previous behaviour when the log
    # directory did not exist -> FileNotFoundError on every emit()).
    file_logging = False
    if LOG_DIR:
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            log_file = os.path.join(LOG_DIR, "adaptive-auth.log")
            # makedirs succeeds on a directory that already exists but that this
            # user cannot write (a root-owned volume once the image runs as
            # non-root, or a read-only mount). The handler would then fail on
            # every emit(), and logging prints each failure as a traceback.
            # Check up front instead: the handler needs the directory for its
            # lock file and for rotation, and the file itself for appending.
            if not os.access(LOG_DIR, os.W_OK | os.X_OK):
                raise PermissionError(f"directory is not writable: {LOG_DIR}")
            with open(log_file, "a", encoding="utf-8"):
                pass
            file_handler = ConcurrentRotatingFileHandler(
                log_file,
                mode="a",
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level)
            logger.addHandler(file_handler)
            file_logging = True
        except OSError as exc:
            logger.warning(
                "File logging disabled; could not use LOG_DIR=%s: %s", LOG_DIR, exc
            )

    logging.info(
        "Logging is configured (level=%s, file=%s).",
        logging.getLevelName(level),
        file_logging,
    )
