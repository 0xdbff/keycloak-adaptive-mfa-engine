import builtins
import logging

import pytest
from concurrent_log_handler import ConcurrentRotatingFileHandler

import src.core.logger as logger_mod


@pytest.fixture
def root_logger(monkeypatch):
    """setup_logging() replaces the root handlers; put pytest's back afterwards."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    monkeypatch.setattr(logger_mod, "LOG_LEVEL", "INFO")
    yield root
    for handler in root.handlers:
        if handler not in handlers:
            handler.close()
    root.handlers, root.level = handlers, level


def _file_handlers(root):
    return [h for h in root.handlers if isinstance(h, ConcurrentRotatingFileHandler)]


def test_no_log_dir_logs_to_the_console_only(root_logger, monkeypatch, capsys):
    monkeypatch.setattr(logger_mod, "LOG_DIR", None)
    logger_mod.setup_logging()
    assert _file_handlers(root_logger) == []
    assert "file=False" in capsys.readouterr().err


def test_writable_log_dir_writes_the_log_file(root_logger, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(logger_mod, "LOG_DIR", str(tmp_path / "logs"))
    logger_mod.setup_logging()
    assert len(_file_handlers(root_logger)) == 1
    logging.info("hello from the test")
    assert "hello from the test" in (tmp_path / "logs" / "adaptive-auth.log").read_text()
    assert "file=True" in capsys.readouterr().err


def test_unwritable_directory_falls_back_to_one_warning(root_logger, monkeypatch, tmp_path, capsys):
    # A directory that exists but this user cannot write, as a root-owned volume
    # is for the non-root image. Simulated, since the tests may run as root.
    monkeypatch.setattr(logger_mod, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(logger_mod.os, "access", lambda path, mode: False)
    logger_mod.setup_logging()
    for _ in range(5):
        logging.info("still logging")
    err = capsys.readouterr().err
    assert _file_handlers(root_logger) == []
    assert err.count("File logging disabled") == 1
    assert "file=False" in err
    assert err.count("still logging") == 5
    assert "Logging error" not in err


def test_log_file_that_cannot_be_opened_falls_back(root_logger, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(logger_mod, "LOG_DIR", str(tmp_path))
    real_open = builtins.open

    def refuse_log_file(file, *args, **kwargs):
        if str(file).endswith("adaptive-auth.log"):
            raise PermissionError(13, "Permission denied", str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", refuse_log_file)
    logger_mod.setup_logging()
    logging.info("after the fallback")
    err = capsys.readouterr().err
    assert _file_handlers(root_logger) == []
    assert err.count("File logging disabled") == 1
    assert "after the fallback" in err
    assert "Logging error" not in err
