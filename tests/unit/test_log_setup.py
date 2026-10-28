"""Operational logging: handlers, level, file creation and rotation."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from opencanary_correlator.log_setup import (
    DEFAULT_BACKUPS,
    DEFAULT_MAX_BYTES,
    LogSetupError,
    configure_logging,
)

LOGGER_NAME = "opencanary_correlator.test"


def flush_root() -> None:
    """Flush every root handler so the file content is readable immediately."""
    for handler in logging.getLogger().handlers:
        handler.flush()


def test_file_handler_writes_records_and_creates_the_directory(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "logs" / "correlator.log"

    configure_logging("INFO", target)
    logging.getLogger(LOGGER_NAME).warning("delivery failed: http_500")
    flush_root()

    text = target.read_text(encoding="utf-8")
    assert LOGGER_NAME in text
    assert "WARNING" in text
    assert "delivery failed: http_500" in text


def test_level_filters_lower_severity_records(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"
    logger = logging.getLogger(LOGGER_NAME)

    configure_logging("ERROR", target)
    logger.info("routine chatter")
    logger.error("redis unavailable")
    flush_root()

    text = target.read_text(encoding="utf-8")
    assert "redis unavailable" in text
    assert "routine chatter" not in text


def test_configure_logging_sets_the_root_level() -> None:
    configure_logging("DEBUG")

    assert logging.getLogger().level == logging.DEBUG


def test_empty_path_keeps_stderr_only() -> None:
    handlers = configure_logging("INFO", "")

    assert [type(handler).__name__ for handler in handlers] == ["StreamHandler"]


def test_configure_logging_replaces_its_own_handlers(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"

    configure_logging("INFO", target)
    configure_logging("INFO", target)

    managed = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, "occ_managed", False)
    ]
    assert len(managed) == 2  # stderr + file, not two of each


def test_the_file_rotates_at_the_size_limit(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"
    logger = logging.getLogger(LOGGER_NAME)

    configure_logging("INFO", target, max_bytes=512, backups=2)
    for index in range(200):
        logger.warning("event %d %s", index, "x" * 40)
    flush_root()

    assert target.exists()
    assert (tmp_path / "correlator.log.1").exists()
    assert not (tmp_path / "correlator.log.3").exists()


def test_a_payload_cannot_forge_an_extra_log_line(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"

    configure_logging("INFO", target)
    logging.getLogger(LOGGER_NAME).warning(
        "could not render incident %s",
        "incident:hd:1.2.3.4\r\n2026-01-01 ERROR forged line",
    )
    flush_root()

    text = target.read_text(encoding="utf-8")
    lines = text.splitlines()

    # One physical line: the CRLF inside the payload became spaces, so the fake
    # "2026-01-01 ERROR ..." tail stays attached to the real record instead of
    # starting a line of its own.
    assert len(lines) == 1
    assert "\r" not in text
    assert "WARNING" in lines[0]
    assert "could not render incident incident:hd:1.2.3.4" in lines[0]
    assert "2026-01-01 ERROR forged line" in lines[0]


def test_http_request_lines_do_not_carry_the_bot_token(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"

    configure_logging("INFO", target)
    # What httpx writes for every Telegram delivery; the token is part of the URL
    # because the Bot API has no header or body alternative.
    logging.getLogger("httpx").info(
        "HTTP Request: POST "
        'https://api.telegram.org/bot123456:SUPERSECRET/sendMessage "HTTP/1.1 200 OK"'
    )
    flush_root()

    text = target.read_text(encoding="utf-8")
    assert "SUPERSECRET" not in text
    assert "123456" not in text
    assert "https://api.telegram.org/bot***/sendMessage" in text


def test_configured_secrets_are_masked_by_value(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"

    configure_logging("INFO", target, secrets=["/hook/ARBITRARY-SECRET", "tok"])
    logging.getLogger(LOGGER_NAME).warning(
        "POST https://siem.example/hook/ARBITRARY-SECRET failed for token tok"
    )
    flush_root()

    text = target.read_text(encoding="utf-8")
    assert "ARBITRARY-SECRET" not in text
    assert "https://siem.example" in text
    # Too short to be a useful secret: masking it would mangle the log for nothing.
    assert "token tok" in text


def test_a_traceback_does_not_carry_the_token(tmp_path: Path) -> None:
    target = tmp_path / "correlator.log"

    configure_logging("ERROR", target)
    try:
        raise ValueError("Invalid URL 'https://api.telegram.org/bot123456:SUPERSECRET/sendMessage'")
    except ValueError:
        logging.getLogger("opencanary_correlator.test").exception("delivery crashed")
    flush_root()

    text = target.read_text(encoding="utf-8")
    assert "Traceback (most recent call last)" in text
    assert "SUPERSECRET" not in text
    assert "https://api.telegram.org/bot***/sendMessage" in text


def test_an_unopenable_path_raises_instead_of_logging_nowhere(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    with pytest.raises(LogSetupError):
        configure_logging("INFO", blocker / "correlator.log")


def test_defaults_are_documented_values() -> None:
    assert DEFAULT_MAX_BYTES == 10 * 1024 * 1024
    assert DEFAULT_BACKUPS == 5
