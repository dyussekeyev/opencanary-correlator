"""Operational logging for the correlator.

The service writes two independent streams:

* the **operational log** (this module) — timestamp, level, logger name and
  message, sent to stderr and, when ``OCC_LOG_FILE`` is set, also to a
  size-rotated UTF-8 file. This is the stream to read when something fails:
  receiver errors, dispatcher failures and shutdown problems all land here;
* the **audit trail** (``audit.py``) — one JSON object per line on stdout, ready
  for direct ingestion into Elastic Security or Wazuh.

Adding a file must not change container behaviour, so the file handler is
additive: stdout and stderr keep receiving exactly what they did before.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final

from opencanary_correlator.redaction import redact_url_secrets, sanitize_text

#: Timestamp, level, logger and message — greppable and human-readable.
LOG_FORMAT: Final[str] = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
LOG_DATE_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S%z"

#: 10 MiB × 5 keeps an incident-heavy week inside 60 MiB without configuration.
DEFAULT_MAX_BYTES: Final[int] = 10 * 1024 * 1024
DEFAULT_BACKUPS: Final[int] = 5

#: Third-party loggers capped at WARNING, whatever ``OCC_LOG_LEVEL`` says.
#:
#: ``httpx`` logs every request line (``HTTP Request: POST <url>``) at INFO and
#: ``httpcore``/``h11``/``hpack`` log connection and frame details at DEBUG. The
#: Telegram Bot API only accepts its token in the URL path and Slack/Discord
#: keep the secret in the webhook path, so the redaction filters have to reconstruct
#: those URLs from arbitrary text — the reliable answer is not to emit them at all.
#: A genuine failure from these libraries is still logged: it arrives at WARNING
#: or above, which is the level the correlator's own `alert_dispatch` record
#: also reports.
NOISY_LOGGERS: Final[tuple[str, ...]] = ("httpx", "httpcore", "h11", "hpack")

_MANAGED: Final[str] = "occ_managed"
#: Invalid Unicode must never turn a log call into a logging error.
_FILE_ERRORS: Final[str] = "backslashreplace"


class LogSetupError(RuntimeError):
    """Raised when the configured log file cannot be opened."""


class SingleLineFilter(logging.Filter):
    """Keep every record on one line.

    Some log calls carry honeypot data (`src_host` is only length-bounded when
    an event is validated), so a payload could contain CRLF and forge an extra
    line in the file a SIEM agent ingests. Tracebacks stay multi-line: only the
    message itself is flattened, which is what an attacker controls.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Replace CR/LF and remaining control characters with spaces."""
        try:
            message = record.getMessage()
        except Exception:  # a broken record must never block logging
            return True
        cleaned = sanitize_text(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = None
        return True


#: Short strings are not redacted by value: masking every "pass" or "tok"
#: would destroy the log without protecting anything meaningful.
_MIN_SECRET_LENGTH: Final[int] = 8


def normalise_secrets(secrets: Iterable[str] = ()) -> tuple[str, ...]:
    """Return the configured secrets, longest first, ignoring trivial values."""
    unique = {secret for secret in secrets if len(secret) >= _MIN_SECRET_LENGTH}
    return tuple(sorted(unique, key=len, reverse=True))


def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Mask configured secrets and URL-embedded credentials in `text`.

    Configured values are matched literally, so a webhook URL that keeps its
    credential in a path segment no host-based pattern knows about is covered
    too. The pattern pass then catches anything the configuration did not name
    (a token echoed by a library, a Redis URL in an exception).
    """
    text = redact_url_secrets(text)
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


class SecretRedactionFilter(logging.Filter):
    """Mask configured and URL-embedded credentials in the record message.

    The formatter below covers tracebacks, but a handler that formats records
    on its own (``caplog``, an operator's ``SysLogHandler``, the Redis journal)
    would still see the raw text, so the message is redacted at record level too.
    """

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._secrets = normalise_secrets(secrets)

    def filter(self, record: logging.LogRecord) -> bool:
        """Replace configured and URL-embedded secrets in the record message."""
        try:
            message = record.getMessage()
        except Exception:  # a broken record must never block logging
            return True
        redacted = redact_text(message, self._secrets)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


class RedactingFormatter(logging.Formatter):
    """Formatter that masks credentials embedded in URLs.

    Applied at format time, not in a filter, because ``exc_info`` tracebacks are
    rendered by the formatter: an exception whose message carries a request URL
    (``httpx`` reports a URL in ``InvalidURL``) would otherwise keep the token
    even though the log record itself was clean.

    `httpx` logs every request URL at INFO (``HTTP Request: POST <url>``), and the
    Telegram Bot API only accepts the bot token as part of the path — it cannot be
    moved to a header or the body. Slack and Discord webhook URLs hide their
    secret in the path the same way, and Redis/Vault-style URLs may carry a
    password.
    """

    def __init__(
        self,
        fmt: str = LOG_FORMAT,
        datefmt: str = LOG_DATE_FORMAT,
        secrets: Iterable[str] = (),
    ) -> None:
        super().__init__(fmt, datefmt=datefmt)
        self._secrets = normalise_secrets(secrets)

    def format(self, record: logging.LogRecord) -> str:
        """Format the record, then redact configured and URL secrets."""
        return redact_text(super().format(record), self._secrets)


def build_formatter(secrets: Iterable[str] = ()) -> logging.Formatter:
    """Return the formatter shared by the stderr and file handlers."""
    return RedactingFormatter(secrets=secrets)


def _build_file_handler(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backups: int = DEFAULT_BACKUPS,
    secrets: Iterable[str] = (),
) -> RotatingFileHandler:
    """Open (and rotate) the log file, creating its directory if needed."""
    target = Path(path).expanduser()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            target,
            maxBytes=max_bytes,
            backupCount=backups,
            encoding="utf-8",
            errors=_FILE_ERRORS,
        )
    except OSError as exc:
        raise LogSetupError(f"{target}: {exc}") from exc
    handler.setFormatter(build_formatter(secrets))
    handler.addFilter(SingleLineFilter())
    handler.addFilter(SecretRedactionFilter(secrets))
    setattr(handler, _MANAGED, True)
    return handler


def configure_logging(
    level: str,
    log_file: str | Path | None = None,
    *,
    secrets: Iterable[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    backups: int = DEFAULT_BACKUPS,
) -> list[logging.Handler]:
    """Install the stderr handler and, when `log_file` is set, the file handler.

    `secrets` are the configured endpoint URLs and tokens: they are matched
    literally and replaced with `***`, so a credential survives no matter where a
    library decides to print it (query string, path segment of an arbitrary
    webhook host, exception message).

    Handlers installed by a previous call are removed first, so calling this
    twice (tests, a reloaded worker) never duplicates lines. The level is set on
    the root logger, which is what ``OCC_LOG_LEVEL`` promises.

    Returns the installed handlers, and raises :class:`LogSetupError` when the
    log file cannot be opened: silently logging nowhere would hide the very
    failures this file exists for.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, _MANAGED, False):
            root.removeHandler(handler)
            handler.close()

    handlers: list[logging.Handler] = []
    stream = logging.StreamHandler()
    stream.setFormatter(build_formatter(secrets))
    stream.addFilter(SingleLineFilter())
    stream.addFilter(SecretRedactionFilter(secrets))
    setattr(stream, _MANAGED, True)
    handlers.append(stream)
    if log_file:
        handlers.append(
            _build_file_handler(log_file, max_bytes=max_bytes, backups=backups, secrets=secrets)
        )

    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)
    # DEBUG is for the correlator's own decisions. Library chatter carries request
    # URLs and response fragments — the exact places a bot token lives — so those
    # loggers are capped here rather than relying on pattern redaction alone.
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    return handlers


__all__ = [
    "DEFAULT_BACKUPS",
    "DEFAULT_MAX_BYTES",
    "LOG_DATE_FORMAT",
    "LOG_FORMAT",
    "NOISY_LOGGERS",
    "LogSetupError",
    "RedactingFormatter",
    "SecretRedactionFilter",
    "SingleLineFilter",
    "build_formatter",
    "configure_logging",
    "normalise_secrets",
    "redact_text",
]
