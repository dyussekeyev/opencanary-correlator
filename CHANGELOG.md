# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.2] - 2026-10-28

### Added

- `OCC_LOG_FILE` writes the operational log to a size-rotated UTF-8 file
  (10 MiB × 5 backups) in addition to stderr, and `--log-file` overrides it.
  `OCC_LOG_LEVEL` now also accepts `WARN` and `FATAL`. An unopenable log path
  stops startup with exit code `2` instead of running without logs.
- `docker-compose.yml` mounts a `correlator-logs` volume at
  `/var/log/opencanary-correlator` and points `OCC_LOG_FILE` at
  `/var/log/opencanary-correlator/logs/correlator.log`, so a file-based agent can
  collect the rotated log. The image ships that `logs/` directory owned by the
  runtime UID; Docker copies it into the volume with its ownership, so the
  unprivileged process can write without an init container. An empty
  `OCC_LOG_FILE` keeps stderr-only behaviour.
- Log records are flattened to one line, so a payload containing CRLF cannot
  forge an entry in the file a SIEM agent ingests.
- Per-channel alert detail: `OCC_TELEGRAM_DETAIL`, `OCC_SLACK_DETAIL`,
  `OCC_DISCORD_DETAIL`, `OCC_WEBHOOK_DETAIL` and `OCC_SMTP_DETAIL` accept
  `minimal`, `standard` or `detailed`. Chat channels default to `standard`;
  webhook and SMTP stay on `minimal` so SIEM parsers keep the legacy text.
- `connectors/dispatchers/alert_text.py` renders the multiline alert: the
  instance block (node name, host IP) first, then the attacker (IP and source
  port), the detection time and a log message summary. `detailed` adds the
  destination address, the event counter and more log entries.

### Changed

- Telegram sends the rendered layout with `parse_mode=MarkdownV2`, Slack with
  mrkdwn and Discord with markdown; every field is escaped for its channel and
  lines are separated with CRLF.
- Alert fields are sanitised before delivery: control characters are stripped,
  long values are clipped, and `logdata` keys that look like credentials
  (`PASSWORD`, `SECRET`, `TOKEN`, ...) are masked as `***`.

`minimal` stays byte-identical to 0.3.1 on every channel for messages that fit
the channel limit; a truncated message now ends with `…` instead of a hard cut.

### Fixed

- Bot and webhook secrets no longer reach the logs. `httpx` logs every request
  URL at `INFO`, and the Telegram Bot API only accepts the token as part of the
  path, so the token appeared in stderr and in the rotated log file. Log output
  is now redacted in the record and again at format time — covering tracebacks
  as well — masking `api.telegram.org/bot<token>`, Slack and Discord webhook
  paths, URL passwords, `?token=`/`?api_key=`-style query parameters and the
  configured endpoint URLs by exact value (the case of a token in the path of an
  arbitrary webhook host). The same filters cover the legacy console journal.
- Captured credentials are no longer logged. The SMB fallback branch logged the
  raw `logdata`, which can hold a password the canary captured; it now logs the
  incident key.
- Webhook, Slack and Discord URLs are hidden from `repr()` of the settings, and
  configuration errors name the list position and host instead of echoing the
  URL, so a bad entry cannot print its credential on startup.
- SMTP no longer drops an alert when a honeypot field contains CR/LF. Header
  values are flattened before rendering, and a rendering error is returned as a
  failed delivery instead of escaping `dispatch`, so the incident is audited and
  the remaining channels still receive it.

## [0.3.1] - 2026-10-26

Internal refactor. Behaviour, public interfaces, Redis key layout and audit
records are unchanged.

### Changed

- `incident.py` is split into `incident_model.py` (incident types) and
  `incident_report.py` (report building). Lua scripts moved to `storage/scripts.py`.
- Configuration validators moved from `config.py` into `config_validation.py`;
  `config.py` re-exports them, so existing imports keep working.
- TCP and syslog receivers share a base in `connectors/receivers/_base.py`.
- CLI dispatcher wiring uses one helper (`add_endpoints`); receiver arguments are shared.
- `docs/architecture.md` describes the new modules.

## [0.3.0] - 2026-10-25

Beta release. Production-readiness work: the public interfaces stay compatible
with `opencanaryd` (TCP JSON over `SocketHandler`, and syslog).

### Added

- Allowlist for the TCP and syslog receivers (`_allowlist.py`), with tests.
- `.gitattributes` for consistent line endings.
- Audit-event reference (`docs/audit-events.md`) now documents `alert_dispatch` outcomes for alerting.

### Changed

- Incident storage keeps a capped event list. Memory use stops growing once the
  cap is reached; the integration test checks this against a real Redis.
- Audit records always carry `timestamp`, `component`, `action`, `status` and
  `details`.
- README states that the health and `/metrics` ports must not be exposed publicly
  and that `/metrics` is not authenticated.

### Removed

- The legacy Python 2 tree (`opencanary_correlator/`, `bin/`, `setup.py`). The
  `legacy-py2` git tag keeps it in history.

### Security

- Telegram bot tokens are kept out of dispatch results, audit records and
  exception details; there is a test for this.
- Webhook, Slack and Discord URLs are validated in configuration: only http/https, and plain http only for loopback hosts.

## [0.2.0]

- Initial async rewrite: TCP JSON and syslog receivers, Redis-backed correlation,
  dispatchers for Telegram, SIEM webhooks, Slack, Discord and SMTP.
