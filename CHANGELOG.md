# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
