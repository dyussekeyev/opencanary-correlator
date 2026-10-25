# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
