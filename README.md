# OpenCanary Correlator

A stateless, asyncio correlator for [OpenCanary](https://github.com/thinkst/opencanary)
honeypot events. It receives the exact JSON that `opencanaryd` already emits,
coalesces related attempts into incidents, keeps all state in Redis, and pushes
alerts to SMTP, generic SIEM webhooks, Slack, Telegram or Discord.

This is a modern fork of the Python 2 / Twisted
[thinkst/opencanary-correlator](https://github.com/thinkst/opencanary-correlator).
The alerting API keys that the legacy code used (Mandrill, Twilio) are gone;
the wire protocol and the Redis layout are unchanged.

## Compatibility contract

Nothing has to change on the honeypot side.

| Aspect | Behaviour |
|---|---|
| Transport | TCP, newline-delimited UTF-8 JSON, default port `1514` — exactly `opencanary.logger.SocketJSONHandler.makePickle()` (`record.getMessage() + "\n"`) |
| Syslog | RFC 6587 octet-counting or newline framing over TCP, one message per UDP datagram; JSON bodies become events, plain text becomes a synthetic `LOG_BASE_MSG` event |
| Event fields | `src_host`, `src_port`, `dst_host`, `dst_port`, `logtype`, `node_id`, `local_time`, `utc_time`, `logdata` and any extra fields are preserved |
| Lenient parsing | empty `src_host`, `-1` ports, hostnames, unknown `logtype` integers and unparsable timestamps are accepted, never rejected |
| Lifecycle | `SocketJSONHandler` keeps sockets open indefinitely; an idle keep-alive connection is never closed, only a stalled partial line is |
| Redis | legacy keys and incident hash fields are preserved (`incident:ftplogin:<src_host>:<ts>`, `incidents`, `device:<hash>`, …), so existing dashboards keep working |

Malformed input is rejected per line with an audit record: oversized lines,
invalid UTF-8, non-JSON, `[ERR] '…'` lines written by `PyLogger.error()`, NaN or
infinite numbers, excessive `logdata` nesting.

## Requirements

- Python 3.11+ (tested on 3.14)
- Redis 6+ (TLS via `rediss://`, Unix sockets via `unix://`)
- No database or ORM: all correlation state is in Redis

## Install

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install .
```

For development:

```bash
pip install -e ".[dev]"
cp .env.example .env
```

## Run

```bash
# validate configuration and print a secret-free summary, then exit
opencanary-correlator --check-config

# start the service
opencanary-correlator
```

Configuration comes from environment variables (prefix `OCC_`) and an optional
`.env` file. Every setting is documented in [.env.example](.env.example); the
minimum is:

```bash
OCC_REDIS_URL=redis://localhost:6379/0
OCC_SLACK_WEBHOOKS=https://hooks.slack.com/services/...
```

CLI flags: `--config PATH` (import a legacy JSON `.conf`), `--redis-url URL`,
`--log-level LEVEL`, `--health-port PORT` (`0` disables), `--check-config`,
`--version`.

While it runs, the service also appends its own log lines to the legacy `logs`
Redis list (newest first, trimmed to 1000), so the old console shows a populated
journal instead of an empty one. These lines are separate from the JSON audit
trail on stdout and never block ingestion.

### Point a canary at the correlator

Add an `opencanary.logger.SocketJSONHandler` to the node's `logger` section —
the correlator accepts it unmodified:

```json
"logger": {
  "class": "PyLogger",
  "kwargs": {
    "handlers": {
      "json-tcp": {
        "class": "opencanary.logger.SocketJSONHandler",
        "host": "correlator.example.internal",
        "port": 1514
      }
    }
  }
}
```

For syslog, use `logging.handlers.SysLogHandler` pointing at `OCC_SYSLOG_HOST` /
`OCC_SYSLOG_PORT` (UDP `5514` by default) and set `OCC_SYSLOG_ENABLED=true`.

### Migrating from the Python 2 release

The old `opencanary_correlator.conf` can be imported directly:

```bash
opencanary-correlator --config ./opencanary_correlator.conf
```

Migrated keys: `console.incident_horizon`, the per-incident horizons
`ftp.incident_horizon`, `http.incident_horizon`, `ssh.incident_horizon`,
`telnet.incident_horizon`, `httproxy.incident_horizon`, `mysql.incident_horizon`,
`mssql.incident_horizon`, `tftp.incident_horizon`, `ntp.incident_horizon`,
`vnc.incident_horizon`, `snmp.incident_horizon`, `rdp.incident_horizon`,
`sip.incident_horizon`, `smb.file_open_horizon`,
`scans.host_portscan_horizon`, `scans.network_portscan_horizon`, plus
`portscan.packet_threshold`, `portscan.monitor_period`,
`networkscan.packet_threshold`, `networkscan.monitor_period`,
`console.email_notification_address`, `console.email_host`,
`console.email_port` and `console.slack_notification_webhook`.
Twilio and Mandrill keys are ignored (with a log line), because SMS and the
deprecated Mandrill SDK are not part of this release.

## Alert channels

| Channel | Settings |
|---|---|
| Generic webhook / SIEM | `OCC_WEBHOOK_URLS` — JSON `{"title", "text", "key"}`, one URL per delivery |
| Slack | `OCC_SLACK_WEBHOOKS` — incoming webhook, compact report in `text` |
| Telegram | `OCC_TELEGRAM_TOKEN`, `OCC_TELEGRAM_CHAT_IDS` — one message per chat, truncated to 4096 chars |
| Discord | `OCC_DISCORD_WEBHOOKS` — `content` under 2000 chars, otherwise a single embed; both `200` and `204 No Content` count as success |
| SMTP | `OCC_SMTP_HOST`, `OCC_SMTP_PORT`, `OCC_SMTP_FROM`, `OCC_SMTP_TO`, optional `OCC_SMTP_USERNAME` / `OCC_SMTP_PASSWORD`, `OCC_SMTP_STARTTLS` |

HTTP channels retry 429/5xx and transport errors three times with exponential
backoff and jitter, honour `Retry-After`, and share a Redis circuit breaker so a
dead endpoint is not hammered by every replica. `OCC_DISPATCH_TIMEOUT` bounds a
single delivery. One failing channel never blocks the others and never blocks
ingestion.

## Correlation semantics

- Global horizon `OCC_INCIDENT_HORIZON` (60 s): a repeat from the same `src_host`
  for the same incident type merges into the open incident (`events_count`,
  `events_list`) instead of alerting again.
- Per-incident overrides in `OCC_INCIDENT_HORIZONS`, a JSON object keyed by
  canonical incident name (for example
  `OCC_INCIDENT_HORIZONS='{"ftp.login_attempt": 300}'`). Legacy
  `<type>.incident_horizon` keys from the old `.conf` are imported into it.
- Host port scan: `OCC_SCAN_HOST_THRESHOLD` distinct ports (5) within
  `OCC_SCAN_HOST_HORIZON` (50 s) on one canary.
- Network port scan: `OCC_SCAN_NETWORK_THRESHOLD` canary targets (2) for the same
  `src_host`/`dst_port` within `OCC_SCAN_NETWORK_HORIZON` (3600 s).
- Duplicate events are dropped with a SHA-256 fingerprint (`OCC_DEDUP_TTL`), so a
  retransmitted log never inflates an incident.
- Unknown `logtype` values are audited as `event_unrouted` and otherwise ignored.

## Scaling

The process holds no correlation state: Redis stores windows, counters, locks,
dedup keys and incidents. Run any number of replicas behind a load balancer,
point them at the same Redis, and create-or-merge on the incident is serialised
with a short distributed lock, so N replicas still produce one incident and one
notification. Receivers are bounded (connections, queue size, line size) and
rate limits are shared through Redis.

`GET /healthz` and `GET /readyz` return `200` with `{"status":"ok","redis":true}`,
or `503` when Redis is unreachable. Use them for load-balancer and Kubernetes
probes.

Audit records are JSON lines on stdout — see
[docs/audit-events.md](docs/audit-events.md).

## Docker

```bash
cp .env.example .env          # fill in OCC_REDIS_URL and channels
docker compose up -d --build
```

The image runs as an unprivileged user, listens on `1514/tcp` and `5514/udp`,
and declares a `HEALTHCHECK` against `/healthz`. The compose file starts Redis
and the correlator on a private network; publish `1514` only to your canary
network.

## Quality gates

```bash
ruff check .
ruff format --check .
mypy src
pytest
```

The suite covers unit logic, socket-level receiver tests, dispatcher delivery
against local HTTP/SMTP servers, two-replica atomicity on a shared Redis, and a
full `SocketJSONHandler → incident → alert` end-to-end test. See
[docs/validation.md](docs/validation.md) for the acceptance record.

Optional checks against real infrastructure (skipped when the variable is
unset):

```bash
# disposable database, never production
OCC_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/integration/test_real_redis.py -v
python tools/bench_ingest.py --redis-url redis://localhost:6379/15 --events 10000 --hosts 100
```

## Architecture

See [docs/architecture.md](docs/architecture.md) and the refactoring plan in
[docs/EXECPLAN-refactor.md](docs/EXECPLAN-refactor.md).

## License

BSD 3-Clause, see [LICENSE](LICENSE). Original work © Thinkst Applied Research.
