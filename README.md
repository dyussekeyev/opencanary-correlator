# OpenCanary Correlator

[![CI](https://github.com/dyussekeyev/opencanary-correlator/actions/workflows/ci.yml/badge.svg)](https://github.com/dyussekeyev/opencanary-correlator/actions/workflows/ci.yml)

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
- Redis 6+ as one logical server, with scripting enabled (`EVAL`/`EVALSHA`
  drive the atomic incident write and lock release), TLS via `rediss://`, Unix
  sockets via `unix://`; Redis Cluster is not supported (see [Scaling](#scaling))
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
`console.email_notification_enable`, `console.email_notification_address`,
`console.email_host`,
`console.email_port`, `console.slack_notification_enable` and
`console.slack_notification_webhook`.
Twilio and Mandrill keys are ignored (with a log line), because SMS and the
deprecated Mandrill SDK are not part of this release. As in the Python 2
notifier, a missing `*_notification_enable` key means the channel stays
disabled; an explicit `OCC_SMTP_ENABLED=true` / `OCC_SLACK_ENABLED=true`
override re-enables it.

## Alert channels

| Channel | Settings |
|---|---|
| Generic webhook / SIEM | `OCC_WEBHOOK_URLS` — JSON `{"title", "text", "key"}`, one URL per delivery |
| Slack | `OCC_SLACK_ENABLED`, `OCC_SLACK_WEBHOOKS` — incoming webhook, compact report in `text` |
| Telegram | `OCC_TELEGRAM_TOKEN`, `OCC_TELEGRAM_CHAT_IDS` — one message per chat, truncated to 4096 chars |
| Discord | `OCC_DISCORD_WEBHOOKS` — `content` under 2000 chars, otherwise a single embed; both `200` and `204 No Content` count as success |
| SMTP | `OCC_SMTP_ENABLED`, `OCC_SMTP_HOST`, `OCC_SMTP_PORT`, `OCC_SMTP_FROM`, `OCC_SMTP_TO`, optional `OCC_SMTP_USERNAME` / `OCC_SMTP_PASSWORD`, `OCC_SMTP_STARTTLS` (port 587), `OCC_SMTP_USE_TLS` (implicit TLS, usually port 465; mutually exclusive with STARTTLS) |

HTTP channels retry 429/5xx and transport errors three times with exponential
backoff and jitter, honour `Retry-After`, and share a Redis circuit breaker per
endpoint (keyed by a hash of the URL or Telegram chat id), so a dead endpoint is
not hammered by every replica while the other URLs of the same channel keep
receiving alerts. `OCC_DISPATCH_TIMEOUT` bounds a single delivery. One failing
endpoint never blocks the others and never blocks ingestion.

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
  Both scan windows use a **fixed** TTL: the expiry is anchored when the window
  is created and is never extended by later packets, so sustained scanning
  cannot keep the window (or a stale threshold count) alive indefinitely.
- Duplicate events are dropped with a SHA-256 fingerprint (`OCC_DEDUP_TTL`,
  default 60 s), so a retransmitted log never inflates an incident. The Python 2
  correlator counted every repeat, so set `OCC_DEDUP_TTL=0` to merge them again.
- Stored incident history is capped at `OCC_MAX_STORED_EVENTS` (default `100`,
  the number of entries the legacy console renders). `events_count` always stays
  exact: once the cap is reached the timestamp CSV and `logdata` are **frozen**
  rather than trimmed, the merge writes the counters only, and the hash stops
  growing. The `events_truncated` field marks a partial history, and the console
  payload reports the difference as `events_skipped`. Port scans keep every
  distinct port or target — they store one entry per member, not per event.
- Unknown `logtype` values are audited as `event_unrouted` and otherwise ignored.

## Scaling

The process holds no correlation state: Redis stores windows, counters, locks,
dedup keys and incidents. Run any number of **correlator** replicas behind a load
balancer, point them at the same Redis, and create-or-merge on the incident is
serialised with a short distributed lock, so N replicas still produce one
incident and one notification. Receivers are bounded (connections, queue size,
line size) and rate limits are shared through Redis.

Two settings carry the throughput:

- `OCC_EVENT_CONCURRENCY` (default 8) runs that many consumer lanes per
  receiver, sharded by `src_host`. Different hosts progress in parallel; one
  host keeps arrival order, so merging stays deterministic and a slow host or
  channel cannot stall the others. Events still cost about six Redis round
  trips each, so this is the knob that matters for a remote Redis.
- Incident lookup is O(1): `incident-latest:<incident>:<src_host>` points at the
  newest incident for that host, instead of scanning every incident inside the
  horizon. The pointer falls back to the index when it is missing or stale, so
  an upgrade or a deleted incident stays correct, and that fallback inspects at
  most `OCC_INCIDENT_LOOKUP_SCAN_LIMIT` (default `100`) newest index members, so
  per-event cost stays flat as the index grows. A fallback cut short by the cap
  is audited as `incident_lookup_truncated` rather than assumed empty.

Per-event cost no longer depends on how large an incident already is: a single
host flooding 10,000 events into one incident took 77.2 s before stored history
was capped and takes 17.7 s now, with the incident hash stable at about 4 KB
instead of growing towards half a megabyte.

Measured on a real Redis 7 server (10,000 events, 100 hosts): 2.6 s with 8
lanes. With 5,000 live incidents in the index, an older build that scanned the
index took 47.9 s for 2,000 events; the pointer version takes 4.6 s. Details and
caveats are in [docs/validation.md](docs/validation.md).

That Redis must be one logical server (a primary with replicas, or a failover
endpoint/VIP, is fine). **Redis Cluster is not supported**: the incident write
script touches an `incident:*` hash, the `incidents` ZSET and the host pointer,
and those keys live in different slots, so Cluster answers `CROSSSLOT`.
Hash-tagging them would change the legacy key layout and break existing
consoles, so it is deliberately out of scope. Scale Redis vertically or by using
a single failover endpoint; scale the correlator itself horizontally. Redis
scripting must be available, as it is on every supported server release.

`GET /healthz` and `GET /readyz` return `200` with `{"status":"ok","redis":true}`,
or `503` when Redis is unreachable. The path is matched exactly after stripping
the query string, so `/healthz?x=1` is still a real Redis probe while
`/healthzfoo` is a 404. Use them for load-balancer and Kubernetes probes.

`GET /metrics` (same listener) exports Prometheus text: event outcomes, queue
depth, active connections and rejections, rule failures, alert delivery results
and build information. Metrics are process-local — scrape every replica — and
carry only low-cardinality labels, never incident keys or payload data.
The endpoint does not ping Redis, so it stays scrapeable during a Redis outage.
Set `OCC_HEALTH_PORT=0` to disable both the health and metrics listener.

Set `OCC_HEALTH_HOST=127.0.0.1` (or `::1`) to keep the listener on loopback. The
default is `0.0.0.0`, because Kubernetes probes and the Docker bridge arrive from
another address; the endpoint has no authentication, so a wildcard binding
exposes incident and delivery counters to anything that can reach the port. With
a loopback binding, probe it from the same host, a sidecar, or `docker exec`.

The container `HEALTHCHECK` follows both variables: it dials `OCC_HEALTH_HOST`
when one is set (mapping `0.0.0.0`/`::` back to `127.0.0.1`) and skips the request
entirely when the port is `0`.

Audit records are JSON lines on stdout — see
[docs/audit-events.md](docs/audit-events.md).

## Docker

```bash
cp .env.example .env          # fill in channels; compose supplies Redis
docker compose up -d --build
```

The image runs as an unprivileged user, accepts canary JSON on `1514/tcp`, and
includes the syslog receiver for `5514/tcp` + `5514/udp`. Base images (Python,
the `uv` builder and `redis:7-alpine`) are pinned by multi-arch digest, and the
build installs exactly `uv.lock` with `uv sync --frozen`. The image declares a `HEALTHCHECK`
that reads `OCC_HEALTH_PORT` and `OCC_HEALTH_HOST` from the container environment;
changing the port, narrowing the binding to loopback, or setting the port to `0`
to disable the endpoint keeps the health status meaningful instead of probing a
dead 8080 or the wrong address.

Compose publishes both intake ports, so external canaries can reach the handler
without editing the file; set `OCC_SYSLOG_ENABLED=true` (and
`OCC_SYSLOG_UDP_ENABLED=true` for UDP) in `.env` to start the syslog listener.
The health port stays container-internal. Inspect it with
`docker inspect --format '{{.State.Health.Status}}' <container>`, or publish it
yourself if an external probe needs it.

The compose file starts Redis and the correlator on a private network. Restrict
the published intake ports (`1514`, `5514`) to your canary network at the
firewall or cloud security-group level; they accept untrusted traffic by
design.

## Quality gates

Dependencies are locked in [uv.lock](uv.lock). CI installs that lockfile with
`uv sync --frozen`; `uv lock --check` fails the build when `pyproject.toml` and
the lockfile drift apart.

```bash
uv sync --frozen --extra dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src tools
uv run pytest
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
# Redis p99 from a second client: idle, then while the benchmark runs
python tools/latency_probe.py --redis-url redis://localhost:6379/15 --duration 5
```

### Linux parity check

A green suite on Windows does not prove Linux behaviour: the POSIX selector
transport, signal delivery and socket semantics differ, and type checking does
too - mypy narrows `sys.platform` to the platform doing the checking, so a
Windows-run guard can be unreachable under Linux and vice versa. CI is the only
automatic guard. `tools/linux_check.sh` runs `ruff check`, `ruff format --check`,
`mypy src tools` and the suite on Python 3.11 in a container built from the
locked dependencies, with a disposable `redis:7-alpine` for the opt-in
real-server tests, so the CI lint and test jobs are reproducible locally:

```bash
tools/linux_check.sh                      # ruff, mypy, whole suite, Redis included
tools/linux_check.sh tests/integration    # subset; extra arguments go to pytest (static gates skipped)
tools/linux_check.sh --no-redis           # skip the real-Redis tests
tools/linux_check.sh --rebuild            # rebuild the test image
```

The image is cached by `pyproject.toml` and `uv.lock`, so routine runs start in
seconds. POSIX-only tests are marked `@pytest.mark.linux`, so a Windows run can
select or skip them with `-m linux` / `-m "not linux"`. `tools/install_hooks.sh`
points this clone at [.githooks](.githooks) so the same check runs before a push
that touches Python, tests or dependencies; documentation-only pushes and a
stopped Docker daemon are skipped, and `SKIP_LINUX_CHECK=1 git push` bypasses it
once.

## Architecture

See [docs/architecture.md](docs/architecture.md) and the refactoring plan in
[docs/EXECPLAN-refactor.md](docs/EXECPLAN-refactor.md).

## License

BSD 3-Clause, see [LICENSE](LICENSE). Original work © Thinkst Applied Research.
