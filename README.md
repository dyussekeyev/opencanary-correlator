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
| Transport | TCP, newline-delimited UTF-8 JSON, default port `15140` — exactly `opencanary.logger.SocketJSONHandler.makePickle()` (`record.getMessage() + "\n"`) |
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
`--log-level LEVEL`, `--log-file PATH`, `--health-port PORT` (`0` disables),
`--check-config`, `--version`.

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
        "port": 15140
      }
    }
  }
}
```

For syslog, use `logging.handlers.SysLogHandler` pointing at `OCC_SYSLOG_HOST` /
`OCC_SYSLOG_PORT` (UDP `15141` by default) and set `OCC_SYSLOG_ENABLED=true`.

Both receivers bind to `127.0.0.1` by default: the usual deployment runs the
canary and the correlator on one host, and an intake port open on every
interface is an unauthenticated write path. A canary on another machine needs
`OCC_TCP_HOST=0.0.0.0` (or its own address) — and the same for syslog — plus the
firewall rule described in [Transport security](#transport-security).

Two known `opencanaryd` problems — a `SocketJSONHandler` that does not reconnect
after a correlator restart, and a `twistd.pid` that survives a container restart
— are honeypot-side and cannot be fixed from here. [docs/opencanary-side.md](docs/opencanary-side.md)
has the patch and the workarounds, plus what the correlator does to make a silent
canary visible.

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
| Slack | `OCC_SLACK_ENABLED`, `OCC_SLACK_WEBHOOKS` — incoming webhook, report in `text`. Off by default: `OCC_SLACK_ENABLED=true` without a webhook is a startup error, and a webhook with the switch off logs a warning |
| Telegram | `OCC_TELEGRAM_TOKEN`, `OCC_TELEGRAM_CHAT_IDS` — one message per chat, truncated to 4096 chars |
| Discord | `OCC_DISCORD_WEBHOOKS` — `content` under 2000 chars, otherwise a single embed; both `200` and `204 No Content` count as success |
| SMTP | `OCC_SMTP_ENABLED`, `OCC_SMTP_HOST`, `OCC_SMTP_PORT`, `OCC_SMTP_FROM`, `OCC_SMTP_TO`, optional `OCC_SMTP_USERNAME` / `OCC_SMTP_PASSWORD`, `OCC_SMTP_STARTTLS` (port 587), `OCC_SMTP_USE_TLS` (implicit TLS, usually port 465; mutually exclusive with STARTTLS) |

### Message detail

Each channel has its own detail level: `OCC_TELEGRAM_DETAIL`, `OCC_SLACK_DETAIL`,
`OCC_DISCORD_DETAIL`, `OCC_WEBHOOK_DETAIL` and `OCC_SMTP_DETAIL`. Three values
are accepted (case-insensitive; `brief`/`short` mean `minimal`, `full`/`verbose`
mean `detailed`):

| Level | Message |
|---|---|
| `minimal` | The legacy alert, byte-identical for messages that fit the channel limit |
| `standard` | Instance name and address (`IP:port`), then attacker IP and source port, the detection time and a one-entry log summary |
| `detailed` | `standard` plus the event count and up to three log entries |

The instance address carries its own port, so no second row repeats the same
host. Lines are separated with CRLF, and chat channels use their native markup:
MarkdownV2 for Telegram (with every field escaped, so no payload can break the
message), mrkdwn for Slack and markdown for Discord. Chat channels default to
`standard`; webhook and SMTP default to `minimal`, so existing SIEM parsers and
mail filters keep receiving exactly the legacy text until you raise the level.
Log values whose key looks like a credential (`PASSWORD`, `SECRET`, `TOKEN`,
`AUTH`, ...) are masked as `***` at every level that shows log data.

```
🛡 OpenCanary: *RDP Login Attempt*

🖥 *Instance:* opencanary-embassy
🌐 *IP:* 89.126.202.164:3389

🎯 *Attacker:* 66.132.159.132:52344
🕒 *Time:* 2026-10-26 07:01:15 UTC

📝 *Log:* USERNAME=admin, PASSWORD=***
```

HTTP channels retry 429/5xx and transport errors three times with exponential
backoff and jitter, honour `Retry-After`, and share a Redis circuit breaker per
endpoint (keyed by a hash of the URL or Telegram chat id), so a dead endpoint is
not hammered by every replica while the other URLs of the same channel keep
receiving alerts. `OCC_DISPATCH_TIMEOUT` bounds a single delivery. One failing
endpoint never blocks the others and never blocks ingestion.

## Attacker enrichment (optional)

The attacker block can carry where the address comes from and how VirusTotal
rates it. Both providers are off until configured; with neither, alerts are
byte-identical to a build without the feature.

```bash
# Country/city/ASN from local files — nothing leaves the host
OCC_GEOIP_CITY_DB=/data/geoip/dbip-city-lite.mmdb
OCC_GEOIP_ASN_DB=/data/geoip/dbip-asn-lite.mmdb
# VirusTotal reputation — setting the key is the consent to send IPs there
OCC_VIRUSTOTAL_API_KEY=<key>
```

| Level | Rows added under the attacker block |
|---|---|
| `minimal` | none |
| `standard` | `📍 Location: Kazakhstan`, `🦠 VT: 0/94 malicious` |
| `detailed` | `📍 Location: Kazakhstan, Almaty`, `🏢 ASN: AS202958 …`, `🦠 VT: 0/94 malicious, reputation 0, 2026-10-26` |

```
🛡 OpenCanary: *RDP Login Attempt*

🖥 *Instance:* opencanary-embassy
🌐 *IP:* 2.126.2.164:3389

🎯 *Attacker:* 89.126.202.164:52344
🕒 *Time:* 2026-10-28 17:30:28 UTC
📍 *Location:* Kazakhstan, Almaty
🏢 *ASN:* AS202958 LLP "Kompaniya Hoster.KZ"
🦠 *VT:* 0/94 malicious, reputation 0, 2026-10-26
📊 *Events:* 1
📝 *Log:* USERNAME=administrator
```

**Geo data is local.** The correlator reads MMDB files, so country, city and
ASN work without a key, a quota or a network call, and an attacker address never
leaves the host. The reader is an extra (`pip install
"opencanary-correlator[geo]"`, already in the image); without it the correlator
starts normally and only complains when `OCC_GEOIP_CITY_DB` is set. A configured
path that cannot be opened is a startup error, not a silent gap. Private,
loopback and invalid addresses are skipped — `10.0.0.5` gets no country.

**VirusTotal is opt-in and quota-first.** The free public API allows 4 lookups
per minute, 500 per day and 15.5K per month. Before every request the client
reserves a slot in all three windows through one atomic Redis script
(`OCC_VIRUSTOTAL_PER_MINUTE`, `OCC_VIRUSTOTAL_PER_DAY`,
`OCC_VIRUSTOTAL_PER_MONTH`), so replicas cannot exceed the limits together, and a
verdict is cached per address for `OCC_VIRUSTOTAL_CACHE_TTL` (7 days). An empty
window renders `🦠 VT: quota exhausted`, a timeout or HTTP error renders
`🦠 VT: unavailable` — the alert itself is always delivered, and enrichment can
never delay it by more than `OCC_ENRICHMENT_TIMEOUT` (6 s). The key travels in
the `x-apikey` header, so it cannot appear in a request-URL log line, and it is
hidden from `repr()` and `--check-config`.

**Attribution.** IP geolocation data from [DB-IP](https://db-ip.com) Lite,
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

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
- Node lifecycle records (`1000` boot, `1001` base message — which is also what a
  plain-text syslog body becomes — `1002` debug, `1003` error, `1004` ping,
  `1005` config save, `1006` example) are audited as `event_ignored` at **INFO**.
  Any other `logtype` that no rule handles is a routing gap and stays
  `event_unrouted` at **WARNING**.

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
  per-event cost stays flat as the index grows. When that capped fallback finds
  nothing, the full horizon window is read once before a new incident is created,
  so a live incident behind the cap is merged instead of duplicated.

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

`OCC_HEALTH_ALLOWED_IPS` restricts which peers may read `/healthz`, `/readyz` and
`/metrics`, as a comma-separated list of addresses or CIDRs. It defaults to
`127.0.0.1/32,::1/128`; an empty value also means loopback. Other peers receive
`403`. Widen it (for example to a Kubernetes or Docker subnet) only when the probe
source address falls outside loopback.

The container `HEALTHCHECK` follows both variables: it dials `OCC_HEALTH_HOST`
(`127.0.0.1` when it is unset, blank, `0.0.0.0` or `::`; `::1` and explicit addresses are used as given) and skips the request
entirely when the port is `0`.

### Logs

The service keeps three separate streams, so container setups and file-based
deployments both work:

| Stream | Where | What |
|---|---|---|
| Operational log | stderr, plus `OCC_LOG_FILE` when set | Timestamp, level, logger and message: receiver errors, dispatcher failures, shutdown problems, Redis errors |
| Audit trail | stdout | One JSON object per line (`timestamp`, `component`, `action`, `status`, `details`) — see [docs/audit-events.md](docs/audit-events.md) |
| Legacy console journal | Redis `logs` list | The operational lines mirrored for the legacy console |

`OCC_LOG_LEVEL` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
(case-insensitive; `WARN` and `FATAL` are accepted too) and defaults to `INFO`.
Use `DEBUG` when chasing a correlation or dispatch problem; `INFO` is enough to
see every failed delivery, rejected event and start/stop reason.

`DEBUG` applies to the correlator's own loggers only. `httpx`, `httpcore`, `h11`
and `hpack` are pinned to `WARNING` at startup, whatever the root level says:
`httpx` logs every request URL at INFO and the other three log connection and
frame details at DEBUG, and a Telegram bot token or a Slack/Discord webhook
secret lives in that URL path. Their real failures (`WARNING` and above) are
still logged and still pass through the redaction filters.

`OCC_LOG_FILE` adds a log file next to stderr without removing it, so
`docker logs` keeps working. The file is UTF-8, rotates at 10 MiB and keeps 5
backups (`correlator.log`, `correlator.log.1`, …); its directory is created if
missing. An empty value means stderr only, which is enough when the runtime
already collects stderr; the bundled `docker-compose.yml` instead mounts a
volume and points this variable at it — see
[Log files in Docker](#log-files-in-docker).
If the file cannot be opened the correlator exits with code `2` and prints the
reason instead of running blind.

A fatal startup failure and an unhandled crash are logged at `CRITICAL` with
their traceback, so the file always explains why the process stopped; startup
and shutdown records stay in the JSON audit trail on stdout.

Every line is flattened (CR/LF, control characters and the Unicode line
separators `U+0085/U+2028/U+2029` become spaces) and secrets are masked before
it reaches stderr, the file, the audit trail or the legacy console journal,
including inside tracebacks: bot tokens, webhook paths and `?token=`-style query
parameters, `user:pass@` URL passwords, and the configured endpoints by exact
value (which covers a token in the path of an arbitrary webhook host). That matters because
`httpx` logs every request URL at `INFO`, and the Telegram Bot API only accepts
the bot token as part of the path — there is no header or body alternative —
while Slack and Discord webhook URLs carry their secret in the path as well. A
delivery line therefore reads
`POST https://api.telegram.org/bot***/sendMessage` instead of exposing the token.

```dotenv
OCC_LOG_LEVEL=DEBUG
OCC_LOG_FILE=/var/log/opencanary-correlator/logs/correlator.log
```

## Docker

```bash
cp .env.example .env          # fill in channels and OCC_REDIS_PASSWORD
docker compose up -d --build
```

The bundled Redis requires a password: `OCC_REDIS_PASSWORD` has no default, and
compose refuses to start without it. Use letters, digits, `-` and `_` only, since
the password is embedded in the correlator's `OCC_REDIS_URL` unescaped.

The image runs as an unprivileged user, accepts canary JSON on `15140/tcp`, and
includes the syslog receiver for `15141/tcp` + `15141/udp`. Base images (Python,
the `uv` builder and `redis:7-alpine`) are pinned by multi-arch digest, and the
build installs exactly `uv.lock` with `uv sync --frozen`. The image declares a `HEALTHCHECK`
that reads `OCC_HEALTH_PORT` and `OCC_HEALTH_HOST` from the container environment;
changing the port, narrowing the binding to loopback, or setting the port to `0`
to disable the endpoint keeps the health status meaningful instead of probing a
dead `15142` or the wrong address.

Compose publishes both intake ports **on `127.0.0.1` only**, because the canary
normally shares the host with the correlator. The binding is a variable, so it
survives `docker compose` updates instead of being re-widened by them:

```bash
# .env — canaries on other machines
OCC_TCP_PUBLISH_HOST=0.0.0.0
OCC_TCP_HOST=0.0.0.0          # inside the container
OCC_SYSLOG_PUBLISH_HOST=0.0.0.0
OCC_SYSLOG_HOST=0.0.0.0
```

`OCC_TCP_HOST`/`OCC_SYSLOG_HOST` stay `0.0.0.0` **inside** the container: Docker
forwards the published port to the container's bridge address, so a loopback
listener there would never be reached through the mapping. The loopback part of
the default is the host-side publish address. Set `OCC_SYSLOG_ENABLED=true` (and
`OCC_SYSLOG_UDP_ENABLED=true` for UDP) in `.env` to start the syslog listener.
The health port (`15142`) stays container-internal. Inspect it with
`docker inspect --format '{{.State.Health.Status}}' <container>`, or publish it
yourself if an external probe needs it.

Compose passes `OCC_HEALTH_HOST` through from the shell or `.env`, defaulting to
`127.0.0.1`. The health port is not published, so the listener and its counters stay
inside the container while the image `HEALTHCHECK` keeps reporting `healthy`.
Set `OCC_HEALTH_HOST=0.0.0.0` only together with a published health port.

The compose file starts Redis and the correlator on a private network. If you
widen the published intake ports (`15140`, `15141`) to a network interface,
restrict them to your canary subnet at the firewall or cloud security-group
level; they accept untrusted traffic by design.

### Log files in Docker

Compose mounts the named volume `correlator-logs` at
`/var/log/opencanary-correlator` and sets
`OCC_LOG_FILE=/var/log/opencanary-correlator/logs/correlator.log`, so the rotated
log survives container restarts and a file-based agent (Wazuh, Filebeat, Fluent
Bit) or `docker compose cp` can collect it. `docker logs` is unchanged: stderr
still receives the same lines, and the JSON audit trail still goes to stdout.

The extra `logs/` level is deliberate. Docker creates the root of a named volume
as `root:root` and only copies the *content* of the image directory into it, not
the mount point's own ownership, so the process running as UID 10001 could not
create a file directly under the mount. The image ships
`/var/log/opencanary-correlator/logs` owned by `10001:10001`, and that directory
is copied into the volume with its ownership intact.

Read or copy it from the host:

```bash
docker compose exec correlator tail -f /var/log/opencanary-correlator/logs/correlator.log
docker compose cp correlator:/var/log/opencanary-correlator/logs/correlator.log ./correlator.log
```

To let an agent read a host directory directly, swap the named volume for a bind
mount:

```yaml
    volumes:
      - ./logs:/var/log/opencanary-correlator
```

A bind mount does not inherit the image's ownership either, so hand the directory
to the container user first: `sudo mkdir -p ./logs && sudo chown -R 10001:10001 ./logs`.
The correlator then creates the `logs/` subdirectory itself before opening the
file.

Rotation bounds the volume: 10 MiB per file and 5 backups, so at most 60 MiB,
regardless of how long the container runs.

To keep the volume mounted but stop writing the file, set an empty value in
`.env` — compose passes it through as-is and the correlator falls back to stderr:

```dotenv
OCC_LOG_FILE=
```

### Transport limitation: honeypot traffic is plaintext

The stock OpenCanary `SocketHandler` (and `SyslogHandler`) cannot speak TLS, so
events travel from each honeypot to the correlator as unencrypted JSON. The
correlator does not add TLS on its intake ports, by design: changing the honeypot
side is out of scope. Anyone on the network path can read or forge events.

If the path between a honeypot and the correlator is not trusted, wrap it in a
tunnel that you operate. The correlator keeps listening on plain loopback or the
private interface behind it; the tunnel is the only thing that reaches it.

- **SSH local/remote forwarding.** On the honeypot, forward a local port to the
  correlator's intake port through a key-only SSH session, for example
  `ssh -N -L 127.0.0.1:15140:127.0.0.1:15140 correlator-host` with the OpenCanary
  `logger` pointed at `127.0.0.1:15140`. Restrict the key with
  `permitopen="127.0.0.1:15140"` and `no-pty` in `authorized_keys`. Keep the
  autossh or systemd unit that restarts it.
- **WireGuard or IPsec site-to-site VPN.** Put the honeypots and the correlator
  on one tunnel subnet and point the intake to the tunnel address. Both are
  kernel-level, so the application needs no change. IPsec (strongSwan) is the
  usual choice where a managed gateway already exists.
- **Stunnel or a TLS reverse proxy** is an option only if you control the
  receiving end. The honeypot still sends plaintext to a local proxy, so the
  proxy must run on the honeypot itself.

Whichever you choose, do not expose the intake ports directly to the internet.
Restrict them to the tunnel or canary network as described above.

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

See [docs/architecture.md](docs/architecture.md).

## License

BSD 3-Clause, see [LICENSE](LICENSE). Original work © Thinkst Applied Research.
