# Audit events

Every operational event is written to **stdout as one JSON object per line**,
ready for Elastic Agent, Wazuh, Filebeat, Fluent Bit or `docker logs` without a
custom parser. Records do not repeat the five mandatory fields anywhere else, so
a single `json` codec is enough.

```json
{"timestamp":"2026-10-24T10:00:00.123456Z","component":"correlator","action":"startup","status":"info","details":{"receivers":["tcp_json"],"rules":["login","smb","host_portscan","network_portscan"],"channels":["slack"]}}
```

## Schema

| Field | Type | Notes |
|---|---|---|
| `timestamp` | ISO 8601 UTC string | microsecond precision, always `Z`-suffixed |
| `component` | string | `correlator` (lowercase, `[a-z0-9_.-]`, ≤ 64 chars) |
| `action` | string | one of the actions below |
| `status` | `success` \| `info` \| `warning` \| `error` | severity of the outcome |
| `details` | object | action-specific, secrets redacted, control characters stripped |

The schema is `extra="forbid"`: a record with an unexpected field is a bug, not
a compatibility risk, because consumers only rely on these five keys.

## Actions

| `action` | `status` | Emitted when | Notable `details` |
|---|---|---|---|
| `startup` | `info` | all receivers and the health listener are bound | `receivers`, `rules`, `channels` |
| `startup_failed` | `error` | Redis unreachable or a listener cannot bind | `reason: redis_unavailable` or `error_type` |
| `shutdown` | `info` | graceful stop finished | `receivers` |
| `receiver_started` | `info` | a receiver is listening | `receiver`, `host`, `port` |
| `receiver_stopped` | `info` | a receiver closed | `receiver`, `accepted` |
| `connection_rejected` | `warning` | connection cap, per-IP budget or source allowlist refused the peer | `reason: connection_limit` / `connection_rate_limited` / `peer_not_allowed`, `peer` |
| `connection_closed` | `warning` | a connection was closed for a policy reason | `reason`: `line_too_large`, `partial_line_timeout`, `connection_limit`, `connection_rate_limited` |
| `connection_closed` | `info` | the **peer** closed the connection (a canary went silent) | `reason: peer_closed`, `receiver`, `peer` |
| `connection_limiter_error` | `error` | the Redis limiter failed while accepting | `error_type` |
| `event_rejected` | `warning` | one line/datagram failed parsing or validation | `reason`, `peer`, plus reason-specific fields |
| `event_dropped` | `error` | the bounded event queue was full | `reason: queue_full`, `node_id`, `logtype` |
| `event_dropped` | `warning` | the drain before shutdown ran out of time, so a backlog was cancelled | `reason: shutdown`, `count` |
| `event_dropped` | `warning` | the incident lock timed out, so nothing was written; the dedup claim is withdrawn and a redelivery correlates | `reason: incident_lock_timeout`, `rule`, `incident`, `node_id`, `logtype` |
| `event_rate_limited` | `warning` | the node exceeded its event budget | `node_id`, `logtype` |
| `event_deduplicated` | `info` | an identical event was seen inside the dedup TTL | `node_id`, `logtype` |
| `event_dedup_lease_lost` | `info` | the dedup claim expired before the event was correlated (a rule slower than `OCC_DEDUP_LEASE`); the incident exists, a redelivery would merge | `node_id`, `logtype` |
| `event_ignored` | `info` | the `logtype` is node lifecycle (boot, base message, debug, ping, config save), which nothing correlates | `node_id`, `logtype` |
| `event_ignored` | `info` | the payload held only framing (a keep-alive newline or NUL), so there was nothing to parse | `reason: empty_payload` |
| `event_ignored` | `info` | an SMB audit action is listed in `OCC_SMB_IGNORE_ACTIONS`, so the event is valid but deliberately not correlated | `reason: smb_action`, `action`, `node_id`, `src_host` |
| `event_unrouted` | `warning` | no rule handles this `logtype`, and it is not a known lifecycle type | `node_id`, `logtype` |
| `event_dispatch_failed` | `error` | the sink raised while handling one event | `node_id`, `error_type` |
| `datagram_error` | `error` | UDP syslog processing raised | `receiver`, `error_type` |
| `rule_failed` | `error` | a correlation rule raised | `rule`, `node_id`, `error_type` |
| `incident_created` | `info` | a new incident hash was written | `incident`, `key`, `node_id`, `src_host` |
| `incident_updated` | `info` | an event merged into an existing incident | `incident`, `key`, `events_count` |
| `incident_lock_timeout` | `error` | the create-or-merge lock was not acquired in time; the event was **not** stored (it is not a merge) | `incident`, `src_host` |
| `alert_dispatch` | `success` / `error` | one delivery attempt finished | `dispatcher`, `incident`, `status`, `duration_ms` |
| `alert_retry` | `warning` | an attempt failed and the outbox scheduled another | `dispatcher`, `incident`, `attempts`, `reason`, `next_attempt_in` |
| `alert_dead_letter` | `error` | the outbox gave up; the entry is in `outbox:dead` | `dispatcher`, `incident`, `attempts`, `reason` (`timeout`, `error`, `unknown_channel`, `incident_gone`) |
| `outbox_failed` | `error` | one worker iteration raised and was skipped | `error_type` |
| `service_message_sent` | `success` / `error` | a service message about the correlator reached (or failed on) one channel | `kind`, `dispatcher`, `status`, `count` |
| `service_message_suppressed` | `info` | the cooldown muted a repeat of the same `(kind, subject)` | `kind`, `subject`, `count` |
| `canary_silent` | `warning` | a node delivered nothing for longer than `OCC_CANARY_SILENT_AFTER` | `node_id`, `last_seen`, `silent_seconds` |
| `health_watch_failed` | `error` | one window check raised and was skipped | `error_type` |
| `service_message_failed` | `error` | a channel could not carry the service message | `kind`, `dispatcher`, `reason: timeout` / `not_supported`, or `error_type` |
| `digest_sent` | `success` / `error` | the daily digest was produced (or no channel accepted it) | `day`, `incidents`, `replicas`, `events` |
| `digest_failed` | `error` | one digest iteration raised and was skipped | `error_type` |
| `stats_heartbeat_failed` | `warning` | the replica could not publish its heartbeat (a digest field is missing, nothing else) | `error_type` |
| `alert_suppressed` | `warning` | the alert budget withheld this notification; the incident itself is stored | `incident`, `node_id`, `src_host` |
| `alert_summary` | `info` / `success` / `error` | a closed window's withheld count was summarised, then sent per channel | `window_start`, `window_end`, `suppressed`, `sources`; then `dispatcher`, `status`, `detail` |
| `alert_summary_failed` | `error` | one summary iteration raised and was skipped | `error_type` |
| `alert_budget_failed` | `error` | the budget could not count, so the alert was sent anyway (fails open) | `incident`, `error_type` |
| `enrichment_skipped` | `info` | a provider quota window was full, so no lookup was made (the alert says `VT: quota exhausted`) | `provider`, `reason: quota` |
| `enrichment_failed` | `warning` / `error` | a provider timed out, failed or raised (the alert says `VT: unavailable`) | `provider`, `reason: timeout` / `unavailable`, or `error_type` |
| `health_request_failed` | `warning` | a probe timed out or disconnected | `reason: timeout` |

Rejection reasons: `invalid_utf8`, `line_too_large`, `canary_error_line` (an
`[ERR] '…'` line from `PyLogger.error()`), `malformed_json`, `non_object_payload`,
`schema_validation`, `malformed_syslog`, `datagram_too_large`.

## Redaction and injection defence

`details` is passed through `redaction.redact_mapping()` before serialisation:

- keys matching `(?i)(pass(word|wd)?|secret|token|api[_-]?key|auth|credential|private[_-]?key)`
  are replaced with `***`;
- list/tuple/set values are redacted element-wise;
- CR, LF, NUL and other control characters are replaced with a space, so a
  malicious `node_id` cannot forge an extra audit line;
- nesting deeper than 8 levels collapses to `***`.

`logdata` is never written to the audit trail wholesale; only identifiers such
as `node_id` and `logtype` are.

## Shipping examples

**Elastic Agent / Filebeat**

```yaml
filebeat.inputs:
  - type: container
    paths: ["/var/lib/docker/containers/*/*.log"]
    processors:
      - decode_json_fields:
          fields: ["message"]
          target: ""
          overwrite_keys: true
```

**Wazuh** (`/var/ossec/etc/decoders/opencanary-correlator.xml`)

```xml
<decoder name="occ-audit">
  <prematch>^\{"timestamp":</prematch>
  <json_null_field>details</json_null_field>
</decoder>
<rule id="100500" level="3">
  <decoded_as>occ-audit</decoded_as>
  <field name="component">^correlator$</field>
  <description>OpenCanary correlator audit event</description>
</rule>
```

**journald / systemd** — stdout is line-buffered and flushed per record, so
`journalctl -u opencanary-correlator -o cat` yields clean JSON lines. The Docker
image writes the same stream; `docker logs --tail 100 … | jq .` parses it.

## Console log list

Separately from the audit trail, `RedisLogHandler` keeps the legacy `logs` list
(newest first, 1000 entries) for the old console. It is fed by stdlib logging,
not by audit records, and `run_correlator` attaches it to the
`opencanary_correlator` package logger for the lifetime of the process. Each
record is written with `RedisStore.push_log()` (`LPUSH` + `LTRIM` in one
transaction), and a background task drains the queue so an unavailable Redis
never blocks a receiver. `dropped` counts records lost to a full queue or a
failed sink.
