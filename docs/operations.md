# Operations runbook

Short, testable procedures for the failures the correlator can report about
itself. Every command reads configuration from the environment or `.env`, so the
same values the service uses apply here; none of them touches Redis keys by hand.

## Backup, RPO and RTO

One Redis is the single state store. Replication and failover belong to the
infrastructure around it; the correlator does not provide either. With the
compose defaults (`--appendonly yes`, AOF `appendfsync everysec` and
`save 60 1`) the exposure is:

- **RPO:** at most about one second of acknowledged Redis writes when the process
  or host crashes, plus whatever the OS page cache had not flushed. Losing the
  whole dataset (deleted volume, disk failure without a replica) is only covered
  by a backup.
- **RTO:** measured locally on 2026-11-04 with `redis:7-alpine` (7.4.11),
  5 001 keys / 0.84 MB in the RDB: **0.95 s from `docker start` to accepting
  connections**, of which 12 ms was loading the file. Container start dominates at
  that size, so measure again with the real dataset and storage before promising a
  number. Take the backup while writers are stopped, as in §Restore after a lost
  dataset.

## Alert rules

Starting points for metrics the correlator already exports; tune them to the
actual traffic. Each row names the runbook section to open when it fires.

| Signal | Threshold | Meaning | Action |
|---|---|---|---|
| `/readyz` | `503` for 2 min | Redis or a critical task is down; intake may accept but cannot persist | §Redis is unreachable or read-only |
| `opencanary_events_dropped_total{reason="queue_full"}` | sustained increase | intake is the bottleneck; events are lost before correlation | §Redis is out of memory (check load first) |
| `opencanary_event_queue_depth` | near the configured queue bound | receivers are not draining fast enough | raise `OCC_EVENT_CONCURRENCY` or shed load at the edge |
| `opencanary_outbox_oldest_pending_age_seconds` | > 600 s | a channel is slow or the worker is stuck | §Slow or failing channel |
| `opencanary_outbox_dead_entries` | > 0 and rising | deliveries are being buried faster than an operator clears them | §Dead letters |
| `opencanary_outbox_dead_total{channel}` | any increase | a target rejected or exhausted its attempts | §Dead letters; fix the destination, then replay one entry |
| `opencanary_enrichment_requests_total{provider="opencti",outcome="unauthorized"}` | any increase | the OpenCTI token is rejected; alerts still deliver | §OpenCTI lookup or write failure |
| `opencanary_retention_protected_total` | keeps rising | dead letters or queued deliveries pin incidents that should expire | §Retention |
| `opencanary_retention_removed_total` | flat while retention is enabled and the dataset grows | the janitor is not running | §Retention; check `--retention-run` |
| Redis `used_memory` / `maxmemory` | > 80 % | `noeviction` will start refusing writes | §Redis is out of memory |
| `opencanary_node_registry_overflow_total` | any increase | node bookkeeping is truncated, so silent-canary evidence is incomplete | §Silent canary |

## Redis is unreachable or read-only

1. `curl -fsS http://127.0.0.1:15142/readyz` on the replica reports `503` with
   the failing dependency.
2. `redis-cli -u "$OCC_REDIS_URL" PING` distinguishes a network problem from an
   authentication or ACL one.
3. A read-only replica (`READONLY You can't write against a read only replica`)
   means the correlator was pointed at a replica endpoint: it needs the primary
   or a failover address that is writable.
4. Intake is best-effort while Redis is down: receivers drop events and count
   them. The `opencanary_events_dropped_total{reason="queue_full"}` rate is the
   accounting of what was lost.

## Redis is out of memory or `noeviction`

`OOM command not allowed when used memory > 'maxmemory'` on a write means the
deployment must not evict correlation state silently. Either raise the limit, or
enable retention (below): it is the supported way to bound the dataset. Do not
set `maxmemory-policy allkeys-lru` — it would delete incidents and pending
deliveries without any of the protection described here.

## Restore after a lost dataset

1. Stop every replica; an empty Redis plus running workers recreates state with
   duplicate alerts.
2. Restore the AOF/RDB snapshot into the same logical endpoint.
3. Start one replica and confirm `/readyz`, then `opencanary-correlator
   --dlq-list 20` shows the dead letters the snapshot carried.
4. Start the rest. Each replica re-registers its heartbeat; pending deliveries
   resume from the index.

## Upgrade and rollback

The outbox layout is versioned (`outbox:v2:*`), so an upgrade is a
stop-the-workers operation, not a rolling one:

1. Stop every old correlator worker and intake listener. Mixed old/new ingestion is
   unsupported: even with isolated outboxes, both share incident merge state.
2. Take a protected Redis backup (`BGSAVE`, then copy the RDB/AOF) while nothing writes.
3. Start the new build. At startup it counts the legacy `outbox:alerts` index and
   audits `outbox_legacy_quarantined`; those records are preserved in place and never
   mapped to a destination, because a legacy record carries no reliable recipient
   identity. They are not delivered, and they must not be treated as delivered.
4. Reconcile legacy debts against the delivery history and choose each recipient
   explicitly before any manual transfer. Automatic transfer or replay is not
   provided, so do not expect the new build to drain them.
5. Rollback means stopping every new worker first and then starting the old build.
   v2 debts stay in `outbox:v2:*`, and an old worker cannot process them: drain or
   preserve and reconcile them separately before rolling back.

The full rationale and the `outbox:v2:*` key layout are in `README.md`.

## Dead letters

```bash
opencanary-correlator --dlq-list 50            # newest first, read-only
opencanary-correlator --dlq-replay ENTRY_ID    # requeue exactly one
```

Inspection prints the entry id, target, incident, attempts and the classifier's
reason; the stored payload is never echoed. A replay resets attempts to zero and
puts the entry back in the delivery index with the same identity, so the retry is
the same delivery, not a new one. Replay after fixing the cause (a rotated token,
a hostname that did not resolve); a second replay of the same entry is refused.

A dead letter protects its incident from retention. `OCC_DLQ_RETENTION_DAYS`
must therefore be shorter than `OCC_RETENTION_DAYS`; startup rejects the other
order because it would keep every failed incident forever.
`opencanary_outbox_dead_entries` is how many are retained right now: it should
fall back towards zero once the channel is fixed and the dead letters expire.

## Slow or failing channel

`opencanary_outbox_oldest_pending_age_seconds` growing while
`opencanary_outbox_pending` stays flat means attempts are happening and failing
on backoff. Check `opencanary_alerts_total{dispatcher,status}` and
`opencanary_outbox_terminal_total{reason}` for whether deliveries are being
buried. Disable the broken channel rather than lowering `outbox_max_attempts`:
the other channels keep their own debts.

## GeoIP database failure

`opencanary_enrichment_geo_total{result="error"}` plus an `enrichment_failed`
audit record with `details.failures = ["city:ValueError"]` means the reader
raised, not that the address is unknown (`result="no_match"`). The alert still
goes out with whatever the other database returned; replace the MMDB file and
restart. A path that cannot be opened is a startup error by design.

## OpenCTI lookup or write failure

`opencti_failed` names the failing stage: `unauthorized` (HTTP 401/403, audit
status `error`) means the API token is rejected; `timeout`, `network_error`,
`http_error`, `invalid_response` and `response_too_large` leave the alert intact
with `🔎 OpenCTI: unavailable`. A skipped write is `opencti_create_skipped` with
`lookup_unavailable`, `lookup_unauthorized` or `missing_indicator_id`; a
non-public address surfaces as `opencti_lookup` with `status=unavailable` and
`outcome=skipped`, and a label that could not be resolved appears as
`enrichment_request_skipped{provider="opencti",reason="label_unavailable"}`
without blocking the indicator.

Mutations are deliberately not retried: a create that timed out may already have
been applied, so check the platform for the exact STIX pattern before re-running
anything by hand. Repeated alerts are safe by design — `missing` and `always`
search the exact pattern first, and `always` patches the existing indicator
instead of adding a second one. If writes fail with `unauthorized`, rotate
`OCC_OPENCTI_TOKEN`; if only labels fail, create them in OpenCTI or remove them
from `OCC_OPENCTI_LABELS`.

## Silent canary

`canary_silent` (audit) or the `canary.silent` service message names the node and
its last delivery. Silence means "no events arrived", which is also what a quiet
honeypot looks like: confirm the node is up and its logger points at this
correlator before changing anything. Nodes listed in `OCC_CANARY_EXPECTED_NODES`
are checked after `OCC_CANARY_STARTUP_GRACE`; a node that never appeared is
reported as never seen rather than as silent for an implausible duration.

## Retention

Retention is off by default and deletes nothing until it is enabled:

```bash
OCC_RETENTION_ENABLED=true
OCC_RETENTION_DAYS=30
OCC_RETENTION_INTERVAL=3600
OCC_RETENTION_BATCH=200
OCC_DLQ_RETENTION_DAYS=14
opencanary-correlator --retention-run     # one bounded pass, prints counts
```

These are the recommended starting values for production. `OCC_DLQ_RETENTION_DAYS`
must stay below `OCC_RETENTION_DAYS` (startup validation refuses the opposite), and
`--retention-run` performs one bounded pass immediately instead of waiting for the
interval, which is what you want after changing the policy.

The pass is bounded by `OCC_RETENTION_BATCH` per object type, runs on one
elected replica per `OCC_RETENTION_INTERVAL`, and keeps any incident whose
delivery is still preparing, queued or dead. `opencanary_retention_protected_total`
counts the ones it kept, so a growing value means dead letters or a stuck
channel, not a retention bug; `opencanary_retention_removed_total` counts what
the pass actually deleted, by scope.

## Slow audit consumer

The audit trail is JSON lines on stdout and the file handler writes
`OCC_LOG_FILE`. If the container's log driver cannot keep up, records are queued
and then dropped by the bounded handler; `RedisLogHandler.dropped` is the
accounting. Use a local log driver with rotation rather than raising the queue
without a sink that drains it.
