# ExecPlan: Bounded incident event storage

Status: **closed 2026-10-25 with deviations.** Milestones 1-4 implemented. Milestone 5 is closed with the ≤ 5 s throughput target not met (unit and query tests and the benchmark are in; steps 10-11 were not written). Milestone 6 is done. See [Implementation notes](#implementation-notes).

## 1. Goal

Remove the quadratic merge cost and the unbounded growth of a single incident
without changing what the legacy console shows.

Today every merge rewrites the whole incident: `IncidentRepository.record()`
reads the entire hash (`hgetall`), parses the growing `logdata` JSON, concatenates
the growing `events_list` string and sends every field back to Redis as script
arguments ([incident.py:388-400](../src/opencanary_correlator/core/incident.py),
[redis_store.py:51-58](../src/opencanary_correlator/storage/redis_store.py)).
The cost is O(n²) in bytes per incident: a single host sending 10,000 events
produces a ~0.6 MB hash, roughly 3 GB of traffic in each direction, and the
measured 77.2 s merge time (see [validation.md](validation.md#performance)).
The same volume is replicated to every replica and to the AOF, so the
amplification is not limited to the client.

The plan bounds the stored event list at `OCC_MAX_STORED_EVENTS`
(default `MAX_EVENT_COUNT` = 100), keeps `events_count` exact, records an
explicit truncation flag and derives `events_skipped` from the counter.

Why 100 is compatible rather than a product compromise: the legacy console
itself caps at 100. `jsonify_incident()` in the upstream code (`294470d`,
`opencanary_correlator/common/queries.py`) defines `MAX_EVENT_COUNT = 100`,
renders `events[:100]`, truncates `logdata[:100]` and reports the remainder as
`events_skipped`. Our port does the same
([queries.py:50-65](../src/opencanary_correlator/storage/queries.py),
[constants.py:141](../src/opencanary_correlator/constants.py)). Anything stored
beyond 100 events is never displayed; it only slows writes down.

Non-goals:

- no new Redis keys and no change to the key layout or to `incident:*` field
  names that already exist;
- no full-history archive (`incident-events:<key>` stream, option B) — that is a
  separate, opt-in decision;
- no destructive trimming of incidents that are already oversized: they are
  frozen (no longer rewritten) and expire with their horizon;
- no change to deduplication, horizons, incident identity or alert payload
  metadata.

## 2. Progress and Milestones

- [x] Milestone 1: Setting and constants — `OCC_MAX_STORED_EVENTS`, validation,
      `.env.example`, `--check-config` output. (2026-10-24)
- [x] Milestone 2: Incident model — `events_truncated`, capped append, frozen
      log list and untruncated set-shaped scan evidence. (2026-10-24)
- [x] Milestone 3: Repository write path — bounded fields and a partial hash
      write once the cap is reached. (2026-10-24)
- [x] Milestone 4: Query compatibility — `events_skipped` derived from
      `events_count`, `events_truncated` exposed, legacy fallback. (2026-10-24)
- [x] Milestone 5: Tests and benchmark, closed with deviations (2026-10-25): unit and query tests are in; the single-host benchmark improved 4.4x but misses the 5 s target, so the round-trip consolidation was evaluated in [EXECPLAN-merge-consolidation.md](EXECPLAN-merge-consolidation.md) and not implemented; steps 10-11 are not written.
- [x] Milestone 6: Documentation and sign-off (2026-10-25) — README, architecture, validation
      record, progress entry in the main exec-plan.

## 3. Plan of Work

**Compatibility contract.** The Redis shape stays `incident:<type>:<host>:<ts>`
with the existing fields; the two new fields are additive and ignored by older
readers. The rendered console payload for a large incident stays identical:
the same first 100 timestamps, the same first 100 log entries, and
`events_skipped` still equal to `events_count - 100`. No migration step is
needed for readers; writers simply stop appending beyond the cap.

**Where the cap is applied.** Only at the merge point in
`IncidentRepository.record()`. Creating an incident stores exactly one event,
so the create path is unchanged apart from the new fields. This keeps the rule
layer untouched and makes the behaviour independent of the incident type.

**Two merge shapes.** Login-class incidents append one entry per event, so the
cap is "keep the first N entries", which is exactly the slice the console
renders. Port-scan incidents merge a *set* (distinct ports or distinct targets),
so the cap keeps the first N sorted members while `logdata_count` records the
true number of distinct members; without that counter a 500-port scan would
claim 100 ports. Both shapes live in overridable class methods, so a future
incident type declares its own merge rule instead of inheriting the wrong one.

**Partial writes.** Once an incident holds N events, further merges must not
send the large fields at all. The repository passes a small dict
(`events_count`, `updated`, `events_truncated`, and `logdata`/`logdata_count`
only when the set actually changed) to `save_incident()`, which already accepts
an arbitrary field mapping, so no Lua change is required. This is what removes
the O(n²) traffic; truncating alone would still rewrite a constant small string
but would keep the same call shape.

**Existing oversized incidents.** An incident created before this change may
already hold 10,000 events. It is not rewritten and not trimmed: the merge path
sees `len(events_list) >= cap`, updates only the counters and lets the incident
expire with its horizon. This avoids silently destroying data that an operator
might still be investigating, and it gives the same cost profile immediately.

**Configuration.** `OCC_MAX_STORED_EVENTS` defaults to 100 and is bounded to
`1..10_000`. Values above 100 are allowed for operators who parse Redis
directly, but the console still renders 100; the setting is documented with that
consequence. `0` is rejected: an incident without any event would break the
legacy `events_list` rendering.

**Risks.**

- *Under-reporting in a notification*: alert bodies already omit raw `logdata`
  for webhooks; e-mail and chat still show the truncated list. Mitigation: the
  report keeps `events_count` in the audit entry and in the query payload, and
  `logdata_count` covers scans.
- *A future consumer needs full history*: mitigated by the explicit
  `events_truncated` marker and by treating option B as an additive follow-up,
  not a rewrite.
- *Setting drift across replicas*: the cap is per-process but affects only how
  much is appended, so mixed values converge to the larger one; the field stays
  readable and the counter exact.

## 4. Concrete Steps

1. `src/opencanary_correlator/config.py`
   - add `max_stored_events: int = Field(default=MAX_EVENT_COUNT, ge=1, le=10_000)`
     next to the scan/dedup settings, importing `MAX_EVENT_COUNT` from
     `constants`;
   - include it in the `--check-config` summary (`cli.py`, next to
     `dedup_ttl`/`scan_host_threshold`).
2. `.env.example`
   - document `OCC_MAX_STORED_EVENTS=100` with a one-paragraph explanation that
     it bounds stored history, that the console renders at most 100 entries, and
     that the counter stays exact.
3. `src/opencanary_correlator/core/incident.py`
   - add `events_truncated: bool = False` and `logdata_count: int = 0` to
     `Incident`;
   - extend `to_fields()` to emit `events_truncated` and `logdata_count` (only
     when true/non-zero, to keep small incidents byte-compatible), and accept
     their absence in `from_fields()`;
   - add `append_event_timestamp(existing: str, now: int, limit: int) -> tuple[str, bool]`
     returning the (possibly unchanged) CSV and whether it is now truncated;
   - replace `merge_logdata()` with
     `merge_logdata(existing: str | None, new: Any, *, limit: int) -> tuple[str, int]`
     on the base class (append, keep first `limit`, return total entries) and
     override it in `IncidentHostPortScan` and `IncidentNetworkPortScan`
     (deduplicate as today, keep the first `limit` sorted members, return the
     distinct total).
4. `src/opencanary_correlator/core/incident.py` — `IncidentRepository.record()`
   - compute `cap = self._settings.max_stored_events`;
   - on merge: increment `events_count`; call the capped helpers; set
     `events_truncated` when the stored list reached `cap` (or was already
     truncated);
   - when truncated, call `save_incident()` with a **partial** field dict
     instead of `merged.to_fields()`, including `logdata` only if its value
     changed;
   - keep `incident_updated` audit details and add `events_truncated` there.
5. `src/opencanary_correlator/storage/queries.py`
   - `events_skipped = max(events_count - len(rendered), 0)` when the stored
     hash carries `events_count`; fall back to `len(events) - MAX_EVENT_COUNT`
     for incidents written by an older build;
   - pass `logdata_count` through when present and keep `logdata[:MAX_EVENT_COUNT]`.
6. `tests/unit/test_incident.py`
   - 250 merges on one host: stored `events_list` holds `cap` timestamps,
     `events_count == 250`, `events_truncated is True`, and the serialized field
     dict stays under 4 KB;
   - a merge after the cap leaves `events_list` byte-identical (no growth);
   - host port scan with 300 distinct ports: 100 stored, `logdata_count == 300`,
     members sorted; network port scan with 50 targets behaves the same;
   - create path stores one event and no truncation flag.
7. `tests/unit/test_portscan_rules.py`
   - the existing threshold tests keep passing; add one that exceeds the cap and
     asserts both the stored prefix and `logdata_count`.
8. `tests/unit/test_queries.py`
   - a 10,000-event incident renders 100 timestamps, 100 log entries and
     `events_skipped == 9900`;
   - an incident without `events_count` still renders the legacy count.
9. `tests/unit/test_config.py`
   - default 100, `1` accepted, `0` and `10_001` rejected, environment parsing.
10. `tests/integration/test_redis_atomicity.py`
    - 200 concurrent distinct events on one host: one incident,
      `events_count == 200`, 100 stored timestamps, one notification.
11. `tests/integration/test_real_redis.py`
    - opt-in merge of 1,000 events: `MEMORY USAGE` on the incident hash stays
      under 16 KB and the counter is exact.
12. Documentation
    - `README.md`: the setting in the configuration table and a migration note
      ("existing incidents are frozen, not rewritten");
    - `docs/architecture.md`: replace the "merge rewrites the growing list" note
      with the capped/partial-write behaviour;
    - `docs/validation.md`: add the before/after benchmark and the console
      parity check;
    - this file: tick milestones with dates and record deviations;
    - `docs/EXECPLAN-refactor.md`: one progress entry pointing here.

## 5. Validation and Acceptance

**Quality gates**

- `ruff check .` and `ruff format --check .` clean; `mypy src tools` clean.
- `pytest` green with coverage ≥ 91 % (no test may be removed or weakened).
- `tools/linux_check.sh` green, because the merge path is exercised by the
  socket-level and real-Redis tests.

**Functional acceptance**

- 10,000 events from a **single** host through the real receiver:
  `events_count == 10000`, stored `events_list` holds exactly 100 timestamps,
  stored `logdata` holds exactly 100 entries, `events_skipped == 9900`, and
  `MEMORY USAGE incident:<key>` < 16 KB.
- Merge time for that workload drops from the recorded **77.2 s** to **≤ 5 s**
  on the same machine and the same real Redis container; the number is recorded
  in `docs/validation.md` with the measurement method, not asserted as a guess.
- `bench_ingest.py --events 10000 --hosts 1` reproduces the acceptance numbers,
  with 0 dropped and 0 rejected events.
- Console parity: the rendered payload for the 10,000-event incident is
  identical to the current one for the first 100 timestamps and 100 log entries,
  and `events_skipped` stays 9900.
- Key layout unchanged: `redis-cli --scan --pattern 'incident*'` returns the
  same key families, and no new key is created.

**Regression checks**

- 100 concurrent distinct events → one incident, `events_count == 100`, no
  truncation flag until the 101st event.
- Port-scan incidents still merge distinct ports and fire at the configured
  thresholds; `logdata_count` is exact for a scan larger than the cap.
- Existing oversized incidents created before the change are read correctly and
  are not rewritten on merge (byte-identical `events_list` before/after).

**Rollback**: raise `OCC_MAX_STORED_EVENTS` (up to 10,000) to store more, or
revert the merge-path commit; readers need no rollback because the new fields
are additive and ignored by older code.

## Implementation notes

**Deviations from the approved plan.**

- Set-shaped `logdata` (host/network port scans) is **not** capped and there is
  no `logdata_count` field. A scan records one entry per distinct port or
  target, so its list is bounded by that universe rather than by event volume,
  and truncating it would destroy the evidence the incident exists to record.
  Only append-shaped data — `events_list` and login/SMB log entries — is capped,
  which is where the per-event growth came from. The create path uses the same
  rule via a `trim_logdata()` override, so a first event carrying 300 ports
  keeps all 300.
- `events_truncated` and the partial write are one mechanism: the flag is what
  selects the counter-only update, so an observer can tell why stored history
  stopped growing.
- The query-side change (milestone 4) was pulled into this batch because
  capping without it would have reported `events_skipped = 0` for large
  incidents — a console regression, not a cosmetic detail.

**Measured (same machine, Redis 7 in a Linux container, Windows Docker Desktop).**

| Workload | Before | After |
|---|---|---|
| 10,000 events, one source host, repository merges only | 77.2 s recorded earlier | **13.3 s** in a repository-only run, 754 merges/s, hash **5,918 bytes** |
| Same workload through the receiver (`bench_ingest.py --hosts 1 --concurrency 1 --queue-size 20000`) | — | 17.4 s, 0 dropped, 1 incident |
| Stored history at 10,000 events | ~0.6 MB, 10,000 timestamps | 100 timestamps, 100 log entries, `events_count = 10000`, `events_truncated = True` |

**Decision (2026-10-25): the ≤ 5 s target is closed as not met for this plan.** Native Linux runs of the same commit gave 5.1 s and 12.0 s, so the number is dominated by runner noise and per-command overhead. The round-trip consolidation was evaluated in [EXECPLAN-merge-consolidation.md](EXECPLAN-merge-consolidation.md) and not implemented. Steps 10-11 of Concrete Steps (200-event atomicity test and the opt-in 1,000-event `MEMORY USAGE` test) were not written; the existing atomicity test covers 20 concurrent events. The byte cost is gone (the hash no
longer grows), so what remains is round trips: a merge still costs six commands
(dedup, lock acquire, pointer read, hash read, save script, lock release). At
~0.2 ms per local round trip that is ~13 s for 10k events. Closing the gap needs
the merge path collapsed into one script (pointer lookup + read + merge + write)
with the lock taken inside it, which is a larger, separate change — it is not
part of milestones 1-3 and should be planned on its own.
