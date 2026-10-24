# ExecPlan: Single-round-trip incident merge

Status: **closed at Milestone 0 (2026-10-24) — not implemented.** The measurement
this plan asked for says the consolidation targets the wrong third of the cost:
on a native Linux server the six round trips are ~31-33 % of an event, and the
ceiling of the rewrite is about **28 %** of wall time. Milestones 1-5 are not
planned. Evidence and reasoning: [Milestone 0 result and decision](#milestone-0-result-and-decision).

## 1. Goal

Take the merge path of a hot incident from six Redis round trips to one, so a
single source host can no longer be limited by per-event latency, without
changing the Redis key layout, the incident field names that the legacy console
reads, or the guarantee that N replicas produce exactly one incident and one
alert.

The remaining cost is now entirely round trips. Measured on the same
`python:3.11-slim` + `redis:7-alpine` loopback pair used for the acceptance
numbers in [validation.md](validation.md#performance):

| Measurement | Value | What it means |
|---|---|---|
| `PING` through the async client, 2 000 calls | **0.183 ms** | cost of one round trip |
| `IncidentRepository.record()` against real Redis | **1.331 ms** | 5 hops + Python |
| the same `record()` against an in-process stub store | **0.097 ms** | the merge logic itself |
| difference | **1.234 ms** | **93 % of a merge is the network** |

`record()` issues five commands today (lock `SET NX`, pointer `HGETALL`, hash
`HGETALL`, save `EVALSHA`, release `EVALSHA`). The receiver path adds dedup, so
`INFO commandstats` for 2 000 events shows exactly six hops per event: `set`
2 per event, `hgetall` 2, `evalsha` 2. At 0.183 ms per hop that is the measured
1.77 ms/event, 17.7 s for 10 000 events.

Rebuilding the merge in Python cannot help: it is 7 % of the cost. The win is
available only by removing hops.

Non-goals:

- no new keys, no change to `incident:*`, `incidents` or
  `incident-latest:*`; the existing `incident-lock:*` key is reused, not
  replaced;
- no change to what the console reads: same field names, same `events_skipped`
  and `events_truncated` semantics, same alert payloads;
- no dedup semantics change (see the note on dedup below — this is the reason
  the end-to-end target is stated separately);
- no Redis Cluster support: the script keeps touching keys in several slots,
  which stays a documented limitation.

## 2. Progress and Milestones

- [x] Milestone 0: Reference measurement on native Linux — run on
      `ubuntu-latest` (2026-10-24). Verdict: the rewrite is not worth its risk;
      closed here.
- [~] Milestone 1-5: not planned. Kept below as the design record for the case
      where throughput on a server-class host ever becomes the constraint.

## 3. Plan of Work

### Milestone 0 gate: is the target a VM artifact?

Docker Desktop reports a 0.183 ms loopback round trip. Native Linux loopback is
an order of magnitude cheaper, so the same code may already meet the target on
the platform the numbers are compared on. Before writing Lua, run
`tools/bench_ingest.py --events 10000 --hosts 1 --concurrency 1` on a native
Linux host (a `ubuntu-latest` runner is enough) and record the RTT with
`redis-cli --latency`.

- If the receiver path is already ≤ 5 s there, the honest deliverable is the
  measurement plus a CI benchmark, not a rewrite — and this plan stops at
  Milestone 0.
- If it is not, the projections below apply and the work proceeds.

### Milestone 0 result and decision

The gate was run as a `benchmark` job on `ubuntu-latest` with a **native**
`redis-server` (not a service container, which would smuggle the Docker
network back in). Three invocations of the same commit; the third reproduced
Run B (12.404 s at a 0.057 ms round trip), so the spread is the runner:

| | Run A | Run B | Docker Desktop (recorded earlier) |
|---|---|---|---|
| Loopback round trip | **0.029 ms** (p50 0.031) | **0.063 ms** (p50 0.063) | 0.183 ms |
| Hot incident, 10k events, 1 lane | **5.145 s** (1 943 ev/s) | **12.040 s** (831 ev/s) | 17.707 s |
| ms per event | 0.514 | 1.204 | 1.771 |
| of which six round trips | 0.171 (33 %) | 0.379 (31 %) | 1.098 (62 %) |
| of which Python + receiver | 0.343 (67 %) | 0.825 (69 %) | 0.673 (38 %) |
| Other workload (100 hosts, 8 lanes) | 4.347 s | 11.094 s | — |

Three conclusions, and the third is the one that decides the plan:

1. **The Docker Desktop penalty is real but not a redesign trigger.** Loopback
   costs 0.183 ms there against 0.029-0.063 ms natively, which is most of the
   17.7 s → 5.1 s difference. The 77.2 s → 17.7 s improvement recorded for the
   capped history stands; the 5 s target was being missed largely by the VM.
2. **A shared runner cannot gate a wall-time target.** The same commit took
   5.145 s, 12.040 s and 12.404 s on consecutive runs, with the round trip
   doubling alongside it — CPU steal on `ubuntu-latest` is the variable, not
   the code.
   That is why the CI job records numbers and never asserts one.
3. **The rewrite addresses the smaller share on real hardware.** On Docker
   Desktop the six hops were 62-93 % of a merge, which is what made this plan
   look attractive. On a native server they are ~31-33 %, the ceiling of
   removing five of them is ~28 % of wall time (5.1 s → ~3.7 s on the fast run),
   and the dominant cost becomes Python: parsing, Pydantic validation, the
   merge logic (0.097 ms alone) and the receiver/queue path.

**Decision:** do not implement milestones 1-5. Spending a `cjson` merge
implementation, a parity test suite and a lock-semantics change to move a third
of the cost is a bad trade, and the remaining third is where any future
throughput work belongs. The plan is kept as the design record, and the
`benchmark` job stays as a regression record for both workloads.

If throughput becomes a requirement, the cheaper first steps are, in order:
profile the 0.343-0.825 ms of non-Redis work per event; look at whether the
incident hash needs a full Pydantic round trip on every merge; and only then
reconsider the single-script merge.

### The three shapes a merge can take

| | Hops per event | Projected repository merge, 10k events | Projected receiver path | Lock |
|---|---|---|---|---|
| Today | 6 (dedup + 5) | 13.3 s measured | 17.7 s measured | outside, compare-and-delete |
| B: hybrid | 2 (dedup + merge) | ~4 s | ~7 s | kept, but must survive a cross-script gap |
| C: one script | 1 (dedup + merge) | ~4 s | ~6.5 s | taken and released **inside** the script |

Projections are `hops × 0.183 ms + 0.097 ms` plus the measured per-hop excess
for larger payloads (~0.25 ms observed, not 0.183); they are estimates to verify,
not claims.

**Variant C is the one this plan recommends**, for a reason that is architectural
rather than numeric: a single script makes the "create or merge" decision atomic
inside Redis, which is precisely the job the lock was introduced for. Variant B
keeps the Python merge and therefore keeps needing the lock across a gap between
two scripts — that gap is where the interesting failure modes live.

### What happens to the lock

The lock exists because create-or-merge spans several round trips: two replicas
that both see "no incident" would create two incidents and send two alerts. Its
release is already a compare-and-delete script, because a `GET` + `DEL` pair
could delete a successor's lock after a TTL expiry (the P2 fix).

Four options, with what each costs and risks:

1. **Lock outside, as today (status quo).** Correct, but it is one of the five
   hops, and it can only protect a decision that happens outside Redis.
2. **Lock dropped entirely.** Tempting — Redis executes a script atomically, so
   a `SET NX` becomes redundant *for a fleet of new replicas*. It is **not**
   safe during a rolling upgrade: an old replica still acquires the lock and
   decides outside a script, so an old and a new replica can interleave and both
   create an incident. Rejected for that reason alone.
3. **Lock taken and released inside the script (recommended).** The script does
   `SET key token NX PX ttl` on the **existing** `incident-lock:<type>:<host>`
   key as its first step and `DEL`s it as its last, both inside the same
   atomic execution. Cross-version mutual exclusion is preserved verbatim (the
   lock name and TTL are unchanged), and it costs no extra round trip because it
   is inside the script we were already sending. If the lock is held, the script
   returns `BUSY` immediately instead of blocking Redis, and the Python caller
   retries with a short sleep, reusing today's 5 s wait budget.
4. **Fencing token / optimistic revision.** Needed only if the merge spans
   round trips (variant B): a revision field would have to be added to the
   legacy hash to detect a concurrent writer, which changes the stored fields
   older readers see. Rejected: option 3 gets atomicity without a new field.

The compare-and-delete semantics are preserved in option 3 but become
unobservable from outside: there is no window in which the lock outlives the
merge, because both happen in one execution. The existing
`RedisStore._release_lock` stays for the paths that still take the lock the
normal way, and the P2 test for it stays.

### What the script must do, in order

1. `SET incident-lock:<type>:<host> <token> NX PX 5000` → `BUSY` if held.
2. Read `incident-latest:<type>:<host>`; accept its `key` only when it starts
   with the caller's prefix **and** its score is inside the horizon.
3. On a miss, `ZREVRANGEBYSCORE incidents +inf <min_score>` and match the
   prefix inside Lua (the fallback that keeps old replicas' incidents
   mergeable). Still one round trip.
4. `HGETALL` the resolved key, or report "no incident".
5. Merge according to a `mode` argument the Python side supplies — see below.
6. `HSET` the changed fields, `ZADD incidents`, `HSET` the pointer.
7. `DEL` the lock, return status (`created` / `merged` / `busy`), the key and
   `events_count`.

### Keeping the merge logic in one place

The five incident classes differ only in how `logdata` merges: append one entry
(login/SMB classes) or union a set (both scan classes), and the scan classes
never truncate. The script therefore implements **two generic modes**,
`append` and `set`, selected by an argument that the Python incident class
already knows. The Python implementations (`append_timestamp`,
`merge_logdata`, `trim_logdata`) stay in the model as the reference
implementation:

- they keep serving the create path, which is one event and needs no script;
- they become the oracle for a parity test that runs random event sequences
  through both implementations and compares the resulting field dict.

This is the main correctness risk of the plan, so it gets an explicit guard
rather than good intentions: if the Lua merge and the Python merge ever disagree,
the parity test fails on the sequence that caused it.

### Note on dedup, and why the end-to-end target is stated separately

Deduplication happens in `CorrelationEngine.handle_event()` **before** the rules
run, because a retransmitted event must not advance a port-scan window. Folding
it into the merge script would move it after rule evaluation and change scan
behaviour. It therefore stays a separate hop, and the honest targets are:

- repository merge for a hot incident: **≤ 5 s** for 10 000 events (from 13.3 s);
- receiver end to end, including dedup: **≤ 8 s** (from 17.7 s).

Reaching ≤ 5 s end to end would require removing the dedup hop as well, which is
a semantics change for scan rules and is out of scope here.

### Risks

- **Lua/cjson round-tripping of `logdata`.** `cjson.decode`/`encode` can reorder
  object keys and cannot represent integers beyond 2^53 exactly. Passwords,
  usernames and ports in the observed events are strings and small integers, but
  a honeypot payload is attacker-controlled. Mitigation: a parity test with
  hostile `logdata` (floats, large integers, unicode, nested objects, empty
  object, non-object entries) must produce byte-identical stored JSON or a
  documented, tested normalisation.
- **Script CPU blocks the server.** A longer script holds Redis's single thread.
  At the measured ~14 µs per `EVALSHA` today there is headroom, but the merged
  script is bigger. Mitigation: `redis-cli --latency` p99 during a 10k-event run
  must stay under the 2 ms already promised in the acceptance record.
- **Divergence between two merge implementations.** Covered by the parity test
  in Milestone 4; the Python version remains the reference.
- **Truncation bookkeeping moving into Lua.** The `events_truncated` flag,
  the frozen CSV and the counters-only write are the semantics we just merged;
  a Lua re-implementation can quietly change what the console sees. Mitigation:
  the parity test compares the full field dict, not just the counters, and the
  console payload test for a 10 000-event incident stays as it is.
- **Mixed-version fleet.** Preserved by option 3 (same lock key, same TTL); a
  test starts an old-style lock holder and asserts the script reports `BUSY`
  instead of creating a second incident.
- **fakeredis fidelity.** The unit suite runs Lua through `lupa`; results must
  be confirmed against real `redis:7-alpine` in the opt-in integration tests,
  because the two interpreters differ on error messages and on `cjson` edge
  cases.

## 4. Concrete Steps

1. `tools/bench_ingest.py`
   - add `--print-rtt` (measure `PING` before the run) and report the per-hop
     cost and hops-per-event in the JSON summary, so the attribution above is
     reproducible instead of quoted from this document.
2. `.github/workflows/ci.yml`
   - add a `benchmark` job on `ubuntu-latest` that starts the digest-pinned Redis
     service, runs the hot-incident bench (2 000 events, deterministic) and
     prints the summary; not a gate on wall time, only a recorded number — this
     is what makes Milestone 0 repeatable.
3. `src/opencanary_correlator/storage/redis_store.py`
   - add `MERGE_INCIDENT_LUA` implementing the seven steps above, with the two
     merge modes inline;
   - add `async def merge_incident(...)` returning a small result object
     (`status`, `key`, `events_count`, `events_truncated`), taking the prefix,
     pointer key, lock key, horizon, score, cap, mode and the new logdata entry
     as arguments;
   - keep `save_incident()` untouched: the create path still uses it, and it is
     the script the new one is validated against.
4. `src/opencanary_correlator/core/incident.py`
   - give `Incident` a `merge_mode: ClassVar[str] = "append"` and override it
     with `"set"` on both scan classes;
   - in `IncidentRepository.record()`, replace the lock block, the
     `find_recent_incident()` call, the `hgetall()` and the `save_incident()`
     call with one `merge_incident()` call; keep the create branch and
     `save_incident()` for the `created` case;
   - keep the retry loop for `status == "busy"` inside the existing
     `DEFAULT_LOCK_WAIT_SECONDS` budget, and keep the
     `incident_lock_timeout` audit record for the exhausted case;
   - keep `append_timestamp`, `merge_logdata` and `trim_logdata` as the
     reference implementation; they must not become dead code — the parity test
     and the create path use them.
5. `tests/unit/test_incident_parity.py` (new)
   - random event sequences (1–300 events, mixed `logdata` shapes) driven
     through the script on fakeredis and through the Python model, comparing the
     whole stored field dict;
   - hostile `logdata`: floats, integers above 2^53, unicode, nested objects,
     empty object, list payloads;
   - cap boundary: 99, 100, 101 and 250 merges for both modes.
6. `tests/unit/test_incident.py`
   - existing merge tests must pass unchanged against the new path, including
     prefix collision, stale pointer, corrupt pointer and per-incident horizons;
   - add: `BUSY` when the lock key is already held; no incident created on
     `BUSY`; retry until the holder releases;
   - add: a merge never leaves the lock key behind (assert the key is absent
     after `record()`).
7. `tests/integration/test_redis_atomicity.py`
   - 200 concurrent distinct events on one host through two repositories against
     one real Redis: one incident, `events_count == 200`, one notification, no
     residual lock key.
8. `tests/integration/test_real_redis.py`
   - the opt-in 1 000-event merge asserts the hash stays under 16 KB and
     `USER`/`PASSWORD` values survive the `cjson` round trip byte-identically.
9. Documentation
   - `docs/validation.md`: add the attribution table (RTT, merge, Python-only),
     the hop counts from `INFO commandstats`, the native-Linux reference and the
     before/after for both targets;
   - `docs/architecture.md`: the merge is one script — update the "Redis state"
     paragraph that currently lists six commands and the "Redis topology"
     paragraph, which still holds;
   - `README.md`: replace "Events still cost about six Redis round trips each"
     with the measured number and the new shape;
   - this file: tick milestones with dates and record deviations;
   - `docs/EXECPLAN-refactor.md`: one progress entry pointing here.

## 5. Validation and Acceptance

**Quality gates**

- `ruff check .`, `ruff format --check .`, `mypy src tools` clean.
- `pytest` green, coverage not below the current 91 %; no existing test is
  weakened or removed.
- `tools/linux_check.sh` green — the script must behave the same under `lupa`
  and under a real server.

**Measured acceptance (same machine and container as the recorded numbers)**

- Hot-incident merge, 10 000 events from one host: **≤ 5 s**, down from the
  recorded 13.3 s.
- Receiver path, same workload: **≤ 8 s**, down from the recorded 17.7 s.
- `INFO commandstats` for that run: **one `evalsha` per event** (plus the dedup
  `set`), no `hgetall`, no plain `set` for the lock, no `del` outside a script.
- Incident hash stays at the recorded 4 329 bytes with
  `events_count == 10000` and `events_truncated == True`.
- `redis-cli --latency` average during the run stays within 10 % of the idle
  value, p99 under 2 ms.

**Correctness acceptance**

- Parity: for every generated sequence, the script and the Python model produce
  identical field dicts.
- One incident, one alert under 200 concurrent events from two repositories.
- A held lock yields `BUSY` and no second incident; the legacy
  `incident-lock:*` key name is unchanged, so an old replica still excludes a
  new one.
- Prefix collisions still do not merge (`10.0.0.5` vs `10.0.0.55`).
- Port scans keep every distinct port/target and never truncate.
- The console payload for a 10 000-event incident is byte-identical to the
  current one apart from timestamps.

**Rollback**: revert the commit that switches `record()` to `merge_incident()`;
the stored fields are unchanged, so no data migration is needed in either
direction. The script and the Python merge coexist during the change, which is
what makes a revert safe.

## 6. Open questions (moot after Milestone 0)

Kept so a future reader can see what was undecided when the plan was written:

1. Whether the ≤ 5 s target meant per repository merge or end to end including
   dedup. Answered by the measurement: on native hardware neither is worth a
   rewrite.
2. Whether to land the script anyway for the reduced server load. Answered by
   the 28 % ceiling and the `cjson` parity risk.
3. Whether taking the legacy lock key inside the script is acceptable. Never
   needed to be decided, since option 3 was only chosen by this plan.
