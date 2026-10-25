"""Attribute the per-event ingestion cost to the code that actually spends it.

Milestone 0 of ``docs/internal/EXECPLAN-merge-consolidation.md`` showed that a merge is
round-trip bound, not byte bound. This tool answers the next question: of the
remaining in-process time, how much is JSON parsing, how much is Pydantic
validation, how much is fingerprinting, and how much is the correlation logic
around the Redis calls.

Two independent views, because they measure different things:

``cpu``
    Pure-Python loop over a realistic payload: ``json.loads`` ->
    ``CanaryEvent.model_validate`` -> ``event_fingerprint``. Timed with
    ``perf_counter`` per stage and profiled with ``cProfile`` for function-level
    shares. No I/O, so the numbers are reproducible everywhere.

``pipeline``
    The real engine against a real Redis. Measures the loopback round trip, then
    the per-event cost of deduplication and of a whole ``handle_event``, plus the
    number of Redis commands per event taken from ``INFO commandstats``. That
    separates ``commands x round trip`` from the Python time around it.

``commands``
    Decomposes the residual the `pipeline` mode leaves unexplained. One command
    costs more than one PING, and this mode separates the parts: a raw RESP PING
    over the same socket (kernel loopback plus asyncio streams), a redis-py PING
    (library plumbing), the same hash read with and without ``decode_responses``
    (string decoding), and - when ``hiredis`` is installed - the same commands
    with the C parser instead of the pure-Python one.

    python tools/profile_hot_path.py cpu --iterations 20000
    python tools/profile_hot_path.py pipeline --redis-url redis://localhost:6379/15
    python tools/profile_hot_path.py commands --redis-url redis://localhost:6379/15

Use a **disposable** database: the pipeline mode creates incidents for synthetic
hosts ``10.44.x.y`` and removes them afterwards, and the commands mode writes
``profile-cmd:*`` keys and deletes them on the way out.
"""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import importlib.util
import io
import json
import pstats
import statistics
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit

from redis import _parsers
from redis.asyncio import Redis

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import INCIDENT_TYPES, IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache, event_fingerprint
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.redis_store import RedisStore

PROFILE_HOST_PREFIX = "10.44."
DEFAULT_ITERATIONS = 20_000
DEFAULT_PIPELINE_EVENTS = 2_000
DEFAULT_COMMAND_ITERATIONS = 500
TOP_FUNCTIONS = 18
COMMAND_WARMUP = 20
STRING_KEY = "profile-cmd:string"
HASH_KEY = "profile-cmd:hash"
POINTER_KEY = "profile-cmd:pointer"
INDEX_KEY = "profile-cmd:index"
PROFILE_COMMAND_PREFIX = "profile-cmd:"
#: The only two fields a merge still needs once the stored history is capped.
MERGE_FIELDS = ("events_count", "events_truncated")

BASE_EVENT: dict[str, Any] = {
    "dst_host": "10.0.0.2",
    "dst_port": 21,
    "logtype": 2000,
    "node_id": "bench-1",
    "local_time": "2026-10-24 10:00:00.000000",
    "utc_time": "2026-10-24 10:00:00.000000",
    "logdata": {"USERNAME": "admin", "PASSWORD": "x"},
}


def build_lines(count: int, hosts: int = 0) -> list[bytes]:
    """Return `count` newline-terminated JSON lines, as a canary sends them.

    `hosts=0` gives every event its own source host, so the engine creates a new
    incident each time; `hosts=1` sends everything from one host into a single
    incident, which is the hot-merge shape.
    """
    lines: list[bytes] = []
    for index in range(count):
        host = (index % hosts) if hosts > 0 else index
        payload = dict(
            BASE_EVENT,
            src_host=f"{PROFILE_HOST_PREFIX}{host // 250}.{host % 250}",
            src_port=10000 + index,
        )
        lines.append((json.dumps(payload) + "\n").encode("utf-8"))
    return lines


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def _timed(stage_calls: Any, iterations: int) -> list[float]:
    """Run `stage_calls` `iterations` times and return per-call seconds."""
    samples: list[float] = []
    for index in range(iterations):
        started = time.perf_counter()
        stage_calls(index)
        samples.append(time.perf_counter() - started)
    return samples


def summarise(samples: list[float]) -> dict[str, float]:
    """Return mean/p50/p95 in microseconds."""
    return {
        "mean_us": round(statistics.fmean(samples) * 1e6, 3),
        "p50_us": round(_percentile(samples, 0.50) * 1e6, 3),
        "p95_us": round(_percentile(samples, 0.95) * 1e6, 3),
        "total_s": round(sum(samples), 4),
    }


def measure_merge(iterations: int) -> dict[str, dict[str, float]]:
    """Time the pure-Python half of a merge into a capped incident.

    The `pipeline` mode counts only parse/validate/fingerprint as CPU, so the
    rebuild-merge-write logic and the audit record show up in its residual.
    Measured here on the same incident shape the pipeline produces.
    """
    incident_cls = INCIDENT_TYPES["ftp.login_attempt"]
    fields = incident_fields()
    details: dict[str, Any] = {
        "incident": "ftp.login_attempt",
        "key": HASH_KEY,
        "events_count": 100,
        "events_truncated": True,
    }
    audit_logger = AuditLogger("profile", stream=io.StringIO())
    rebuilt = incident_cls.from_fields(HASH_KEY, fields)
    for _ in range(200):
        incident_cls.from_fields(HASH_KEY, fields)
        audit_logger.emit("incident_updated", "info", details)

    def merge_step(index: int) -> None:
        rebuilt.events_list, _changed = incident_cls.append_timestamp(
            rebuilt.events_list, 1_700_000_100, limit=100
        )
        rebuilt.logdata = incident_cls.merge_logdata(
            rebuilt.logdata, BASE_EVENT["logdata"], limit=100
        )
        rebuilt.to_fields()

    return {
        "from_fields": summarise(
            _timed(lambda index: incident_cls.from_fields(HASH_KEY, fields), iterations)
        ),
        "merge_and_to_fields": summarise(_timed(merge_step, iterations)),
        "decode_logdata": summarise(
            _timed(lambda index: json.loads(fields["logdata"]), iterations)
        ),
        "split_events_list": summarise(
            _timed(lambda index: fields["events_list"].split(","), iterations)
        ),
        "to_fields": summarise(_timed(lambda index: rebuilt.to_fields(), iterations)),
        "audit_emit": summarise(
            _timed(lambda index: audit_logger.emit("incident_updated", "info", details), iterations)
        ),
    }


def run_cpu(iterations: int) -> dict[str, Any]:
    """Time and profile the pure-Python part of ingestion."""
    lines = build_lines(iterations)
    texts = [line.decode("utf-8").strip() for line in lines]

    # Warm up: first-call costs (imports, caches, datetime tables) are not per-event.
    for text in texts[:200]:
        event_fingerprint(CanaryEvent.model_validate(json.loads(text)))

    parse = _timed(lambda index: json.loads(texts[index]), iterations)
    parsed = [json.loads(text) for text in texts]
    validate = _timed(lambda index: CanaryEvent.model_validate(parsed[index]), iterations)
    events = [CanaryEvent.model_validate(raw) for raw in parsed]
    fingerprint = _timed(lambda index: event_fingerprint(events[index]), iterations)

    profiler = cProfile.Profile()
    profiler.enable()
    for text in texts:
        event_fingerprint(CanaryEvent.model_validate(json.loads(text)))
    profiler.disable()
    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream).sort_stats("tottime")
    stats.print_stats(TOP_FUNCTIONS)
    # `pstats.Stats.stats` and `total_tt` are documented but missing from the
    # typeshed stubs, so they are read through `cast`/`getattr`.
    entries = cast(
        "dict[tuple[str, int, str], tuple[int, int, float, float, Any]]",
        vars(stats)["stats"],
    )
    total_tt = float(getattr(stats, "total_tt", 0.0))
    top = [
        {
            "function": function,
            "tottime_us_per_event": round(entry[2] / iterations * 1e6, 3),
            "cumtime_us_per_event": round(entry[3] / iterations * 1e6, 3),
            "calls_per_event": round(entry[1] / iterations, 2),
        }
        for function, entry in sorted(entries.items(), key=lambda item: item[1][2], reverse=True)[
            :TOP_FUNCTIONS
        ]
    ]

    return {
        "mode": "cpu",
        "iterations": iterations,
        "stages_us": {
            "json.loads": summarise(parse),
            "model_validate": summarise(validate),
            "event_fingerprint": summarise(fingerprint),
        },
        "merge_stages_us": measure_merge(iterations),
        "cpu_per_event_us": round(
            sum(statistics.fmean(samples) for samples in (parse, validate, fingerprint)) * 1e6, 3
        ),
        "profile_total_s": round(total_tt, 4),
        "top_functions": top,
    }


@dataclass(slots=True)
class CommandCounter:
    """Per-command call counts from ``INFO commandstats``."""

    store: RedisStore

    async def snapshot(self) -> dict[str, int]:
        """Return the number of calls per command name so far."""
        info = await self.store.client.info("commandstats")
        counts: dict[str, int] = {}
        for name, entry in info.items():
            if not isinstance(name, str) or not name.startswith("cmdstat_"):
                continue
            command = name.removeprefix("cmdstat_")
            if isinstance(entry, str):
                try:
                    counts[command] = int(entry.split("calls=")[1].split(",")[0])
                except (IndexError, ValueError):
                    continue
            elif isinstance(entry, dict):
                counts[command] = int(entry.get("calls", 0))
        return counts


def diff_counts(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    """Return per-command deltas, dropping commands that did not run."""
    return {
        command: after.get(command, 0) - before.get(command, 0)
        for command in set(before) | set(after)
        if after.get(command, 0) - before.get(command, 0)
    }


async def run_pipeline(redis_url: str, events: int, hosts: int = 0) -> dict[str, Any]:
    """Measure the asynchronous path against a real Redis."""
    store = RedisStore.from_url(redis_url)
    if not await store.ping():
        raise SystemExit(f"Redis is not reachable: {redis_url}")

    settings = Settings(
        redis_url=redis_url,
        _env_file=None,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
    )
    audit = AuditLogger("profile", stream=io.StringIO())
    repository = IncidentRepository(store, settings, audit)
    dedup = DedupCache(store, ttl=settings.dedup_ttl)
    rules = build_rules(store, repository, settings)
    engine = CorrelationEngine(
        rules=rules,
        dispatchers=[],
        dedup=dedup,
        settings=settings,
        audit=audit,
    )

    for _ in range(50):
        await store.ping()

    rtt: list[float] = []
    for _ in range(300):
        started = time.perf_counter()
        await store.ping()
        rtt.append(time.perf_counter() - started)
    rtt_mean = statistics.fmean(rtt)

    counter = CommandCounter(store)
    before = await counter.snapshot()
    dedup_samples: list[float] = []
    for index in range(events):
        started = time.perf_counter()
        await dedup.first_seen(f"profile-dedup-{index}")
        dedup_samples.append(time.perf_counter() - started)
    dedup_calls = sum(diff_counts(before, await counter.snapshot()).values())
    await store.client.delete(*(f"dedup:profile-dedup-{index}" for index in range(events)))

    lines = build_lines(events, hosts)
    texts = [line.decode("utf-8").strip() for line in lines]
    parse_samples = _timed(lambda index: json.loads(texts[index]), events)
    parsed = [json.loads(text) for text in texts]
    validate_samples = _timed(lambda index: CanaryEvent.model_validate(parsed[index]), events)
    events_parsed = [CanaryEvent.model_validate(raw) for raw in parsed]
    fingerprint_samples = _timed(lambda index: event_fingerprint(events_parsed[index]), events)
    match_samples = _timed(
        lambda index: [rule for rule in rules if rule.matches(events_parsed[index])], events
    )

    before = await counter.snapshot()
    handle_samples: list[float] = []
    for event in events_parsed:
        started = time.perf_counter()
        await engine.handle_event(event)
        handle_samples.append(time.perf_counter() - started)
    deltas = diff_counts(before, await counter.snapshot())

    # A second pass over the same hosts, timed around `record()` alone: every
    # event merges into the incident the first pass created, so this is the hot
    # merge with its exact command count.
    before = await counter.snapshot()
    record_samples: list[float] = []
    for event in events_parsed:
        started = time.perf_counter()
        await repository.record("ftp.login_attempt", event)
        record_samples.append(time.perf_counter() - started)
    record_deltas = diff_counts(before, await counter.snapshot())

    # `INFO commandstats` counts the commands a Lua script runs internally too.
    # Each event runs two scripts: the incident write (HSET x2 + ZADD) and the
    # lock release (GET + DEL). Those five never reach the wire, so subtracting
    # them leaves the round trips the event actually pays for.
    script_internal = 5
    total_commands = sum(deltas.values())
    script_calls = deltas.get("evalsha", 0)
    round_trips = total_commands - (script_calls // 2) * script_internal

    commands_per_event = total_commands / events
    round_trips_per_event = max(0.0, round_trips) / events
    rtt_per_event = round_trips_per_event * rtt_mean
    handle_mean = statistics.fmean(handle_samples)
    cpu_per_event = sum(
        statistics.fmean(samples)
        for samples in (parse_samples, validate_samples, fingerprint_samples)
    )
    residual = handle_mean - rtt_per_event - cpu_per_event
    incidents = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    summary = {
        "mode": "pipeline",
        "events": events,
        "hosts": hosts or events,
        "incidents": len([key for key in incidents if f":{PROFILE_HOST_PREFIX}" in key]),
        "rtt_us": {
            "mean": round(rtt_mean * 1e6, 3),
            "p50": round(_percentile(rtt, 0.50) * 1e6, 3),
            "p95": round(_percentile(rtt, 0.95) * 1e6, 3),
        },
        "redis": {
            "commands_per_dedup": round(dedup_calls / events, 2),
            "commands_per_event": round(commands_per_event, 2),
            "script_calls_per_event": round(script_calls / events, 2),
            "round_trips_per_event": round(round_trips_per_event, 2),
            "command_mix_per_event": {
                command: round(calls / events, 2) for command, calls in sorted(deltas.items())
            },
        },
        "cost_us_per_event": {
            "handle_event": round(handle_mean * 1e6, 3),
            "measured_cpu_parse_validate_fingerprint": round(cpu_per_event * 1e6, 3),
            "estimated_round_trips_x_ping": round(rtt_per_event * 1e6, 3),
            "residual_event_loop_and_protocol": round(residual * 1e6, 3),
        },
        "share_pct": {
            "cpu": round(cpu_per_event / handle_mean * 100, 1),
            "round_trips_x_ping": round(rtt_per_event / handle_mean * 100, 1),
            "residual": round(residual / handle_mean * 100, 1),
        },
        "dedup": summarise(dedup_samples),
        "handle_event": summarise(handle_samples),
        "record": summarise(record_samples),
        "record_commands_per_call": round(sum(record_deltas.values()) / events, 2),
        "rule_matches_only": summarise(match_samples),
        "parse": summarise(parse_samples),
        "validate": summarise(validate_samples),
        "fingerprint": summarise(fingerprint_samples),
    }
    await cleanup(store)
    await store.aclose()
    return summary


async def cleanup(store: RedisStore) -> None:
    """Remove incidents created for the synthetic hosts."""
    for key in await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf"):
        if f":{PROFILE_HOST_PREFIX}" in key:
            await store.delete(key)
            await store.client.zrem(KEY_INCIDENTS, key)


def print_human(summary: dict[str, Any]) -> None:
    """Print a compact table next to the JSON payload."""
    print(json.dumps(summary, indent=2))
    print()
    if summary["mode"] == "cpu":
        total = summary["cpu_per_event_us"]
        print(f"python per event: {total} us over {summary['iterations']} events")
        for stage, values in summary["stages_us"].items():
            print(
                f"  {stage:<18} mean {values['mean_us']:>8.2f} us   p95 {values['p95_us']:>8.2f} us"
            )
        print("\nmerge into a capped incident (pure Python, per call):")
        for stage, values in summary["merge_stages_us"].items():
            print(
                f"  {stage:<20} mean {values['mean_us']:>8.2f} us   p95 {values['p95_us']:>8.2f} us"
            )
        print("\ntop functions by own time per event:")
        for entry in summary["top_functions"][:10]:
            own = entry["tottime_us_per_event"]
            cumulative = entry["cumtime_us_per_event"]
            print(f"  {own:>8.2f} us  cum {cumulative:>8.2f} us  {entry['function'][:76]}")
    elif summary["mode"] == "commands":
        print(f"raw RESP PING (socket + asyncio only): {summary['raw_resp_ping']['mean_us']} us")
        print(f"hiredis available: {summary['hiredis_available']}")
        scenarios = ["ping", "hmget_two", "hgetall", "hset", "save_incident", "dedup"]
        header = "variant".ljust(9) + "".join(name.rjust(16) for name in scenarios)
        print("\n" + header)
        for variant, values in summary["variants_us"].items():
            row = variant.ljust(9) + "".join(
                f"{values[name]['mean_us']:>16.1f}" for name in scenarios
            )
            print(row)
        print("\ninterleaved deltas (median / p25 / p75, us; positive = second is slower):")
        for label, values in summary["paired_deltas_us"].items():
            print(
                f"  {label:<28} {values['median_us']:>8.1f}  {values['p25_us']:>7.1f}"
                f"  {values['p75_us']:>7.1f}"
            )
        print("\nderived (us):")
        for name, value in summary["derived_us"].items():
            print(f"  {name:<28} {value:>8.1f}")
    else:
        rtt = summary["rtt_us"]
        handle = summary["handle_event"]
        cost = summary["cost_us_per_event"]
        share = summary["share_pct"]
        print(
            f"ping rtt mean {rtt['mean']} us | handle_event mean {handle['mean_us']} us"
            f" ({summary['redis']['round_trips_per_event']} round trips per event,"
            f" {summary['redis']['commands_per_event']} commands including scripts)"
        )
        print(
            f"  measured CPU       {cost['measured_cpu_parse_validate_fingerprint']:>9.1f} us"
            f"  {share['cpu']:>5.1f}%"
        )
        print(
            f"  round trips x ping {cost['estimated_round_trips_x_ping']:>9.1f} us"
            f"  {share['round_trips_x_ping']:>5.1f}%"
        )
        print(
            f"  event loop + proto {cost['residual_event_loop_and_protocol']:>9.1f} us"
            f"  {share['residual']:>5.1f}%"
        )
        mix = summary["redis"]["command_mix_per_event"]
        print(
            "\ncommands per event: " + ", ".join(f"{name} {count}" for name, count in mix.items())
        )


def incident_fields() -> dict[str, str]:
    """A capped incident hash, the shape a hot merge reads and rewrites."""
    events = ",".join(str(1_700_000_000 + index) for index in range(100))
    logdata = json.dumps(
        [{"USERNAME": f"user{index}", "PASSWORD": "x" * 8} for index in range(100)]
    )
    return {
        "node_id": "bench-1",
        "src_host": f"{PROFILE_HOST_PREFIX}0.1",
        "src_port": "40000",
        "dst_host": "10.0.0.2",
        "dst_port": "21",
        "logtype": "2000",
        "created": "1700000000",
        "events_list": events,
        "events_count": "100",
        "events_truncated": "True",
        "acknowledged": "False",
        "notified": "False",
        "updated": "True",
        "description": "FTP Login Attempt",
        "logdata": logdata,
    }


async def _sample(call: Callable[[], Awaitable[Any]], iterations: int) -> dict[str, float]:
    """Time one awaitable call, discarding the warm-up."""
    for _ in range(COMMAND_WARMUP):
        await call()
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        await call()
        samples.append(time.perf_counter() - started)
    return summarise(samples)


async def measure_raw_ping(redis_url: str, iterations: int) -> dict[str, float]:
    """PING written by hand, so only the kernel loopback and asyncio remain."""
    parts = urlsplit(redis_url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 6379
    reader, writer = await asyncio.open_connection(host, port)
    request = b"*1\r\n$4\r\nPING\r\n"
    samples: list[float] = []
    try:
        for index in range(iterations + COMMAND_WARMUP):
            started = time.perf_counter()
            writer.write(request)
            await writer.drain()
            reply = await reader.readline()
            elapsed = time.perf_counter() - started
            if reply != b"+PONG\r\n":
                raise SystemExit(f"unexpected PING reply: {reply!r}")
            if index >= COMMAND_WARMUP:
                samples.append(elapsed)
    finally:
        writer.close()
        await writer.wait_closed()
    return summarise(samples)


def build_clients(redis_url: str) -> dict[str, Redis]:
    """One client per parser/decoding variant available on this interpreter."""
    clients: dict[str, Redis] = {
        "str": Redis.from_url(redis_url, decode_responses=True),
        "bytes": Redis.from_url(redis_url, decode_responses=False),
    }
    # redis-py 6 keeps the parser classes private and names the asyncio one
    # `_AsyncHiredisParser` (older releases exported `HiredisParser`), so the
    # class is resolved dynamically: absence means "hiredis not installed",
    # which is a valid state of the tool, not an error.
    parser_class = getattr(_parsers, "_AsyncHiredisParser", None) or getattr(
        _parsers, "HiredisParser", None
    )
    # The class exists even when the C parser does not: its `__init__` raises
    # "Hiredis is not available". Presence of the class therefore says nothing,
    # and the module has to be looked up as well - without this check `commands`
    # failed outright on an interpreter without hiredis.
    if parser_class is None or importlib.util.find_spec("hiredis") is None:
        return clients
    clients["hiredis"] = Redis.from_url(redis_url, decode_responses=True, parser_class=parser_class)
    return clients


async def _hmget(client: Redis, key: str, names: Sequence[str]) -> list[Any]:
    """Read selected hash fields, awaiting the coroutine redis-py returns."""
    pending = cast(Awaitable[Any], client.hmget(key, list(names)))
    return cast(list[Any], await pending)


async def measure_client(store: RedisStore, iterations: int) -> dict[str, dict[str, float]]:
    """Time the commands one hot event issues against one client variant."""
    fields = incident_fields()
    await store.client.set(STRING_KEY, "x" * 64)
    await store.hset_mapping(HASH_KEY, fields)
    counter = 0

    def next_dedup() -> str:
        nonlocal counter
        counter += 1
        return f"profile-cmd-{counter}"

    return {
        "ping": await _sample(lambda: store.client.ping(), iterations),
        "hgetall": await _sample(lambda: store.hgetall(HASH_KEY), iterations),
        "hmget_two": await _sample(
            lambda: _hmget(store.client, HASH_KEY, ("events_count", "events_truncated")),
            iterations,
        ),
        "hset": await _sample(lambda: store.hset_mapping(HASH_KEY, fields), iterations),
        "save_incident": await _sample(
            lambda: store.save_incident(
                HASH_KEY, fields, score=1_700_000_000, pointer_key=POINTER_KEY
            ),
            iterations,
        ),
        "dedup": await _sample(lambda: store.acquire_dedup(next_dedup(), ttl=5.0), iterations),
    }


async def _paired(
    first: Callable[[], Awaitable[Any]],
    second: Callable[[], Awaitable[Any]],
    iterations: int,
) -> dict[str, float]:
    """Median of ``second - first`` with the two calls interleaved.

    A shared host drifts by tens of microseconds between runs, which is the same
    order as the deltas this mode is looking for (a parser swap, string
    decoding). Differencing two interleaved calls inside one loop cancels that
    drift, and the median ignores the occasional stall.
    """
    for _ in range(COMMAND_WARMUP):
        await first()
        await second()
    deltas: list[float] = []
    for index in range(iterations):
        started = time.perf_counter()
        if index % 2 == 0:
            await first()
            middle = time.perf_counter()
            await second()
            finished = time.perf_counter()
            deltas.append((finished - middle) - (middle - started))
        else:
            await second()
            middle = time.perf_counter()
            await first()
            finished = time.perf_counter()
            deltas.append((middle - started) - (finished - middle))
    return {
        "median_us": round(statistics.median(deltas) * 1e6, 3),
        "mean_us": round(statistics.fmean(deltas) * 1e6, 3),
        "p25_us": round(_percentile(deltas, 0.25) * 1e6, 3),
        "p75_us": round(_percentile(deltas, 0.75) * 1e6, 3),
    }


async def run_commands(redis_url: str, iterations: int) -> dict[str, Any]:
    """Decompose the per-command cost above a bare round trip."""
    raw = await measure_raw_ping(redis_url, iterations)
    clients = build_clients(redis_url)
    stores = {name: RedisStore(client) for name, client in clients.items()}
    fields = incident_fields()
    variants: dict[str, dict[str, dict[str, float]]] = {}
    paired: dict[str, dict[str, float]] = {}
    try:
        for name, store in stores.items():
            if not await store.ping():
                raise SystemExit(f"Redis is not reachable: {redis_url}")
            variants[name] = await measure_client(store, iterations)

        text = stores["str"]
        pairs: dict[str, tuple[Callable[[], Awaitable[Any]], Callable[[], Awaitable[Any]]]] = {
            "hgetall over hmget(2 fields)": (
                lambda: _hmget(text.client, HASH_KEY, MERGE_FIELDS),
                lambda: text.hgetall(HASH_KEY),
            ),
            "hgetall over ping": (lambda: text.client.ping(), lambda: text.hgetall(HASH_KEY)),
            "bytes over str hgetall": (
                lambda: text.hgetall(HASH_KEY),
                lambda: stores["bytes"].hgetall(HASH_KEY),
            ),
            "save_incident over ping": (
                lambda: text.client.ping(),
                lambda: text.save_incident(
                    HASH_KEY, fields, score=1_700_000_000, pointer_key=POINTER_KEY
                ),
            ),
        }
        if "hiredis" in stores:
            hired = stores["hiredis"]
            pairs["hiredis over str hgetall"] = (
                lambda: text.hgetall(HASH_KEY),
                lambda: hired.hgetall(HASH_KEY),
            )
            pairs["hiredis over str ping"] = (
                lambda: text.client.ping(),
                lambda: hired.client.ping(),
            )
        for label, (first, second) in pairs.items():
            paired[label] = await _paired(first, second, iterations)
    finally:
        for client in clients.values():
            for key in (STRING_KEY, HASH_KEY, POINTER_KEY):
                await client.delete(key)
            await client.zrem(KEY_INCIDENTS, HASH_KEY)
            await client.aclose()

    derived = {
        "redis_py_over_raw_ping": round(variants["str"]["ping"]["mean_us"] - raw["mean_us"], 3),
    }
    parts = urlsplit(redis_url)
    return {
        "mode": "commands",
        "iterations": iterations,
        "redis": f"{parts.hostname or '127.0.0.1'}:{parts.port or 6379}",
        "hiredis_available": "hiredis" in variants,
        "raw_resp_ping": raw,
        "variants_us": variants,
        "paired_deltas_us": paired,
        "derived_us": derived,
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    cpu = sub.add_parser("cpu", help="time and profile the pure-Python path")
    cpu.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    pipeline = sub.add_parser("pipeline", help="measure the engine against a real Redis")
    pipeline.add_argument("--redis-url", required=True)
    pipeline.add_argument("--events", type=int, default=DEFAULT_PIPELINE_EVENTS)
    pipeline.add_argument(
        "--hosts",
        type=int,
        default=0,
        help="0 = a new host per event, 1 = hot merge into one incident",
    )
    commands = sub.add_parser("commands", help="decompose the per-command cost")
    commands.add_argument("--redis-url", required=True)
    commands.add_argument("--iterations", type=int, default=DEFAULT_COMMAND_ITERATIONS)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one profiling mode."""
    args = build_parser().parse_args(argv)
    if args.mode == "cpu":
        summary = run_cpu(args.iterations)
    elif args.mode == "commands":
        summary = asyncio.run(run_commands(args.redis_url, args.iterations))
    else:
        summary = asyncio.run(run_pipeline(args.redis_url, args.events, args.hosts))
    print_human(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
