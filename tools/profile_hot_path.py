"""Attribute the per-event ingestion cost to the code that actually spends it.

Milestone 0 of ``docs/EXECPLAN-merge-consolidation.md`` showed that a merge is
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

    python tools/profile_hot_path.py cpu --iterations 20000
    python tools/profile_hot_path.py pipeline --redis-url redis://localhost:6379/15

Use a **disposable** database: the pipeline mode creates incidents for synthetic
hosts ``10.44.x.y`` and removes them afterwards.
"""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import io
import json
import pstats
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Any, cast

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache, event_fingerprint
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.redis_store import RedisStore

PROFILE_HOST_PREFIX = "10.44."
DEFAULT_ITERATIONS = 20_000
DEFAULT_PIPELINE_EVENTS = 2_000
TOP_FUNCTIONS = 18

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
        print("\ntop functions by own time per event:")
        for entry in summary["top_functions"][:10]:
            own = entry["tottime_us_per_event"]
            cumulative = entry["cumtime_us_per_event"]
            print(f"  {own:>8.2f} us  cum {cumulative:>8.2f} us  {entry['function'][:76]}")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one profiling mode."""
    args = build_parser().parse_args(argv)
    if args.mode == "cpu":
        summary = run_cpu(args.iterations)
    else:
        summary = asyncio.run(run_pipeline(args.redis_url, args.events, args.hosts))
    print_human(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
