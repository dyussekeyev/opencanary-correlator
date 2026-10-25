"""Ingestion benchmark for the TCP JSON receiver and correlation engine.

Runs the real receiver over loopback, feeds `--events` newline-delimited events
shaped like `SocketJSONHandler` output, and reports throughput. With
`--redis-url` it uses a real Redis database; without one it falls back to
fakeredis so the benchmark also runs on a workstation.

    python tools/bench_ingest.py --redis-url redis://localhost:6379/15

Use a **disposable** database: the tool creates incidents for synthetic hosts
``10.42.x.y`` and removes them afterwards, but dedup/rate-limit keys expire on
their own and other keys are left untouched.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
import time
from typing import Any

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.receivers.tcp_json import TCPJSONReceiver
from opencanary_correlator.constants import KEY_INCIDENTS
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.storage.redis_store import RedisStore
from opencanary_correlator.utils.memory import current_rss_bytes, peak_rss_bytes

BENCH_HOST_PREFIX = "10.42."
SEED_HOST_PREFIX = "10.43."
DEFAULT_EVENTS = 10_000
DEFAULT_HOSTS = 100
DEFAULT_TIMEOUT = 300.0


def build_parser() -> argparse.ArgumentParser:
    """Return the benchmark argument parser."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS)
    parser.add_argument("--hosts", type=int, default=DEFAULT_HOSTS)
    parser.add_argument(
        "--redis-url",
        help="Redis URL (use a disposable database); omit to use fakeredis",
    )
    parser.add_argument("--queue-size", type=int, default=0, help="0 = events * 2")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="consumer lanes (default: the OCC_EVENT_CONCURRENCY setting)",
    )
    parser.add_argument(
        "--seed-incidents",
        type=int,
        default=0,
        help=(
            "pre-create N incidents inside the horizon for unrelated hosts, to "
            "measure how incident lookup scales with the index size"
        ),
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    return parser


async def make_store(redis_url: str | None) -> tuple[RedisStore, str]:
    """Return a store and a human-readable backend name."""
    if redis_url:
        store = RedisStore.from_url(redis_url)
        if not await store.ping():
            raise SystemExit(f"Redis is not reachable: {redis_url}")
        return store, "redis"
    import fakeredis.aioredis

    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return RedisStore(client), "fakeredis"


def build_payload(events: int, hosts: int) -> bytes:
    """Build one newline-delimited batch shaped like canary output."""
    base: dict[str, Any] = {
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "node_id": "bench-1",
        "local_time": "2026-10-24 10:00:00.000000",
        "utc_time": "2026-10-24 10:00:00.000000",
        "logdata": {"USERNAME": "admin", "PASSWORD": "x"},
    }
    lines: list[str] = []
    for index in range(events):
        host = index % hosts
        event = dict(
            base,
            src_host=f"{BENCH_HOST_PREFIX}{host // 250}.{host % 250}",
            src_port=10000 + index,
        )
        lines.append(json.dumps(event) + "\n")
    return "".join(lines).encode()


async def cleanup(store: RedisStore) -> None:
    """Remove incidents created for the synthetic hosts."""
    for key in await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf"):
        if f":{BENCH_HOST_PREFIX}" in key or f":{SEED_HOST_PREFIX}" in key:
            await store.delete(key)
            await store.client.zrem(KEY_INCIDENTS, key)


async def seed_incidents(store: RedisStore, count: int) -> int:
    """Create `count` live incidents for unrelated hosts.

    A busy deployment accumulates incidents inside the horizon too, so this
    models the index size that every per-event lookup has to walk when there is
    no per-host pointer.
    """
    if count <= 0:
        return 0
    now = int(time.time())
    async with store.client.pipeline(transaction=False) as pipe:
        for index in range(count):
            key = f"incident:ftplogin:{SEED_HOST_PREFIX}{index // 250}.{index % 250}:{now}"
            pipe.hset(key, mapping={"created": str(now), "events_count": "1"})
            pipe.zadd(KEY_INCIDENTS, {key: now})
            if index % 500 == 499:
                await pipe.execute()
        await pipe.execute()
    return count


def to_mib(value: int | None) -> float | None:
    """Convert bytes to MiB, keeping an unavailable figure visibly unavailable."""
    return None if value is None else round(value / 1024 / 1024, 1)


async def run(args: argparse.Namespace) -> int:
    """Execute one benchmark run and print a JSON summary."""
    store, backend = await make_store(args.redis_url)
    rss_before = current_rss_bytes()
    settings = Settings(
        redis_url=args.redis_url or "redis://localhost:6379/0",
        _env_file=None,
        syslog_enabled=False,
        health_port=None,
        rate_limit_events_per_minute=0,
    )
    seeded = await seed_incidents(store, args.seed_incidents)
    audit = AuditLogger("bench", stream=io.StringIO())
    repository = IncidentRepository(store, settings, audit)
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[],
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
    )
    queue_size = args.queue_size or args.events * 2
    concurrency = args.concurrency or settings.event_concurrency
    receiver = TCPJSONReceiver(
        sink=engine,
        audit=audit,
        host="127.0.0.1",
        port=0,
        queue_size=queue_size,
        concurrency=concurrency,
    )
    await receiver.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", receiver.bound_port)
    payload = build_payload(args.events, args.hosts)
    started = time.perf_counter()
    writer.write(payload)
    await writer.drain()
    deadline = started + args.timeout
    while receiver.stats.accepted + receiver.stats.dropped < args.events:
        if time.perf_counter() >= deadline:
            break
        await asyncio.sleep(0.02)
    elapsed = time.perf_counter() - started
    incidents = await store.zrangebyscore(KEY_INCIDENTS, "-inf", "+inf")
    summary = {
        "backend": backend,
        "events": args.events,
        "hosts": args.hosts,
        "concurrency": concurrency,
        "seeded_incidents": seeded,
        "payload_mib": round(len(payload) / 1024 / 1024, 2),
        "accepted": receiver.stats.accepted,
        "dropped": receiver.stats.dropped,
        "rejected": receiver.stats.rejected,
        "elapsed_seconds": round(elapsed, 3),
        "events_per_second": round(receiver.stats.accepted / elapsed) if elapsed else 0,
        "incidents": len([key for key in incidents if f":{BENCH_HOST_PREFIX}" in key]),
        # Resident memory while the run is carried out, so the footprint is a
        # measurement rather than an opinion. `null` means the platform could not
        # answer; it is never filled in.
        "rss_mib": {
            "before": to_mib(rss_before),
            "after": to_mib(current_rss_bytes()),
            "peak": to_mib(peak_rss_bytes()),
        },
    }
    print(json.dumps(summary, indent=2))
    writer.close()
    await writer.wait_closed()
    await receiver.stop()
    await cleanup(store)
    await store.aclose()
    complete = summary["accepted"] + summary["dropped"] == args.events
    return 0 if complete else 1


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the benchmark."""
    args = build_parser().parse_args(argv)
    if args.events < 1 or args.hosts < 1:
        raise SystemExit("--events and --hosts must be positive")
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
