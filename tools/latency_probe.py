"""Server latency probe: PING round trips from a process of its own.

The acceptance record asks how far the Redis server's p99 latency degrades
*while* the correlator is ingesting, and nothing measured that: the benchmark
reports only its own elapsed time, and `redis-benchmark` measures a different
thing (throughput of a closed loop, not the latency a second client sees).

The probe therefore runs as a separate process with its own connection, paces
itself at a fixed interval and reports the percentile distribution of PING round
trips. Started before a benchmark and stopped after it, its numbers describe the
server under that load; run alone, they describe an idle server.

    python tools/latency_probe.py --redis-url redis://localhost:6379/15 --duration 5
    python tools/latency_probe.py --redis-url redis://localhost:6379/15 --duration 120 &
    # ... the workload runs here ...
    kill -TERM %1   # prints what it collected so far and exits 0

`--duration` is a safety cap: on SIGTERM or SIGINT the probe stops early and
still prints its summary, so a caller can bracket an arbitrarily long workload.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import signal
import time
from typing import Any
from urllib.parse import urlsplit

from redis.asyncio import Redis

DEFAULT_DURATION = 5.0
DEFAULT_INTERVAL = 0.005
PERCENTILES = (50, 95, 99)


def percentile(samples: list[float], percent: float) -> float | None:
    """Return the nearest-rank percentile of `samples`, or `None` when empty.

    Nearest rank is deliberate: a p99 of 200 samples is the 198th value, which is
    what an operator reads off a table, rather than an interpolation that reports
    a latency no request actually saw.
    """
    if not samples:
        return None
    ordered = sorted(samples)
    rank = max(1, math.ceil(percent / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def summarise(deltas_us: list[float]) -> dict[str, Any]:
    """Describe a sample of round trips in microseconds."""
    if not deltas_us:
        return {
            "samples": 0,
            "mean_us": None,
            "max_us": None,
            **{f"p{percent}_us": None for percent in PERCENTILES},
        }
    summary: dict[str, Any] = {
        "samples": len(deltas_us),
        "mean_us": round(sum(deltas_us) / len(deltas_us), 1),
        "max_us": round(max(deltas_us), 1),
    }
    for percent in PERCENTILES:
        value = percentile(deltas_us, percent)
        summary[f"p{percent}_us"] = None if value is None else round(value, 1)
    return summary


async def measure(
    url: str, duration: float, interval: float, stop: asyncio.Event | None = None
) -> dict[str, Any]:
    """Ping `url` every `interval` seconds, for `duration` or until `stop` is set."""
    client = Redis.from_url(url, decode_responses=True)
    deltas: list[float] = []
    errors = 0
    deadline = time.monotonic() + duration
    pacing = time.monotonic()

    try:
        await client.ping()
        while stop is None or not stop.is_set():
            now = time.monotonic()
            if now >= deadline:
                break
            if now < pacing:
                # Short sleeps so a stop signal is noticed within one interval
                # rather than after a long pause between round trips.
                await asyncio.sleep(min(pacing - now, 0.02))
                continue
            started = time.perf_counter()
            try:
                await client.ping()
            except (ConnectionError, TimeoutError):
                errors += 1
            else:
                deltas.append((time.perf_counter() - started) * 1e6)
            pacing += interval
            # A stalled loop must not turn into a burst of catch-up pings: what
            # the probe reports has to stay comparable between runs.
            if pacing < time.monotonic() - interval:
                pacing = time.monotonic()
    finally:
        await client.aclose()

    parts = urlsplit(url)
    return {
        "redis": f"{parts.hostname or '127.0.0.1'}:{parts.port or 6379}",
        "duration_seconds": duration,
        "interval_seconds": interval,
        "errors": errors,
        "rtt_us": summarise(deltas),
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    parser.add_argument(
        "--duration",
        type=float,
        default=DEFAULT_DURATION,
        help="upper bound in seconds; SIGTERM or SIGINT stops the probe early",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="seconds between round trips (0.005 = 200/s)",
    )
    return parser


def _install_signal_handlers(stop: asyncio.Event) -> None:
    """Stop early on SIGTERM/SIGINT, where the platform can deliver them."""
    loop = asyncio.get_running_loop()
    for name in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:  # pragma: no cover - Windows
            # Windows cannot interrupt the loop this way; `--duration` bounds the
            # run instead, and the caller's stop arrives as process termination.
            return


async def run(args: argparse.Namespace) -> dict[str, Any]:
    """Run one probe bounded by `--duration` or by a stop signal."""
    stop = asyncio.Event()
    _install_signal_handlers(stop)
    return await measure(args.redis_url, args.duration, args.interval, stop)


def main(argv: list[str] | None = None) -> int:
    """Run the probe and print its summary as JSON."""
    args = build_parser().parse_args(argv)
    summary = asyncio.run(run(args))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
