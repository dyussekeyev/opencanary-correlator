"""Tests for `tools/latency_probe.py`: the percentile maths and the loop."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import fakeredis.aioredis
import pytest


def _load_tool(name: str) -> ModuleType:
    """Import a script from `tools/`, which is not an installed package."""
    path = Path(__file__).resolve().parents[2] / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


latency_probe = _load_tool("latency_probe")


def test_percentile_uses_nearest_rank() -> None:
    samples = [float(value) for value in range(1, 101)]

    assert latency_probe.percentile(samples, 50) == 50.0
    assert latency_probe.percentile(samples, 95) == 95.0
    assert latency_probe.percentile(samples, 99) == 99.0
    assert latency_probe.percentile(samples, 100) == 100.0


def test_percentile_never_invents_a_value_outside_the_sample() -> None:
    samples = [10.0, 20.0, 30.0]

    assert latency_probe.percentile(samples, 1) == 10.0
    assert latency_probe.percentile(samples, 99) == 30.0


def test_percentile_of_nothing_is_none() -> None:
    assert latency_probe.percentile([], 99) is None


def test_summary_reports_the_mandatory_percentiles() -> None:
    summary = latency_probe.summarise([100.0, 200.0, 300.0, 4_000.0])

    assert summary["samples"] == 4
    assert summary["mean_us"] == 1150.0
    assert summary["max_us"] == 4000.0
    assert summary["p50_us"] == 200.0
    assert summary["p99_us"] == 4000.0


def test_summary_of_no_samples_is_null_not_zero() -> None:
    summary = latency_probe.summarise([])

    assert summary["samples"] == 0
    assert summary["mean_us"] is None
    assert summary["p99_us"] is None


def test_probe_stops_when_the_stop_event_is_set(monkeypatch) -> None:
    monkeypatch.setattr(
        latency_probe.Redis,
        "from_url",
        lambda *args, **kwargs: fakeredis.aioredis.FakeRedis(decode_responses=True),
    )

    async def scenario() -> dict[str, object]:
        stop = asyncio.Event()
        task = asyncio.create_task(
            latency_probe.measure("redis://localhost:6379/15", 60.0, 0.001, stop)
        )
        await asyncio.sleep(0.15)
        stop.set()
        return await asyncio.wait_for(task, timeout=5)

    summary = asyncio.run(scenario())
    rtt = summary["rtt_us"]

    assert isinstance(rtt, dict)
    assert summary["duration_seconds"] == 60.0
    # The run ended by the signal, not by the 60 s cap.
    assert rtt["samples"] > 0
    assert rtt["p99_us"] is not None
    assert summary["errors"] == 0


def test_probe_honours_the_duration_cap(monkeypatch) -> None:
    monkeypatch.setattr(
        latency_probe.Redis,
        "from_url",
        lambda *args, **kwargs: fakeredis.aioredis.FakeRedis(decode_responses=True),
    )

    summary = asyncio.run(latency_probe.measure("redis://localhost:6379/15", 0.1, 0.001))

    rtt = summary["rtt_us"]
    assert isinstance(rtt, dict)
    assert rtt["samples"] > 0


def test_main_prints_one_json_document(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        latency_probe.Redis,
        "from_url",
        lambda *args, **kwargs: fakeredis.aioredis.FakeRedis(decode_responses=True),
    )

    assert latency_probe.main(["--duration", "0.1", "--interval", "0.001"]) == 0

    summary = json.loads(capsys.readouterr().out)
    assert summary["redis"] == "localhost:6379"
    assert summary["rtt_us"]["samples"] > 0


@pytest.mark.parametrize("duration", [0.0, -1.0])
def test_a_non_positive_duration_returns_an_empty_summary(monkeypatch, duration) -> None:
    monkeypatch.setattr(
        latency_probe.Redis,
        "from_url",
        lambda *args, **kwargs: fakeredis.aioredis.FakeRedis(decode_responses=True),
    )

    summary = asyncio.run(latency_probe.measure("redis://localhost:6379/15", duration, 0.001))

    rtt = summary["rtt_us"]
    assert isinstance(rtt, dict)
    assert rtt["samples"] == 0
    assert rtt["p99_us"] is None
