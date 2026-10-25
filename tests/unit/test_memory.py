"""The resident-set-size probe the benchmarks report memory with."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from opencanary_correlator.utils import memory


def test_current_rss_reports_a_plausible_figure() -> None:
    value = memory.current_rss_bytes()

    assert value is None or value > 1_000_000


def test_rss_prefers_proc_status_when_it_is_readable(monkeypatch: Any, tmp_path: Any) -> None:
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nVmRSS:\t  512 kB\nVmHWM:\t 1024 kB\n", encoding="ascii")
    monkeypatch.setattr(memory, "_PROC_STATUS", status)

    assert memory.current_rss_bytes() == 512 * 1024
    assert memory.peak_rss_bytes() == 1024 * 1024


def test_peak_rss_is_at_least_the_current_figure() -> None:
    current = memory.current_rss_bytes()
    peak = memory.peak_rss_bytes()
    if current is None or peak is None:
        pytest.skip("this platform does not report resident memory")

    assert peak >= current * 0.9


@pytest.mark.parametrize("field", ["VmRSS:", "VmHWM:"])
def test_proc_status_parses_kilobytes_as_bytes(monkeypatch: Any, tmp_path: Any, field: Any) -> None:
    status = tmp_path / "status"
    status.write_text(f"Name:\tpython\n{field}\t   1024 kB\n", encoding="ascii")
    monkeypatch.setattr(memory, "_PROC_STATUS", status)

    assert memory._proc_status(field) == 1024 * 1024


def test_proc_status_returns_none_for_an_unknown_field(monkeypatch: Any, tmp_path: Any) -> None:
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nVmRSS:\t   1024 kB\n", encoding="ascii")
    monkeypatch.setattr(memory, "_PROC_STATUS", status)

    assert memory._proc_status("VmSwap:") is None


def test_proc_status_is_absent_off_linux(monkeypatch: Any, tmp_path: Any) -> None:
    monkeypatch.setattr(memory, "_PROC_STATUS", tmp_path / "missing")

    assert memory._proc_status("VmRSS:") is None


def test_windows_probe_is_skipped_elsewhere(monkeypatch: Any) -> None:
    monkeypatch.setattr(sys, "platform", "linux")

    assert memory._windows_counters() is None
