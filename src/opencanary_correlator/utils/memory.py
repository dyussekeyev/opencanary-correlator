"""Resident set size of the current process, read portably.

The benchmark reports memory so a footprint claim is a measurement instead of an
estimate. Linux exposes both the current and the peak value exactly in
``/proc/self/status``; every other POSIX system can answer the peak through
``resource.getrusage()``; Windows needs ``GetProcessMemoryInfo()``, which is read
here with a correctly sized ``PROCESS_MEMORY_COUNTERS`` structure - the earlier
probe declared its fields as ``c_ulong`` on 64-bit Windows, so the call failed and
returned nothing.

A platform that cannot answer returns ``None``, and callers report ``null`` rather
than a fabricated figure.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_PROC_STATUS = Path("/proc/self/status")


def _proc_status(field: str) -> int | None:
    """Read one ``Vm*`` field from ``/proc/self/status``, in bytes."""
    try:
        text = _PROC_STATUS.read_text(encoding="ascii")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(field):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _windows_counters() -> tuple[int | None, int | None] | None:  # pragma: no cover - Windows only
    """Return ``(working_set, peak_working_set)`` from ``psapi``, in bytes."""
    # Read through ``str()`` so the comparison is not narrowed to the platform
    # doing the type checking: mypy reports the rest of the function as
    # unreachable under Linux, while the guard is still needed at run time.
    if str(sys.platform) != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(ProcessMemoryCounters)
    # `ctypes.WinDLL` is absent from the POSIX typeshed stub, so the module is
    # reached through an ``Any`` alias: the platform guard above already made
    # this branch Windows-only at run time, while reading the attribute directly
    # fails type checking under Linux and a `type: ignore` would be unused - and
    # therefore an error - on Windows.
    ctypes_any: Any = ctypes
    psapi = ctypes_any.WinDLL("psapi")
    kernel32 = ctypes_any.WinDLL("kernel32")
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    ok = psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    )
    if not ok:
        return None
    return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)


def current_rss_bytes() -> int | None:
    """Resident memory in use right now, in bytes."""
    value = _proc_status("VmRSS:")
    if value is not None:
        return value
    counters = _windows_counters()  # pragma: no cover - Windows only
    return counters[0] if counters is not None else None  # pragma: no cover


def peak_rss_bytes() -> int | None:
    """Highest resident memory reached so far, in bytes."""
    value = _proc_status("VmHWM:")
    if value is not None:
        return value
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows only
        counters = _windows_counters()
        return counters[1] if counters is not None else None
    # Read through getattr because the Windows typeshed ships a `resource` stub
    # without these attributes, and a blanket ignore would be unused on POSIX.
    getrusage = getattr(resource, "getrusage", None)
    if getrusage is None:  # pragma: no cover - partial stub on some platforms
        return None
    usage = int(getrusage(getattr(resource, "RUSAGE_SELF", 0)).ru_maxrss)
    # `ru_maxrss` is bytes on macOS and kilobytes on the other POSIX systems.
    return usage if sys.platform == "darwin" else usage * 1024


__all__ = ["current_rss_bytes", "peak_rss_bytes"]
