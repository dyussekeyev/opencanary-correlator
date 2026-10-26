"""Legacy plain-text alert templates for incidents.

These render the exact strings the original OpenCanary correlator sent to
e-mail, webhook and chat channels. They are pure functions over primitive
values, so the incident model stays free of presentation details. Output must
stay byte-identical: the legacy console and operators compare these alerts.
"""

from __future__ import annotations

from datetime import UTC, datetime

_RULE = "=" * 70
_BANNER = f"\n{_RULE}\n                                ALERT\n{_RULE}\n\n"


def render_title(description: str, src_host: str, node_id: str, dst_host: str) -> str:
    """One-line title used as an e-mail or webhook subject."""
    return f"{description} by {src_host} on {node_id} ({dst_host})"


def render_report(
    *,
    description: str,
    created: int,
    src_host: str,
    dst_host: str,
    node_id: str,
    extra: str = "",
) -> str:
    """Full alert. `extra` replaces the placeholder line (empty leaves a blank line)."""
    when = datetime.fromtimestamp(created, tz=UTC).strftime("%Y-%m-%d %H:%M:%S (UTC)")
    return (
        f"{_BANNER}"
        f"  Incident: {description}\n"
        f"  Time    : {when}\n"
        f"  Source  : {src_host}\n"
        f"  Target  : {dst_host} (id {node_id})\n"
        f"{extra}\n"
        f"{_RULE}\n"
    )


def render_report_short(
    *,
    description: str,
    src_host: str,
    node_id: str,
    dst_host: str,
    extra: str = "",
) -> str:
    """Compact one-line alert for size-limited channels."""
    return (
        f"Canary Incident: {description}. Source {src_host}. Target {node_id} ({dst_host}).{extra}"
    )


def render_scan_report(
    *,
    description: str,
    created: int,
    src_host: str,
    dst_port: int,
    targets: str,
) -> str:
    """Alert used by the legacy distributed (network) port-scan template."""
    return (
        f"{_BANNER}"
        f"  Incident: {description}\n"
        f"  Time    : {created}\n"
        f"  Source  : {src_host}\n"
        f"  Port    : {dst_port}\n"
        f"  Targets : {targets}\n\n"
        f"{_RULE}\n"
    )


__all__ = ["render_report", "render_report_short", "render_scan_report", "render_title"]
