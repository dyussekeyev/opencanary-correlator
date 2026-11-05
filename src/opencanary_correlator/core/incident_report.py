"""Legacy plain-text alert templates for incidents.

These render the strings the original OpenCanary correlator sent to e-mail,
webhook and chat channels. They are pure functions over primitive values, so the
incident model stays free of presentation details.

Since 0.7.0 the canary's own address (`dst_host`) is deliberately absent from
every template, these legacy ones included: an alert that leaves the estate for
chat, mail or a SIEM must not describe the estate. Labels, spacing and ordering
are otherwise unchanged, so the removal is the single visible difference.
"""

from __future__ import annotations

from datetime import UTC, datetime

_RULE = "=" * 70
_BANNER = f"\n{_RULE}\n                                ALERT\n{_RULE}\n\n"


def render_title(description: str, src_host: str, node_id: str) -> str:
    """One-line title used as an e-mail or webhook subject."""
    return f"{description} by {src_host} on {node_id}"


def render_report(
    *,
    description: str,
    created: int,
    src_host: str,
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
        f"  Target  : {node_id}\n"
        f"{extra}\n"
        f"{_RULE}\n"
    )


def render_report_short(
    *,
    description: str,
    src_host: str,
    node_id: str,
    extra: str = "",
) -> str:
    """Compact one-line alert for size-limited channels."""
    return f"Canary Incident: {description}. Source {src_host}. Target {node_id}.{extra}"


def render_scan_report(
    *,
    description: str,
    created: int,
    src_host: str,
    dst_port: int,
    targets: int,
) -> str:
    """Alert used by the legacy distributed (network) port-scan template.

    `targets` is a count, not a list: the list held the addresses of the honeypots
    the scan reached, which is the deployment's own map. The count keeps the size
    of the scan without naming a single canary.
    """
    plural = "host" if targets == 1 else "hosts"
    return (
        f"{_BANNER}"
        f"  Incident: {description}\n"
        f"  Time    : {created}\n"
        f"  Source  : {src_host}\n"
        f"  Port    : {dst_port}\n"
        f"  Targets : {targets} {plural}\n\n"
        f"{_RULE}\n"
    )


__all__ = ["render_report", "render_report_short", "render_scan_report", "render_title"]
