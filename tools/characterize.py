"""Freeze the observable behaviour of the correlator into a golden snapshot.

A structural refactor is only safe if "nothing changed" can be *checked*, not
argued. This tool renders the artefacts a user or a SIEM actually sees — alert
text per channel and detail level, the `--check-config` document, the CLI flags,
stored incident fields, the audit action stream and the Redis keys of one
scripted run — into one JSON file.

    python tools/characterize.py --write    # regenerate tests/characterization/golden/snapshot.json
    python tools/characterize.py            # compare, exit 1 on any difference

`tests/characterization/test_golden.py` runs the comparison, so a refactor that
changes a byte of output fails the suite and points at the key that moved.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
from pathlib import Path
from typing import Any, Final

import fakeredis.aioredis
from pydantic import SecretStr

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.cli import build_parser, describe_settings
from opencanary_correlator.config import Settings
from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.dispatchers import (
    DiscordDispatcher,
    SlackDispatcher,
    SmtpDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
)
from opencanary_correlator.connectors.dispatchers.alert_text import ALERT_DETAIL_LEVELS, AlertDetail
from opencanary_correlator.core.engine import CorrelationEngine
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.incident_model import (
    Incident,
    IncidentFTPLogin,
    IncidentHostPortScan,
    IncidentHTTPRequest,
    IncidentRDPLogin,
    IncidentSMBFileOpen,
)
from opencanary_correlator.core.rules import build_rules
from opencanary_correlator.core.windows import DedupCache
from opencanary_correlator.enrichment.models import Enrichment, GeoInfo, VirusTotalReport
from opencanary_correlator.schemas import CanaryEvent
from opencanary_correlator.storage.redis_store import RedisStore

#: Fixed instant used everywhere a timestamp would otherwise be "now".
FIXED_TIME: Final[int] = 1_793_207_641
#: The project root, so the tool works from any working directory.
ROOT: Final[Path] = Path(__file__).resolve().parent.parent
DEFAULT_GOLDEN: Final[Path] = ROOT / "tests" / "characterization" / "golden" / "snapshot.json"
#: Placeholder bot credential: the snapshot must never contain a real one.
FAKE_TELEGRAM_BOT: Final[str] = "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _incident(cls: type[Incident], **overrides: Any) -> Incident:
    """Build a fixed, persisted-looking incident of one type."""
    params: dict[str, Any] = {
        "key": "incident:ftplogin:10.0.0.5:1793207641",
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "src_port": 40000,
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "created": FIXED_TIME,
        "events_list": str(FIXED_TIME),
        "events_count": 1,
    }
    params.update(overrides)
    return cls(**params)


def incidents() -> dict[str, Incident]:
    """The fixed incident set every renderer is measured with."""
    enriched = _incident(
        IncidentRDPLogin,
        key=f"incident:rdplogin:89.126.202.164:{FIXED_TIME}",
        src_host="89.126.202.164",
        src_port=52344,
        dst_host="2.126.2.164",
        dst_port=3389,
        logtype=14001,
        logdata=json.dumps([{"USERNAME": "administrator"}]),
    )
    enriched.enrichment = Enrichment(
        geo=GeoInfo(
            country_code="KZ",
            country="Kazakhstan",
            city="Almaty",
            asn=202958,
            as_org='LLP "Kompaniya Hoster.KZ"',
        ),
        virus_total=VirusTotalReport(
            malicious=15,
            suspicious=3,
            harmless=46,
            undetected=28,
            reputation=3,
            checked="2026-10-28",
        ),
        virus_total_status="ok",
    )
    return {
        "ftp_login": _incident(
            IncidentFTPLogin,
            logdata=json.dumps(
                [{"USERNAME": "admin", "PASSWORD": "hunter2", "CREDENTIAL": "abc123"}]
            ),
        ),
        "rdp_enriched": enriched,
        "http_request": _incident(
            IncidentHTTPRequest,
            key=f"incident:httprequest:10.0.0.9:{FIXED_TIME}",
            src_host="10.0.0.9",
            dst_host="10.0.0.2",
            dst_port=80,
            logtype=3000,
            logdata=json.dumps(
                [{"METHOD": "GET", "PATH": "/admin", "HOST": "10.0.0.2", "USERAGENT": "curl/8.4"}]
            ),
        ),
        "smb_file_open": _incident(
            IncidentSMBFileOpen,
            key=f"incident:smbfileopen:10.0.0.7:{FIXED_TIME}",
            src_host="10.0.0.7",
            dst_port=445,
            logtype=5000,
            logdata=json.dumps([{"FILENAME": "payroll.xlsx", "USER": "CORP\\alice"}]),
        ),
        "host_portscan": _incident(
            IncidentHostPortScan,
            key=f"incident:hostportscan:10.0.0.8:{FIXED_TIME}",
            src_host="10.0.0.8",
            dst_port=-1,
            logtype=5003,
            events_count=4,
            logdata=json.dumps([21, 22, 23, 3389]),
        ),
    }


def render_all() -> dict[str, Any]:
    """Render every incident through every channel at every detail level."""
    rendered: dict[str, Any] = {}
    for name, incident in incidents().items():
        for level in ALERT_DETAIL_LEVELS:
            detail: AlertDetail = level
            rendered[f"{name}/telegram/{level}"] = TelegramDispatcher(
                token=SecretStr(FAKE_TELEGRAM_BOT), chat_id="42", detail=detail
            ).build_payload(incident)["text"]
            rendered[f"{name}/slack/{level}"] = SlackDispatcher(
                url="https://hooks.slack.com/services/T000/B000/XXXX", detail=detail
            ).build_payload(incident)["text"]
            rendered[f"{name}/discord/{level}"] = DiscordDispatcher(
                url="https://discord.com/api/webhooks/1/xxxx", detail=detail
            ).build_payload(incident)["content"]
            rendered[f"{name}/webhook/{level}"] = WebhookDispatcher(
                url="https://siem.example.test/hook", detail=detail
            ).build_payload(incident)
            message = SmtpDispatcher(
                host="smtp.example.test",
                port=587,
                sender="alerts@example.test",
                recipients=["soc@example.test"],
                detail=detail,
            ).build_message(incident)
            rendered[f"{name}/smtp/{level}"] = {
                # `message["Subject"]` is a header object; its text is the contract.
                "subject": str(message["Subject"]),
                "body": message.get_content(),
            }
    return rendered


def describe() -> dict[str, Any]:
    """The `--check-config` document for one fixed configuration."""
    settings = Settings(
        redis_url="redis://:s3cret@redis.example.test:6379/3",
        telegram_token=SecretStr(FAKE_TELEGRAM_BOT),
        telegram_chat_ids=["42"],
        webhook_urls=["https://siem.example.test/hook?token=abc"],
        discord_webhooks=["https://discord.com/api/webhooks/1/xxxx"],
        slack_enabled=True,
        slack_webhooks=["https://hooks.slack.com/services/T000/B000/XXXX"],
        smtp_host="smtp.example.test",
        smtp_to=["soc@example.test"],
        geoip_city_db="/data/geoip/city.mmdb",
        virustotal_api_key=SecretStr("vt-secret-key"),
        _env_file=None,
    )
    return describe_settings(settings)


class _RecordingDispatcher(BaseDispatcher):
    """Dispatcher that accepts everything and records the incident keys."""

    name = "recording"

    def __init__(self) -> None:
        self.keys: list[str] = []

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        self.keys.append(incident.key)
        return DispatchResult(dispatcher=self.name, status="success")


def _event(**overrides: Any) -> CanaryEvent:
    """One canary event with a stable shape."""
    params: dict[str, Any] = {
        "node_id": "canary-1",
        "src_host": "10.0.0.5",
        "src_port": 40000,
        "dst_host": "10.0.0.2",
        "dst_port": 21,
        "logtype": 2000,
        "logdata": {"USERNAME": "admin"},
    }
    params.update(overrides)
    return CanaryEvent(**params)


async def _run_stream() -> dict[str, Any]:
    """Feed a fixed event stream through the real engine and capture the result."""
    store = RedisStore(fakeredis.aioredis.FakeRedis(decode_responses=True))
    settings = Settings(redis_url="redis://localhost:6379/0", _env_file=None)
    stream = io.StringIO()
    audit = AuditLogger("correlator", stream=stream)

    def clock() -> float:
        return float(FIXED_TIME)

    repository = IncidentRepository(store, settings, audit, clock=clock)
    dispatcher = _RecordingDispatcher()
    engine = CorrelationEngine(
        rules=build_rules(store, repository, settings),
        dispatchers=[dispatcher],
        dedup=DedupCache(store, ttl=settings.dedup_ttl),
        settings=settings,
        audit=audit,
        clock=clock,
    )

    await engine.handle_event(_event())
    await engine.handle_event(_event())  # identical: deduplicated, no alert
    await engine.handle_event(_event(logtype=4002, dst_port=22))  # ssh login
    await engine.handle_event(_event(logtype=1001, dst_port=-1))  # ignored node record
    await engine.handle_event(_event(logtype=9999, dst_port=-1))  # unrouted

    records: list[Any] = []
    for line in stream.getvalue().splitlines():
        record = json.loads(line)
        details = record.get("details") or {}
        # Wall-clock durations are the only non-deterministic field.
        stable = {key: value for key, value in details.items() if key != "duration_ms"}
        records.append([record["action"], record["status"], stable])

    keys = sorted(str(key) for key in await store.client.keys("*"))
    incidents = [str(member) for member in await store.client.zrange("incidents", 0, -1)]
    await store.aclose()
    return {
        "audit": records,
        "redis_keys": keys,
        "incidents": incidents,
        "delivered": dispatcher.keys,
    }


def _cli_surface() -> list[str]:
    """Every flag the parser accepts, sorted.

    The rendered `--help` cannot be pinned across the versions CI runs: 3.11 and
    3.12 print `-c PATH, --config PATH` with an indented description, while 3.13
    and later print `-c, --config PATH` inline. Those are cosmetic, and an oracle
    that holds on one interpreter only is worse than none, so the snapshot records
    the flags themselves — the part that must not change by accident.
    """
    parser = build_parser()
    return sorted(option for action in parser._actions for option in action.option_strings)


def snapshot() -> dict[str, Any]:
    """Everything the golden file records."""
    return {
        "alerts": render_all(),
        "describe_settings": describe(),
        "cli_options": _cli_surface(),
        "incident_fields": {name: incident.to_fields() for name, incident in incidents().items()},
        "engine": asyncio.run(_run_stream()),
    }


def dump(value: dict[str, Any]) -> str:
    """Serialise a snapshot the same way on every platform."""
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def differences(expected: Any, actual: Any, path: str = "") -> list[str]:
    """Return a short list of paths where two snapshots disagree."""
    if type(expected) is not type(actual):
        return [f"{path or '<root>'}: type {type(expected).__name__} != {type(actual).__name__}"]
    if isinstance(expected, dict):
        found: list[str] = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                found.append(f"{path}/{key}: added")
            elif key not in actual:
                found.append(f"{path}/{key}: removed")
            else:
                found.extend(differences(expected[key], actual[key], f"{path}/{key}"))
        return found
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [f"{path}: length {len(expected)} != {len(actual)}"]
        found = []
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            found.extend(differences(left, right, f"{path}[{index}]"))
        return found
    if expected != actual:
        return [f"{path}: {expected!r} != {actual!r}"]
    return []


def main(argv: list[str] | None = None) -> int:
    """Write or compare the golden snapshot."""
    # A Windows console cannot encode the emoji in a rendered alert; a diff must
    # still print rather than crash on it.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(prog="characterize", description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="regenerate the golden file")
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_GOLDEN,
        help=f"golden file (default: {DEFAULT_GOLDEN.relative_to(ROOT)})",
    )
    args = parser.parse_args(argv)

    actual = snapshot()
    text = dump(actual)
    if args.write:
        args.path.parent.mkdir(parents=True, exist_ok=True)
        args.path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {args.path}")
        return 0

    if not args.path.is_file():
        print(f"missing golden file: {args.path} (run with --write)")
        return 2
    expected = json.loads(args.path.read_text(encoding="utf-8"))
    found = differences(expected, actual)
    if not found:
        print(f"golden snapshot matches ({len(actual['alerts'])} rendered alerts)")
        return 0
    print(f"{len(found)} difference(s) from {args.path}:")
    for item in found[:40]:
        print(f"  {item}")
    if len(found) > 40:
        print(f"  ... and {len(found) - 40} more")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
