"""SMB rule: structured access records, and the optional action ignore list."""

from __future__ import annotations

import json
from typing import Any

import pytest

from opencanary_correlator import metrics
from opencanary_correlator.constants import LogType
from opencanary_correlator.core.incident import IncidentRepository
from opencanary_correlator.core.rules.smb import SmbFileOpenRule, build_smb_rule
from opencanary_correlator.schemas import CanaryEvent

#: The fields OpenCanary's Samba watcher puts on an SMB event.
SMB_LOG_DATA: dict[str, Any] = {
    "USER": "root",
    "REMOTENAME": "817dc13f4973",
    "SHARENAME": "share",
    "LOCALNAME": "SRV01",
    "SMBVER": "SMB3_11",
    "SMBARCH": "Vista",
    "DOMAIN": "WORKGROUP",
    "AUDITACTION": "openat",
    "STATUS": "fail (No such file or directory)",
    "FILENAME": "/samba/probe.txt",
}

SMB_PREFIX = "incident:smbfileopen:85.117.126.153:"


def smb_event(event_factory: Any, **overrides: Any) -> CanaryEvent:
    """Build a validated SMB event as the Samba watcher emits it."""
    logdata = overrides.pop("logdata", SMB_LOG_DATA)
    payload = event_factory(
        logtype=int(LogType.LOG_SMB_FILE_OPEN),
        src_host="85.117.126.153",
        src_port=-1,
        dst_host="172.19.0.2",
        dst_port=445,
        logdata=logdata,
    )
    payload.update(overrides)
    return CanaryEvent.model_validate(payload)


async def stored_incidents(store: Any, settings: Any) -> list[str]:
    """Keys of the SMB incidents the store currently holds."""
    lookup = await store.find_recent_incident(
        SMB_PREFIX, min_score=0.0, pointer_key=None, scan_limit=None
    )
    return [] if lookup.key is None else [lookup.key]


async def test_an_smb_event_creates_one_incident(
    repository: Any, clock: Any, event_factory: Any
) -> None:
    rule = SmbFileOpenRule(repository)

    incidents = await rule.apply(smb_event(event_factory), now=clock.now)

    assert len(incidents) == 1
    assert incidents[0].INCIDENT_NAME == "smb.file_open"
    assert incidents[0].src_host == "85.117.126.153"
    assert incidents[0].dst_port == 445
    # The whole audit record is kept, so the alert renderer can show it.
    stored = json.loads(incidents[0].logdata or "[]")
    assert stored[0]["FILENAME"] == "/samba/probe.txt"


def test_the_ignore_list_is_empty_by_default(repository: Any) -> None:
    """An upgrade must not change which events are correlated."""
    assert SmbFileOpenRule(repository).ignored_actions == frozenset()


async def test_an_ignored_action_creates_no_incident(
    repository: Any, store: Any, settings_factory: Any, clock: Any, event_factory: Any
) -> None:
    rule = build_smb_rule(repository, ["flistxattr"])
    event = smb_event(event_factory, logdata={**SMB_LOG_DATA, "AUDITACTION": "flistxattr"})

    incidents = await rule.apply(event, now=clock.now)

    assert incidents == []
    assert await stored_incidents(store, settings_factory()) == []


async def test_the_ignore_list_is_case_insensitive(
    repository: Any, clock: Any, event_factory: Any
) -> None:
    """Samba writes lower case, but a configuration file may not."""
    rule = build_smb_rule(repository, ["FlistXattr"])
    event = smb_event(event_factory, logdata={**SMB_LOG_DATA, "AUDITACTION": "flistxattr"})

    assert await rule.apply(event, now=clock.now) == []


async def test_an_ignored_action_is_audited_with_a_reason(
    store: Any, settings_factory: Any, audit: Any, audit_stream: Any, clock: Any, event_factory: Any
) -> None:
    """A suppression must be visible, not indistinguishable from a lost event."""
    repository = IncidentRepository(store, settings_factory(), audit, clock=clock)
    rule = build_smb_rule(repository, ["flistxattr"], audit)
    event = smb_event(event_factory, logdata={**SMB_LOG_DATA, "AUDITACTION": "flistxattr"})

    await rule.apply(event, now=clock.now)

    records = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    ignored = [record for record in records if record["action"] == "event_ignored"]
    assert len(ignored) == 1
    assert ignored[0]["details"]["reason"] == "smb_action"
    assert ignored[0]["details"]["action"] == "flistxattr"


async def test_an_ignored_action_is_counted(
    repository: Any, clock: Any, event_factory: Any
) -> None:
    rule = build_smb_rule(repository, ["flistxattr"])
    event = smb_event(event_factory, logdata={**SMB_LOG_DATA, "AUDITACTION": "flistxattr"})
    before = metrics.EVENTS_IGNORED.labels(reason="smb_action")._value.get()

    await rule.apply(event, now=clock.now)

    after = metrics.EVENTS_IGNORED.labels(reason="smb_action")._value.get()
    assert after == before + 1


@pytest.mark.parametrize("action", ["openat", "create_file", "connect"])
async def test_actions_outside_the_list_still_alert(
    repository: Any, clock: Any, event_factory: Any, action: str
) -> None:
    rule = build_smb_rule(repository, ["flistxattr"])
    event = smb_event(event_factory, logdata={**SMB_LOG_DATA, "AUDITACTION": action})

    assert len(await rule.apply(event, now=clock.now)) == 1


async def test_a_payload_the_typed_view_refuses_still_alerts(
    repository: Any, clock: Any, event_factory: Any
) -> None:
    """A nested object where a string belongs must not make the rule raise."""
    rule = build_smb_rule(repository, ["flistxattr"])
    event = smb_event(event_factory, logdata={**SMB_LOG_DATA, "FILENAME": {"nested": "x"}})

    incidents = await rule.apply(event, now=clock.now)

    assert len(incidents) == 1


def test_the_rule_covers_smb_events_only(repository: Any, event_factory: Any) -> None:
    rule = SmbFileOpenRule(repository)

    assert rule.matches(smb_event(event_factory))
    assert not rule.matches(
        CanaryEvent.model_validate(event_factory(logtype=int(LogType.LOG_PORT_SYN)))
    )
