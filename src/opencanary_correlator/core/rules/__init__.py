"""Correlation rules and the default rule set."""

from __future__ import annotations

from opencanary_correlator.audit import AuditLogger
from opencanary_correlator.config import Settings
from opencanary_correlator.core.incident import Incident, IncidentRepository
from opencanary_correlator.core.rules.base import Rule
from opencanary_correlator.core.rules.http import HttpRequestRule
from opencanary_correlator.core.rules.login import LoginRule, build_login_rules
from opencanary_correlator.core.rules.portscan import HostPortScanRule, NetworkPortScanRule
from opencanary_correlator.core.rules.smb import SmbFileOpenRule, build_smb_rule
from opencanary_correlator.storage.redis_store import RedisStore


def build_rules(
    store: RedisStore,
    repository: IncidentRepository,
    settings: Settings,
    audit: AuditLogger | None = None,
) -> list[Rule]:
    """Build the default rule set."""
    rules: list[Rule] = list(build_login_rules(repository))
    rules.append(HttpRequestRule(repository))
    rules.append(build_smb_rule(repository, settings.smb_ignore_actions, audit))
    rules.append(HostPortScanRule(store=store, repository=repository, settings=settings))
    rules.append(NetworkPortScanRule(store=store, repository=repository, settings=settings))
    return rules


__all__ = [
    "HostPortScanRule",
    "HttpRequestRule",
    "Incident",
    "LoginRule",
    "NetworkPortScanRule",
    "Rule",
    "SmbFileOpenRule",
    "build_login_rules",
    "build_rules",
    "build_smb_rule",
]
