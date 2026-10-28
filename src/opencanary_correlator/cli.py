"""Command-line entry point and runtime wiring.

The implementation lives in :mod:`opencanary_correlator.app`, split by
responsibility (`parser`, `wiring`, `describe`, `runner`). This module keeps
every name importable from where it has always been, so `python -m
opencanary_correlator`, the console script and operator scripts do not move.
"""

from __future__ import annotations

from opencanary_correlator.app.channels import build_dispatchers, channel_names
from opencanary_correlator.app.describe import describe_settings, log_secrets, safe_redis_url
from opencanary_correlator.app.parser import CorrelatorStartupError, build_parser, load_settings
from opencanary_correlator.app.runner import install_signal_handlers, main, run_correlator
from opencanary_correlator.app.wiring import (
    build_enricher,
    build_health_server,
    build_rate_limiter,
    build_receivers,
)

__all__ = [
    "CorrelatorStartupError",
    "build_dispatchers",
    "build_enricher",
    "build_health_server",
    "build_parser",
    "build_rate_limiter",
    "build_receivers",
    "channel_names",
    "describe_settings",
    "install_signal_handlers",
    "load_settings",
    "log_secrets",
    "main",
    "run_correlator",
    "safe_redis_url",
]
