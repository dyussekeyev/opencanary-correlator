"""Command-line arguments and the settings they produce."""

from __future__ import annotations

import argparse
from typing import Any

from opencanary_correlator import __version__
from opencanary_correlator.config import Settings

PROG = "opencanary-correlator"


class CorrelatorStartupError(RuntimeError):
    """Raised when the correlator cannot start (for example Redis is down)."""


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for the correlator executable."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Stateless OpenCanary event correlator",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="legacy JSON configuration file (migrated on startup)",
    )
    parser.add_argument("--redis-url", help="override OCC_REDIS_URL")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="override OCC_LOG_LEVEL",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="override OCC_LOG_FILE (adds a rotated log file next to stderr)",
    )
    parser.add_argument(
        "--health-port",
        type=int,
        help="override OCC_HEALTH_PORT (0 disables the endpoint)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and exit",
    )
    return parser


def load_settings(args: argparse.Namespace) -> Settings:
    """Build settings from the legacy file, the environment and CLI overrides.

    The overrides are handed to the constructor instead of being merged into an
    already-built settings object: `redis_url` has no default, so a flag that is
    meant to supply it has to be visible to validation. Merging afterwards made
    `opencanary-correlator --redis-url redis://host:6379/0` exit 2 with
    "redis_url: Field required" unless the variable was also exported.
    """
    overrides: dict[str, Any] = {}
    if args.redis_url:
        overrides["redis_url"] = args.redis_url
    if args.log_level:
        overrides["log_level"] = args.log_level.upper()
    if args.log_file:
        overrides["log_file"] = args.log_file
    if args.health_port is not None:
        overrides["health_port"] = args.health_port if args.health_port > 0 else None
    if args.config:
        return Settings.from_legacy_json(args.config, overrides=overrides)
    return Settings(**overrides)


__all__ = [
    "PROG",
    "CorrelatorStartupError",
    "build_parser",
    "load_settings",
]
