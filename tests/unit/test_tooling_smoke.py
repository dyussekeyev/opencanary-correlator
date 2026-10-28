"""Milestone 1 smoke tests: packaging, tooling configuration and entry point."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

import opencanary_correlator
from opencanary_correlator.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def read_pyproject() -> dict[str, Any]:
    """Parse the project's `pyproject.toml`."""
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_package_exposes_semver_version() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", opencanary_correlator.__version__)


def test_pyproject_declares_runtime_requirements() -> None:
    config = read_pyproject()["project"]

    assert config["requires-python"] == ">=3.11"
    assert config["scripts"]["opencanary-correlator"] == "opencanary_correlator.cli:main"
    dependencies = " ".join(config["dependencies"])
    for package in ("pydantic", "pydantic-settings", "redis", "httpx", "aiosmtplib"):
        assert package in dependencies
    assert "twisted" not in dependencies.lower()
    assert "mandrill" not in dependencies.lower()
    assert "twilio" not in dependencies.lower()


def test_tooling_configuration_is_enforced() -> None:
    tool = read_pyproject()["tool"]

    assert tool["ruff"]["line-length"] == 100
    assert "S" in tool["ruff"]["lint"]["select"]
    assert tool["mypy"]["strict"] is True
    assert tool["pytest"]["ini_options"]["asyncio_mode"] == "auto"
    assert tool["coverage"]["report"]["fail_under"] == 85


def test_env_example_documents_operational_settings() -> None:
    content = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")

    for key in (
        "OCC_TCP_PORT",
        "OCC_REDIS_URL",
        "OCC_MAX_LINE_BYTES",
        "OCC_PARTIAL_LINE_TIMEOUT",
        "OCC_WEBHOOK_URLS",
        "OCC_DISCORD_WEBHOOKS",
    ):
        assert key in content


SECRET_SETTING_SUFFIXES = (
    "_TOKEN",
    "_PASSWORD",
    "_KEY",
    "_SECRET",
    "_URLS",
    "_WEBHOOKS",
    "_CHAT_IDS",
    "_TO",
)


def test_env_example_has_no_secret_values() -> None:
    for line in (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.endswith(SECRET_SETTING_SUFFIXES):
            assert value == "", f"{key} must stay blank in the template"


def test_legacy_tree_is_gone() -> None:
    for legacy_path in (
        "setup.py",
        "requirements.txt",
        "bin/opencanary-correlator",
        "opencanary_correlator",
        "opencanary_correlator/opencanary_correlator.conf",
    ):
        assert not (PROJECT_ROOT / legacy_path).exists(), f"{legacy_path} should be deleted"


def test_version_flag_exits_zero(capsys: Any) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert "opencanary-correlator" in capsys.readouterr().out


def test_running_without_configuration_reports_the_missing_setting(
    monkeypatch: Any, capsys: Any
) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    assert main([]) == 2
    assert "redis_url" in capsys.readouterr().err


def test_module_entry_point_runs_from_the_repository_root() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "opencanary_correlator", "--version"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "opencanary-correlator 0.3.2" in result.stdout
