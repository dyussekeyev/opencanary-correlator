"""CLI flags: what the parser accepts and how settings are loaded."""

from __future__ import annotations

import json
from typing import Any

from opencanary_correlator.app.parser import build_parser
from opencanary_correlator.app.runner import main


def test_the_parser_accepts_the_documented_flags() -> None:
    args = build_parser().parse_args(
        ["--redis-url", "redis://r:6379/0", "--check-config", "--health-port", "0"]
    )

    assert args.redis_url == "redis://r:6379/0"
    assert args.check_config is True
    assert args.health_port == 0


def test_the_cli_facade_still_exports_the_public_names() -> None:
    """`opencanary_correlator.cli` is the documented import path."""
    from opencanary_correlator import cli

    for name in (
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
    ):
        assert callable(getattr(cli, name)), name


def test_check_config_rejects_invalid_override(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")

    code = main(["--check-config", "--redis-url", "http://localhost:6379/0"])

    assert code == 2
    assert "redis_url" in capsys.readouterr().err


def test_check_config_without_redis_url_fails(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    code = main(["--check-config"])

    assert code == 2
    assert "redis_url" in capsys.readouterr().err


def test_redis_url_flag_alone_satisfies_the_required_setting(monkeypatch: Any, capsys: Any) -> None:
    """`--redis-url` exists to supply the required URL, so it must reach validation."""
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)

    code = main(["--check-config", "--redis-url", "redis://127.0.0.1:6390/0"])

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["redis_url"] == "redis://127.0.0.1:6390/0"


def test_log_level_flag_overrides_the_environment(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setenv("OCC_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OCC_LOG_LEVEL", "WARNING")

    code = main(["--check-config", "--log-level", "DEBUG"])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["log_level"] == "DEBUG"


def test_main_reports_a_missing_legacy_config(monkeypatch: Any, capsys: Any, tmp_path: Any) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)
    missing = tmp_path / "absent.conf"

    code = main(["--config", str(missing)])

    captured = capsys.readouterr()
    assert code == 2
    assert "cannot load configuration" in captured.err
    assert "absent.conf" in captured.err


def test_main_reports_a_malformed_legacy_config(
    monkeypatch: Any, capsys: Any, tmp_path: Any
) -> None:
    monkeypatch.delenv("OCC_REDIS_URL", raising=False)
    broken = tmp_path / "broken.conf"
    broken.write_text("{not json", encoding="utf-8")

    code = main(["--config", str(broken)])

    captured = capsys.readouterr()
    assert code == 2
    assert "cannot load configuration" in captured.err
