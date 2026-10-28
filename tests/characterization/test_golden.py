"""The golden snapshot is the refactor's safety net.

`tools/characterize.py` renders the observable behaviour of the correlator —
alert text for every channel and detail level, the `--check-config` document,
CLI help, stored incident fields, and the audit/Redis outcome of a fixed event
stream. This test recomputes it and compares, so any unintended change in output
fails here with the exact key that moved.

Regenerate deliberately with `uv run python tools/characterize.py --write`, and
explain the diff in the commit message: the golden file is an oracle, not a
rubber stamp.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "characterization" / "golden" / "snapshot.json"


def _tool() -> ModuleType:
    """Load `tools/characterize.py` by path (it is a script, not a package)."""
    tool_path = ROOT / "tools" / "characterize.py"
    spec = importlib.util.spec_from_file_location("characterize", tool_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_the_golden_snapshot_matches_the_current_behaviour() -> None:
    tool = _tool()
    found = tool.differences(_golden(), tool.snapshot())

    assert found == [], (
        "observable behaviour changed; regenerate with "
        "`uv run python tools/characterize.py --write` and justify the diff:\n  "
        + "\n  ".join(found[:20])
    )


def test_the_snapshot_holds_no_real_looking_credentials() -> None:
    """The golden file is committed: placeholder secrets must stay masked in it."""
    tool = _tool()
    text = tool.dump(tool.snapshot())

    assert tool.FAKE_TELEGRAM_BOT not in text
    assert "s3cret" not in text  # Redis password from the described configuration
    assert "vt-secret-key" not in text  # VirusTotal key from the described configuration


def test_the_characterisation_tool_writes_what_it_compares() -> None:
    """`--write` and the comparison must agree, or the oracle is meaningless."""
    tool = _tool()
    actual = tool.snapshot()

    assert tool.differences(actual, json.loads(tool.dump(actual))) == []
