"""The release body is the changelog section for the tag, not a hand-typed copy.

`tools/release_notes.py` feeds `gh release create/edit --notes-file` in the
release workflow, so these tests pin the extraction rules the workflow relies on:
one version only, no neighbouring section, and a loud failure when the changelog
has nothing to say about the version being released.
"""

from __future__ import annotations

import functools
import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]

CHANGELOG = """# Changelog

## [Unreleased]

### Added

- something not yet released

## [0.5.1] - 2026-10-29

### Fixed

- the bug that mattered

## [0.5.0] - 2026-10-28

### Added

- the older feature
"""


@functools.lru_cache(maxsize=1)
def _tool() -> ModuleType:
    """Load `tools/release_notes.py` by path (it is a script, not a package).

    Cached so `NotesError` is one class: a fresh module per call would raise a
    class the test's `pytest.raises` has never seen.
    """
    tool_path = ROOT / "tools" / "release_notes.py"
    spec = importlib.util.spec_from_file_location("release_notes", tool_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_section_is_rendered_without_neighbours() -> None:
    assert _tool().render_notes(CHANGELOG, "0.5.1") == "### Fixed\n\n- the bug that mattered\n"


def test_version_prefix_does_not_match_a_longer_version() -> None:
    with pytest.raises(_tool().NotesError, match=re.escape("no section for 0.5")):
        _tool().render_notes(CHANGELOG, "0.5")


def test_a_bare_heading_is_accepted() -> None:
    assert _tool().render_notes("## 1.0.0\n\n- first\n", "1.0.0") == "- first\n"


def test_missing_section_names_the_version() -> None:
    with pytest.raises(_tool().NotesError, match=re.escape("no section for 9.9.9")):
        _tool().render_notes(CHANGELOG, "9.9.9")


def test_empty_section_is_refused() -> None:
    with pytest.raises(_tool().NotesError, match="is empty"):
        _tool().render_notes("## [1.0.0]\n\n## [0.9.0]\n\n- old\n", "1.0.0")


def test_cli_writes_the_notes_file(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG, encoding="utf-8")
    output = tmp_path / "notes.md"

    code = _tool().main(["--tag", "v0.5.1", "--changelog", str(changelog), "--output", str(output)])

    assert code == 0
    assert output.read_text(encoding="utf-8") == "### Fixed\n\n- the bug that mattered\n"


def test_cli_fails_loudly_for_a_tag_the_changelog_does_not_know(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG, encoding="utf-8")

    code = _tool().main(["--tag", "v9.9.9", "--changelog", str(changelog)])

    assert code == 1


def test_the_released_version_has_a_changelog_section() -> None:
    """A tag is only releaseable if the changelog already describes it."""
    import opencanary_correlator

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    notes = _tool().render_notes(changelog, opencanary_correlator.__version__)

    assert notes.startswith("### "), notes
