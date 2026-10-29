#!/usr/bin/env python3
"""Render a GitHub release body from the matching `CHANGELOG.md` section.

The release body used to be typed out by hand next to the changelog, so the two
could drift; a re-run of the workflow then re-uploaded the artifacts but left the
old body in place. This script takes the section for one version — the
`## [1.2.3] - 2026-10-29` block — and renders everything between that heading and
the next `## ` heading, so the release notes are exactly what the changelog says.

Usage:
    python tools/release_notes.py --tag v0.5.1
    python tools/release_notes.py --tag 0.5.1 --output /tmp/notes.md
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_SECTION = re.compile(r"^##\s+")


class NotesError(Exception):
    """There is no usable changelog section for the requested version."""


def render_notes(changelog: str, version: str) -> str:
    """Return the body of the `version` section, without its heading.

    The heading may be bracketed (`## [0.5.1] - 2026-10-29`, the Keep a
    Changelog form this project uses) or bare (`## 0.5.1`). The match is
    anchored on a word boundary so `0.5.1` never selects `0.5.10`.
    """
    heading = re.compile(rf"^##\s+\[?{re.escape(version)}\]?(?:\s|$)")
    lines = changelog.splitlines()
    for index, line in enumerate(lines):
        if not heading.match(line):
            continue
        body: list[str] = []
        for following in lines[index + 1 :]:
            if _SECTION.match(following):
                break
            body.append(following)
        notes = "\n".join(body).strip()
        if not notes:
            raise NotesError(f"the CHANGELOG.md section for {version} is empty")
        return f"{notes}\n"
    raise NotesError(f"CHANGELOG.md has no section for {version}")


def main(argv: list[str] | None = None) -> int:
    """Render the notes for `--tag`, to stdout or `--output`."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag or bare version")
    parser.add_argument("--changelog", default=str(ROOT / "CHANGELOG.md"))
    parser.add_argument("--output", help="write the notes here instead of stdout")
    args = parser.parse_args(argv)
    version = args.tag.removeprefix("v")
    try:
        notes = render_notes(Path(args.changelog).read_text(encoding="utf-8"), version)
    except (OSError, NotesError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        Path(args.output).write_text(notes, encoding="utf-8")
        print(f"wrote {len(notes)} characters of {version} notes to {args.output}")
    else:
        sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
