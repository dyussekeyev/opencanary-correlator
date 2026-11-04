#!/usr/bin/env python3
"""Release qualification rules, kept out of YAML so they can be tested.

Three questions decide whether a release may exist, and all three are answered
here rather than in a shell conditional inside the workflow:

* Is CI green for the exact commit the tag points at? A release that skips the
  test suite is a release nobody verified, and re-running a separate subset in
  the release job would be a second, weaker definition of "green".
* May these artifacts be uploaded? A draft was never published, so replacing its
  assets is the point of re-running; a published release is immutable, and
  silently swapping its binaries would break every checksum a consumer recorded.
* What are the artifact digests? The manifest is generated from the files that
  are actually uploaded and verified again after upload.

Usage:
    python tools/release_guard.py ci --runs runs.json --sha <sha>
    python tools/release_guard.py plan --release release.json --tag v1.2.3
    python tools/release_guard.py checksums --dist dist --output dist/SHA256SUMS
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

CREATE_DRAFT = "create-draft"
REPLACE_DRAFT = "replace-draft"
REFUSE_PUBLISHED = "refuse-published"

PENDING = "pending"
SUCCESS = "success"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_PENDING = 3


class GuardError(Exception):
    """The release must not continue."""


def ci_state(runs: dict[str, Any], sha: str) -> str:
    """Return `success` or `pending` for `sha`, or raise when CI failed.

    Only the CI workflow counts: a green documentation job is not a test run.
    The newest run for the commit wins, so a fixed re-run supersedes an earlier
    failure instead of being ignored.
    """
    candidates = [
        run
        for run in runs.get("workflow_runs", [])
        if run.get("head_sha") == sha and str(run.get("path", "")).endswith("ci.yml")
    ]
    if not candidates:
        # A tag push may not be listed by the API in the first seconds.
        return PENDING
    latest = max(
        candidates,
        key=lambda run: (str(run.get("run_started_at") or ""), int(run.get("id") or 0)),
    )
    if latest.get("status") != "completed":
        return PENDING
    conclusion = latest.get("conclusion")
    if conclusion != "success":
        raise GuardError(
            f"the CI run for {sha} concluded {conclusion!r}; fix the commit and tag "
            "again instead of publishing unverified artifacts"
        )
    return SUCCESS


def upload_mode(release: dict[str, Any] | None, tag: str) -> str:
    """Decide between creating a draft, replacing draft assets and refusing."""
    if release is None:
        return CREATE_DRAFT
    tag_name = release.get("tagName")
    if tag_name not in (None, tag):
        raise GuardError(f"release {tag_name!r} does not match tag {tag!r}")
    if release.get("isDraft"):
        return REPLACE_DRAFT
    return REFUSE_PUBLISHED


def checksums(directory: Path) -> str:
    """Render a sorted `sha256sum -c` manifest for the artifacts in `directory`."""
    files = sorted(
        path for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    )
    if not files:
        raise GuardError(f"no artifacts to checksum in {directory}")
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in files]
    return "\n".join(lines) + "\n"


def _read_json(path: str) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise GuardError(f"{path} is not a JSON object")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)

    ci = actions.add_parser("ci", help="require a green CI run for one commit")
    ci.add_argument("--runs", required=True, help="JSON from the Actions runs API")
    ci.add_argument("--sha", required=True)

    plan = actions.add_parser("plan", help="print how the release assets may be handled")
    plan.add_argument("--release", help="JSON from `gh release view`, omitted when absent")
    plan.add_argument("--tag", required=True)

    sums = actions.add_parser("checksums", help="write a SHA256SUMS manifest")
    sums.add_argument("--dist", required=True)
    sums.add_argument("--output", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "ci":
            state = ci_state(_read_json(args.runs), args.sha)
            print(state)
            return EXIT_OK if state == SUCCESS else EXIT_PENDING
        if args.command == "plan":
            release = _read_json(args.release) if args.release else None
            mode = upload_mode(release, args.tag)
            if mode == REFUSE_PUBLISHED:
                print(
                    f"error: {args.tag} is already published and its assets are immutable; "
                    "release a new version instead of replacing published binaries",
                    file=sys.stderr,
                )
                return EXIT_REFUSED
            print(mode)
            return EXIT_OK
        manifest = checksums(Path(args.dist))
        Path(args.output).write_text(manifest, encoding="utf-8")
        print(manifest, end="")
        return EXIT_OK
    except (OSError, ValueError, GuardError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
