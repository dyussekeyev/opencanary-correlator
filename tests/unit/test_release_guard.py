"""Release gate: CI must be green, published assets stay immutable, digests add up."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from tools.release_guard import (
    CREATE_DRAFT,
    REFUSE_PUBLISHED,
    REPLACE_DRAFT,
    GuardError,
    checksums,
    ci_state,
    main,
    upload_mode,
)

SHA = "a" * 40


def run(
    *,
    sha: str = SHA,
    status: str = "completed",
    conclusion: str = "success",
    path: str = ".github/workflows/ci.yml",
    started: str = "2026-11-04T10:00:00Z",
) -> dict:
    return {
        "head_sha": sha,
        "status": status,
        "conclusion": conclusion,
        "path": path,
        "run_started_at": started,
        "id": int(started[-4:-1].replace(":", "")) if started[-4:-1].isdigit() else 1,
    }


def test_a_green_ci_run_admits_the_release() -> None:
    assert ci_state({"workflow_runs": [run()]}, SHA) == "success"


def test_an_unfinished_run_is_pending_not_a_failure() -> None:
    assert (
        ci_state({"workflow_runs": [run(status="in_progress", conclusion=None)]}, SHA) == "pending"
    )


def test_a_missing_run_is_pending_so_a_new_tag_can_still_arrive() -> None:
    assert ci_state({"workflow_runs": []}, SHA) == "pending"


def test_a_failed_run_refuses_the_release() -> None:
    with pytest.raises(GuardError, match="concluded 'failure'"):
        ci_state({"workflow_runs": [run(conclusion="failure")]}, SHA)


def test_a_green_run_of_another_commit_does_not_count() -> None:
    assert ci_state({"workflow_runs": [run(sha="b" * 40)]}, SHA) == "pending"


def test_a_green_run_of_another_workflow_does_not_count() -> None:
    runs = {"workflow_runs": [run(path=".github/workflows/docs.yml")]}
    assert ci_state(runs, SHA) == "pending"


def test_the_newest_run_decides_after_a_fixed_retry() -> None:
    runs = {
        "workflow_runs": [
            run(conclusion="failure", started="2026-11-04T10:00:00Z"),
            run(conclusion="success", started="2026-11-04T11:00:00Z"),
        ]
    }
    assert ci_state(runs, SHA) == "success"


def test_a_missing_release_creates_a_draft() -> None:
    assert upload_mode(None, "v1.2.3") == CREATE_DRAFT


def test_a_draft_may_be_replaced() -> None:
    assert upload_mode({"tagName": "v1.2.3", "isDraft": True}, "v1.2.3") == REPLACE_DRAFT


def test_a_published_release_is_immutable() -> None:
    assert upload_mode({"tagName": "v1.2.3", "isDraft": False}, "v1.2.3") == REFUSE_PUBLISHED


def test_a_release_for_another_tag_is_refused() -> None:
    with pytest.raises(GuardError, match="does not match tag"):
        upload_mode({"tagName": "v1.2.2", "isDraft": True}, "v1.2.3")


def test_the_manifest_covers_every_artifact_sorted_and_excludes_itself(tmp_path: Path) -> None:
    (tmp_path / "b.whl").write_bytes(b"wheel")
    (tmp_path / "a.tar.gz").write_bytes(b"sdist")
    (tmp_path / "SHA256SUMS").write_text("stale\n", encoding="utf-8")

    manifest = checksums(tmp_path)

    assert [line.split("  ")[1] for line in manifest.splitlines()] == ["a.tar.gz", "b.whl"]
    assert f"{hashlib.sha256(b'sdist').hexdigest()}  a.tar.gz" in manifest


def test_an_empty_dist_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(GuardError, match="no artifacts"):
        checksums(tmp_path)


def test_hidden_build_files_are_not_release_assets(tmp_path: Path) -> None:
    (tmp_path / "a.whl").write_bytes(b"wheel")
    (tmp_path / ".gitignore").write_text("*\n", encoding="utf-8")

    manifest = checksums(tmp_path)

    assert ".gitignore" not in manifest
    assert "a.whl" in manifest


def test_the_manifest_uses_lf_so_sha256sum_can_read_it(tmp_path: Path) -> None:
    (tmp_path / "a.whl").write_bytes(b"wheel")
    output = tmp_path / "SHA256SUMS"

    assert main(["checksums", "--dist", str(tmp_path), "--output", str(output)]) == 0

    assert b"\r" not in output.read_bytes()
    assert output.read_text(encoding="utf-8").endswith("\n")
