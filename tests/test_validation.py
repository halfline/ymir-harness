from __future__ import annotations

import json
import subprocess
from pathlib import Path

import ymir_harness.validation as validation_module
from ymir_harness.reports import write_validation_reports
from ymir_harness.validation import validate_case_directory


def test_validate_case_directory_accepts_replay_fixture(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(cases_dir, repo_path, pre_fix_ref)

    report = validate_case_directory(cases_dir)

    assert not report.has_blocking_errors
    assert report.summary() == {
        "valid": 1,
        "invalid": 0,
        "warning-only": 0,
        "skipped": 0,
        "global_errors": 0,
        "global_warnings": 0,
    }
    assert report.cases[0].case_id == "RHEL-12345"


def test_validate_case_directory_checks_mock_repo_source_url(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        remote_url="https://gitlab.example/group/pkg.git",
        source_url=str(repo_path),
    )

    report = validate_case_directory(cases_dir)

    assert not report.has_blocking_errors
    assert report.cases[0].status == "valid"


def test_validate_case_directory_reports_blocking_errors(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 99,
            "case_id": "RHEL-99999",
            "case_type": "unknown",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "expected_basis": "merged_mr",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "live_non_reproducible",
        },
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    assert report.summary()["invalid"] == 1
    categories = {issue.category for issue in report.cases[0].issues}
    assert "schema_mismatch" in categories
    assert "network_policy_invalid" in categories


def test_validate_case_directory_reports_invalid_backport_source(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "redis",
            "target_branch": "rhel-9.6.z",
            "expected_basis": "merged_mr",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "quarantined",
            "network_mode": "replay_only",
            "backport_source": "downstream",
        },
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    assert any(
        issue.category == "schema_mismatch" and "backport_source must be one of" in issue.message
        for issue in report.cases[0].issues
    )


def test_strict_validation_reports_missing_source_cache(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(issue.category == "source_cache_incomplete" for issue in issues)


def test_strict_validation_skips_source_cache_for_triage_workflow(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )

    report = validate_case_directory(cases_dir, workflow="ymir-triage")

    assert not report.has_blocking_errors
    issues = report.cases[0].issues
    assert not any(issue.category == "source_cache_incomplete" for issue in issues)


def test_strict_validation_reports_missing_source_cache_upstream(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir(parents=True)
    (lookaside_dir / ".keep").write_text("placeholder\n", encoding="utf-8")

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete" and "upstream" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_empty_source_cache_upstream(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "upstream directory is empty" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_source_cache_upstream_without_clone_or_archive(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / ".keep").write_text("placeholder\n", encoding="utf-8")
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir()
    (lookaside_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "upstream must include a git clone or source archive" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_unreadable_source_cache_upstream_archive(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    archive_path = upstream_dir / "source.tar.gz"
    archive_path.write_text("cached source\n", encoding="utf-8")
    archive_path.chmod(0)
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir()
    (lookaside_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "source archive is not readable" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_missing_source_cache_lookaside(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete" and "lookaside" in issue.message
        for issue in issues
    )


def test_strict_validation_accepts_distgit_backport_without_lookaside(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        requires_source_cache=True,
    )
    expected_path = cases_dir / "expected" / "RHEL-12345.expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    expected["backport_source"] = "distgit"
    _write_json(expected_path, expected)
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--bare", str(repo_path), str(upstream_dir / "distgit.git")],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    report = validate_case_directory(cases_dir)

    assert not report.has_blocking_errors


def test_strict_validation_reports_empty_source_cache_lookaside(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir()

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "lookaside directory is empty" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_source_cache_lookaside_without_artifact_files(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    (lookaside_dir / "nested").mkdir(parents=True)

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "lookaside must include artifact files" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_unreadable_source_cache_lookaside_artifact(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir()
    artifact_path = lookaside_dir / "source.tar.gz"
    artifact_path.write_text("cached source\n", encoding="utf-8")
    artifact_path.chmod(0)

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "lookaside artifact is not readable" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_missing_required_source_cache_file(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir()
    (lookaside_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")
    expected_path = cases_dir / "expected" / "RHEL-12345.expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    expected["required_source_cache_files"] = [
        "lookaside/source.tar.gz",
        "upstream/missing.tar.gz",
    ]
    _write_json(expected_path, expected)

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "required source cache file is missing" in issue.message
        and issue.path == str(upstream_dir / "missing.tar.gz")
        for issue in issues
    )


def test_strict_validation_reports_source_cache_checksum_mismatch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )
    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "source.tar.gz").write_text("cached source\n", encoding="utf-8")
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir()
    artifact_path = lookaside_dir / "source.tar.gz"
    artifact_path.write_text("cached source\n", encoding="utf-8")
    expected_path = cases_dir / "expected" / "RHEL-12345.expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    expected["source_cache_checksums"] = {
        "lookaside/source.tar.gz": f"sha256:{'0' * 64}",
    }
    _write_json(expected_path, expected)

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "source_cache_incomplete"
        and "checksum mismatch" in issue.message
        and issue.path == str(artifact_path)
        for issue in issues
    )

def test_strict_validation_reports_missing_reference_patch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_exists=False,
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "reference_patch_invalid" and "reference patch" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_malformed_reference_patch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_text="not a patch\n",
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "reference_patch_invalid" and "parse" in issue.message for issue in issues
    )


def test_strict_validation_reports_reference_patch_without_touched_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
    )
    real_run = validation_module.subprocess.run

    def fake_run(command, *args, **kwargs):
        if command[:3] == ["git", "apply", "--numstat"]:
            return subprocess.CompletedProcess(command, 0, stdout="1\t1\t\n", stderr="")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(validation_module.subprocess, "run", fake_run)

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "reference_patch_invalid" and "touched-file list" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_reference_patch_apply_failure(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_mode="applies",
        reference_patch_text=(
            "diff --git a/source.c b/source.c\n"
            "index 4447cd3..c8c45c2 100644\n"
            "--- a/source.c\n"
            "+++ b/source.c\n"
            "@@ -1 +1 @@\n"
            "-int main(void) { return 2; }\n"
            "+int main(void) { return 1; }\n"
        ),
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "reference_patch_invalid" and "apply" in issue.message for issue in issues
    )


def test_strict_validation_reports_reference_patch_already_present(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, _pre_fix_ref = _create_git_repo(tmp_path)
    (repo_path / "source.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
    _run_git("add", repo_path, "source.c")
    _run_git("commit", repo_path, "-m", "fixed")
    fixed_ref = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    _write_replay_case(
        cases_dir,
        repo_path,
        fixed_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_mode="applies",
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(issue.category == "fix_already_present" for issue in issues)


def test_strict_validation_reports_invalid_reference_patch_mode(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_mode="source_tree",
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "schema_mismatch" and "reference_patch_mode" in issue.message
        for issue in issues
    )


def test_strict_validation_reports_missing_reference_patch_mode(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_mode=None,
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "missing_metadata" and "reference_patch_mode" in issue.message
        for issue in issues
    )


def test_write_validation_reports(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(cases_dir, repo_path, pre_fix_ref)
    report = validate_case_directory(cases_dir)

    paths = write_validation_reports(report, cases_dir / "reports")

    assert [path.name for path in paths] == [
        "fixture-validation.json",
        "fixture-validation.md",
        "fixture-validation-errors.md",
    ]
    assert json.loads(paths[0].read_text(encoding="utf-8"))["summary"]["valid"] == 1
    assert "No validation errors." in paths[2].read_text(encoding="utf-8")


def _write_replay_case(
    cases_dir: Path,
    repo_path: Path,
    pre_fix_ref: str,
    *,
    zstream_override: dict[str, str] | None = None,
    requires_source_cache: bool = False,
    network_mode: str = "replay_only",
    patch_urls: list[str] | None = None,
    reference_patch_mode: str | None = "applies",
    reference_patch_exists: bool = True,
    remote_url: str | None = None,
    source_url: str | None = None,
    reference_patch_text: str = (
        "diff --git a/source.c b/source.c\n"
        "index 4447cd3..c8c45c2 100644\n"
        "--- a/source.c\n"
        "+++ b/source.c\n"
        "@@ -1 +1 @@\n"
        "-int main(void) { return 0; }\n"
        "+int main(void) { return 1; }\n"
    ),
) -> None:
    case_id = "RHEL-12345"
    case_type = "cve_backport"
    if patch_urls is None:
        patch_urls = ["https://example.invalid/fix.patch"]
    if zstream_override is None:
        zstream_override = {"8": "rhel-8.10.z"}
    _write_json(
        cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": case_type,
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "cve_ids": ["CVE-2026-0001"],
            "patch_urls": patch_urls,
            "expected_basis": "merged_mr",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "case_status_reason": None,
            "network_mode": network_mode,
            "requires_source_cache": requires_source_cache,
            "reference_patch_mode": reference_patch_mode,
        },
    )
    mock_data = {
        "schema_version": 1,
        "case_id": case_id,
        "case_type": case_type,
        "repos": [
            {
                "package": "dnsmasq",
                "remote_url": remote_url or str(repo_path),
                "pre_fix_ref": pre_fix_ref,
                "branch": "c9s",
            }
        ],
    }
    if source_url is not None:
        mock_data["repos"][0]["source_url"] = source_url
    mock_data["zstream_override"] = zstream_override
    _write_json(cases_dir / "mock_data" / "triage" / f"{case_id}.json", mock_data)
    if reference_patch_exists:
        reference_patch_path = (
            cases_dir / "mock_data" / "triage" / "reference_patches" / f"{case_id}.patch"
        )
        reference_patch_path.parent.mkdir(parents=True, exist_ok=True)
        reference_patch_path.write_text(reference_patch_text, encoding="utf-8")
    _write_json(
        cases_dir / "web_cache" / case_id / "manifest.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": case_type,
            "required_urls": ["https://example.invalid/fix.patch"],
            "recorded_files": {
                "https://example.invalid/fix.patch": "commits/fix.patch",
            },
        },
    )
    patch_path = cases_dir / "web_cache" / case_id / "commits" / "fix.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text("diff --git a/source.c b/source.c\n", encoding="utf-8")


def _create_git_repo(tmp_path: Path) -> tuple[Path, str]:
    repo_path = tmp_path / "source-repo"
    repo_path.mkdir()
    _run_git("init", repo_path)
    (repo_path / "source.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    _run_git("add", repo_path, "source.c")
    _run_git("commit", repo_path, "-m", "initial")
    rev = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return repo_path, rev


def _run_git(command: str, repo_path: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "-c",
            "user.name=Ymir Harness Tests",
            "-c",
            "user.email=ymir-harness@example.invalid",
            command,
            *args,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
