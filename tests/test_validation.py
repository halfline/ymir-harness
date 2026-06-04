from __future__ import annotations

import json
import subprocess
from pathlib import Path

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


def test_validate_case_directory_reports_invalid_ymir_jira_mock(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "expected_basis": "historical_jira_state",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": [],
        },
    )

    report = validate_case_directory(cases_dir)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "jira_mock_invalid" and "fields must be an object" in issue.message
        for issue in issues
    )


def test_phase2_reports_target_branch_missing_from_mock_fixture(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(cases_dir, repo_path, pre_fix_ref)

    report = validate_case_directory(cases_dir, phase=2)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "mock_repo_mismatch" and "target_branch or fix_version" in issue.message
        for issue in issues
    )


def test_phase2_accepts_zstream_override_target_branch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(cases_dir, repo_path, pre_fix_ref, zstream_override={"8": "rhel-8.10.z"})

    report = validate_case_directory(cases_dir, phase=2)

    assert not report.has_blocking_errors


def test_phase2_reports_missing_source_cache(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        requires_source_cache=True,
    )

    report = validate_case_directory(cases_dir, phase=2)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(issue.category == "source_cache_incomplete" for issue in issues)


def test_phase2_reports_invalid_reference_patch_mode(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    repo_path, pre_fix_ref = _create_git_repo(tmp_path)
    _write_replay_case(
        cases_dir,
        repo_path,
        pre_fix_ref,
        zstream_override={"8": "rhel-8.10.z"},
        reference_patch_mode="source_tree",
    )

    report = validate_case_directory(cases_dir, phase=2)

    assert report.has_blocking_errors
    issues = report.cases[0].issues
    assert any(
        issue.category == "schema_mismatch" and "reference_patch_mode" in issue.message
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
    reference_patch_mode: str | None = None,
) -> None:
    case_id = "RHEL-12345"
    case_type = "cve_backport"
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
            "patch_urls": ["https://example.invalid/fix.patch"],
            "expected_basis": "merged_mr",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "case_status_reason": None,
            "network_mode": "replay_only",
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
                "remote_url": str(repo_path),
                "pre_fix_ref": pre_fix_ref,
                "branch": "c9s",
            }
        ],
    }
    if zstream_override is not None:
        mock_data["zstream_override"] = zstream_override
    _write_json(cases_dir / "mock_data" / "triage" / f"{case_id}.json", mock_data)
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
