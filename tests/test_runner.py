from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ymir_harness.models import CaseValidationResult, ValidationReport
from ymir_harness.runner import (
    DEFAULT_CHAT_MODEL,
    build_no_write_environment,
    build_run_report,
    load_case_manifest,
    select_validation_cases,
)


def test_build_no_write_environment_forces_safety_flags(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "reports"

    env = build_no_write_environment(
        cases_dir,
        results_dir,
        base_env={
            "PATH": "/usr/bin",
            "DRY_RUN": "false",
            "MOCK_JIRA": "false",
            "JIRA_EMAIL": "prod@example.com",
            "JIRA_TOKEN": "prod-token",
            "GITLAB_TOKEN": "prod-token",
            "JIRA_PASSWORD": "prod-password",
            "KEYTAB_FILE": "/etc/ymir/prod.keytab",
            "KRB5CCNAME": "/tmp/prod-krb5",
            "YMIR_BENCHMARK_CASE_ID": "RHEL-OLD",
            "BENCHMARK_MAX_ITERATIONS_OVERRIDE": "50",
            "BEEAI_MAX_ITERATIONS": "255",
        },
    )

    assert env["PATH"] == "/usr/bin"
    assert env["DRY_RUN"] == "true"
    assert env["MOCK_JIRA"] == "true"
    assert env["JIRA_DRY_RUN"] == "true"
    assert env["JIRA_EMAIL"] == "ymir-harness@example.invalid"
    assert env["JIRA_TOKEN"] == "ymir-harness-token"
    assert env["AUTO_CHAIN"] == "false"
    assert env["SILENT_RUN"] == "true"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_AUTHOR_NAME"] == "Ymir Harness"
    assert env["GIT_AUTHOR_EMAIL"] == "ymir-harness@example.invalid"
    assert env["GIT_COMMITTER_NAME"] == "Ymir Harness"
    assert env["GIT_COMMITTER_EMAIL"] == "ymir-harness@example.invalid"
    assert env["CHAT_MODEL"] == DEFAULT_CHAT_MODEL
    assert env["GOOGLE_VERTEX_LOCATION"] == "global"
    assert env["BENCHMARK_MAX_ITERATIONS_OVERRIDE"] == "50"
    assert env["BEEAI_MAX_ITERATIONS"] == "50"
    assert env["GITLAB_TOKEN"] == "prod-token"
    assert "JIRA_PASSWORD" not in env
    assert "KEYTAB_FILE" not in env
    assert "KRB5CCNAME" not in env
    assert "YMIR_BENCHMARK_CASE_ID" not in env
    assert env["JIRA_MOCK_FILES"] == str((cases_dir / "jiras").resolve())
    assert env["MOCK_REPOS_DIR"] == str((cases_dir / "mock_data").resolve())
    assert env["YMIR_BENCHMARK_CASES_DIR"] == str(cases_dir.resolve())
    assert env["YMIR_BENCHMARK_RESULTS_DIR"] == str(results_dir.resolve())


def test_build_no_write_environment_normalizes_vertex_claude_env(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "reports"

    env = build_no_write_environment(
        cases_dir,
        results_dir,
        base_env={
            "CHAT_MODEL": "vertexai:claude-sonnet-4-6",
            "ANTHROPIC_VERTEX_PROJECT_ID": "itpc-gcp-core-pe-eng-claude",
            "CLOUD_ML_REGION": "global",
        },
    )

    assert env["ANTHROPIC_VERTEX_PROJECT_ID"] == "itpc-gcp-core-pe-eng-claude"
    assert env["GOOGLE_VERTEX_PROJECT"] == "itpc-gcp-core-pe-eng-claude"
    assert env["CLOUD_ML_REGION"] == "global"
    assert env["GOOGLE_VERTEX_LOCATION"] == "global"
    assert "GOOGLE_CLOUD_PROJECT" not in env


def test_build_no_write_environment_records_case_id(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "reports"

    env = build_no_write_environment(
        cases_dir,
        results_dir,
        base_env={},
        case_id="RHEL-12345",
    )

    assert env["YMIR_BENCHMARK_CASE_ID"] == "RHEL-12345"
    shim_dir = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"])
    assert env["PATH"].split(":")[0] == str(shim_dir)
    assert (shim_dir / "rhpkg").is_file()
    assert (shim_dir / "centpkg").is_file()
    assert (shim_dir / "rpmbuild").is_file()
    assert (shim_dir / "patch").is_file()


def test_dry_run_patch_shim_does_not_apply_changes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "file.txt").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True, text=True)

    patch = tmp_path / "change.patch"
    patch.write_text(
        "diff --git a/file.txt b/file.txt\n"
        "index 3303b7b..4f40e8d 100644\n"
        "--- a/file.txt\n"
        "+++ b/file.txt\n"
        "@@ -1 +1 @@\n"
        "-before\n"
        "+after\n",
        encoding="utf-8",
    )
    env = build_no_write_environment(
        tmp_path / "cases",
        tmp_path / "results",
        base_env={"PATH": "/usr/bin:/bin"},
        case_id="RHEL-12345",
    )
    shim = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"]) / "patch"

    subprocess.run(
        [str(shim), "--dry-run", "-p1", str(patch)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    assert (repo / "file.txt").read_text(encoding="utf-8") == "before\n"

    subprocess.run(
        [str(shim), "-p1", str(patch)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    assert (repo / "file.txt").read_text(encoding="utf-8") == "after\n"


def test_dry_run_package_shim_writes_non_empty_srpm(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "redis.spec").write_text("Name: redis\n", encoding="utf-8")
    env = build_no_write_environment(
        tmp_path / "cases",
        tmp_path / "results",
        base_env={"PATH": "/usr/bin:/bin"},
        case_id="RHEL-12345",
    )
    rhpkg = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"]) / "rhpkg"

    completed = subprocess.run(
        [str(rhpkg), "--offline", "--released", "srpm"],
        cwd=workdir,
        check=True,
        capture_output=True,
        text=True,
    )

    srpm_path = workdir / "redis-dry-run.src.rpm"
    assert completed.stdout == f"Wrote: {srpm_path}\n"
    assert srpm_path.read_text(encoding="utf-8") == "ymir-harness dry-run SRPM for redis\n"


def test_load_case_manifest_reads_case_ids(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    cases_dir.mkdir()
    (cases_dir / "cases.yaml").write_text(
        "cases:\n  - RHEL-23456\n  - case_id: RHEL-12345\n",
        encoding="utf-8",
    )

    case_ids, issues = load_case_manifest(cases_dir)

    assert case_ids == ["RHEL-23456", "RHEL-12345"]
    assert issues == []


def test_load_case_manifest_reports_schema_errors(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    cases_dir.mkdir()
    (cases_dir / "cases.yaml").write_text(
        "cases:\n  - package: dnsmasq\n",
        encoding="utf-8",
    )

    case_ids, issues = load_case_manifest(cases_dir)

    assert case_ids == []
    assert len(issues) == 1
    assert issues[0].category == "schema_mismatch"


def test_select_validation_cases_filters_in_request_order(tmp_path: Path) -> None:
    validation_report = ValidationReport(
        cases_dir=tmp_path / "benchmark_cases",
        cases=[
            CaseValidationResult(case_id="RHEL-12345", case_type="cve_backport"),
            CaseValidationResult(case_id="RHEL-23456", case_type="rebase"),
        ],
    )

    selected = select_validation_cases(validation_report, ["RHEL-23456", "RHEL-12345"])

    assert [case.case_id for case in selected.cases] == ["RHEL-23456", "RHEL-12345"]
    assert not selected.has_blocking_errors


def test_select_validation_cases_reports_missing_cases(tmp_path: Path) -> None:
    validation_report = ValidationReport(
        cases_dir=tmp_path / "benchmark_cases",
        cases=[CaseValidationResult(case_id="RHEL-12345", case_type="cve_backport")],
    )

    selected = select_validation_cases(validation_report, ["RHEL-99999"])

    assert selected.cases == []
    assert selected.has_blocking_errors
    assert selected.global_issues[0].case_id == "RHEL-99999"
    assert selected.global_issues[0].message == "requested case was not found"


def test_build_run_report_assigns_actual_paths(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(cases_dir, "RHEL-12345")
    _write_expected(cases_dir, "RHEL-23456")
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="not_affected",
                status="valid",
            ),
            CaseValidationResult(
                case_id="RHEL-23456",
                case_type="not_affected",
                status="skipped",
            ),
        ],
    )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        repeat=2,
    )

    entries = {(entry.case_id, entry.repetition): entry for entry in report.entries}
    assert entries["RHEL-12345", 1].actual_path == (
        results_dir.resolve() / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert entries["RHEL-12345", 2].actual_path == (
        results_dir.resolve() / "repeat-2" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert entries["RHEL-23456", 1].actual_path is None
    assert entries["RHEL-23456", 2].actual_path is None


def test_build_run_report_records_provenance(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(cases_dir, "RHEL-12345")
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="not_affected",
                status="valid",
            ),
        ],
    )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        ymir_sha="abc123",
        features=["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
        base_env={
            "CHAT_MODEL": "vertexai:claude-opus-4-6",
            "CONTAINER_IMAGE_DIGEST": "sha256:container",
        },
        provenance={"agentic_skills_sha": "def456"},
    )

    assert report.to_json()["provenance"] == {
        "ymir_sha": "abc123",
        "feature_flags": ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
        "container_image_digest": "sha256:container",
        "chat_model": "vertexai:claude-opus-4-6",
        "agentic_skills_sha": "def456",
    }



def _write_expected(cases_dir: Path, case_id: str, data: object | None = None) -> None:
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected_path.parent.mkdir(parents=True, exist_ok=True)
    expected_path.write_text(json.dumps(data or {}) + "\n", encoding="utf-8")
