from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import ymir_harness.runner as runner_module
import ymir_harness.workflow_worker as workflow_worker
from ymir_harness.models import CaseValidationResult, ValidationReport
from ymir_harness.runner import (
    DEFAULT_CHAT_MODEL,
    RunCaseExecution,
    build_no_write_environment,
    build_run_report,
    load_case_manifest,
    select_validation_cases,
)
from ymir_harness.source_fixtures import (
    find_source_cache_repository,
    find_source_fixture_repository,
    materialize_case_source_cache,
    source_cache_git_aliases,
    source_cache_git_rewrites,
    write_source_fixture_from_repository,
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
            "UV_PUBLISH_TOKEN": "publish-token",
            "JIRA_PASSWORD": "prod-password",
            "KEYTAB_FILE": "/etc/ymir/prod.keytab",
            "KRB5CCNAME": "/tmp/prod-krb5",
            "ANTHROPIC_API_KEY": "prod-anthropic-key",
            "GEMINI_API_KEY": "prod-gemini-key",
            "OPENAI_API_TOKEN": "prod-openai-token",
            "FREEDESKTOP_API_KEY": "prod-freedesktop-key",
            "XDG_SESSION_ID": "desktop-session",
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
    assert env["YMIR_HARNESS_FS_ISOLATION"] == "podman"
    assert "GITLAB_TOKEN" not in env
    assert "UV_PUBLISH_TOKEN" not in env
    assert "JIRA_PASSWORD" not in env
    assert "KEYTAB_FILE" not in env
    assert "KRB5CCNAME" not in env
    assert env["ANTHROPIC_API_KEY"] == "prod-anthropic-key"
    assert env["GEMINI_API_KEY"] == "prod-gemini-key"
    assert env["OPENAI_API_TOKEN"] == "prod-openai-token"
    assert "FREEDESKTOP_API_KEY" not in env
    assert "XDG_SESSION_ID" not in env
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


def test_isolated_worker_environment_omits_build_only_and_sensitive_values(
    tmp_path: Path,
) -> None:
    env = runner_module._isolated_worker_environment(
        {
            "CHAT_MODEL": "vertexai:claude-sonnet-4-6",
            "YMIR_BENCHMARK_CASE_ID": "RHEL-12345",
            "INTERNAL_REPO_URL_C9S": "https://repo.example/c9s",
            "EXTRA_PACKAGES": "python3-rpm",
            "YMIR_HARNESS_WORKER_IMAGE": "localhost/custom-worker:test",
            "ANTHROPIC_API_KEY": "prod-anthropic-key",
            "GEMINI_API_KEY": "prod-gemini-key",
            "OPENAI_API_TOKEN": "prod-openai-token",
            "JIRA_TOKEN": "prod-jira-token",
        },
        tmp_path / "worker-home",
        container_version="c9s",
    )

    assert env["CHAT_MODEL"] == "vertexai:claude-sonnet-4-6"
    assert env["YMIR_BENCHMARK_CASE_ID"] == "RHEL-12345"
    assert env["YMIR_HARNESS_CONTAINER_VERSION"] == "c9s"
    assert env["CONTAINER_VERSION"] == "c9s"
    assert "INTERNAL_REPO_URL_C9S" not in env
    assert "EXTRA_PACKAGES" not in env
    assert "YMIR_HARNESS_WORKER_IMAGE" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "GEMINI_API_KEY" not in env
    assert "OPENAI_API_TOKEN" not in env
    assert "JIRA_TOKEN" not in env


def test_isolated_worker_environment_keeps_no_write_jira_token(tmp_path: Path) -> None:
    env = runner_module._isolated_worker_environment(
        {
            "JIRA_DRY_RUN": "true",
            "JIRA_EMAIL": "ymir-harness@example.invalid",
            "JIRA_TOKEN": "ymir-harness-token",
            "MOCK_JIRA": "true",
        },
        tmp_path / "worker-home",
        container_version="c10s",
    )

    assert env["JIRA_DRY_RUN"] == "true"
    assert env["JIRA_EMAIL"] == "ymir-harness@example.invalid"
    assert env["JIRA_TOKEN"] == "ymir-harness-token"
    assert env["MOCK_JIRA"] == "true"


def test_isolated_worker_environment_keeps_command_shims_on_container_path(
    tmp_path: Path,
) -> None:
    shim_dir = tmp_path / "shims"

    env = runner_module._isolated_worker_environment(
        {
            "PATH": "/host/bin",
            "YMIR_BENCHMARK_COMMAND_SHIMS": str(shim_dir),
        },
        tmp_path / "worker-home",
        container_version="c10s",
    )

    assert env["PATH"].split(":")[0] == str(shim_dir)
    assert "/opt/beeai-venv/bin" in env["PATH"].split(":")
    assert "/host/bin" not in env["PATH"].split(":")


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
    assert (shim_dir / "dnf").is_file()
    assert (shim_dir / "dnf5").is_file()
    assert (shim_dir / "microdnf").is_file()
    assert (shim_dir / "rpmbuild").is_file()
    assert (shim_dir / "patch").is_file()
    assert (shim_dir / "yum").is_file()


def test_package_manager_shims_block_runtime_installs(tmp_path: Path) -> None:
    env = build_no_write_environment(
        tmp_path / "cases",
        tmp_path / "results",
        base_env={"PATH": "/usr/bin:/bin"},
        case_id="RHEL-12345",
    )
    shim_dir = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"])

    for command in ("dnf", "dnf5", "microdnf", "yum"):
        completed = subprocess.run(
            [str(shim_dir / command), "-y", "install", "redis"],
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 1
        assert f"ymir-harness offline mode blocked {command}: -y install redis" in (
            completed.stderr
        )
        assert "package-manager operations must use declared benchmark fixtures" in (
            completed.stderr
        )


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


def test_dry_run_package_shim_copies_lookaside_sources(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir(parents=True)
    (lookaside_dir / "redis.tar.gz").write_text("cached source\n", encoding="utf-8")
    (lookaside_dir / "future.tar.gz").write_text("future source\n", encoding="utf-8")
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "sources").write_text(
        "SHA512 (redis.tar.gz) = deadbeef\n",
        encoding="utf-8",
    )
    env = build_no_write_environment(
        cases_dir,
        tmp_path / "results",
        base_env={"PATH": "/usr/bin:/bin"},
        case_id="RHEL-12345",
    )
    rhpkg = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"]) / "rhpkg"

    subprocess.run(
        [str(rhpkg), "sources"],
        cwd=workdir,
        env={**os.environ, **env},
        check=True,
        capture_output=True,
        text=True,
    )

    assert (workdir / "redis.tar.gz").read_text(encoding="utf-8") == "cached source\n"
    assert not (workdir / "future.tar.gz").exists()


def test_dry_run_package_shim_reports_missing_referenced_lookaside_source(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "cases"
    lookaside_dir = cases_dir / "source_cache" / "RHEL-12345" / "lookaside"
    lookaside_dir.mkdir(parents=True)
    (lookaside_dir / "redis.tar.gz").write_text("cached source\n", encoding="utf-8")
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "sources").write_text(
        "SHA512 (future.tar.gz) = deadbeef\n",
        encoding="utf-8",
    )
    env = build_no_write_environment(
        cases_dir,
        tmp_path / "results",
        base_env={"PATH": "/usr/bin:/bin"},
        case_id="RHEL-12345",
    )
    rhpkg = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"]) / "rhpkg"

    completed = subprocess.run(
        [str(rhpkg), "sources"],
        cwd=workdir,
        env={**os.environ, **env},
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stderr == "future.tar.gz was not available in the lookaside cache\n"


def test_dry_run_package_shim_warns_on_noop_commands(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    workdir.mkdir()
    env = build_no_write_environment(
        tmp_path / "cases",
        tmp_path / "results",
        base_env={"PATH": "/usr/bin:/bin"},
        case_id="RHEL-12345",
    )
    rhpkg = Path(env["YMIR_BENCHMARK_COMMAND_SHIMS"]) / "rhpkg"

    completed = subprocess.run(
        [str(rhpkg), "new-sources", "redis-6.2.22.tar.gz"],
        cwd=workdir,
        env={**os.environ, **env},
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout == ""
    assert completed.stderr == (
        "ymir-harness warning: dry-run rhpkg no-op for unsupported command: "
        "new-sources redis-6.2.22.tar.gz\n"
    )


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


def test_build_run_report_calls_executor_for_runnable_cases(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(cases_dir, "RHEL-12345")
    _write_expected(cases_dir, "RHEL-23456")
    _write_structured_jira(cases_dir, "RHEL-12345")
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
    requests = []
    clock_values = iter([10.0, 12.5, 20.0, 21.25])
    monkeypatch.setattr(runner_module.time, "monotonic", lambda: next(clock_values))

    def executor(request):
        requests.append(request)
        return RunCaseExecution(status="passed", reason="workflow completed")

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        features=["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
        repeat=2,
        executor=executor,
        base_env={
            "PATH": "/usr/bin",
            "JIRA_TOKEN": "prod-token",
        },
    )

    assert len(requests) == 2
    assert [request.repetition for request in requests] == [1, 2]
    assert {request.case_id for request in requests} == {"RHEL-12345"}
    assert requests[0].cases_dir == cases_dir.resolve()
    assert requests[0].results_dir == results_dir.resolve()
    assert requests[0].expected_path == cases_dir.resolve() / "expected" / (
        "RHEL-12345.expected.json"
    )
    assert requests[0].actual_path == (
        results_dir.resolve() / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert requests[0].variant == "baseline"
    assert requests[0].features == ("YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK",)
    assert requests[0].environment["PATH"].endswith(":/usr/bin")
    assert requests[0].environment["YMIR_BENCHMARK_COMMAND_SHIMS"] == str(
        results_dir.resolve() / ".ymir-harness-shims-RHEL-12345"
    )
    assert requests[0].environment["DRY_RUN"] == "true"
    assert requests[0].environment["YMIR_BENCHMARK_CASE_ID"] == "RHEL-12345"
    assert requests[0].environment["YMIR_BENCHMARK_REPETITION"] == "1"
    assert requests[0].environment["JIRA_TOKEN"] == "ymir-harness-token"
    assert requests[0].environment["CHAT_MODEL"] == DEFAULT_CHAT_MODEL
    assert requests[0].environment["JIRA_MOCK_FILES"] == str(
        results_dir.resolve() / "repeat-1" / "jira-mock"
    )
    assert requests[1].environment["JIRA_MOCK_FILES"] == str(
        results_dir.resolve() / "repeat-2" / "jira-mock"
    )
    assert requests[1].environment["YMIR_BENCHMARK_REPETITION"] == "2"
    jira_payload = json.loads(
        (results_dir.resolve() / "repeat-1" / "jira-mock" / "RHEL-12345").read_text(
            encoding="utf-8"
        )
    )
    assert jira_payload["fields"]["comment"]["comments"] == [{"body": "Please backport this fix."}]
    assert jira_payload["remote_links"] == [
        {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
    ]

    entries = {(entry.case_id, entry.repetition): entry for entry in report.entries}
    assert entries["RHEL-12345", 1].status == "passed"
    assert entries["RHEL-12345", 1].actual_path == requests[0].actual_path
    assert entries["RHEL-12345", 1].runtime_seconds == 2.5
    assert entries["RHEL-12345", 1].reason == "workflow completed"
    assert entries["RHEL-12345", 2].status == "passed"
    assert entries["RHEL-12345", 2].runtime_seconds == 1.25
    assert entries["RHEL-23456", 1].status == "skipped"
    assert entries["RHEL-23456", 1].actual_path is None
    assert entries["RHEL-23456", 2].status == "skipped"
    assert entries["RHEL-23456", 2].actual_path is None


def test_build_run_report_isolates_real_ymir_executor_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(cases_dir, "RHEL-12345")
    _write_structured_jira(cases_dir, "RHEL-12345")
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
    isolated_calls = []

    def executor(_request):
        raise AssertionError("isolatable Ymir executor should run in a worker process")

    executor.ymir_workflow = "ymir-triage"
    executor.ymir_isolatable = True

    def isolated(workflow, request):
        isolated_calls.append((workflow, request))
        return RunCaseExecution(status="passed", reason="isolated workflow completed")

    monkeypatch.setattr(runner_module, "_execute_isolated_case_workflow", isolated)

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
        base_env={"PATH": "/usr/bin"},
    )

    assert len(isolated_calls) == 1
    assert isolated_calls[0][0] == "ymir-triage"
    assert isolated_calls[0][1].environment["YMIR_HARNESS_FS_ISOLATION"] == "podman"
    assert report.entries[0].status == "passed"
    assert report.entries[0].reason == "isolated workflow completed"


def test_filesystem_isolation_command_runs_container_without_harness_bind(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    expected_path = cases_dir / "expected" / "RHEL-12345.expected.json"
    actual_path = results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    worker_home = results_dir / "repeat-1" / "workflow-worker" / "home"
    request_path = results_dir / "repeat-1" / "workflow-worker" / "RHEL-12345.request.json"
    result_path = results_dir / "repeat-1" / "workflow-worker" / "RHEL-12345.result.json"
    cases_mount_source = results_dir / "repeat-1" / "workflow-worker" / "cases-view"
    results_dir.mkdir(parents=True)
    worker_home.mkdir(parents=True)
    cases_mount_source.mkdir(parents=True)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")

    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=expected_path,
        actual_path=actual_path,
        environment={"GEMINI_API_KEY": "prod-gemini-key", "PATH": "/usr/bin"},
        variant="baseline",
        features=(),
    )

    command = runner_module._filesystem_isolation_command(
        request,
        request_path=request_path,
        result_path=result_path,
        worker_home=worker_home,
        worker_image="localhost/ymir-harness-worker:c10s",
        cases_mount_source=cases_mount_source,
    )

    volumes = _option_values(command, "--volume")
    env_values = _option_values(command, "--env")
    harness_root = runner_module._harness_root()
    assert command[:4] == ["podman", "run", "--rm", "--pull=never"]
    assert command[command.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert "localhost/ymir-harness-worker:c10s" in command
    assert f"{cases_mount_source}:{cases_dir}:ro" in volumes
    assert f"{cases_dir}:{cases_dir}:ro" not in volumes
    assert f"{results_dir}:{runner_module.WORKER_CONTAINER_RESULTS_DIR}:rw" in volumes
    assert f"{results_dir}:{results_dir}:rw" not in volumes
    assert "GEMINI_API_KEY" in env_values
    assert "prod-gemini-key" not in command
    assert command[-2:] == [
        str(
            runner_module.WORKER_CONTAINER_RESULTS_DIR
            / "repeat-1"
            / "workflow-worker"
            / "RHEL-12345.request.json"
        ),
        str(
            runner_module.WORKER_CONTAINER_RESULTS_DIR
            / "repeat-1"
            / "workflow-worker"
            / "RHEL-12345.result.json"
        ),
    ]
    assert not any(str(harness_root) in volume for volume in volumes)
    assert not any(str(harness_root.parent) in volume for volume in volumes)
    assert "--unshare-pid" not in command


def test_filesystem_isolation_command_mounts_package_manager_shims(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    worker_home = results_dir / "repeat-1" / "workflow-worker" / "home"
    request_path = results_dir / "repeat-1" / "workflow-worker" / "RHEL-12345.request.json"
    result_path = results_dir / "repeat-1" / "workflow-worker" / "RHEL-12345.result.json"
    shim_dir = results_dir / ".ymir-harness-shims-RHEL-12345"
    worker_home.mkdir(parents=True)
    shim_dir.mkdir(parents=True)
    for name in runner_module.PACKAGE_MANAGER_SHIM_NAMES:
        shim = shim_dir / name
        shim.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        shim.chmod(0o755)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")

    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=cases_dir / "expected" / "RHEL-12345.expected.json",
        actual_path=results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment={"YMIR_BENCHMARK_COMMAND_SHIMS": str(shim_dir)},
        variant="baseline",
        features=(),
    )

    command = runner_module._filesystem_isolation_command(
        request,
        request_path=request_path,
        result_path=result_path,
        worker_home=worker_home,
        worker_image="localhost/ymir-harness-worker:c10s",
    )

    volumes = _option_values(command, "--volume")
    for name in runner_module.PACKAGE_MANAGER_SHIM_NAMES:
        assert f"{shim_dir / name}:/usr/bin/{name}:ro" in volumes


def test_container_worker_request_translates_result_paths(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    container_results_dir = runner_module.WORKER_CONTAINER_RESULTS_DIR
    mock_repo_path = results_dir / "repeat-1" / "mock-repos" / "RHEL-12345" / "pkg"
    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=cases_dir / "expected" / "RHEL-12345.expected.json",
        actual_path=results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment={},
        variant="baseline",
        features=(),
    )
    environment = {
        "GIT_CONFIG_GLOBAL": str(results_dir / "repeat-1" / "source-cache-gitconfig"),
        "HOME": str(results_dir / "repeat-1" / "workflow-worker" / "home"),
        "JIRA_MOCK_FILES": str(cases_dir / "jiras"),
        "MOCK_BLOCKED_URLS": "https://example.invalid/repo.git",
        "PATH": f"{results_dir / '.ymir-harness-shims-RHEL-12345'}{os.pathsep}/usr/bin",
        "YMIR_BENCHMARK_ARTIFACT_DIR": str(
            results_dir / "repeat-1" / "artifacts" / "RHEL-12345"
        ),
        "YMIR_BENCHMARK_MOCK_REPOS": json.dumps(
            [
                {
                    "local_path": str(mock_repo_path),
                    "original_url": "https://example.invalid/repo.git",
                }
            ]
        ),
        "YMIR_BENCHMARK_RESULTS_DIR": str(results_dir),
    }

    container_request = runner_module._container_worker_request(
        request,
        environment,
        container_results_dir=container_results_dir,
    )

    assert container_request.cases_dir == cases_dir
    assert container_request.expected_path == request.expected_path
    assert container_request.results_dir == container_results_dir
    assert container_request.actual_path == (
        container_results_dir
        / "repeat-1"
        / "actual-results"
        / "RHEL-12345.actual.json"
    )
    assert container_request.environment["HOME"] == str(
        container_results_dir / "repeat-1" / "workflow-worker" / "home"
    )
    assert container_request.environment["GIT_CONFIG_GLOBAL"] == str(
        container_results_dir / "repeat-1" / "source-cache-gitconfig"
    )
    assert container_request.environment["JIRA_MOCK_FILES"] == str(cases_dir / "jiras")
    assert container_request.environment["MOCK_BLOCKED_URLS"] == (
        "https://example.invalid/repo.git"
    )
    assert container_request.environment["PATH"] == (
        f"{container_results_dir / '.ymir-harness-shims-RHEL-12345'}{os.pathsep}/usr/bin"
    )
    assert container_request.environment["YMIR_BENCHMARK_ARTIFACT_DIR"] == str(
        container_results_dir / "repeat-1" / "artifacts" / "RHEL-12345"
    )
    mock_repos = json.loads(container_request.environment["YMIR_BENCHMARK_MOCK_REPOS"])
    assert mock_repos[0]["local_path"] == str(
        container_results_dir / "repeat-1" / "mock-repos" / "RHEL-12345" / "pkg"
    )
    assert mock_repos[0]["original_url"] == "https://example.invalid/repo.git"
    assert container_request.environment["YMIR_BENCHMARK_RESULTS_DIR"] == str(
        container_results_dir
    )


def test_host_execution_from_container_translates_result_paths(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    container_results_dir = runner_module.WORKER_CONTAINER_RESULTS_DIR
    execution = RunCaseExecution(
        status="passed",
        actual_path=container_results_dir
        / "repeat-1"
        / "actual-results"
        / "RHEL-12345.actual.json",
        actual_result={
            "case_id": "RHEL-12345",
            "generated_artifacts": [
                str(container_results_dir / "repeat-1" / "artifacts" / "RHEL-12345")
            ],
            "external_url": "https://example.invalid/artifact",
        },
    )

    translated = runner_module._host_execution_from_container(
        execution,
        host_results_dir=results_dir,
        container_results_dir=container_results_dir,
    )

    assert translated.actual_path == (
        results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert translated.actual_result == {
        "case_id": "RHEL-12345",
        "generated_artifacts": [
            str(results_dir / "repeat-1" / "artifacts" / "RHEL-12345")
        ],
        "external_url": "https://example.invalid/artifact",
    }


def test_translate_worker_gitconfig_result_paths(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    container_results_dir = runner_module.WORKER_CONTAINER_RESULTS_DIR
    gitconfig_path = results_dir / "repeat-1" / "mock-repos" / "RHEL-12345" / "gitconfig"
    gateway_gitconfig_path = results_dir / ".mock_gitconfig_RHEL-12345"
    gitconfig_path.parent.mkdir(parents=True)
    content = (
        f'[url "file://{results_dir}/repeat-1/mock-repos/RHEL-12345/pkg"]\n'
        "\tinsteadOf = https://example.invalid/pkg.git\n\n"
        f"[include]\n\tpath = {results_dir}/repeat-1/source-cache-gitconfig\n"
    )
    gitconfig_path.write_text(content, encoding="utf-8")
    gateway_gitconfig_path.write_text(content, encoding="utf-8")

    runner_module._translate_worker_gitconfig_result_paths(
        {
            "GIT_CONFIG_GLOBAL": str(gitconfig_path),
            "YMIR_BENCHMARK_GITCONFIG": str(gitconfig_path),
        },
        results_dir,
        container_results_dir,
    )

    expected = (
        f'[url "file://{container_results_dir}/repeat-1/mock-repos/RHEL-12345/pkg"]\n'
        "\tinsteadOf = https://example.invalid/pkg.git\n\n"
        f"[include]\n\tpath = {container_results_dir}/repeat-1/source-cache-gitconfig\n"
    )
    assert gitconfig_path.read_text(encoding="utf-8") == expected
    assert gateway_gitconfig_path.read_text(encoding="utf-8") == expected


def test_materialize_worker_cases_view_excludes_reports_and_other_cases(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    worker_dir = results_dir / "repeat-1" / "workflow-worker"
    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="cve_backport",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=cases_dir / "expected" / "RHEL-12345.expected.json",
        actual_path=results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment={},
        variant="baseline",
        features=(),
    )

    cases_dir.mkdir()
    (cases_dir / "cases.yaml").write_text("cases: []\n", encoding="utf-8")
    _write_expected(cases_dir, "RHEL-12345")
    _write_expected(cases_dir, "RHEL-99999")
    (cases_dir / "jiras" / "RHEL-12345" / "issue.json").parent.mkdir(parents=True)
    (cases_dir / "jiras" / "RHEL-12345" / "issue.json").write_text("{}", encoding="utf-8")
    (cases_dir / "jiras" / "RHEL-99999" / "issue.json").parent.mkdir(parents=True)
    (cases_dir / "jiras" / "RHEL-99999" / "issue.json").write_text("{}", encoding="utf-8")
    (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").parent.mkdir(parents=True)
    (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").write_text(
        "{}",
        encoding="utf-8",
    )
    source_cache = cases_dir / "source_cache" / "RHEL-12345"
    (source_cache / "lookaside").mkdir(parents=True)
    (source_cache / "lookaside" / "redis.tar.gz").write_text("archive\n", encoding="utf-8")
    (source_cache / "upstream" / "redis-fixture.json").parent.mkdir(parents=True)
    (source_cache / "upstream" / "redis-fixture.json").write_text("{}", encoding="utf-8")
    (source_cache / "upstream" / "redis-worktree").mkdir()
    (source_cache / "upstream" / "redis-worktree" / "leaked.txt").write_text(
        "repo worktree\n",
        encoding="utf-8",
    )
    (cases_dir / "mock_data" / "backport").mkdir(parents=True)
    (cases_dir / "mock_data" / "backport" / "RHEL-12345.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (cases_dir / "mock_data" / "backport" / "RHEL-99999.json").write_text(
        "{}",
        encoding="utf-8",
    )
    report_tarball = (
        cases_dir / "reports" / "runs" / "old-run" / "RHEL-12345" / "redis-6.2.22.tar.gz"
    )
    report_tarball.parent.mkdir(parents=True)
    report_tarball.write_text("old report tarball\n", encoding="utf-8")

    view = runner_module._materialize_worker_cases_view(request, worker_dir)

    assert (view / "cases.yaml").is_file()
    assert (view / "expected" / "RHEL-12345.expected.json").is_file()
    assert not (view / "expected" / "RHEL-99999.expected.json").exists()
    assert (view / "jiras" / "RHEL-12345" / "issue.json").is_file()
    assert not (view / "jiras" / "RHEL-99999").exists()
    assert (view / "source_cache" / "RHEL-12345" / "lookaside" / "redis.tar.gz").is_file()
    assert (view / "source_cache" / "RHEL-12345" / "upstream" / "redis-fixture.json").is_file()
    assert not (view / "source_cache" / "RHEL-12345" / "upstream" / "redis-worktree").exists()
    assert (view / "mock_data" / "backport" / "RHEL-12345.json").is_file()
    assert not (view / "mock_data" / "backport" / "RHEL-99999.json").exists()
    assert not (view / "reports").exists()


def test_workflow_container_version_follows_target_branch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    expected_path = cases_dir / "expected" / "RHEL-12345.expected.json"
    _write_json(
        expected_path,
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "target_branch": "rhel-9.8.0",
        },
    )
    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="cve_backport",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=tmp_path / "results",
        expected_path=expected_path,
        actual_path=tmp_path / "results" / "actual.json",
        environment={},
        variant="baseline",
        features=(),
    )

    assert runner_module._workflow_container_version("ymir-backport", request) == "c9s"

    _write_json(
        expected_path,
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "target_branch": "rhel-10.2",
        },
    )

    assert runner_module._workflow_container_version("ymir-backport", request) == "c10s"
    assert runner_module._workflow_container_version("ymir-triage", request) == "c10s"


def test_ensure_worker_container_image_builds_from_local_ymir_submodule(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "harness"
    ymir_context = root / "ai-workflows"
    ymir_context.mkdir(parents=True)
    (ymir_context / "Containerfile.c9s").write_text("FROM scratch\n", encoding="utf-8")
    (root / "Containerfile.ymir-harness-worker").write_text("FROM scratch\n", encoding="utf-8")
    commands = []

    monkeypatch.setattr(runner_module, "_harness_root", lambda: root)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        runner_module, "_run_container_tool", lambda command, _action: commands.append(command)
    )
    monkeypatch.setattr(runner_module, "_BUILT_WORKER_IMAGES", set())

    image = runner_module._ensure_worker_container_image("c9s", {})

    assert image == "localhost/ymir-harness-worker:c9s"
    assert commands == [
        [
            "podman",
            "build",
            "--pull=missing",
            "-t",
            "localhost/ymir-harness-ymir-base:c9s",
            "-f",
            str(ymir_context / "Containerfile.c9s"),
            str(ymir_context),
        ],
        [
            "podman",
            "build",
            "--pull=never",
            "-t",
            "localhost/ymir-harness-worker:c9s",
            "--build-arg",
            "BASE_IMAGE=localhost/ymir-harness-ymir-base:c9s",
            "-f",
            str(root / "Containerfile.ymir-harness-worker"),
            str(root),
        ],
    ]


def test_ensure_worker_container_image_requires_prebuilt_images_for_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "harness"
    ymir_context = root / "ai-workflows"
    ymir_context.mkdir(parents=True)
    (ymir_context / "Containerfile.c10s").write_text("FROM scratch\n", encoding="utf-8")
    (root / "Containerfile.ymir-harness-worker").write_text("FROM scratch\n", encoding="utf-8")
    commands = []

    monkeypatch.setattr(runner_module, "_harness_root", lambda: root)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        runner_module, "_run_container_tool", lambda command, _action: commands.append(command)
    )
    monkeypatch.setattr(runner_module, "_BUILT_WORKER_IMAGES", set())
    monkeypatch.setattr(runner_module, "_container_image_available", lambda _tool, _image: False)
    monkeypatch.setattr(runner_module, "_worker_source_fingerprint", lambda: "abcdef1234567890")

    with pytest.raises(RuntimeError, match="required for replay/offline workflow runs"):
        runner_module._ensure_worker_container_image(
            "c10s",
            {"YMIR_BENCHMARK_NETWORK_MODE": "replay_only"},
        )

    assert commands == []


def test_ensure_worker_container_image_builds_source_image_for_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "harness"
    ymir_context = root / "ai-workflows"
    ymir_context.mkdir(parents=True)
    (ymir_context / "Containerfile.c10s").write_text("FROM scratch\n", encoding="utf-8")
    (root / "Containerfile.ymir-harness-worker").write_text("FROM scratch\n", encoding="utf-8")
    (root / "Containerfile.ymir-harness-source-worker").write_text(
        "FROM scratch\n",
        encoding="utf-8",
    )
    commands = []
    available_images = {"localhost/ymir-harness-worker:c10s"}

    def image_available(_tool: str, image: str) -> bool:
        return image in available_images

    def run_container_tool(command, _action) -> None:
        commands.append(command)
        available_images.add(command[command.index("-t") + 1])

    monkeypatch.setattr(runner_module, "_harness_root", lambda: root)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(runner_module, "_run_container_tool", run_container_tool)
    monkeypatch.setattr(runner_module, "_BUILT_WORKER_IMAGES", set())
    monkeypatch.setattr(runner_module, "_container_image_available", image_available)
    monkeypatch.setattr(runner_module, "_worker_source_fingerprint", lambda: "abcdef1234567890")

    image = runner_module._ensure_worker_container_image(
        "c10s",
        {"YMIR_BENCHMARK_NETWORK_MODE": "network_denied"},
    )

    assert image == "localhost/ymir-harness-worker:c10s-source-abcdef123456"
    assert commands == [
        [
            "podman",
            "build",
            "--pull=never",
            "-t",
            "localhost/ymir-harness-worker:c10s-source-abcdef123456",
            "--build-arg",
            "BASE_IMAGE=localhost/ymir-harness-worker:c10s",
            "-f",
            str(root / "Containerfile.ymir-harness-source-worker"),
            str(root),
        ]
    ]


def test_ensure_worker_container_image_reuses_source_image_for_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "harness"
    ymir_context = root / "ai-workflows"
    ymir_context.mkdir(parents=True)
    (ymir_context / "Containerfile.c10s").write_text("FROM scratch\n", encoding="utf-8")
    (root / "Containerfile.ymir-harness-worker").write_text("FROM scratch\n", encoding="utf-8")
    commands = []

    monkeypatch.setattr(runner_module, "_harness_root", lambda: root)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        runner_module, "_run_container_tool", lambda command, _action: commands.append(command)
    )
    monkeypatch.setattr(runner_module, "_BUILT_WORKER_IMAGES", set())
    monkeypatch.setattr(
        runner_module,
        "_container_image_available",
        lambda _tool, image: image == "localhost/ymir-harness-worker:c10s-source-abcdef123456",
    )
    monkeypatch.setattr(runner_module, "_worker_source_fingerprint", lambda: "abcdef1234567890")

    image = runner_module._ensure_worker_container_image(
        "c10s",
        {"YMIR_BENCHMARK_NETWORK_MODE": "network_denied"},
    )

    assert image == "localhost/ymir-harness-worker:c10s-source-abcdef123456"
    assert commands == []


def test_ensure_worker_container_image_allows_internal_repo_build_for_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "harness"
    ymir_context = root / "ai-workflows"
    ymir_context.mkdir(parents=True)
    (ymir_context / "Containerfile.c9s").write_text("FROM scratch\n", encoding="utf-8")
    (root / "Containerfile.ymir-harness-worker").write_text("FROM scratch\n", encoding="utf-8")
    commands = []

    monkeypatch.setattr(runner_module, "_harness_root", lambda: root)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        runner_module, "_run_container_tool", lambda command, _action: commands.append(command)
    )
    monkeypatch.setattr(runner_module, "_BUILT_WORKER_IMAGES", set())
    monkeypatch.setattr(runner_module, "_container_image_available", lambda _tool, _image: False)

    image = runner_module._ensure_worker_container_image(
        "c9s",
        {
            "YMIR_BENCHMARK_NETWORK_MODE": "replay_only",
            "INTERNAL_REPO_URL_C9S": "https://repo.example/c9s",
        },
    )

    assert image == "localhost/ymir-harness-worker:c9s"
    assert commands[0][:4] == ["podman", "build", "--pull=missing", "-t"]
    assert "--build-arg" in commands[0]
    assert "INTERNAL_REPO_URL=https://repo.example/c9s" in commands[0]


def test_ensure_worker_container_image_allows_debug_override(monkeypatch) -> None:
    commands = []

    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        runner_module, "_run_container_tool", lambda command, _action: commands.append(command)
    )

    image = runner_module._ensure_worker_container_image(
        "c10s",
        {"YMIR_HARNESS_WORKER_IMAGE": "localhost/custom-worker:debug"},
    )

    assert image == "localhost/custom-worker:debug"
    assert commands == []


def test_write_worker_container_artifacts_keeps_debug_state_host_visible(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    worker_dir = results_dir / "repeat-1" / "workflow-worker"
    worker_dir.mkdir(parents=True)
    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=cases_dir / "expected" / "RHEL-12345.expected.json",
        actual_path=results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment={"PATH": "/usr/bin"},
        variant="baseline",
        features=(),
    )
    command = [
        "podman",
        "run",
        "--rm",
        "localhost/ymir-harness-worker:c10s",
        "python",
        "-m",
        "ymir_harness.workflow_worker",
    ]

    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        runner_module,
        "_container_image_metadata",
        lambda _tool, image: {"id": f"id-for-{image}"},
    )
    monkeypatch.setattr(
        runner_module,
        "_git_source_metadata",
        lambda path: {"path": str(path), "head": "abc123", "dirty": False},
    )

    runner_module._write_worker_container_artifacts(
        worker_dir,
        request=request,
        workflow="ymir-triage",
        container_version="c10s",
        worker_image="localhost/ymir-harness-worker:c10s",
        command=command,
    )

    command_payload = json.loads(
        (worker_dir / "RHEL-12345.container-command.json").read_text(encoding="utf-8")
    )
    metadata = json.loads((worker_dir / "RHEL-12345.container.json").read_text(encoding="utf-8"))
    run_script = (worker_dir / "RHEL-12345.container-run.sh").read_text(encoding="utf-8")
    debug_script = (worker_dir / "RHEL-12345.container-debug-shell.sh").read_text(encoding="utf-8")

    assert command_payload["run_command"] == command
    assert command_payload["debug_shell_command"][-2:] == ["bash", "-l"]
    assert metadata["workflow"] == "ymir-triage"
    assert metadata["worker_image"] == "localhost/ymir-harness-worker:c10s"
    assert metadata["worker_image_inspect"] == {"id": "id-for-localhost/ymir-harness-worker:c10s"}
    assert metadata["ymir_source"]["head"] == "abc123"
    assert metadata["run_as_uid"] == os.getuid()
    assert "ymir_harness.workflow_worker" in run_script
    assert "bash \\\n  -l" in debug_script


def _option_values(command: list[str], option: str) -> list[str]:
    return [command[index + 1] for index, item in enumerate(command[:-1]) if item == option]


def test_build_run_report_fails_invalid_structured_jira(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(cases_dir, "RHEL-12345")
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": [],
        },
    )
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
    requests = []

    def executor(request):
        requests.append(request)
        return RunCaseExecution(status="passed")

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    assert requests == []
    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.reason is not None
    assert entry.reason.startswith("Jira mock setup failed: JiraMockMaterializationError:")


def test_build_run_report_passes_replay_policy_environment(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "network_mode": "replay_only",
        },
    )
    _write_web_manifest(
        cases_dir,
        "RHEL-12345",
        ["https://example.invalid/advisory"],
    )
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
    requests = []

    def executor(request):
        requests.append(request)
        return RunCaseExecution(status="passed")

    build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    env = requests[0].environment
    assert env["YMIR_BENCHMARK_NETWORK_MODE"] == "replay_only"
    assert env["YMIR_BENCHMARK_REPLAY_MANIFEST"] == str(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").resolve()
    )
    assert json.loads(env["YMIR_BENCHMARK_RECORDED_URLS"]) == ["https://example.invalid/advisory"]
    assert env["YMIR_BENCHMARK_WEB_CACHE_DIR"] == str(
        (cases_dir / "web_cache" / "RHEL-12345").resolve()
    )
    assert env["YMIR_BENCHMARK_SOURCE_CACHE_DIR"] == str(
        (cases_dir / "source_cache" / "RHEL-12345").resolve()
    )


def test_build_run_report_writes_executor_actual_result(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
        },
    )
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "package": "dnsmasq",
                "resolution": "not_affected",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "passed"
    assert entry.actual_path == (
        results_dir.resolve() / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert json.loads(entry.actual_path.read_text(encoding="utf-8")) == {
        "case_id": "RHEL-12345",
        "package": "dnsmasq",
        "resolution": "not_affected",
    }


def test_build_run_report_scores_executor_actual_result(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
        },
    )
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "package": "dnsmasq",
                "resolution": "not_affected",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "passed"
    assert entry.score is not None
    assert entry.score.passed
    payload = report.to_json()["cases"][0]["score"]
    assert payload["summary"]["passed"] is True
    assert {metric["name"]: metric["status"] for metric in payload["metrics"]}["package"] == "pass"


def test_build_run_report_enforces_event_safety_and_replay(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "network_mode": "replay_only",
        },
    )
    _write_web_manifest(
        cases_dir,
        "RHEL-12345",
        ["https://example.invalid/recorded"],
    )
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "package": "dnsmasq",
                "resolution": "not_affected",
                "events": [
                    {
                        "tool": "http",
                        "method": "GET",
                        "url": "https://example.invalid/unrecorded",
                    },
                    {
                        "tool": "shell",
                        "argv": ["git", "push", "origin", "HEAD"],
                    },
                ],
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.reason == "deterministic score failed"
    assert entry.score is not None
    failed = {metric.name: metric for metric in entry.score.metrics if metric.status == "fail"}
    assert failed["unsafe_operations"].actual == [
        "{'category': 'git_push', 'detail': 'git push: git push origin HEAD', 'source': 'shell'}"
    ]
    assert "replay_violations" not in failed
    actual = json.loads(entry.actual_path.read_text(encoding="utf-8"))
    assert actual["unsafe_operations"] == [
        {
            "category": "git_push",
            "detail": "git push: git push origin HEAD",
            "source": "shell",
        }
    ]
    assert actual["replay_misses"] == ["unrecorded URL: https://example.invalid/unrecorded"]
    assert "replay_violations" not in actual


def test_build_run_report_captures_workflow_output_replay_violations(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "replay_only",
        },
    )
    _write_web_manifest(cases_dir, "RHEL-12345", [])
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(_request):
        print(
            "BenchmarkBoundaryViolation: unrecorded replay URL blocked: "
            "https://example.invalid/missing.patch"
        )
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.reason == "deterministic score failed"
    actual = json.loads(entry.actual_path.read_text(encoding="utf-8"))
    assert actual["replay_violations"] == [
        "unrecorded replay URL blocked: https://example.invalid/missing.patch"
    ]
    assert "missing.patch" in runner_module.workflow_stdout_path(
        results_dir,
        "RHEL-12345",
        1,
    ).read_text(encoding="utf-8")


def test_build_run_report_records_workflow_output_replay_misses_without_failing(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "replay_only",
        },
    )
    _write_web_manifest(cases_dir, "RHEL-12345", [])
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(_request):
        print(
            "replay miss: URL is not recorded in replay cache: "
            "https://example.invalid/missing.patch"
        )
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "passed"
    assert entry.reason is None
    actual = json.loads(entry.actual_path.read_text(encoding="utf-8"))
    assert actual["replay_misses"] == ["replay miss: https://example.invalid/missing.patch"]
    assert "replay_violations" not in actual


def test_build_run_report_records_workflow_output_warnings(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(_request):
        print(
            "ymir-harness warning: dry-run rhpkg no-op for unsupported command: "
            "new-sources source.tar.gz",
            file=sys.stderr,
        )
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    assert report.entries[0].warnings == [
        "dry-run rhpkg no-op for unsupported command: new-sources source.tar.gz"
    ]
    assert report.to_json()["cases"][0]["warnings"] == report.entries[0].warnings


def test_build_run_report_ignores_replay_misses_in_worker_case_view(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "replay_only",
        },
    )
    _write_web_manifest(cases_dir, "RHEL-12345", ["https://example.invalid/recorded.spec"])
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        stale_fixture = (
            request.results_dir
            / f"repeat-{request.repetition}"
            / "workflow-worker"
            / "cases-view"
            / "triage_results"
            / "RHEL-12345.actual.json"
        )
        stale_fixture.parent.mkdir(parents=True)
        stale_fixture.write_text(
            json.dumps(
                {
                    "replay_misses": [
                        "replay miss: URL is not recorded in replay cache: "
                        "https://example.invalid/recorded.spec"
                    ]
                }
            ),
            encoding="utf-8",
        )
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "passed"
    actual = json.loads(entry.actual_path.read_text(encoding="utf-8"))
    assert "replay_misses" not in actual


def test_build_run_report_summarizes_artifact_replay_violations_on_executor_failure(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "replay_only",
        },
    )
    _write_web_manifest(cases_dir, "RHEL-12345", [])
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(_request):
        print(
            "BenchmarkBoundaryViolation: external subprocess URL blocked: "
            "https://gitlab.example/group/pkg.git"
        )
        raise RuntimeError("agent crashed")

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.reason == (
        "executor failed: RuntimeError: agent crashed; replay violations: "
        "external subprocess URL blocked: https://gitlab.example/group/pkg.git"
    )


def test_build_run_report_materializes_local_mock_repos(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "network_denied",
        },
    )
    _write_json(
        cases_dir / "mock_data" / "triage" / "RHEL-12345.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "zstream_override": {"8": "rhel-8.10.z"},
            "repos": [
                {
                    "package": "dnsmasq",
                    "remote_url": str(source_repo),
                    "pre_fix_ref": pre_fix_ref,
                    "branch": "c9s",
                    "branch_aliases": ["rhel-8.10.0"],
                }
            ],
        },
    )
    requests = []
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        requests.append(request)
        repos = json.loads(request.environment["YMIR_BENCHMARK_MOCK_REPOS"])
        local_path = Path(repos[0]["local_path"])
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
                "target_branch": "rhel-8.10.z",
                "generated_artifacts": [str(local_path / "source.c")],
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    env = requests[0].environment
    repos = json.loads(env["YMIR_BENCHMARK_MOCK_REPOS"])
    local_path = Path(repos[0]["local_path"])
    assert report.entries[0].status == "passed"
    assert (local_path / "source.c").read_text(encoding="utf-8") == "pre-fix\n"
    alias_ref = subprocess.check_output(
        ["git", "-C", str(local_path), "rev-parse", "rhel-8.10.0"],
        text=True,
    ).strip()
    assert alias_ref == pre_fix_ref
    assert Path(env["GIT_CONFIG_GLOBAL"]).is_file()
    assert str(source_repo) in Path(env["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8")
    assert env["MOCK_BLOCKED_URLS"] == str(source_repo)
    assert json.loads(env["YMIR_BENCHMARK_ZSTREAM_OVERRIDE"]) == {"8": "rhel-8.10.z"}


def test_build_run_report_clones_mock_repo_source_url(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    original_url = "https://gitlab.example/group/pkg.git"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "network_denied",
        },
    )
    _write_json(
        cases_dir / "mock_data" / "triage" / "RHEL-12345.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "repos": [
                {
                    "package": "dnsmasq",
                    "remote_url": original_url,
                    "source_url": str(source_repo),
                    "pre_fix_ref": pre_fix_ref,
                    "branch": "c9s",
                }
            ],
        },
    )
    requests = []
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        requests.append(request)
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    env = requests[0].environment
    repos = json.loads(env["YMIR_BENCHMARK_MOCK_REPOS"])
    local_path = Path(repos[0]["local_path"])
    gitconfig_text = Path(env["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8")
    gateway_gitconfig = results_dir / ".mock_gitconfig_RHEL-12345"
    assert report.entries[0].status == "passed"
    assert (local_path / "source.c").read_text(encoding="utf-8") == "pre-fix\n"
    branch_ref = subprocess.run(
        ["git", "-C", str(local_path), "rev-parse", "c9s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    assert branch_ref == pre_fix_ref
    assert repos[0]["original_url"] == original_url
    assert original_url in gitconfig_text
    assert original_url.removesuffix(".git") in gitconfig_text
    assert str(source_repo) not in gitconfig_text
    assert gateway_gitconfig.read_text(encoding="utf-8") == gitconfig_text
    assert env["MOCK_BLOCKED_URLS"].splitlines() == [
        original_url,
        original_url.removesuffix(".git"),
    ]


def test_build_run_report_mock_repo_advertises_source_cache_heads(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    _run_git(source_repo, "branch", "rhel-10.0", pre_fix_ref)
    _run_git(source_repo, "branch", "rhel-10.2", fix_ref)
    _run_git(source_repo, "checkout", "rhel-10.0")
    _run_git(source_repo, "branch", "-D", "master")
    original_url = "https://gitlab.com/redhat/rhel/rpms/dnsmasq.git"
    _write_source_fixture(cases_dir, tmp_path, "RHEL-12345", source_repo, original_url)
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "network_denied",
        },
    )
    _write_json(
        cases_dir / "mock_data" / "backport" / "RHEL-12345.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "repos": [
                {
                    "package": "dnsmasq",
                    "remote_url": original_url,
                    "pre_fix_ref": pre_fix_ref,
                    "branch": "rhel-10.0",
                }
            ],
        },
    )
    requests = []
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        requests.append(request)
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    local_path = Path(
        json.loads(requests[0].environment["YMIR_BENCHMARK_MOCK_REPOS"])[0]["local_path"]
    )
    branchless_clone = tmp_path / "branchless-clone"
    subprocess.run(["git", "clone", "--quiet", str(local_path), str(branchless_clone)], check=True)
    subprocess.run(
        ["git", "-C", str(branchless_clone), "cat-file", "-e", f"{fix_ref}^{{commit}}"],
        check=True,
    )
    fixed_text = subprocess.run(
        ["git", "-C", str(branchless_clone), "show", f"{fix_ref}:source.c"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout

    assert report.entries[0].status == "passed"
    assert fixed_text == "fixed\n"


def test_build_run_report_materializes_https_mock_repo_from_source_fixture_manifest(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    original_url = "https://gitlab.com/redhat/centos-stream/rpms/dnsmasq.git"
    _write_source_fixture(cases_dir, tmp_path, "RHEL-12345", source_repo, original_url)
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "network_mode": "network_denied",
        },
    )
    _write_json(
        cases_dir / "mock_data" / "backport" / "RHEL-12345.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "repos": [
                {
                    "package": "dnsmasq",
                    "remote_url": original_url,
                    "pre_fix_ref": pre_fix_ref,
                    "branch": "c9s",
                }
            ],
        },
    )
    requests = []
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        requests.append(request)
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    env = requests[0].environment
    repos = json.loads(env["YMIR_BENCHMARK_MOCK_REPOS"])
    local_path = Path(repos[0]["local_path"])
    source_cache_dir = Path(env["YMIR_BENCHMARK_SOURCE_CACHE_DIR"])
    materialized_repo = source_cache_dir / "upstream" / "dnsmasq-1442c4b3594a.git"
    branch_ref = subprocess.run(
        ["git", "-C", str(local_path), "rev-parse", "c9s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    assert report.entries[0].status == "passed"
    assert (local_path / "source.c").read_text(encoding="utf-8") == "pre-fix\n"
    assert branch_ref == pre_fix_ref
    assert source_cache_dir.is_relative_to(results_dir)
    assert materialized_repo.is_dir()
    assert not (materialized_repo / "objects" / "info" / "alternates").exists()
    subprocess.run(
        ["git", "--git-dir", str(materialized_repo), "cat-file", "-e", f"{pre_fix_ref}^{{commit}}"],
        check=True,
    )
    assert not (cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "dnsmasq.git").exists()


def test_build_run_report_selects_source_fixture_containing_mock_ref(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    fedora_repo, _fedora_ref = _create_git_repo(
        tmp_path,
        name="fedora-repo",
        pre_fix_text="fedora\n",
    )
    centos_repo, pre_fix_ref = _create_git_repo(
        tmp_path,
        name="centos-repo",
        pre_fix_text="centos\n",
    )
    original_url = "https://gitlab.com/redhat/centos-stream/rpms/postgresql-jdbc.git"
    fedora_url = "https://src.fedoraproject.org/rpms/postgresql-jdbc.git"
    _write_source_fixture(cases_dir, tmp_path, "RHEL-12345", fedora_repo, fedora_url)
    _write_source_fixture(cases_dir, tmp_path, "RHEL-12345", centos_repo, original_url)
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "postgresql-jdbc",
            "network_mode": "network_denied",
        },
    )
    _write_json(
        cases_dir / "mock_data" / "backport" / "RHEL-12345.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "repos": [
                {
                    "package": "postgresql-jdbc",
                    "remote_url": original_url,
                    "pre_fix_ref": pre_fix_ref,
                    "branch": "c8s",
                }
            ],
        },
    )
    requests = []
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        requests.append(request)
        repos = json.loads(request.environment["YMIR_BENCHMARK_MOCK_REPOS"])
        local_path = Path(repos[0]["local_path"])
        assert (local_path / "source.c").read_text(encoding="utf-8") == "centos\n"
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "postgresql-jdbc",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    local_path = Path(
        json.loads(requests[0].environment["YMIR_BENCHMARK_MOCK_REPOS"])[0]["local_path"]
    )
    branch_ref = subprocess.run(
        ["git", "-C", str(local_path), "rev-parse", "c8s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    assert report.entries[0].status == "passed"
    assert branch_ref == pre_fix_ref


def test_build_run_report_rewrites_source_cache_git_remotes(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, _pre_fix_ref = _create_git_repo(tmp_path)
    original_url = "https://gitlab.com/redhat/centos-stream/rpms/glib2.git"
    internal_rhel_url = "https://gitlab.com/redhat/rhel/rpms/glib2.git"
    fedora_url = "https://src.fedoraproject.org/rpms/glib2.git"
    _write_source_fixture(cases_dir, tmp_path, "RHEL-12345", source_repo, original_url)
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "glib2",
            "network_mode": "network_denied",
        },
    )
    requests = []
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="valid",
            ),
        ],
    )

    def executor(request):
        requests.append(request)
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "glib2",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    env = requests[0].environment
    gitconfig_text = Path(env["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8")
    gateway_gitconfig = results_dir / ".mock_gitconfig_RHEL-12345"
    blocked_urls = env["MOCK_BLOCKED_URLS"].splitlines()
    assert report.entries[0].status == "passed"
    assert original_url in gitconfig_text
    assert original_url.removesuffix(".git") in gitconfig_text
    assert internal_rhel_url in gitconfig_text
    assert internal_rhel_url.removesuffix(".git") in gitconfig_text
    assert fedora_url in gitconfig_text
    assert fedora_url.removesuffix(".git") in gitconfig_text
    assert gateway_gitconfig.read_text(encoding="utf-8") == gitconfig_text
    assert original_url in blocked_urls
    assert internal_rhel_url in blocked_urls
    assert fedora_url in blocked_urls


def test_source_cache_directory_passes_base_env_to_materialization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "cases"
    results_dir = tmp_path / "results"
    base_env = {"GITLAB_TOKEN_FILE": str(tmp_path / "gitlab-token")}
    captured = []

    def fake_materialize_case_source_cache(
        cases_dir_arg: Path,
        case_id: str,
        destination: Path,
        *,
        git_env=None,
    ) -> Path:
        captured.append((cases_dir_arg, case_id, destination, git_env))
        return destination

    monkeypatch.setattr(
        runner_module,
        "materialize_case_source_cache",
        fake_materialize_case_source_cache,
    )

    source_cache_dir = runner_module._source_cache_directory(
        cases_dir,
        results_dir,
        "RHEL-12345",
        2,
        base_env=base_env,
    )

    assert source_cache_dir == results_dir / "repeat-2" / "source-cache" / "RHEL-12345"
    assert captured == [
        (
            cases_dir,
            "RHEL-12345",
            source_cache_dir,
            base_env,
        )
    ]


def test_source_cache_git_aliases_include_related_forges() -> None:
    distgit_aliases = source_cache_git_aliases(
        "https://gitlab.com/redhat/centos-stream/rpms/qt6-qtdeclarative.git"
    )
    assert "https://gitlab.com/redhat/rhel/rpms/qt6-qtdeclarative.git" in distgit_aliases
    assert "https://gitlab.com/redhat/rhel/rpms/qt6-qtdeclarative" in distgit_aliases
    assert "https://pkgs.devel.redhat.com/git/rpms/qt6-qtdeclarative" in distgit_aliases
    assert "git://pkgs.devel.redhat.com/rpms/qt6-qtdeclarative" in distgit_aliases
    assert "https://pkgs.devel.redhat.com/cgit/rpms/qt6-qtdeclarative" in distgit_aliases

    github_qt_aliases = source_cache_git_aliases("https://github.com/qt/qtdeclarative.git")
    assert "https://code.qt.io/qt/qtdeclarative.git" in github_qt_aliases
    assert "https://code.qt.io/qt/qtdeclarative" in github_qt_aliases

    code_qt_aliases = source_cache_git_aliases("https://code.qt.io/qt/qtdeclarative.git")
    assert "https://github.com/qt/qtdeclarative.git" in code_qt_aliases
    assert "https://github.com/qt/qtdeclarative" in code_qt_aliases


def test_source_cache_git_rewrites_prefer_exact_distgit_fixture(tmp_path: Path) -> None:
    source_cache = tmp_path / "source-cache"
    upstream = source_cache / "upstream"
    upstream.mkdir(parents=True)
    centos_repo = upstream / "00-perl-HTTP-Daemon.git"
    rhel_repo = upstream / "01-perl-HTTP-Daemon.git"
    centos_url = "https://gitlab.com/redhat/centos-stream/rpms/perl-HTTP-Daemon.git"
    rhel_url = "https://gitlab.com/redhat/rhel/rpms/perl-HTTP-Daemon.git"

    for repo, remote_url in ((centos_repo, centos_url), (rhel_repo, rhel_url)):
        subprocess.run(["git", "init", "--bare", str(repo)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(
            ["git", "--git-dir", str(repo), "config", "remote.origin.url", remote_url],
            check=True,
        )

    rewrites = source_cache_git_rewrites(source_cache)
    rewrite_map = dict(rewrites)

    assert len([alias for alias, _local in rewrites if alias == rhel_url]) == 1
    assert len([alias for alias, _local in rewrites if alias == centos_url]) == 1
    assert rewrite_map[rhel_url] == rhel_repo.resolve().as_uri()
    assert rewrite_map[centos_url] == centos_repo.resolve().as_uri()


def test_source_fixture_lookup_prefers_exact_remote_match(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    rhel_url = "https://gitlab.com/redhat/rhel/rpms/dnsmasq.git"
    centos_url = "https://gitlab.com/redhat/centos-stream/rpms/dnsmasq.git"
    for name, remote_url in (("centos", centos_url), ("rhel", rhel_url)):
        mirror = tmp_path / f"{name}-dnsmasq.git"
        subprocess.run(
            ["git", "clone", "--mirror", "--quiet", str(source_repo), str(mirror)],
            check=True,
        )
        write_source_fixture_from_repository(
            cases_dir,
            "RHEL-12345",
            mirror,
            remote_url=remote_url,
            overwrite=True,
        )

    fixture = find_source_fixture_repository(
        cases_dir,
        "RHEL-12345",
        rhel_url,
        obj=pre_fix_ref,
    )
    source_cache_dir = materialize_case_source_cache(
        cases_dir,
        "RHEL-12345",
        tmp_path / "materialized-source-cache",
    )
    repository = find_source_cache_repository(source_cache_dir, rhel_url, obj=pre_fix_ref)

    assert fixture is not None
    assert fixture.remote_url == rhel_url
    assert repository is not None
    remote = subprocess.run(
        ["git", "--git-dir", str(repository), "config", "--get", "remote.origin.url"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    assert remote == rhel_url


def test_build_run_report_marks_cost_cap_overages_timeout(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
        },
    )
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "package": "dnsmasq",
                "resolution": "not_affected",
                "total_cost_usd": 7.25,
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
        base_env={"BENCHMARK_MAX_COST_PER_RUN": "5"},
    )

    assert report.has_failures
    assert report.summary()["timeout"] == 1
    entry = report.entries[0]
    assert entry.status == "timeout"
    assert entry.reason == (
        "budget guardrail exceeded: total_cost_usd 7.25 > BENCHMARK_MAX_COST_PER_RUN 5"
    )
    assert entry.score is not None
    assert entry.score.passed
    assert json.loads(entry.actual_path.read_text(encoding="utf-8"))["total_cost_usd"] == 7.25


def test_build_run_report_warns_on_cost_alert_threshold(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
        },
    )
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "package": "dnsmasq",
                "resolution": "not_affected",
                "total_cost_usd": 7.25,
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
        base_env={
            "BENCHMARK_COST_ALERT_THRESHOLD": "5",
            "BENCHMARK_MAX_COST_PER_RUN": "10",
        },
    )

    assert not report.has_failures
    assert report.summary()["warnings"] == 1
    entry = report.entries[0]
    assert entry.status == "passed"
    assert entry.warnings == [
        "budget alert threshold exceeded: total_cost_usd 7.25 > BENCHMARK_COST_ALERT_THRESHOLD 5"
    ]
    assert report.to_json()["cases"][0]["warnings"] == entry.warnings


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


def test_build_run_report_fails_executor_score_mismatches(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        {
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
        },
    )
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={
                "case_id": "RHEL-12345",
                "package": "libtiff",
                "resolution": "not_affected",
            },
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    assert report.has_failures
    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.reason == "deterministic score failed"
    assert entry.score is not None
    assert not entry.score.passed
    failed = {metric.name: metric for metric in entry.score.metrics if metric.status == "fail"}
    assert failed["package"].actual == "libtiff"


def test_build_run_report_records_actual_result_write_failures(tmp_path: Path) -> None:
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

    def executor(_request):
        return RunCaseExecution(
            status="passed",
            actual_result={"case_id": "RHEL-12345", "unserializable": object()},
        )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    assert report.has_failures
    assert report.summary()["failed"] == 1
    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.actual_path == (
        results_dir.resolve() / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert entry.reason is not None
    assert entry.reason.startswith("actual result write failed: TypeError:")
    assert not entry.actual_path.exists()


def test_build_run_report_records_executor_failures(tmp_path: Path) -> None:
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

    def executor(_request):
        raise RuntimeError("adapter stopped")

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    assert report.has_failures
    assert report.summary()["failed"] == 1
    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.actual_path == (
        results_dir.resolve() / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert entry.reason == "executor failed: RuntimeError: adapter stopped"


def test_build_run_report_records_executor_exception_group_details(tmp_path: Path) -> None:
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

    def executor(_request):
        raise ExceptionGroup("workflow failed", [RuntimeError("inner stopped")])

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
    )

    entry = report.entries[0]
    assert entry.status == "failed"
    assert entry.reason == (
        "executor failed: ExceptionGroup: workflow failed (1 sub-exception) "
        "[RuntimeError: inner stopped]"
    )


def test_build_run_report_records_timeout_exception_groups_as_timeout(tmp_path: Path) -> None:
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

    def executor(_request):
        raise ExceptionGroup("workflow failed", [TimeoutError()])

    executor.ymir_workflow = "ymir-backport"

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
        base_env={"YMIR_HARNESS_AGENT_TIMEOUT_SECONDS": "300"},
    )

    assert report.has_failures
    assert report.summary()["timeout"] == 1
    entry = report.entries[0]
    assert entry.status == "timeout"
    assert entry.reason == "ymir-backport workflow timed out after 300s"


def test_build_run_report_records_chained_timeout_groups_as_timeout(tmp_path: Path) -> None:
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

    def executor(_request):
        raise RuntimeError("framework wrapper") from ExceptionGroup(
            "workflow failed",
            [TimeoutError()],
        )

    executor.ymir_workflow = "ymir-backport"

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
        base_env={"YMIR_HARNESS_AGENT_TIMEOUT_SECONDS": "300"},
    )

    entry = report.entries[0]
    assert entry.status == "timeout"
    assert entry.reason == "ymir-backport workflow timed out after 300s"


def test_build_run_report_records_configured_timeout_cancellations_as_timeout(
    tmp_path: Path,
) -> None:
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

    def executor(_request):
        raise asyncio.CancelledError()

    executor.ymir_workflow = "ymir-backport"

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        executor=executor,
        base_env={"YMIR_HARNESS_AGENT_TIMEOUT_SECONDS": "10"},
    )

    assert report.has_failures
    assert report.summary()["timeout"] == 1
    entry = report.entries[0]
    assert entry.status == "timeout"
    assert entry.reason == "ymir-backport workflow timed out after 10s"


def test_workflow_worker_serializes_timeout_exception_groups(tmp_path: Path, monkeypatch) -> None:
    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=tmp_path / "benchmark_cases",
        results_dir=tmp_path / "results",
        expected_path=tmp_path / "benchmark_cases" / "expected" / "RHEL-12345.expected.json",
        actual_path=tmp_path / "results" / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment={"YMIR_HARNESS_AGENT_TIMEOUT_SECONDS": "42"},
        variant="baseline",
        features=(),
    )
    request_path = tmp_path / "request.json"
    result_path = tmp_path / "result.json"
    request_path.write_text(
        json.dumps(
            {
                "workflow": "ymir-backport",
                "request": runner_module._request_payload(request),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("GEMINI_API_KEY", "prod-gemini-key")
    captured_environment = {}

    def executor(_request):
        captured_environment.update(_request.environment)
        raise ExceptionGroup("workflow failed", [TimeoutError()])

    monkeypatch.setattr(workflow_worker, "_executor_for_workflow", lambda _workflow: executor)

    assert workflow_worker.main([str(request_path), str(result_path)]) == 0
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert captured_environment["GEMINI_API_KEY"] == "prod-gemini-key"
    assert payload == {
        "actual_path": None,
        "actual_result": None,
        "reason": "ymir-backport workflow timed out after 42s",
        "status": "timeout",
    }


def test_workflow_worker_serializes_configured_timeout_cancellations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=tmp_path / "benchmark_cases",
        results_dir=tmp_path / "results",
        expected_path=tmp_path / "benchmark_cases" / "expected" / "RHEL-12345.expected.json",
        actual_path=tmp_path / "results" / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment={"YMIR_HARNESS_AGENT_TIMEOUT_SECONDS": "10"},
        variant="baseline",
        features=(),
    )
    request_path = tmp_path / "request.json"
    result_path = tmp_path / "result.json"
    request_path.write_text(
        json.dumps(
            {
                "workflow": "ymir-backport",
                "request": runner_module._request_payload(request),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def executor(_request):
        raise asyncio.CancelledError()

    monkeypatch.setattr(workflow_worker, "_executor_for_workflow", lambda _workflow: executor)

    assert workflow_worker.main([str(request_path), str(result_path)]) == 0
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert payload["status"] == "timeout"
    assert payload["reason"] == "ymir-backport workflow timed out after 10s"


def _write_expected(cases_dir: Path, case_id: str, data: object | None = None) -> None:
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected_path.parent.mkdir(parents=True, exist_ok=True)
    expected_path.write_text(json.dumps(data or {}) + "\n", encoding="utf-8")


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_structured_jira(cases_dir: Path, case_id: str) -> None:
    _write_json(
        cases_dir / "jiras" / case_id / "issue.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "key": case_id,
            "fields": {"summary": "Backport CVE fix"},
        },
    )
    _write_json(
        cases_dir / "jiras" / case_id / "comments.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "comments": [{"body": "Please backport this fix."}],
        },
    )
    _write_json(
        cases_dir / "jiras" / case_id / "links.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "links": [{"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}],
        },
    )


def _write_web_manifest(cases_dir: Path, case_id: str, required_urls: list[str]) -> None:
    manifest_path = cases_dir / "web_cache" / case_id / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": case_id,
                "case_type": "not_affected",
                "required_urls": required_urls,
                "recorded_files": {url: "recorded.txt" for url in required_urls},
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _create_git_repo(
    tmp_path: Path,
    *,
    name: str = "source-repo",
    pre_fix_text: str = "pre-fix\n",
) -> tuple[Path, str]:
    repo_path = tmp_path / name
    repo_path.mkdir()
    _run_git(repo_path, "init")
    (repo_path / "source.c").write_text(pre_fix_text, encoding="utf-8")
    _run_git(repo_path, "add", "source.c")
    _run_git(repo_path, "commit", "-m", "initial")
    rev = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    (repo_path / "source.c").write_text("fixed\n", encoding="utf-8")
    _run_git(repo_path, "add", "source.c")
    _run_git(repo_path, "commit", "-m", "fixed")
    return repo_path, rev


def _write_source_fixture(
    cases_dir: Path,
    tmp_path: Path,
    case_id: str,
    source_repo: Path,
    remote_url: str,
) -> None:
    mirror = tmp_path / f"{case_id}-{source_repo.name}-source.git"
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(mirror)],
        check=True,
    )
    write_source_fixture_from_repository(
        cases_dir,
        case_id,
        mirror,
        remote_url=remote_url,
        overwrite=True,
    )


def _run_git(repo_path: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "-c",
            "user.name=Ymir Harness Tests",
            "-c",
            "user.email=ymir-harness@example.invalid",
            *args,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
