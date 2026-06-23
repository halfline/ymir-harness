from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path

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
    assert "ANTHROPIC_API_KEY" not in env
    assert "OPENAI_API_TOKEN" not in env
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
            "OPENAI_API_TOKEN": "prod-openai-token",
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
    assert "OPENAI_API_TOKEN" not in env


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
    results_dir.mkdir(parents=True)
    worker_home.mkdir(parents=True)
    monkeypatch.setattr(runner_module.shutil, "which", lambda _name: "/usr/bin/podman")

    request = runner_module.RunCaseRequest(
        case_id="RHEL-12345",
        case_type="not_affected",
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=expected_path,
        actual_path=actual_path,
        environment={"PATH": "/usr/bin"},
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
    harness_root = runner_module._harness_root()
    assert command[:4] == ["podman", "run", "--rm", "--pull=never"]
    assert command[command.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert "localhost/ymir-harness-worker:c10s" in command
    assert f"{cases_dir}:{cases_dir}:ro" in volumes
    assert f"{results_dir}:{results_dir}:rw" in volumes
    assert not any(str(harness_root) in volume for volume in volumes)
    assert not any(str(harness_root.parent) in volume for volume in volumes)
    assert "--unshare-pid" not in command


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


def test_source_cache_git_aliases_include_related_forges() -> None:
    distgit_aliases = source_cache_git_aliases(
        "https://gitlab.com/redhat/centos-stream/rpms/qt6-qtdeclarative.git"
    )
    assert "https://gitlab.com/redhat/rhel/rpms/qt6-qtdeclarative.git" in distgit_aliases
    assert "https://gitlab.com/redhat/rhel/rpms/qt6-qtdeclarative" in distgit_aliases

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

    def executor(_request):
        raise ExceptionGroup("workflow failed", [TimeoutError()])

    monkeypatch.setattr(workflow_worker, "_executor_for_workflow", lambda _workflow: executor)

    assert workflow_worker.main([str(request_path), str(result_path)]) == 0
    payload = json.loads(result_path.read_text(encoding="utf-8"))
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
