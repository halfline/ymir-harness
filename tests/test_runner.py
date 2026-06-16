from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import ymir_harness.runner as runner_module
from ymir_harness.models import CaseValidationResult, ValidationReport
from ymir_harness.runner import (
    DEFAULT_CHAT_MODEL,
    RunCaseExecution,
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


def test_build_run_report_materializes_https_mock_repo_from_source_cache(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    original_url = "https://gitlab.com/redhat/centos-stream/rpms/dnsmasq.git"
    cached_repo = cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "dnsmasq.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            original_url,
        ],
        check=True,
    )
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
    gitconfig_text = Path(env["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8")
    branch_ref = subprocess.run(
        ["git", "-C", str(local_path), "rev-parse", "c9s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    assert report.entries[0].status == "passed"
    assert (local_path / "source.c").read_text(encoding="utf-8") == "pre-fix\n"
    assert branch_ref == pre_fix_ref
    assert f'[url "{local_path.resolve().as_uri()}"]' in gitconfig_text
    assert f'[url "{cached_repo.resolve().as_uri()}"]\n\tinsteadOf = {original_url}' not in (
        gitconfig_text
    )


def test_build_run_report_rewrites_source_cache_git_remotes(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    source_repo, _pre_fix_ref = _create_git_repo(tmp_path)
    cached_repo = cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "glib2.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    original_url = "https://gitlab.com/redhat/centos-stream/rpms/glib2.git"
    fedora_url = "https://src.fedoraproject.org/rpms/glib2.git"
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            original_url,
        ],
        check=True,
    )
    shutil.rmtree(cached_repo / "refs")
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
    assert fedora_url in gitconfig_text
    assert fedora_url.removesuffix(".git") in gitconfig_text
    assert gateway_gitconfig.read_text(encoding="utf-8") == gitconfig_text
    assert original_url in blocked_urls
    assert fedora_url in blocked_urls


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


def _create_git_repo(tmp_path: Path) -> tuple[Path, str]:
    repo_path = tmp_path / "source-repo"
    repo_path.mkdir()
    _run_git(repo_path, "init")
    (repo_path / "source.c").write_text("pre-fix\n", encoding="utf-8")
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
