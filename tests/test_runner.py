from __future__ import annotations

import json
from pathlib import Path

import ymir_harness.runner as runner_module
from ymir_harness.models import CaseValidationResult, ValidationReport
from ymir_harness.runner import (
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
            "GITLAB_TOKEN": "prod-token",
            "JIRA_PASSWORD": "prod-password",
            "KEYTAB_FILE": "/etc/ymir/prod.keytab",
            "KRB5CCNAME": "/tmp/prod-krb5",
            "YMIR_BENCHMARK_CASE_ID": "RHEL-OLD",
        },
    )

    assert env["PATH"] == "/usr/bin"
    assert env["DRY_RUN"] == "true"
    assert env["MOCK_JIRA"] == "true"
    assert env["JIRA_DRY_RUN"] == "true"
    assert env["AUTO_CHAIN"] == "false"
    assert env["SILENT_RUN"] == "true"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "GITLAB_TOKEN" not in env
    assert "JIRA_PASSWORD" not in env
    assert "KEYTAB_FILE" not in env
    assert "KRB5CCNAME" not in env
    assert "YMIR_BENCHMARK_CASE_ID" not in env
    assert env["JIRA_MOCK_FILES"] == str((cases_dir / "jiras").resolve())
    assert env["MOCK_REPOS_DIR"] == str((cases_dir / "mock_data").resolve())
    assert env["YMIR_BENCHMARK_CASES_DIR"] == str(cases_dir.resolve())
    assert env["YMIR_BENCHMARK_RESULTS_DIR"] == str(results_dir.resolve())


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
        phase=1,
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
        phase=1,
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
        phase=1,
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
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        phase=1,
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
    assert requests[0].environment["PATH"] == "/usr/bin"
    assert requests[0].environment["DRY_RUN"] == "true"
    assert requests[0].environment["YMIR_BENCHMARK_CASE_ID"] == "RHEL-12345"
    assert "JIRA_TOKEN" not in requests[0].environment

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
        phase=1,
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
        phase=1,
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
        phase=1,
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
        phase=1,
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
        phase=1,
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


def _write_expected(cases_dir: Path, case_id: str, data: object | None = None) -> None:
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected_path.parent.mkdir(parents=True, exist_ok=True)
    expected_path.write_text(json.dumps(data or {}) + "\n", encoding="utf-8")
