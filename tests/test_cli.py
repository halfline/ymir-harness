from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from ymir_harness import __version__
from ymir_harness.capture_missing import (
    CapturedJiraRequest,
    CapturedResponse,
    CaptureFailure,
    CaptureMissingResult,
)
import ymir_harness.cli as cli_module
from ymir_harness.cli import main
from ymir_harness.collect_case import CollectCaseResult
from ymir_harness.models import CaseValidationResult, RunCaseResult, RunReport, ValidationReport
from ymir_harness.runner import RunCaseExecution
from ymir_harness.source_fixtures import write_source_fixture_from_repository


def test_cli_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"ymir-harness {__version__}\n"


def test_prepare_run_environment_defaults_agent_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(cli_module.AGENT_TIMEOUT_ENV, raising=False)

    environment = cli_module._prepare_run_environment()

    assert (
        environment[cli_module.AGENT_TIMEOUT_ENV]
        == cli_module.DEFAULT_PREPARE_AGENT_TIMEOUT_SECONDS
    )


def test_prepare_run_environment_preserves_configured_agent_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(cli_module.AGENT_TIMEOUT_ENV, "45")

    environment = cli_module._prepare_run_environment()

    assert environment[cli_module.AGENT_TIMEOUT_ENV] == "45"


def test_cli_scores_result_to_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    expected_path = tmp_path / "expected.json"
    actual_path = tmp_path / "actual.json"
    expected_path.write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            }
        ),
        encoding="utf-8",
    )
    actual_path.write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            }
        ),
        encoding="utf-8",
    )

    assert main(["score-result", str(expected_path), str(actual_path)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["passed"] is True


def test_cli_scores_result_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    output_path = tmp_path / "reports" / "results.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "expected_basis": "historical_jira_state",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "replay_only",
            "requires_source_cache": False,
        },
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )

    assert (
        main(
            [
                "score-results",
                str(cases_dir),
                str(actual_dir),
                "--output",
                str(output_path),
                "--run-id",
                "baseline-1",
                "--ymir-sha",
                "6e22912f83d57ddae1031e6207d4716171a99be0",
                "--variant",
                "baseline",
            ]
        )
        == 0
    )

    assert "1 headline passed" in capsys.readouterr().out
    output = json.loads(output_path.read_text(encoding="utf-8"))
    assert output["summary"]["headline_passed"] == 1
    assert output["run_id"] == "baseline-1"
    assert output["ymir_sha"] == "6e22912f83d57ddae1031e6207d4716171a99be0"
    assert output["variant"] == "baseline"


def test_cli_capture_missing_invokes_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    requests = []

    def fake_capture_missing(request):
        requests.append(request)
        return CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )

    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)

    assert (
        main(
            [
                "capture-missing",
                "--cases",
                str(tmp_path / "benchmark_cases"),
                "--from-run",
                str(tmp_path / "reports" / "runs" / "triage"),
                "--case",
                "RHEL-12345",
                "--allow-host",
                "gitlab.example",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["case_id"] == "RHEL-12345"
    assert requests[0].case_id == "RHEL-12345"
    assert "gitlab.example" in requests[0].allowed_hosts


def test_cli_collect_case_writes_fixture_tree(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    issue_json = tmp_path / "inputs" / "issue.json"
    web_record = tmp_path / "inputs" / "advisory.html"
    patch_path = tmp_path / "inputs" / "fix.patch"
    _write_json(
        issue_json,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "key": "RHEL-12345",
        },
    )
    web_record.parent.mkdir(parents=True, exist_ok=True)
    web_record.write_text("cached advisory\n", encoding="utf-8")
    patch_path.write_text("diff --git a/source.c b/source.c\n", encoding="utf-8")

    assert (
        main(
            [
                "collect-case",
                "--cases",
                str(cases_dir),
                "--case-id",
                "RHEL-12345",
                "--case-type",
                "cve_backport",
                "--resolution",
                "backport",
                "--package",
                "dnsmasq",
                "--target-branch",
                "rhel-8.10.z",
                "--expected-basis",
                "merged_mr",
                "--network-mode",
                "replay_only",
                "--patch-url",
                "https://example.invalid/advisory",
                "--web-record",
                f"https://example.invalid/advisory={web_record}",
                "--remote-url",
                "https://example.invalid/dnsmasq.git",
                "--pre-fix-ref",
                "abc123",
                "--branch",
                "c9s",
                "--reference-patch",
                str(patch_path),
                "--reference-patch-mode",
                "scope_only",
                "--jira-issue-json",
                str(issue_json),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["case_id"] == "RHEL-12345"
    assert (cases_dir / "expected" / "RHEL-12345.expected.json").is_file()
    assert (cases_dir / "mock_data" / "triage" / "RHEL-12345.json").is_file()
    assert (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").is_file()


def test_cli_collect_case_fetch_options_leave_network_mode_for_collect(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_requests = []

    def fake_collect_case(request):
        captured_requests.append(request)
        return CollectCaseResult(case_id=request.case_id, cases_dir=request.cases_dir)

    monkeypatch.setattr(cli_module, "collect_case", fake_collect_case)

    assert (
        main(
            [
                "collect-case",
                "--cases",
                str(tmp_path / "benchmark_cases"),
                "--case-id",
                "RHEL-12345",
                "--case-type",
                "cve_backport",
                "--resolution",
                "backport",
                "--package",
                "dnsmasq",
                "--target-branch",
                "rhel-8.10.z",
                "--jira-url",
                "https://issues.example.invalid/browse/RHEL-12345",
                "--jira-token-env",
                "JIRA_API_TOKEN",
                "--gitlab-mr",
                "https://gitlab.example/group/pkg/-/merge_requests/7",
                "--gitlab-token-env",
                "GITLAB_API_TOKEN",
                "--http-timeout",
                "12.5",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["case_id"] == "RHEL-12345"
    request = captured_requests[0]
    assert request.network_mode is None
    assert request.jira_url == "https://issues.example.invalid/browse/RHEL-12345"
    assert request.jira_token_env == "JIRA_API_TOKEN"
    assert request.gitlab_mr_url == "https://gitlab.example/group/pkg/-/merge_requests/7"
    assert request.gitlab_token_env == "GITLAB_API_TOKEN"
    assert request.http_timeout == 12.5


def test_cli_collect_case_allows_jira_derived_metadata(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_requests = []

    def fake_collect_case(request):
        captured_requests.append(request)
        return CollectCaseResult(case_id=request.case_id, cases_dir=request.cases_dir)

    monkeypatch.setattr(cli_module, "collect_case", fake_collect_case)

    assert (
        main(
            [
                "collect-case",
                "--cases",
                str(tmp_path / "benchmark_cases"),
                "--case-id",
                "RHEL-12345",
                "--jira-url",
                "https://issues.example.invalid/browse/RHEL-12345",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["case_id"] == "RHEL-12345"
    request = captured_requests[0]
    assert request.case_type is None
    assert request.resolution is None
    assert request.package is None
    assert request.expected_basis is None
    assert request.network_mode is None


def test_cli_activate_case_promotes_quarantined_case(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_activatable_case(cases_dir)
    run_report = cases_dir / "reports" / "runs" / "passing" / "run.json"
    _write_activation_run_report(run_report, "RHEL-12345", ["passed", "passed"])

    assert (
        main(
            [
                "activate-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--run-report",
                str(run_report),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "activated"
    assert output["run_report_entries"] == 2
    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["case_status"] == "active"
    assert "case_status_reason" not in expected
    validation = json.loads(
        (cases_dir / "reports" / "fixture-validation.json").read_text(encoding="utf-8")
    )
    assert validation["summary"]["invalid"] == 0


def test_cli_activate_case_refuses_non_passing_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_activatable_case(cases_dir)
    run_report = cases_dir / "reports" / "runs" / "failed" / "run.json"
    _write_activation_run_report(run_report, "RHEL-12345", ["passed", "failed"])

    assert (
        main(
            [
                "activate-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--run-report",
                str(run_report),
            ]
        )
        == 1
    )

    output = capsys.readouterr()
    assert "non-passing entries" in output.err
    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["case_status"] == "quarantined"
    assert expected["case_status_reason"] == "fixture scaffold prepared for replay experiments"


def test_cli_activate_case_refuses_non_replay_only_case(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_activatable_case(cases_dir, network_mode="network_denied")
    run_report = cases_dir / "reports" / "runs" / "passing" / "run.json"
    _write_activation_run_report(run_report, "RHEL-12345", ["passed"])

    assert (
        main(
            [
                "activate-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--run-report",
                str(run_report),
            ]
        )
        == 1
    )

    assert "network_mode must be 'replay_only'" in capsys.readouterr().err


def test_cli_prepare_case_can_activate_on_pass(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_activatable_case(cases_dir)

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="not_affected",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--activate-on-pass",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["activation"]["status"] == "activated"
    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["case_status"] == "active"
    assert "case_status_reason" not in expected


def test_cli_run_writes_placeholder_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "expected_basis": "maintainer_decision",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
            "requires_source_cache": False,
        },
    )
    _write_json(
        cases_dir / "expected" / "RHEL-23456.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-23456",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "libtiff",
            "expected_basis": "maintainer_decision",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
            "requires_source_cache": False,
        },
    )

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--run-id",
                "baseline-1",
                "--ymir-sha",
                "6e22912f83d57ddae1031e6207d4716171a99be0",
                "--feature",
                "YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK",
                "--case",
                "RHEL-23456",
                "--repeat",
                "3",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert output == written
    assert output["run_id"] == "baseline-1"
    assert output["variant"] == "baseline"
    assert output["ymir_sha"] == "6e22912f83d57ddae1031e6207d4716171a99be0"
    assert output["harness_version"] == __version__
    assert output["features"] == ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"]
    assert output["repeat"] == 3
    assert output["fixture_checksum"].startswith("sha256:")
    assert output["summary"]["not_run"] == 3
    assert [case["repetition"] for case in output["cases"]] == [1, 2, 3]
    assert [case["actual_path"] for case in output["cases"]] == [
        str(
            (
                cases_dir
                / "reports"
                / "runs"
                / "baseline-1"
                / f"repeat-{repetition}"
                / "actual-results"
                / "RHEL-23456.actual.json"
            ).resolve()
        )
        for repetition in (1, 2, 3)
    ]
    assert {case["case_id"] for case in output["cases"]} == {"RHEL-23456"}
    assert {case["status"] for case in output["cases"]} == {"not_run"}
    assert {case["reason"] for case in output["cases"]} == {"workflow adapters are not wired yet"}
    assert (cases_dir / "reports" / "fixture-validation.json").is_file()


def test_cli_run_uses_cases_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    for case_id, package in (("RHEL-12345", "dnsmasq"), ("RHEL-23456", "libtiff")):
        _write_json(
            cases_dir / "expected" / f"{case_id}.expected.json",
            {
                "schema_version": 1,
                "case_id": case_id,
                "case_type": "not_affected",
                "resolution": "not_affected",
                "package": package,
                "expected_basis": "maintainer_decision",
                "ground_truth_confidence": "high",
                "answer_leakage": "none",
                "case_status": "active",
                "network_mode": "network_denied",
            },
        )
    (cases_dir / "cases.yaml").write_text("cases:\n  - RHEL-23456\n", encoding="utf-8")

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert [case["case_id"] for case in output["cases"]] == ["RHEL-23456"]


def test_cli_run_can_use_ymir_triage_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "expected_basis": "maintainer_decision",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
        },
    )
    requests = []

    def make_executor():
        def executor(request):
            requests.append(request)
            return RunCaseExecution(
                status="passed",
                actual_result={
                    "case_id": "RHEL-12345",
                    "case_type": "not_affected",
                    "resolution": "not_affected",
                    "package": "dnsmasq",
                },
            )

        return executor

    monkeypatch.setattr(cli_module, "make_ymir_triage_executor", make_executor)

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--workflow",
                "ymir-triage",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert len(requests) == 1
    assert requests[0].case_id == "RHEL-12345"
    assert output["summary"]["passed"] == 1
    assert output["cases"][0]["status"] == "passed"
    assert output["cases"][0]["score"]["summary"]["passed"] is True
    assert Path(output["cases"][0]["actual_path"]).is_file()


def test_cli_run_prints_concise_metrics_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "expected_basis": "maintainer_decision",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
        },
    )

    def make_executor():
        def executor(_request):
            return RunCaseExecution(
                status="passed",
                actual_result={
                    "case_id": "RHEL-12345",
                    "case_type": "not_affected",
                    "resolution": "not_affected",
                    "package": "dnsmasq",
                    "token_usage": {"input_tokens": 1200, "output_tokens": 300},
                    "tool_call_count": 8,
                    "total_cost_usd": 4.25,
                },
            )

        return executor

    monkeypatch.setattr(cli_module, "make_ymir_triage_executor", make_executor)

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--workflow",
                "ymir-triage",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert (
        "benchmark run: 1 passed, 0 failed, 0 timeout, 0 not run, 0 skipped, 0 unsupported"
        in output
    )
    assert "metrics: runtime " in output
    assert "tokens 1500 avg" in output
    assert "tool calls 8 avg" in output
    assert "cost $4.25 total / $4.25 avg" in output


def test_cli_run_uses_strict_validation_for_selected_triage_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "expected_basis": "historical_jira_state",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
            "requires_source_cache": True,
        },
    )
    requests = []

    def make_executor():
        def executor(request):
            requests.append(request)
            return RunCaseExecution(
                status="passed",
                actual_result={
                    "case_id": "RHEL-12345",
                    "case_type": "cve_backport",
                    "resolution": "backport",
                    "package": "dnsmasq",
                    "target_branch": "rhel-8.10.z",
                },
            )

        return executor

    monkeypatch.setattr(cli_module, "make_ymir_triage_executor", make_executor)

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--workflow",
                "ymir-triage",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert len(requests) == 1
    assert output["summary"]["passed"] == 1
    validation = json.loads(
        (cases_dir / "reports" / "fixture-validation.json").read_text(encoding="utf-8")
    )
    assert validation["summary"]["invalid"] == 0
    assert not any(
        issue["category"] == "source_cache_incomplete"
        for case in validation["cases"]
        for issue in case["issues"]
    )


def test_cli_run_can_use_ymir_backport_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "patch_urls": ["https://example.invalid/fix.patch"],
            "expected_basis": "historical_jira_state",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "replay_only",
            "requires_source_cache": False,
        },
    )
    _write_json(
        cases_dir / "web_cache" / "RHEL-12345" / "manifest.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "required_urls": ["https://example.invalid/fix.patch"],
            "recorded_files": {
                "https://example.invalid/fix.patch": "commits/fix.patch",
            },
        },
    )
    (cases_dir / "web_cache" / "RHEL-12345" / "commits").mkdir(parents=True)
    (cases_dir / "web_cache" / "RHEL-12345" / "commits" / "fix.patch").write_text(
        "diff --git a/file b/file\n",
        encoding="utf-8",
    )
    requests = []

    def make_executor():
        def executor(request):
            requests.append(request)
            return RunCaseExecution(
                status="passed",
                actual_result={
                    "case_id": "RHEL-12345",
                    "case_type": "cve_backport",
                    "resolution": "backport",
                    "package": "dnsmasq",
                    "target_branch": "rhel-8.10.z",
                    "patch_urls": ["https://example.invalid/fix.patch"],
                },
            )

        return executor

    monkeypatch.setattr(cli_module, "make_ymir_backport_executor", make_executor)

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--workflow",
                "ymir-backport",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert len(requests) == 1
    assert requests[0].case_id == "RHEL-12345"
    assert output["summary"]["passed"] == 1
    assert output["cases"][0]["status"] == "passed"
    assert output["cases"][0]["score"]["summary"]["passed"] is True
    assert Path(output["cases"][0]["actual_path"]).is_file()


def test_cli_run_can_use_ymir_rebase_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "rebase",
            "resolution": "rebase",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "version": "2.91",
            "expected_basis": "maintainer_decision",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
            "requires_source_cache": False,
        },
    )
    requests = []

    def make_executor():
        def executor(request):
            requests.append(request)
            return RunCaseExecution(
                status="passed",
                actual_result={
                    "case_id": "RHEL-12345",
                    "case_type": "rebase",
                    "resolution": "rebase",
                    "package": "dnsmasq",
                    "target_branch": "rhel-8.10.z",
                    "version": "2.91",
                },
            )

        return executor

    monkeypatch.setattr(cli_module, "make_ymir_rebase_executor", make_executor)

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--workflow",
                "ymir-rebase",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert len(requests) == 1
    assert requests[0].case_id == "RHEL-12345"
    assert output["summary"]["passed"] == 1
    assert output["cases"][0]["status"] == "passed"
    assert output["cases"][0]["score"]["summary"]["passed"] is True
    assert Path(output["cases"][0]["actual_path"]).is_file()


def test_cli_run_can_use_ymir_rebuild_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "dependency_rebuild",
            "resolution": "rebuild",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "build_result": "passed",
            "dependency_issues": ["RHEL-23456"],
            "expected_basis": "build_result",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
            "requires_source_cache": False,
        },
    )
    requests = []

    def make_executor():
        def executor(request):
            requests.append(request)
            return RunCaseExecution(
                status="passed",
                actual_result={
                    "case_id": "RHEL-12345",
                    "case_type": "dependency_rebuild",
                    "resolution": "rebuild",
                    "package": "dnsmasq",
                    "target_branch": "rhel-8.10.z",
                    "build_result": "passed",
                    "dependency_issues": ["RHEL-23456"],
                },
            )

        return executor

    monkeypatch.setattr(cli_module, "make_ymir_rebuild_executor", make_executor)

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--workflow",
                "ymir-rebuild",
                "--output",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert len(requests) == 1
    assert requests[0].case_id == "RHEL-12345"
    assert output["summary"]["passed"] == 1
    assert output["cases"][0]["status"] == "passed"
    assert output["cases"][0]["score"]["summary"]["passed"] is True
    assert Path(output["cases"][0]["actual_path"]).is_file()


def test_cli_prepare_case_collects_until_run_succeeds(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    collect_requests = []
    capture_requests = []
    run_ids = []
    run_statuses = ["failed", "passed"]

    def fake_collect_case(request):
        collect_requests.append(request)
        return CollectCaseResult(case_id=request.case_id, cases_dir=request.cases_dir)

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    case_status="active",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        status = run_statuses.pop(0)
        run_ids.append(kwargs["run_id"])
        assert (
            kwargs["base_env"][cli_module.AGENT_TIMEOUT_ENV]
            == cli_module.DEFAULT_PREPARE_AGENT_TIMEOUT_SECONDS
        )
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    status=status,
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    def fake_capture_missing(request):
        capture_requests.append(request)
        result = CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )
        if len(capture_requests) == 1:
            result.captured_jira.append(
                CapturedJiraRequest(
                    kind="jira_search",
                    method="POST",
                    url="https://redhat.atlassian.net/rest/api/2/search",
                    relative_path="api/search/abc.json",
                )
            )
        return result

    monkeypatch.setattr(cli_module, "collect_case", fake_collect_case)
    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--jira-url",
                "https://redhat.atlassian.net/browse/RHEL-12345",
                "--jira-token-file",
                str(tmp_path / "jira-token.txt"),
                "--gitlab-token-env",
                "GITLAB_API_TOKEN",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["collected"]["case_id"] == "RHEL-12345"
    assert [iteration["run"]["run_id"] for iteration in output["iterations"]] == [
        "baseline-RHEL-12345-iter-1",
        "baseline-RHEL-12345-iter-2",
    ]
    assert run_ids == ["baseline-RHEL-12345-iter-1", "baseline-RHEL-12345-iter-2"]
    assert len(capture_requests) == 1
    assert capture_requests[0].case_id == "RHEL-12345"
    assert collect_requests[0].jira_url == "https://redhat.atlassian.net/browse/RHEL-12345"
    assert collect_requests[0].mock_agent == "triage"
    assert collect_requests[0].gitlab_token_env == "GITLAB_API_TOKEN"


def test_cli_prepare_backport_runs_triage_when_result_is_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_root = tmp_path / "cases"
    triage_cases_dir = cases_root / "ymir-triage"
    backport_cases_dir = cases_root / "ymir-backport"
    case_id = "RHEL-12345"
    triage_actual = {
        "schema_version": 1,
        "case_id": case_id,
        "case_type": "cve_backport",
        "workflow": "ymir-triage",
        "resolution": "backport",
        "data": {
            "package": "dnsmasq",
            "target_branch": "rhel-9.8.0",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    }
    for cases_dir in (triage_cases_dir, backport_cases_dir):
        _write_json(
            cases_dir / "expected" / f"{case_id}.expected.json",
            {
                "schema_version": 1,
                "case_id": case_id,
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
                "target_branch": "rhel-9.8.0",
                "patch_urls": ["https://example.invalid/fix.patch"],
                "case_status": "quarantined",
                "network_mode": "replay_only",
            },
        )
        _write_json(
            cases_dir / "web_cache" / case_id / "manifest.json",
            {
                "schema_version": 1,
                "case_id": case_id,
                "case_type": "cve_backport",
                "required_urls": [],
                "recorded_files": {},
            },
        )

    build_calls: list[tuple[str, str]] = []

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    case_status="quarantined",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        cases_name = Path(cases_dir_arg).name
        build_calls.append((cases_name, kwargs["run_id"]))
        if cases_name == "ymir-triage":
            actual_path = results_dir / "repeat-1" / "actual-results" / f"{case_id}.actual.json"
            _write_json(actual_path, triage_actual)
            return RunReport(
                cases_dir=cases_dir_arg,
                results_dir=results_dir,
                entries=[
                    RunCaseResult(
                        case_id=case_id,
                        case_type="cve_backport",
                        status="passed",
                        actual_path=actual_path,
                    )
                ],
                run_id=kwargs["run_id"],
                variant=kwargs["variant"],
            )

        triage_result_path = (
            backport_cases_dir / "triage_results" / f"{case_id}.actual.json"
        )
        assert json.loads(triage_result_path.read_text(encoding="utf-8")) == triage_actual
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "_prepare_complete_existing_case", lambda _args: None)
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(backport_cases_dir),
                "--case",
                case_id,
                "--workflow",
                "ymir-backport",
                "--variant",
                "baseline",
                "--activate-on-pass",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["triage_result"]["status"] == "generated"
    assert output["triage_result"]["activation"]["status"] == "activated"
    assert output["activation"]["status"] == "activated"
    assert Path(output["triage_result"]["written_path"]).is_file()
    triage_expected = json.loads(
        (triage_cases_dir / "expected" / f"{case_id}.expected.json").read_text(encoding="utf-8")
    )
    backport_expected = json.loads(
        (backport_cases_dir / "expected" / f"{case_id}.expected.json").read_text(encoding="utf-8")
    )
    assert triage_expected["case_status"] == "active"
    assert backport_expected["case_status"] == "active"
    assert build_calls == [
        ("ymir-triage", "baseline-RHEL-12345-iter-1"),
        ("ymir-backport", "baseline-RHEL-12345-iter-1"),
    ]


def test_cli_prepare_backport_does_not_recollect_existing_triage_fixture(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_root = tmp_path / "cases"
    triage_cases_dir = cases_root / "ymir-triage"
    backport_cases_dir = cases_root / "ymir-backport"
    case_id = "RHEL-12345"
    jira_url = "https://redhat.atlassian.net/browse/RHEL-12345"
    triage_actual = {
        "schema_version": 1,
        "case_id": case_id,
        "case_type": "cve_backport",
        "workflow": "ymir-triage",
        "resolution": "backport",
        "data": {
            "package": "dnsmasq",
            "target_branch": "rhel-9.8.0",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    }
    _write_json(
        triage_cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-9.8.0",
            "patch_urls": ["https://example.invalid/fix.patch"],
            "case_status": "quarantined",
            "network_mode": "replay_only",
        },
    )
    _write_json(
        triage_cases_dir / "web_cache" / case_id / "manifest.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "required_urls": [],
            "recorded_files": {},
        },
    )
    collect_requests: list[tuple[str, str | None]] = []
    build_calls: list[tuple[str, str]] = []

    def fake_collect_case(request):
        collect_requests.append((Path(request.cases_dir).name, request.jira_url))
        return CollectCaseResult(case_id=request.case_id, cases_dir=request.cases_dir)

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    case_status="quarantined",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        cases_name = Path(cases_dir_arg).name
        build_calls.append((cases_name, kwargs["run_id"]))
        if cases_name == "ymir-triage":
            actual_path = results_dir / "repeat-1" / "actual-results" / f"{case_id}.actual.json"
            _write_json(actual_path, triage_actual)
            return RunReport(
                cases_dir=cases_dir_arg,
                results_dir=results_dir,
                entries=[
                    RunCaseResult(
                        case_id=case_id,
                        case_type="cve_backport",
                        status="passed",
                        actual_path=actual_path,
                    )
                ],
                run_id=kwargs["run_id"],
                variant=kwargs["variant"],
            )

        triage_result_path = backport_cases_dir / "triage_results" / f"{case_id}.actual.json"
        assert json.loads(triage_result_path.read_text(encoding="utf-8")) == triage_actual
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    monkeypatch.setattr(cli_module, "collect_case", fake_collect_case)
    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "_prepare_complete_existing_case", lambda _args: None)
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(backport_cases_dir),
                "--case",
                case_id,
                "--workflow",
                "ymir-backport",
                "--jira-url",
                jira_url,
                "--variant",
                "baseline",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["triage_result"]["status"] == "generated"
    assert collect_requests == [("ymir-backport", jira_url)]
    assert build_calls == [
        ("ymir-triage", "baseline-RHEL-12345-iter-1"),
        ("ymir-backport", "baseline-RHEL-12345-iter-1"),
    ]


def test_prepare_backport_triage_args_preserve_collect_inputs_with_overwrite(
    tmp_path: Path,
) -> None:
    cases_root = tmp_path / "cases"
    triage_cases_dir = cases_root / "ymir-triage"
    backport_cases_dir = cases_root / "ymir-backport"
    case_id = "RHEL-12345"
    _write_json(
        triage_cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "resolution": "backport",
        },
    )
    args = argparse.Namespace(
        cases=backport_cases_dir,
        case_id=case_id,
        jira_url="https://redhat.atlassian.net/browse/RHEL-12345",
        jira_base_url=None,
        gitlab_mr_url="https://gitlab.example/group/pkg/-/merge_requests/1",
        overwrite=True,
        run_id="prepare-RHEL-12345",
    )

    triage_args = cli_module._prepare_backport_triage_args(args, triage_cases_dir)

    assert triage_args.jira_url == args.jira_url
    assert triage_args.gitlab_mr_url == args.gitlab_mr_url
    assert triage_args.run_id == "prepare-RHEL-12345-triage"


def test_cli_prepare_backport_uses_existing_triage_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "cases" / "ymir-backport"
    case_id = "RHEL-12345"
    cached_triage_result = {
        "schema_version": 1,
        "case_id": case_id,
        "case_type": "cve_backport",
        "workflow": "ymir-triage",
        "resolution": "backport",
        "data": {
            "package": "dnsmasq",
            "target_branch": "rhel-9.8.0",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    }
    _write_json(
        cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-9.8.0",
            "patch_urls": ["https://example.invalid/fix.patch"],
            "case_status": "quarantined",
            "network_mode": "replay_only",
        },
    )
    _write_json(
        cases_dir / "triage_results" / f"{case_id}.actual.json",
        cached_triage_result,
    )
    _write_json(
        cases_dir / "web_cache" / case_id / "manifest.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "required_urls": [],
            "recorded_files": {},
        },
    )
    build_calls: list[tuple[str, str]] = []

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    case_status="quarantined",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        build_calls.append((Path(cases_dir_arg).name, kwargs["run_id"]))
        triage_result_path = cases_dir / "triage_results" / f"{case_id}.actual.json"
        assert json.loads(triage_result_path.read_text(encoding="utf-8")) == cached_triage_result
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "_prepare_complete_existing_case", lambda _args: None)
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                case_id,
                "--workflow",
                "ymir-backport",
                "--variant",
                "baseline",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["triage_result"] == {
        "case_id": case_id,
        "path": str(cases_dir / "triage_results" / f"{case_id}.actual.json"),
        "status": "cached",
    }
    assert build_calls == [("ymir-backport", "baseline-RHEL-12345-iter-1")]


def test_cli_prepare_backport_activation_promotes_cached_sibling_triage(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_root = tmp_path / "cases"
    triage_cases_dir = cases_root / "ymir-triage"
    backport_cases_dir = cases_root / "ymir-backport"
    case_id = "RHEL-12345"
    cached_triage_result = {
        "schema_version": 1,
        "case_id": case_id,
        "case_type": "cve_backport",
        "workflow": "ymir-triage",
        "resolution": "backport",
        "data": {
            "package": "dnsmasq",
            "target_branch": "rhel-9.8.0",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    }
    for cases_dir in (triage_cases_dir, backport_cases_dir):
        _write_json(
            cases_dir / "expected" / f"{case_id}.expected.json",
            {
                "schema_version": 1,
                "case_id": case_id,
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
                "target_branch": "rhel-9.8.0",
                "patch_urls": ["https://example.invalid/fix.patch"],
                "case_status": "quarantined",
                "network_mode": "replay_only",
            },
        )
    _write_json(
        backport_cases_dir / "triage_results" / f"{case_id}.actual.json",
        cached_triage_result,
    )
    _write_activation_run_report(
        triage_cases_dir / "reports" / "runs" / "passing-triage" / "run.json",
        case_id,
        ["passed"],
    )

    build_calls: list[tuple[str, str]] = []

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    case_status="quarantined",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        build_calls.append((Path(cases_dir_arg).name, kwargs["run_id"]))
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id=case_id,
                    case_type="cve_backport",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "_prepare_complete_existing_case", lambda _args: None)
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(backport_cases_dir),
                "--case",
                case_id,
                "--workflow",
                "ymir-backport",
                "--variant",
                "baseline",
                "--activate-on-pass",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["triage_result"]["status"] == "cached"
    assert output["triage_result"]["activation"]["status"] == "activated"
    assert output["activation"]["status"] == "activated"
    triage_expected = json.loads(
        (triage_cases_dir / "expected" / f"{case_id}.expected.json").read_text(encoding="utf-8")
    )
    backport_expected = json.loads(
        (backport_cases_dir / "expected" / f"{case_id}.expected.json").read_text(encoding="utf-8")
    )
    assert triage_expected["case_status"] == "active"
    assert backport_expected["case_status"] == "active"
    assert build_calls == [("ymir-backport", "baseline-RHEL-12345-iter-1")]


def test_cli_prepare_case_writes_existing_triage_mock_data(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    remote_url = "https://gitlab.com/redhat/centos-stream/rpms/dnsmasq.git"
    _write_json(
        cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "not_affected",
            "case_status": "quarantined",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "fix_version": "rhel-9.8",
            "network_mode": "replay_only",
        },
    )

    source_repo = tmp_path / "source"
    subprocess.run(["git", "init", str(source_repo)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(source_repo), "checkout", "-b", "c9s"], check=True)
    (source_repo / "dnsmasq.spec").write_text("Name: dnsmasq\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source_repo), "add", "dnsmasq.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    pre_fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c9s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    _write_source_fixture(cases_dir, tmp_path, case_id, source_repo, remote_url)

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id=case_id,
                    case_type="not_affected",
                    case_status="quarantined",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        mock_path = cases_dir / "mock_data" / "triage" / f"{case_id}.json"
        mock_data = json.loads(mock_path.read_text(encoding="utf-8"))
        assert mock_data == {
            "case_id": case_id,
            "case_type": "not_affected",
            "repos": [
                {
                    "branch": "c9s",
                    "package": "dnsmasq",
                    "pre_fix_ref": pre_fix_ref,
                    "remote_url": remote_url,
                }
            ],
            "schema_version": 1,
            "zstream_override": {"9": "rhel-9.8"},
        }
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id=case_id,
                    case_type="not_affected",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    monkeypatch.setattr(cli_module, "collect_case", lambda _request: pytest.fail())
    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "_prepare_has_replay_candidates", lambda *_args: False)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                case_id,
                "--workflow",
                "ymir-triage",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    mock_path = cases_dir / "mock_data" / "triage" / f"{case_id}.json"
    assert output["status"] == "succeeded"
    assert output["collected"]["written_paths"] == [str(mock_path)]


def test_cli_prepare_case_infers_mock_data_from_matching_source_branch(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    remote_url = "https://gitlab.com/redhat/centos-stream/rpms/postgresql-jdbc.git"
    fedora_url = "https://src.fedoraproject.org/rpms/postgresql-jdbc.git"

    def create_source_repo(name: str, branch: str, spec_text: str) -> tuple[Path, str]:
        repo = tmp_path / name
        repo.mkdir()
        subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(repo), "checkout", "-b", branch], check=True)
        (repo / "postgresql-jdbc.spec").write_text(spec_text, encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "postgresql-jdbc.spec"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Test User",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "seed",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        ref = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", branch],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        return repo, ref

    fedora_repo, _fedora_ref = create_source_repo(
        "fedora-source",
        "rawhide",
        "Name: postgresql-jdbc\n",
    )
    centos_repo, pre_fix_ref = create_source_repo(
        "centos-source",
        "c8s",
        "Name: postgresql-jdbc\nRelease: 1.el8\n",
    )
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    _write_source_fixture(cases_dir, tmp_path, case_id, fedora_repo, fedora_url)
    _write_source_fixture(cases_dir, tmp_path, case_id, centos_repo, remote_url)

    warnings: list[str] = []
    written_paths: list[Path] = []
    cli_module._prepare_write_inferred_mock_data(
        argparse.Namespace(
            cases=cases_dir,
            case_id=case_id,
            workflow="ymir-triage",
            overwrite=True,
        ),
        {
            "case_id": case_id,
            "case_type": "not_affected",
            "fix_version": "rhel-8.10.z",
            "package": "postgresql-jdbc",
        },
        written_paths,
        warnings,
    )

    mock_path = cases_dir / "mock_data" / "triage" / f"{case_id}.json"
    mock_data = json.loads(mock_path.read_text(encoding="utf-8"))
    assert warnings == []
    assert written_paths == [mock_path]
    assert mock_data["repos"][0] == {
        "branch": "c8s",
        "package": "postgresql-jdbc",
        "pre_fix_ref": pre_fix_ref,
        "remote_url": remote_url,
    }


def test_cli_prepare_case_infers_backport_mock_branch_from_triage_result(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    source_remote_url = "https://gitlab.com/redhat/centos-stream/rpms/qt6-qtdeclarative.git"
    replay_remote_url = "https://gitlab.com/redhat/rhel/rpms/qt6-qtdeclarative.git"

    source_repo = tmp_path / "centos-source"
    source_repo.mkdir()
    subprocess.run(["git", "init", str(source_repo)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(source_repo), "checkout", "-b", "c10s"], check=True)
    (source_repo / "qt6-qtdeclarative.spec").write_text(
        "Name: qt6-qtdeclarative\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "qt6-qtdeclarative.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    pre_fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c10s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    (source_repo / "qt6-qtdeclarative.spec").write_text(
        "Name: qt6-qtdeclarative\nPatch1: fix.patch\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "qt6-qtdeclarative.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fix",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c10s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    _write_source_fixture(cases_dir, tmp_path, case_id, source_repo, source_remote_url)
    _write_json(
        cases_dir / "triage_results" / f"{case_id}.actual.json",
        {
            "case_id": case_id,
            "data": {
                "package": "qt6-qtdeclarative",
            },
            "resolution": "backport",
            "target_branch": "rhel-10.2",
        },
    )
    _write_json(
        cases_dir
        / "web_cache"
        / case_id
        / "gitlab"
        / "internal_rhel"
        / "qt6-qtdeclarative"
        / "branches.json",
        [
            {
                "commit": {
                    "id": fix_ref,
                    "parent_ids": [pre_fix_ref],
                },
                "name": "rhel-10.2",
            }
        ],
    )

    warnings: list[str] = []
    written_paths: list[Path] = []
    cli_module._prepare_write_inferred_mock_data(
        argparse.Namespace(
            cases=cases_dir,
            case_id=case_id,
            workflow="ymir-backport",
            overwrite=True,
        ),
        {
            "case_id": case_id,
            "case_type": "cve_backport",
            "package": "qt6-qtdeclarative",
            "target_branch": "c10s",
        },
        written_paths,
        warnings,
    )

    mock_path = cases_dir / "mock_data" / "backport" / f"{case_id}.json"
    mock_data = json.loads(mock_path.read_text(encoding="utf-8"))
    assert warnings == []
    assert written_paths == [mock_path]
    assert mock_data["repos"][0] == {
        "branch": "rhel-10.2",
        "package": "qt6-qtdeclarative",
        "pre_fix_ref": pre_fix_ref,
        "remote_url": replay_remote_url,
    }
    assert mock_data["zstream_override"] == {"10": "rhel-10.2"}


def test_cli_prepare_case_infers_mock_prefixed_ref_from_distgit_commit_patch(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    remote_url = "https://gitlab.com/redhat/centos-stream/rpms/dnsmasq.git"

    source_repo = tmp_path / "centos-source"
    source_repo.mkdir()
    subprocess.run(["git", "init", str(source_repo)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(source_repo), "checkout", "-b", "c8s"], check=True)
    (source_repo / "dnsmasq.spec").write_text("Name: dnsmasq\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source_repo), "add", "dnsmasq.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    pre_fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c8s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    (source_repo / "dnsmasq.spec").write_text(
        "Name: dnsmasq\nPatch1: fix.patch\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "dnsmasq.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fix",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c8s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    _write_source_fixture(cases_dir, tmp_path, case_id, source_repo, remote_url)

    warnings: list[str] = []
    written_paths: list[Path] = []
    cli_module._prepare_write_inferred_mock_data(
        argparse.Namespace(
            cases=cases_dir,
            case_id=case_id,
            workflow="ymir-backport",
            overwrite=True,
        ),
        {
            "case_id": case_id,
            "case_type": "cve_backport",
            "package": "dnsmasq",
            "patch_urls": [
                f"https://gitlab.com/redhat/centos-stream/rpms/dnsmasq/-/commit/{fix_ref}.patch"
            ],
            "target_branch": "c8s",
        },
        written_paths,
        warnings,
    )

    mock_path = cases_dir / "mock_data" / "backport" / f"{case_id}.json"
    mock_data = json.loads(mock_path.read_text(encoding="utf-8"))
    assert warnings == []
    assert written_paths == [mock_path]
    assert mock_data["repos"][0] == {
        "branch": "c8s",
        "package": "dnsmasq",
        "pre_fix_ref": pre_fix_ref,
        "remote_url": remote_url,
    }


def test_cli_prepare_case_infers_mock_prefixed_ref_from_merge_request_commits(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    remote_url = "https://gitlab.com/redhat/centos-stream/rpms/perl-HTTP-Daemon.git"

    source_repo = tmp_path / "centos-source"
    source_repo.mkdir()
    subprocess.run(["git", "init", str(source_repo)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(source_repo), "checkout", "-b", "c8s"], check=True)
    (source_repo / "perl-HTTP-Daemon.spec").write_text(
        "Name: perl-HTTP-Daemon\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "perl-HTTP-Daemon.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "seed",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    pre_fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c8s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    (source_repo / "perl-HTTP-Daemon.spec").write_text(
        "Name: perl-HTTP-Daemon\nPatch3: CVE.patch\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "perl-HTTP-Daemon.spec"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fix CVE",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    fix_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c8s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    (source_repo / "gating.yaml").write_text("---\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source_repo), "add", "gating.yaml"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "add gating",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    follow_up_ref = subprocess.run(
        ["git", "-C", str(source_repo), "rev-parse", "c8s"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    _write_source_fixture(cases_dir, tmp_path, case_id, source_repo, remote_url)
    _write_json(
        cases_dir / "web_cache" / case_id / "gitlab" / "commits.json",
        [
            {
                "id": follow_up_ref,
                "parent_ids": [fix_ref],
                "title": "add gating",
            },
            {
                "id": fix_ref,
                "parent_ids": [pre_fix_ref],
                "title": "fix CVE",
            },
        ],
    )

    warnings: list[str] = []
    written_paths: list[Path] = []
    cli_module._prepare_write_inferred_mock_data(
        argparse.Namespace(
            cases=cases_dir,
            case_id=case_id,
            workflow="ymir-backport",
            overwrite=True,
        ),
        {
            "case_id": case_id,
            "case_type": "cve_backport",
            "fix_sources": [
                "https://gitlab.com/redhat/centos-stream/rpms/perl-HTTP-Daemon/-/merge_requests/5"
            ],
            "package": "perl-HTTP-Daemon",
            "target_branch": "c8s",
        },
        written_paths,
        warnings,
    )

    mock_path = cases_dir / "mock_data" / "backport" / f"{case_id}.json"
    mock_data = json.loads(mock_path.read_text(encoding="utf-8"))
    assert warnings == []
    assert written_paths == [mock_path]
    assert mock_data["repos"][0] == {
        "branch": "c8s",
        "package": "perl-HTTP-Daemon",
        "pre_fix_ref": pre_fix_ref,
        "remote_url": remote_url,
    }


def test_cli_prepare_case_infers_backport_koji_candidate_builds_from_triage_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    as_of = "2026-05-20T12:00:00.000000Z"
    calls: list[tuple[str, str, str | None, float | None]] = []

    def fake_fetch_candidate_build(
        package: str,
        branch: str,
        *,
        as_of: str | None = None,
        timeout: float | None = None,
    ):
        calls.append((package, branch, as_of, timeout))
        return {
            "dist_git_branch": branch,
            "evr": {
                "epoch": 0,
                "release": "1.el10",
                "version": "6.10.1",
            },
            "package": package,
            "source_ref": f"{package}-{branch}-ref",
        }

    monkeypatch.setattr(cli_module, "fetch_candidate_build", fake_fetch_candidate_build)
    _write_json(
        cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "case_id": case_id,
            "case_type": "cve_backport",
            "network_mode": "replay_only",
            "package": "qt6-qtdeclarative",
            "target_branch": "c10s",
        },
    )
    _write_json(
        cases_dir / "triage_results" / f"{case_id}.actual.json",
        {
            "case_id": case_id,
            "data": {
                "package": "qt6-qtdeclarative",
            },
            "resolution": "backport",
            "target_branch": "rhel-10.2",
        },
    )
    _write_json(cases_dir / "jiras" / case_id / "reconstruction.json", {"as_of": as_of})
    _write_json(
        cases_dir / "web_cache" / case_id / "manifest.json",
        {
            "case_id": case_id,
            "case_type": "cve_backport",
            "koji_candidate_builds": {},
            "recorded_files": {},
            "required_urls": [],
            "schema_version": 1,
        },
    )

    warnings: list[str] = []
    written_paths: list[Path] = []
    expected = cli_module._prepare_load_expected(cases_dir, case_id)
    assert expected is not None
    cli_module._prepare_write_inferred_koji_candidate_builds(
        argparse.Namespace(
            as_of=None,
            cases=cases_dir,
            case_id=case_id,
            http_timeout=12.5,
            workflow="ymir-backport",
            overwrite=False,
        ),
        expected,
        written_paths,
        warnings,
    )

    manifest_path = cases_dir / "web_cache" / case_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert warnings == []
    assert written_paths == [manifest_path]
    assert calls == [
        ("qt6-qtdeclarative", "rhel-10.2", as_of, 12.5),
        ("qt6-qtdeclarative", "rhel-10.3", as_of, 12.5),
    ]
    assert (
        manifest["koji_candidate_builds"]["qt6-qtdeclarative|rhel-10.2"]["source_ref"]
        == "qt6-qtdeclarative-rhel-10.2-ref"
    )
    assert (
        manifest["koji_candidate_builds"]["qt6-qtdeclarative|rhel-10.3"]["source_ref"]
        == "qt6-qtdeclarative-rhel-10.3-ref"
    )


def test_cli_prepare_case_overwrites_backport_expected_branch_from_triage_result(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    _write_json(
        expected_path,
        {
            "case_id": case_id,
            "case_type": "cve_backport",
            "package": "qt6-qtdeclarative",
            "target_branch": "c10s",
        },
    )
    _write_json(
        cases_dir / "triage_results" / f"{case_id}.actual.json",
        {
            "case_id": case_id,
            "data": {
                "package": "qt6-qtdeclarative",
            },
            "resolution": "backport",
            "target_branch": "rhel-10.2",
        },
    )

    warnings: list[str] = []
    written_paths: list[Path] = []
    expected = cli_module._prepare_load_expected(cases_dir, case_id)
    assert expected is not None
    updated = cli_module._prepare_write_inferred_expected_data(
        argparse.Namespace(
            cases=cases_dir,
            case_id=case_id,
            workflow="ymir-backport",
            overwrite=True,
        ),
        expected,
        written_paths,
        warnings,
    )

    expected_fixture = json.loads(expected_path.read_text(encoding="utf-8"))
    assert warnings == []
    assert written_paths == [expected_path]
    assert updated["target_branch"] == "rhel-10.2"
    assert expected_fixture["target_branch"] == "rhel-10.2"


def test_cli_prepare_case_reruns_after_passing_run_captures_replay_miss(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    capture_requests = []
    run_ids = []
    has_replay_candidates = [True, False]

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    case_status="active",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        run_ids.append(kwargs["run_id"])
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    def fake_capture_missing(request):
        capture_requests.append(request)
        result = CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )
        if len(capture_requests) == 1:
            result.candidate_jira_requests.append(
                {
                    "kind": "jira_search",
                    "method": "POST",
                    "url": "https://redhat.atlassian.net/rest/api/2/search",
                    "payload": {"jql": 'component = "sqlite"'},
                }
            )
            result.captured_jira.append(
                CapturedJiraRequest(
                    kind="jira_search",
                    method="POST",
                    url="https://redhat.atlassian.net/rest/api/2/search",
                    relative_path="api/search/abc.json",
                )
            )
        return result

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)
    monkeypatch.setattr(
        cli_module,
        "_prepare_has_replay_candidates",
        lambda *_args: has_replay_candidates.pop(0),
    )
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--max-iterations",
                "2",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert [iteration["run"]["run_id"] for iteration in output["iterations"]] == [
        "baseline-RHEL-12345-iter-1",
        "baseline-RHEL-12345-iter-2",
    ]
    assert run_ids == ["baseline-RHEL-12345-iter-1", "baseline-RHEL-12345-iter-2"]
    assert len(capture_requests) == 1
    assert len(output["iterations"][0]["capture"]["captured_jira"]) == 1
    assert "capture" not in output["iterations"][1]


def test_cli_prepare_case_succeeds_after_recorded_replay_candidate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    capture_requests = []
    run_ids = []
    has_replay_candidates = [True]

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id="RHEL-12345",
                    case_type="not_affected",
                    case_status="active",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        run_ids.append(kwargs["run_id"])
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="not_affected",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    def fake_capture_missing(request):
        capture_requests.append(request)
        result = CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )
        result.skipped.append(
            CaptureFailure(
                url="https://gitlab.example/project/raw/c9s/package.spec",
                reason="URL is already recorded",
            )
        )
        return result

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)
    monkeypatch.setattr(
        cli_module,
        "_prepare_has_replay_candidates",
        lambda *_args: has_replay_candidates.pop(0),
    )
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--max-iterations",
                "2",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert run_ids == ["baseline-RHEL-12345-iter-1"]
    assert len(capture_requests) == 1
    assert output["iterations"][0]["capture"]["skipped"] == [
        {
            "reason": "URL is already recorded",
            "url": "https://gitlab.example/project/raw/c9s/package.spec",
        }
    ]


def test_prepare_recorded_replay_candidate_supersedes_earlier_skip(tmp_path: Path) -> None:
    result = CaptureMissingResult(
        case_id="RHEL-12345",
        cases_dir=tmp_path,
        run_path=tmp_path / "run",
    )
    result.skipped.append(
        CaptureFailure(
            url="https://raw.githubusercontent.com/org/project/main/file",
            reason="host is not allowed",
        )
    )
    result.skipped.append(
        CaptureFailure(
            url="https://raw.githubusercontent.com/org/project/main/file",
            reason="URL is already recorded",
        )
    )
    result.skipped.append(
        CaptureFailure(
            url="https://github.com/org/project",
            reason="source repo is already recorded",
        )
    )

    assert cli_module._prepare_has_only_recorded_replay_candidates(result)


def test_prepare_has_replay_candidates_ignores_recorded_urls(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_dir = tmp_path / "run"
    manifest_path = cases_dir / "web_cache" / "RHEL-12345" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "recorded_files": {
                    "https://example.invalid/recorded.spec": "captured/recorded.spec"
                },
                "required_urls": ["https://example.invalid/recorded.spec"],
            }
        ),
        encoding="utf-8",
    )
    log_path = run_dir / "repeat-1" / "workflow-trace" / "RHEL-12345.stdout.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text(
        "replay miss: URL is not recorded in replay cache: https://example.invalid/recorded.spec\n",
        encoding="utf-8",
    )

    assert not cli_module._prepare_has_replay_candidates(
        run_dir,
        cases_dir,
        "RHEL-12345",
    )


def test_prepare_has_replay_candidates_ignores_recorded_source_cache_repo(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    case_id = "RHEL-12345"
    run_dir = tmp_path / "run"
    blocked_url = "https://github.com/example/project.git"
    log_path = run_dir / "repeat-1" / "workflow-trace" / f"{case_id}.stdout.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text(
        f"external subprocess URL blocked: {blocked_url}\n",
        encoding="utf-8",
    )

    assert cli_module._prepare_has_replay_candidates(run_dir, cases_dir, case_id)

    source_repo = tmp_path / "source"
    source_repo.mkdir()
    subprocess.run(["git", "-C", str(source_repo), "init", "-q"], check=True)
    (source_repo / "source.c").write_text("source\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source_repo), "add", "source.c"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source_repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "seed",
        ],
        check=True,
    )

    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    _write_source_fixture(cases_dir, tmp_path, case_id, source_repo, blocked_url)

    assert not cli_module._prepare_has_replay_candidates(run_dir, cases_dir, case_id)


def test_cli_prepare_case_blocks_passing_run_with_uncaptured_replay_miss(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    case_status="active",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    status="passed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    def fake_capture_missing(request):
        result = CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )
        result.candidate_urls.append("https://example.invalid/missing.patch")
        return result

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)
    monkeypatch.setattr(cli_module, "_prepare_has_replay_candidates", lambda *_args: True)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--json",
            ]
        )
        == 1
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "blocked"
    assert output["iterations"][0]["run"]["summary"]["has_failures"] is False
    assert output["iterations"][0]["capture"]["candidate_urls"] == [
        "https://example.invalid/missing.patch"
    ]


def test_cli_prepare_case_auto_allows_denied_capture_hosts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    capture_requests = []
    run_statuses = ["failed", "passed"]

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    case_status="active",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        status = run_statuses.pop(0)
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    status=status,
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    def fake_capture_missing(request):
        capture_requests.append(request)
        result = CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )
        url = "https://www.sqlite.org/changes.html"
        if "www.sqlite.org" not in request.allowed_hosts:
            result.candidate_urls.append(url)
            result.skipped.append(CaptureFailure(url=url, reason="host is not allowed"))
        else:
            result.candidate_urls.append(url)
            result.captured.append(
                CapturedResponse(
                    url=url,
                    relative_path="captured/www.sqlite.org/changes.html",
                    status=200,
                )
            )
        return result

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--json",
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "succeeded"
    assert output["auto_allowed_hosts"] == ["www.sqlite.org"]
    assert output["iterations"][0]["auto_allowed_hosts"] == ["www.sqlite.org"]
    assert len(output["iterations"][0]["capture"]["captured"]) == 1
    assert output["iterations"][0]["capture"]["skipped"] == []
    assert "www.sqlite.org" not in capture_requests[0].allowed_hosts
    assert "www.sqlite.org" in capture_requests[1].allowed_hosts
    assert len(capture_requests) == 2


def test_cli_prepare_case_does_not_auto_allow_private_hosts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    capture_requests = []

    def fake_validate_case_directory(cases_dir_arg, *, workflow=None):
        return ValidationReport(
            cases_dir=cases_dir_arg,
            cases=[
                CaseValidationResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    case_status="active",
                    status="valid",
                )
            ],
        )

    def fake_build_run_report(cases_dir_arg, results_dir, **kwargs):
        return RunReport(
            cases_dir=cases_dir_arg,
            results_dir=results_dir,
            entries=[
                RunCaseResult(
                    case_id="RHEL-12345",
                    case_type="cve_backport",
                    status="failed",
                )
            ],
            run_id=kwargs["run_id"],
            variant=kwargs["variant"],
        )

    def fake_capture_missing(request):
        capture_requests.append(request)
        result = CaptureMissingResult(
            case_id=request.case_id,
            cases_dir=request.cases_dir,
            run_path=request.run_path,
        )
        url = "http://127.0.0.1/secret"
        result.candidate_urls.append(url)
        result.skipped.append(CaptureFailure(url=url, reason="host is not allowed"))
        return result

    monkeypatch.setattr(cli_module, "validate_case_directory", fake_validate_case_directory)
    monkeypatch.setattr(cli_module, "load_case_manifest", lambda _cases_dir: ([], []))
    monkeypatch.setattr(cli_module, "write_validation_reports", lambda _report, _reports_dir: [])
    monkeypatch.setattr(cli_module, "build_run_report", fake_build_run_report)
    monkeypatch.setattr(cli_module, "capture_missing", fake_capture_missing)
    monkeypatch.setattr(cli_module, "_run_executor", lambda _workflow: None)

    assert (
        main(
            [
                "prepare-case",
                "--cases",
                str(cases_dir),
                "--case",
                "RHEL-12345",
                "--workflow",
                "ymir-triage",
                "--variant",
                "baseline",
                "--json",
            ]
        )
        == 1
    )

    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "blocked"
    assert output["auto_allowed_hosts"] == []
    assert "127.0.0.1" not in capture_requests[0].allowed_hosts
    assert len(capture_requests) == 1


def test_cli_run_blocks_invalid_fixtures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    output_path = tmp_path / "reports" / "run.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 99,
            "case_id": "RHEL-99999",
            "case_type": "not_affected",
            "resolution": "not_affected",
            "package": "dnsmasq",
            "expected_basis": "maintainer_decision",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "network_denied",
        },
    )

    assert (
        main(
            [
                "run",
                "--cases",
                str(cases_dir),
                "--variant",
                "baseline",
                "--output",
                str(output_path),
            ]
        )
        == 1
    )

    output = capsys.readouterr().out
    assert "benchmark run blocked" in output
    assert not output_path.exists()
    assert (cases_dir / "reports" / "fixture-validation-errors.md").is_file()


def test_cli_compares_result_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    markdown_path = tmp_path / "comparison.md"
    _write_result_report(
        baseline_path,
        {
            "RHEL-12345": ("failed", True),
        },
    )
    _write_result_report(
        candidate_path,
        {
            "RHEL-12345": ("passed", True),
        },
    )

    assert (
        main(
            [
                "compare-results",
                str(baseline_path),
                str(candidate_path),
                "--markdown-output",
                str(markdown_path),
            ]
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["wins"] == 1
    assert output["cases"][0]["delta"] == "win"
    assert "RHEL-12345" in markdown_path.read_text(encoding="utf-8")


def _write_result_report(path: Path, cases: dict[str, tuple[str, bool]]) -> None:
    _write_json(
        path,
        {
            "schema_version": 1,
            "cases": [
                {
                    "case_id": case_id,
                    "case_type": "cve_backport",
                    "status": status,
                    "headline": headline,
                }
                for case_id, (status, headline) in cases.items()
            ],
        },
    )


def _write_activatable_case(cases_dir: Path, **overrides: object) -> None:
    case_id = str(overrides.pop("case_id", "RHEL-12345"))
    payload = {
        "schema_version": 1,
        "case_id": case_id,
        "case_type": "not_affected",
        "resolution": "not_affected",
        "package": "dnsmasq",
        "expected_basis": "maintainer_decision",
        "ground_truth_confidence": "high",
        "answer_leakage": "none",
        "case_status": "quarantined",
        "case_status_reason": "fixture scaffold prepared for replay experiments",
        "network_mode": "replay_only",
    }
    payload.update(overrides)
    _write_json(cases_dir / "expected" / f"{case_id}.expected.json", payload)
    _write_json(
        cases_dir / "web_cache" / case_id / "manifest.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "not_affected",
            "required_urls": [],
            "recorded_files": {},
        },
    )


def _write_activation_run_report(path: Path, case_id: str, statuses: list[str]) -> None:
    _write_json(
        path,
        {
            "schema_version": 1,
            "run_id": path.parent.name,
            "variant": "baseline",
            "cases": [
                {
                    "case_id": case_id,
                    "case_type": "not_affected",
                    "status": status,
                    "repetition": index,
                }
                for index, status in enumerate(statuses, start=1)
            ],
        },
    )


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
