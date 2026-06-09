from __future__ import annotations

import json
from pathlib import Path

import pytest

from ymir_harness import __version__
from ymir_harness.capture_missing import CaptureMissingResult
import ymir_harness.cli as cli_module
from ymir_harness.cli import main
from ymir_harness.collect_case import CollectCaseResult
from ymir_harness.runner import RunCaseExecution


def test_cli_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"ymir-harness {__version__}\n"


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


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
