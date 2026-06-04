from __future__ import annotations

from pathlib import Path

from ymir_harness.models import RunCaseResult, RunReport


def test_run_report_serializes_case_results() -> None:
    report = RunReport(
        cases_dir=Path("/tmp/benchmark_cases"),
        results_dir=Path("/tmp/reports/baseline"),
        run_id="baseline-2026-06-04T120000Z",
        variant="baseline",
        ymir_sha="6e22912f83d57ddae1031e6207d4716171a99be0",
        harness_version="0.1.0",
        fixture_checksum="sha256:" + "1" * 64,
        features=["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
        repeat=2,
        entries=[
            RunCaseResult(
                case_id="RHEL-12345",
                case_type="cve_backport",
                status="not_run",
                expected_path=Path("/tmp/benchmark_cases/expected/RHEL-12345.expected.json"),
                reason="runner is not wired yet",
            ),
            RunCaseResult(
                case_id="RHEL-23456",
                case_type="rebase",
                status="unsupported",
                repetition=2,
                expected_path=Path("/tmp/benchmark_cases/expected/RHEL-23456.expected.json"),
                actual_path=Path("/tmp/reports/baseline/RHEL-23456.actual.json"),
                reason="workflow adapter is missing",
            ),
        ],
    )

    payload = report.to_json()

    assert report.summary() == {
        "total": 2,
        "not_run": 1,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "unsupported": 1,
        "has_failures": False,
    }
    assert payload["schema_version"] == 1
    assert payload["run_id"] == "baseline-2026-06-04T120000Z"
    assert payload["variant"] == "baseline"
    assert payload["ymir_sha"] == "6e22912f83d57ddae1031e6207d4716171a99be0"
    assert payload["harness_version"] == "0.1.0"
    assert payload["fixture_checksum"] == "sha256:" + "1" * 64
    assert payload["features"] == ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"]
    assert payload["repeat"] == 2
    assert payload["cases_dir"] == "/tmp/benchmark_cases"
    assert payload["results_dir"] == "/tmp/reports/baseline"
    assert payload["cases"][0]["repetition"] == 1
    assert payload["cases"][1]["repetition"] == 2
    assert payload["cases"][0]["actual_path"] is None
    assert payload["cases"][0]["reason"] == "runner is not wired yet"
    assert payload["cases"][1]["actual_path"] == "/tmp/reports/baseline/RHEL-23456.actual.json"
