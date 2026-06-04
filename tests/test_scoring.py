from __future__ import annotations

import json
from pathlib import Path

from ymir_harness.scoring import score_case, score_result_directory


def test_score_case_accepts_nested_triage_result() -> None:
    expected = {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "cve_ids": ["CVE-2026-0001"],
        "patch_urls": ["https://example.invalid/fix.patch"],
    }
    actual = {
        "resolution": "Resolution.BACKPORT",
        "data": {
            "package": "dnsmasq",
            "fix_version": "rhel-8.10.z",
            "cve_id": "CVE-2026-0001",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    }

    report = score_case(expected, actual)

    assert report.passed
    assert report.summary()["fail"] == 0


def test_score_case_reports_field_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "libtiff",
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name for metric in report.metrics if metric.status == "fail"}
    assert failed == {"package"}


def test_score_case_reports_affectedness_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "not_affected",
        "affectedness": "not affected",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "not_affected",
        "package": "dnsmasq",
        "data": {"affectedness": True},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["affectedness"].expected == "not_affected"
    assert failed["affectedness"].actual == "affected"


def test_score_case_fails_unsafe_operation_attempts() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "unsafe_operations": ["git push origin HEAD"],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["unsafe_operations"].actual == ["git push origin HEAD"]


def test_score_case_fails_replay_violations() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"replay_violations": ["unrecorded URL: https://example.invalid/advisory"]},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["replay_violations"].actual == [
        "unrecorded URL: https://example.invalid/advisory"
    ]


def test_score_case_fails_missing_required_artifacts() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "required_artifacts": ["fix.patch", "dnsmasq.spec"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "generated_artifacts": ["fix.patch"],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["required_artifacts"].actual == ["fix.patch"]
    assert failed["required_artifacts"].notes == "missing required artifacts: dnsmasq.spec"


def test_score_case_reports_touched_file_scope_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "touched_files": ["SPECS/dnsmasq.spec", "SOURCES/fix.patch"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "changed_files": ["SOURCES/fix.patch", "SPECS/dnsmasq.spec", "README.md"],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["touched_files"].actual == [
        "README.md",
        "SOURCES/fix.patch",
        "SPECS/dnsmasq.spec",
    ]
    assert failed["touched_files"].notes == "unexpected touched files: README.md"


def test_score_result_directory_collects_headline_results(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        package="dnsmasq",
        case_status="active",
    )
    _write_expected(
        cases_dir,
        "RHEL-23456",
        package="libtiff",
        case_status="excluded",
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )

    report = score_result_directory(cases_dir, actual_dir)

    assert not report.has_headline_failures
    assert report.summary()["headline_passed"] == 1
    assert report.summary()["skipped"] == 1
    assert [entry.status for entry in report.entries] == ["passed", "skipped"]


def test_score_result_directory_records_run_metadata(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        package="dnsmasq",
        case_status="active",
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )

    report = score_result_directory(
        cases_dir,
        actual_dir,
        run_id="baseline-2026-06-04T120000Z",
        ymir_sha="6e22912f83d57ddae1031e6207d4716171a99be0",
        variant="baseline",
    )

    payload = report.to_json()
    assert payload["run_id"] == "baseline-2026-06-04T120000Z"
    assert payload["ymir_sha"] == "6e22912f83d57ddae1031e6207d4716171a99be0"
    assert payload["variant"] == "baseline"


def _write_expected(
    cases_dir: Path,
    case_id: str,
    *,
    package: str,
    case_status: str,
) -> None:
    _write_json(
        cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": package,
            "expected_basis": "merged_mr",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": case_status,
            "network_mode": "replay_only",
        },
    )


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
