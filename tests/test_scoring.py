from __future__ import annotations

import json
from pathlib import Path

from ymir_harness import __version__
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


def test_score_case_accepts_alternate_acceptable_outcome() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "alternate_acceptable_outcomes": [
            {
                "resolution": "rebase",
                "target_branch": "rhel-9.0.z",
            }
        ],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "rebase",
        "package": "dnsmasq",
        "target_branch": "rhel-9.0.z",
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["alternate_acceptable_outcome"].status == "pass"
    assert metrics["resolution"].expected == "rebase"


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


def test_score_case_fails_unrelated_source_changes() -> None:
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
        "data": {"unrelated_source_changes": ["README.md"]},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["unrelated_source_changes"].expected == []
    assert failed["unrelated_source_changes"].actual == ["README.md"]


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


def test_score_case_reports_spec_patch_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "spec_patches": ["Patch0001: fix-cve.patch"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"spec_patches": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["spec_patches"].expected == ["Patch0001: fix-cve.patch"]
    assert failed["spec_patches"].actual == []


def test_score_case_reports_changelog_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "changelog_entries": ["- Resolves: RHEL-12345 CVE-2026-0001"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"changelog_entries": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["changelog_entries"].expected == ["- Resolves: RHEL-12345 CVE-2026-0001"]
    assert failed["changelog_entries"].actual == []


def test_score_case_reports_build_result_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "build_result": "passed",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"build_result": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["build_result"].expected == "passed"
    assert failed["build_result"].actual == "failed"


def test_score_case_reports_prep_result_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "prep_result": "passed",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"prep_result": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["prep_result"].expected == "passed"
    assert failed["prep_result"].actual == "failed"


def test_score_case_reports_reference_patch_parse_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "reference_patch_parse_status": "parsed",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"reference_patch_parse_status": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["reference_patch_parse_status"].expected == "parsed"
    assert failed["reference_patch_parse_status"].actual == "failed"


def test_score_case_reports_reference_patch_apply_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "reference_patch_apply_status": "applied",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"reference_patch_apply_status": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["reference_patch_apply_status"].expected == "applied"
    assert failed["reference_patch_apply_status"].actual == "failed"


def test_score_case_reports_fix_source_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "fix_sources": ["upstream commit abc123"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"fix_sources": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["fix_sources"].expected == ["upstream commit abc123"]
    assert failed["fix_sources"].actual == []


def test_score_case_reports_dependency_issue_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "dependency_issues": ["RHEL-23456"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "data": {"dependency_issues": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["dependency_issues"].expected == ["RHEL-23456"]
    assert failed["dependency_issues"].actual == []


def test_score_case_reports_sibling_issue_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "sibling_issues": ["RHEL-34567"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "data": {"sibling_issues": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["sibling_issues"].expected == ["RHEL-34567"]
    assert failed["sibling_issues"].actual == []


def test_score_case_records_advisory_metrics_without_failing() -> None:
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
        "runtime_seconds": 42.5,
        "data": {
            "token_usage": {"input": 1200, "output": 300},
            "iteration_count": 12,
            "tool_call_count": 7,
            "retry_count": 1,
            "total_cost_usd": 4.25,
            "llm_judge_notes": "consistent with reference result",
        },
    }

    report = score_case(expected, actual)

    assert report.passed
    assert report.summary()["fail"] == 0
    advisory = {metric["name"]: metric["value"] for metric in report.to_json()["advisory_metrics"]}
    assert advisory == {
        "llm_judge_notes": "consistent with reference result",
        "runtime_seconds": 42.5,
        "token_usage": {"input": 1200, "output": 300},
        "iteration_count": 12,
        "tool_call_count": 7,
        "retry_count": 1,
        "total_cost_usd": 4.25,
    }


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
    assert payload["harness_version"] == __version__
    fixture_checksum = payload["fixture_checksum"]
    assert isinstance(fixture_checksum, str)
    assert fixture_checksum.startswith("sha256:")
    assert len(fixture_checksum) == len("sha256:") + 64

    _write_json(cases_dir / "reports" / "results.json", {"generated": True})
    repeated_payload = score_result_directory(cases_dir, actual_dir).to_json()
    assert repeated_payload["fixture_checksum"] == fixture_checksum


def test_score_result_directory_records_headline_reasons(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        package="dnsmasq",
        case_status="quarantined",
        case_status_reason="requires human judgment",
    )
    _write_expected(
        cases_dir,
        "RHEL-23456",
        package="libtiff",
        case_status="active",
        ground_truth_confidence="low",
    )
    _write_expected(
        cases_dir,
        "RHEL-34567",
        package="openssl",
        case_status="active",
        answer_leakage="explicit",
    )
    _write_expected(
        cases_dir,
        "RHEL-45678",
        package="kernel",
        case_status="active",
        network_mode="live_non_reproducible",
    )
    _write_expected(
        cases_dir,
        "RHEL-56789",
        package="zlib",
        case_status="excluded",
        case_status_reason="fixture cannot be replayed",
    )
    for case_id, package in (
        ("RHEL-12345", "dnsmasq"),
        ("RHEL-23456", "libtiff"),
        ("RHEL-34567", "openssl"),
        ("RHEL-45678", "kernel"),
    ):
        _write_json(
            actual_dir / f"{case_id}.actual.json",
            {
                "case_id": case_id,
                "resolution": "backport",
                "package": package,
            },
        )

    report = score_result_directory(cases_dir, actual_dir)

    entries = {entry.case_id: entry for entry in report.entries}
    assert entries["RHEL-12345"].headline_reason == "case_status is quarantined"
    assert entries["RHEL-23456"].headline_reason == "ground_truth_confidence is low"
    assert entries["RHEL-34567"].headline_reason == "answer_leakage is explicit"
    assert entries["RHEL-45678"].headline_reason == "network_mode is live_non_reproducible"
    assert entries["RHEL-56789"].headline_reason == "case_status is excluded"
    assert entries["RHEL-56789"].reason == "fixture cannot be replayed"
    payload_cases = {case["case_id"]: case for case in report.to_json()["cases"]}
    assert payload_cases["RHEL-12345"]["headline_reason"] == "case_status is quarantined"


def _write_expected(
    cases_dir: Path,
    case_id: str,
    *,
    package: str,
    case_status: str,
    ground_truth_confidence: str = "high",
    answer_leakage: str = "none",
    network_mode: str = "replay_only",
    case_status_reason: str | None = None,
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
            "ground_truth_confidence": ground_truth_confidence,
            "answer_leakage": answer_leakage,
            "case_status": case_status,
            "case_status_reason": case_status_reason,
            "network_mode": network_mode,
        },
    )


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
