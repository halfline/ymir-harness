from __future__ import annotations

import json
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.scoring import score_case

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


def test_score_case_infers_distgit_backport_source_from_patch_urls() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "redis",
        "target_branch": "rhel-9.6.z",
        "patch_urls": [
            "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/"
            "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1.patch"
        ],
        "backport_source": "distgit",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "redis",
        "target_branch": "rhel-9.6.z",
        "patch_urls": [
            "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/"
            "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1.patch"
        ],
    }

    report = score_case(expected, actual)

    assert report.passed
    assert {metric.name: metric for metric in report.metrics}["backport_source"].actual == "distgit"


def test_score_case_reports_backport_source_mismatch() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "kea",
        "target_branch": "rhel-10.0.z",
        "patch_urls": [
            "https://gitlab.com/redhat/centos-stream/rpms/kea/-/commit/"
            "2222222222222222222222222222222222222222.patch"
        ],
        "backport_source": "distgit",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "kea",
        "target_branch": "rhel-10.0.z",
        "patch_urls": [
            "https://github.com/isc-projects/kea/commit/"
            "1111111111111111111111111111111111111111.patch"
        ],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["backport_source"].expected == "distgit"
    assert failed["backport_source"].actual == "upstream"


def test_score_case_extracts_cve_ids_from_modern_triage_text() -> None:
    expected = {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "not_affected",
        "resolution": "not_affected",
        "package": "rpm-ostree",
        "cve_ids": ["CVE-2026-28390"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "not_affected",
        "resolution": "not-affected",
        "package": "rpm-ostree",
        "data": {
            "findings": "CVE-2026-28390 is not in the package execute path.",
        },
    }

    report = score_case(expected, actual)

    assert report.passed


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


def test_score_case_does_not_treat_fix_version_as_target_branch() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "fix_version": "rhel-8.10.z",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "c8s",
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["target_branch"].status == "skipped"


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


def test_score_case_skips_fix_sources_missing_from_actual() -> None:
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
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["fix_sources"].status == "skipped"


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
