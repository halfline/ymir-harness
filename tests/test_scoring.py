from __future__ import annotations

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
