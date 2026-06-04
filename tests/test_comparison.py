from __future__ import annotations

from pathlib import Path

from ymir_harness.comparison import compare_result_payloads


def test_compare_result_payloads_classifies_headline_deltas(tmp_path: Path) -> None:
    baseline = {
        "cases": [
            _case("RHEL-1", "failed", True),
            _case("RHEL-2", "passed", True),
            _case("RHEL-3", "passed", False),
        ]
    }
    candidate = {
        "cases": [
            _case("RHEL-1", "passed", True),
            _case("RHEL-2", "failed", True),
            _case("RHEL-3", "failed", False),
            _case("RHEL-4", "passed", True),
        ]
    }

    report = compare_result_payloads(
        baseline,
        candidate,
        tmp_path / "baseline.json",
        tmp_path / "candidate.json",
    )

    deltas = {entry.case_id: entry.delta for entry in report.entries}
    assert deltas == {
        "RHEL-1": "win",
        "RHEL-2": "regression",
        "RHEL-3": "non_headline",
        "RHEL-4": "missing_in_baseline",
    }
    assert report.has_headline_regressions
    assert report.summary()["wins"] == 1
    assert report.summary()["regressions"] == 1


def _case(case_id: str, status: str, headline: bool) -> dict[str, object]:
    return {
        "case_id": case_id,
        "case_type": "cve_backport",
        "status": status,
        "headline": headline,
    }
