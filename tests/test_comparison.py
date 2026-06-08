from __future__ import annotations

from pathlib import Path

from ymir_harness.comparison import compare_result_payloads, render_comparison_markdown


def test_compare_result_payloads_classifies_headline_deltas(tmp_path: Path) -> None:
    baseline = {
        "cases": [
            _case("RHEL-1", "failed", True),
            _case("RHEL-2", "passed", True),
            _case(
                "RHEL-3",
                "passed",
                False,
                headline_reason="case_status is quarantined",
            ),
        ]
    }
    candidate = {
        "cases": [
            _case("RHEL-1", "passed", True),
            _case("RHEL-2", "failed", True),
            _case(
                "RHEL-3",
                "failed",
                False,
                headline_reason="case_status is quarantined",
            ),
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
    entries = {entry.case_id: entry for entry in report.entries}
    assert entries["RHEL-3"].headline_reason == "case_status is quarantined"
    payload_cases = {case["case_id"]: case for case in report.to_json()["cases"]}
    assert payload_cases["RHEL-3"]["headline_reason"] == "case_status is quarantined"


def test_render_comparison_markdown_lists_case_deltas(tmp_path: Path) -> None:
    report = compare_result_payloads(
        {"cases": [_case("RHEL-1", "failed", True)]},
        {"cases": [_case("RHEL-1", "passed", True)]},
        tmp_path / "baseline.json",
        tmp_path / "candidate.json",
    )

    markdown = render_comparison_markdown(report)

    assert "# Result Comparison" in markdown
    assert "Headline wins: `1`" in markdown
    assert "| RHEL-1 | cve_backport | yes |  | failed | passed | win |" in markdown
    assert "Baseline cost" not in markdown


def test_compare_result_payloads_reports_cost_deltas(tmp_path: Path) -> None:
    report = compare_result_payloads(
        {"cases": [_case("RHEL-1", "passed", True, total_cost_usd=4.5)]},
        {"cases": [_case("RHEL-1", "passed", True, total_cost_usd=7.25)]},
        tmp_path / "baseline.json",
        tmp_path / "candidate.json",
    )

    entry = report.entries[0]
    assert entry.baseline_total_cost_usd == 4.5
    assert entry.candidate_total_cost_usd == 7.25
    assert entry.cost_delta_usd == 2.75

    payload = report.to_json()["cases"][0]
    assert payload["baseline_total_cost_usd"] == 4.5
    assert payload["candidate_total_cost_usd"] == 7.25
    assert payload["cost_delta_usd"] == 2.75

    markdown = render_comparison_markdown(report)
    assert (
        "| Case | Type | Headline | Reason | Baseline | Candidate | Delta | "
        "Baseline cost | Candidate cost | Cost delta |"
    ) in markdown
    assert (
        "| RHEL-1 | cve_backport | yes |  | passed | passed | unchanged_pass | 4.5 | 7.25 | 2.75 |"
    ) in markdown


def _case(
    case_id: str,
    status: str,
    headline: bool,
    *,
    headline_reason: str | None = None,
    total_cost_usd: float | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "case_id": case_id,
        "case_type": "cve_backport",
        "status": status,
        "headline": headline,
    }
    if headline_reason is not None:
        payload["headline_reason"] = headline_reason
    if total_cost_usd is not None:
        payload["score"] = {
            "advisory_metrics": [
                {
                    "name": "total_cost_usd",
                    "value": total_cost_usd,
                }
            ]
        }
    return payload
