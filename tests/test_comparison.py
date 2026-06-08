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


def test_compare_result_payloads_reports_repetition_stability(tmp_path: Path) -> None:
    report = compare_result_payloads(
        {
            "cases": [
                _case("RHEL-1", "failed", True),
                _case("RHEL-1", "passed", True),
            ]
        },
        {
            "cases": [
                _case("RHEL-1", "passed", True),
                _case("RHEL-1", "passed", True),
            ]
        },
        tmp_path / "baseline.json",
        tmp_path / "candidate.json",
    )

    entry = report.entries[0]
    assert entry.baseline_status == "flaky"
    assert entry.candidate_status == "passed"
    assert entry.delta == "win"
    assert entry.baseline_repetitions == 2
    assert entry.candidate_repetitions == 2
    assert entry.baseline_stability == "flaky"
    assert entry.candidate_stability == "stable"
    assert report.summary()["flaky_cases"] == 1
    assert report.summary()["stable_wins"] == 0

    payload = report.to_json()["cases"][0]
    assert payload["baseline_stability"] == "flaky"
    assert payload["candidate_stability"] == "stable"

    markdown = render_comparison_markdown(report)
    assert "Baseline reps" in markdown
    assert (
        "| RHEL-1 | cve_backport | yes |  | flaky | passed | win | 2 | 2 | flaky | stable |"
    ) in markdown


def test_compare_result_payloads_reports_telemetry_deltas(tmp_path: Path) -> None:
    report = compare_result_payloads(
        {
            "cases": [
                _case(
                    "RHEL-1",
                    "passed",
                    True,
                    runtime_seconds=12,
                    token_usage={"input_tokens": 100, "output_tokens": 50},
                    tool_call_count=6,
                    total_cost_usd=5,
                ),
                _case(
                    "RHEL-1",
                    "passed",
                    True,
                    runtime_seconds=10,
                    token_usage={"input_tokens": 120, "output_tokens": 80},
                    tool_call_count=4,
                    total_cost_usd=7,
                ),
            ]
        },
        {
            "cases": [
                _case(
                    "RHEL-1",
                    "passed",
                    True,
                    runtime_seconds=8,
                    token_usage={"input_tokens": 90, "output_tokens": 40},
                    tool_call_count=3,
                    total_cost_usd=4,
                ),
                _case(
                    "RHEL-1",
                    "passed",
                    True,
                    runtime_seconds=6,
                    token_usage={"input_tokens": 110, "output_tokens": 60},
                    tool_call_count=5,
                    total_cost_usd=6,
                ),
            ]
        },
        tmp_path / "baseline.json",
        tmp_path / "candidate.json",
    )

    entry = report.entries[0]
    assert entry.baseline_runtime_seconds == 11
    assert entry.candidate_runtime_seconds == 7
    assert entry.runtime_delta_seconds == -4
    assert entry.baseline_token_count == 175
    assert entry.candidate_token_count == 150
    assert entry.token_delta == -25
    assert entry.baseline_tool_call_count == 5
    assert entry.candidate_tool_call_count == 4
    assert entry.tool_call_delta == -1
    assert entry.baseline_total_cost_usd == 6
    assert entry.candidate_total_cost_usd == 5
    assert entry.cost_delta_usd == -1
    assert report.summary()["stable_wins"] == 0
    assert report.summary()["runtime_delta_seconds"] == -4
    assert report.summary()["token_delta"] == -25
    assert report.summary()["tool_call_delta"] == -1
    assert report.summary()["cost_delta_usd"] == -1

    markdown = render_comparison_markdown(report)
    assert "Runtime delta" in markdown
    assert "Token delta" in markdown
    assert "Tool call delta" in markdown
    assert (
        "| RHEL-1 | cve_backport | yes |  | passed | passed | unchanged_pass | "
        "2 | 2 | stable | stable | 11 | 7 | -4 | 175 | 150 | -25 | "
        "5 | 4 | -1 | 6 | 5 | -1 |"
    ) in markdown


def _case(
    case_id: str,
    status: str,
    headline: bool,
    *,
    headline_reason: str | None = None,
    runtime_seconds: float | None = None,
    token_usage: dict[str, int] | None = None,
    tool_call_count: int | None = None,
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
    if runtime_seconds is not None:
        payload["runtime_seconds"] = runtime_seconds

    advisory_metrics = []
    if token_usage is not None:
        advisory_metrics.append(
            {
                "name": "token_usage",
                "value": token_usage,
            }
        )
    if tool_call_count is not None:
        advisory_metrics.append(
            {
                "name": "tool_call_count",
                "value": tool_call_count,
            }
        )
    if total_cost_usd is not None:
        advisory_metrics.append(
            {
                "name": "total_cost_usd",
                "value": total_cost_usd,
            }
        )
    if advisory_metrics:
        payload["score"] = {
            "advisory_metrics": advisory_metrics,
        }
    return payload
