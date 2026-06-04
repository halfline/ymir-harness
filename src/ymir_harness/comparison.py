from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ymir_harness.models import ComparisonDelta, ComparisonEntry, ComparisonReport
from ymir_harness.scoring import load_json_file


def compare_result_reports(baseline_path: Path, candidate_path: Path) -> ComparisonReport:
    baseline = load_json_file(baseline_path)
    candidate = load_json_file(candidate_path)
    return compare_result_payloads(baseline, candidate, baseline_path, candidate_path)


def compare_result_payloads(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    baseline_path: Path,
    candidate_path: Path,
) -> ComparisonReport:
    baseline_cases = _case_map(baseline)
    candidate_cases = _case_map(candidate)
    case_ids = sorted(baseline_cases.keys() | candidate_cases.keys())
    entries = [
        _compare_case(case_id, baseline_cases.get(case_id), candidate_cases.get(case_id))
        for case_id in case_ids
    ]
    return ComparisonReport(
        baseline_path=baseline_path,
        candidate_path=candidate_path,
        entries=entries,
    )


def render_comparison_markdown(report: ComparisonReport) -> str:
    summary = report.summary()
    lines = [
        "# Result Comparison",
        "",
        f"- Baseline: `{report.baseline_path}`",
        f"- Candidate: `{report.candidate_path}`",
        f"- Headline cases: `{summary['headline_total']}`",
        f"- Headline wins: `{summary['wins']}`",
        f"- Headline regressions: `{summary['regressions']}`",
        f"- Non-headline cases: `{summary['non_headline']}`",
        "",
        "| Case | Type | Headline | Baseline | Candidate | Delta |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for entry in report.entries:
        lines.append(
            "| "
            f"{entry.case_id} | "
            f"{entry.case_type or ''} | "
            f"{_yes_no(entry.headline)} | "
            f"{entry.baseline_status or ''} | "
            f"{entry.candidate_status or ''} | "
            f"{entry.delta} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _case_map(payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    cases = payload.get("cases")
    if not isinstance(cases, list):
        return {}

    mapped: dict[str, Mapping[str, Any]] = {}
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        case_id = case.get("case_id")
        if isinstance(case_id, str) and case_id:
            mapped[case_id] = case
    return mapped


def _compare_case(
    case_id: str,
    baseline: Mapping[str, Any] | None,
    candidate: Mapping[str, Any] | None,
) -> ComparisonEntry:
    case_type = _case_type(baseline, candidate)
    headline = _headline(baseline) or _headline(candidate)
    baseline_status = _status(baseline)
    candidate_status = _status(candidate)
    delta = _delta(headline, baseline_status, candidate_status)
    return ComparisonEntry(
        case_id=case_id,
        case_type=case_type,
        headline=headline,
        baseline_status=baseline_status,
        candidate_status=candidate_status,
        delta=delta,
    )


def _delta(
    headline: bool,
    baseline_status: str | None,
    candidate_status: str | None,
) -> ComparisonDelta:
    if not headline:
        return "non_headline"
    if baseline_status is None:
        return "missing_in_baseline"
    if candidate_status is None:
        return "missing_in_candidate"

    baseline_passed = baseline_status == "passed"
    candidate_passed = candidate_status == "passed"
    if candidate_passed and not baseline_passed:
        return "win"
    if baseline_passed and not candidate_passed:
        return "regression"
    if baseline_passed and candidate_passed:
        return "unchanged_pass"
    return "unchanged_fail"


def _case_type(*cases: Mapping[str, Any] | None) -> str | None:
    for case in cases:
        if case is None:
            continue
        case_type = case.get("case_type")
        if isinstance(case_type, str):
            return case_type
    return None


def _headline(case: Mapping[str, Any] | None) -> bool:
    if case is None:
        return False
    return case.get("headline") is True


def _status(case: Mapping[str, Any] | None) -> str | None:
    if case is None:
        return None
    status = case.get("status")
    if isinstance(status, str):
        return status
    return None


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
