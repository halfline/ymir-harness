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
    baseline_cases = _case_groups(baseline)
    candidate_cases = _case_groups(candidate)
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
    show_stability = any(_has_stability_fields(entry) for entry in report.entries)
    show_runtime = any(_has_runtime_fields(entry) for entry in report.entries)
    show_tokens = any(_has_token_fields(entry) for entry in report.entries)
    show_tool_calls = any(_has_tool_call_fields(entry) for entry in report.entries)
    show_costs = any(_has_cost_fields(entry) for entry in report.entries)
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
    ]

    columns = ["Case", "Type", "Headline", "Reason", "Baseline", "Candidate", "Delta"]
    if show_stability:
        columns.extend(
            [
                "Baseline reps",
                "Candidate reps",
                "Baseline stability",
                "Candidate stability",
            ]
        )
    if show_runtime:
        columns.extend(["Baseline runtime", "Candidate runtime", "Runtime delta"])
    if show_tokens:
        columns.extend(["Baseline tokens", "Candidate tokens", "Token delta"])
    if show_tool_calls:
        columns.extend(
            [
                "Baseline tool calls",
                "Candidate tool calls",
                "Tool call delta",
            ]
        )
    if show_costs:
        columns.extend(["Baseline cost", "Candidate cost", "Cost delta"])

    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join("---" for _ in columns) + " |")

    for entry in report.entries:
        row = [
            entry.case_id,
            entry.case_type or "",
            _yes_no(entry.headline),
            entry.headline_reason or "",
            entry.baseline_status or "",
            entry.candidate_status or "",
            entry.delta,
        ]
        if show_stability:
            row.extend(
                [
                    _format_metric(entry.baseline_repetitions),
                    _format_metric(entry.candidate_repetitions),
                    entry.baseline_stability or "",
                    entry.candidate_stability or "",
                ]
            )
        if show_runtime:
            row.extend(
                [
                    _format_metric(entry.baseline_runtime_seconds),
                    _format_metric(entry.candidate_runtime_seconds),
                    _format_metric(entry.runtime_delta_seconds),
                ]
            )
        if show_tokens:
            row.extend(
                [
                    _format_metric(entry.baseline_token_count),
                    _format_metric(entry.candidate_token_count),
                    _format_metric(entry.token_delta),
                ]
            )
        if show_tool_calls:
            row.extend(
                [
                    _format_metric(entry.baseline_tool_call_count),
                    _format_metric(entry.candidate_tool_call_count),
                    _format_metric(entry.tool_call_delta),
                ]
            )
        if show_costs:
            row.extend(
                [
                    _format_metric(entry.baseline_total_cost_usd),
                    _format_metric(entry.candidate_total_cost_usd),
                    _format_metric(entry.cost_delta_usd),
                ]
            )
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines).rstrip() + "\n"


def _case_groups(payload: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    cases = payload.get("cases")
    if not isinstance(cases, list):
        return {}

    mapped: dict[str, list[Mapping[str, Any]]] = {}
    for case in cases:
        if not isinstance(case, Mapping):
            continue
        case_id = case.get("case_id")
        if isinstance(case_id, str) and case_id:
            mapped.setdefault(case_id, []).append(case)
    return mapped


def _compare_case(
    case_id: str,
    baseline: list[Mapping[str, Any]] | None,
    candidate: list[Mapping[str, Any]] | None,
) -> ComparisonEntry:
    case_type = _case_type(baseline, candidate)
    headline = _headline(baseline) or _headline(candidate)
    baseline_status = _status(baseline)
    candidate_status = _status(candidate)
    delta = _delta(headline, baseline_status, candidate_status)
    headline_reason = None if headline else _headline_reason(baseline, candidate)
    baseline_runtime = _mean_metric(baseline, _runtime_seconds)
    candidate_runtime = _mean_metric(candidate, _runtime_seconds)
    baseline_tokens = _mean_metric(baseline, _token_count)
    candidate_tokens = _mean_metric(candidate, _token_count)
    baseline_tool_calls = _mean_metric(baseline, _tool_call_count)
    candidate_tool_calls = _mean_metric(candidate, _tool_call_count)
    baseline_cost = _mean_metric(baseline, _case_total_cost_usd)
    candidate_cost = _mean_metric(candidate, _case_total_cost_usd)
    return ComparisonEntry(
        case_id=case_id,
        case_type=case_type,
        headline=headline,
        baseline_status=baseline_status,
        candidate_status=candidate_status,
        delta=delta,
        headline_reason=headline_reason,
        baseline_repetitions=_repetition_count(baseline),
        candidate_repetitions=_repetition_count(candidate),
        baseline_stability=_stability(baseline),
        candidate_stability=_stability(candidate),
        baseline_runtime_seconds=baseline_runtime,
        candidate_runtime_seconds=candidate_runtime,
        runtime_delta_seconds=_numeric_delta(baseline_runtime, candidate_runtime),
        baseline_token_count=baseline_tokens,
        candidate_token_count=candidate_tokens,
        token_delta=_numeric_delta(baseline_tokens, candidate_tokens),
        baseline_tool_call_count=baseline_tool_calls,
        candidate_tool_call_count=candidate_tool_calls,
        tool_call_delta=_numeric_delta(baseline_tool_calls, candidate_tool_calls),
        baseline_total_cost_usd=baseline_cost,
        candidate_total_cost_usd=candidate_cost,
        cost_delta_usd=_numeric_delta(baseline_cost, candidate_cost),
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


def _case_type(*groups: list[Mapping[str, Any]] | None) -> str | None:
    for group in groups:
        if not group:
            continue
        for case in group:
            case_type = case.get("case_type")
            if isinstance(case_type, str):
                return case_type
    return None


def _headline(group: list[Mapping[str, Any]] | None) -> bool:
    if not group:
        return False
    return any(case.get("headline") is True for case in group)


def _headline_reason(*groups: list[Mapping[str, Any]] | None) -> str | None:
    reasons = []
    seen: set[str] = set()
    for label, group in zip(("baseline", "candidate"), groups, strict=True):
        if not group:
            continue
        for case in group:
            reason = case.get("headline_reason")
            if isinstance(reason, str) and reason and reason not in seen:
                seen.add(reason)
                reasons.append(f"{label}: {reason}")

    if not reasons:
        return None
    if len(reasons) == 1:
        return reasons[0].split(": ", 1)[1]
    return "; ".join(reasons)


def _status(group: list[Mapping[str, Any]] | None) -> str | None:
    statuses = _statuses(group)
    if not statuses:
        return None
    if len(set(statuses)) == 1:
        return statuses[0]
    return "flaky"


def _statuses(group: list[Mapping[str, Any]] | None) -> list[str]:
    if not group:
        return []
    statuses = []
    for case in group:
        status = case.get("status")
        if isinstance(status, str):
            statuses.append(status)
    return statuses


def _repetition_count(group: list[Mapping[str, Any]] | None) -> int | None:
    if not group:
        return None
    return len(group)


def _stability(group: list[Mapping[str, Any]] | None) -> str | None:
    statuses = _statuses(group)
    if not statuses:
        return None
    if len(set(statuses)) == 1:
        return "stable"
    return "flaky"


def _mean_metric(
    group: list[Mapping[str, Any]] | None,
    extractor: Any,
) -> float | None:
    if not group:
        return None

    values = []
    for case in group:
        value = extractor(case)
        if value is not None:
            values.append(value)
    if not values:
        return None
    return sum(values) / len(values)


def _runtime_seconds(case: Mapping[str, Any]) -> float | None:
    return _number_or_none(
        case.get("runtime_seconds")
        or _advisory_metric(case, "runtime_seconds")
        or _advisory_metric(case, "runtime")
    )


def _token_count(case: Mapping[str, Any]) -> float | None:
    direct = _number_or_none(case.get("token_count") or _advisory_metric(case, "token_count"))
    if direct is not None:
        return direct

    usage = case.get("token_usage") or _advisory_metric(case, "token_usage")
    if isinstance(usage, Mapping):
        token_values = [
            _number_or_none(value) for key, value in usage.items() if "token" in str(key).lower()
        ]
        numbers = [value for value in token_values if value is not None]
        if numbers:
            return sum(numbers)
        all_values = [_number_or_none(value) for value in usage.values()]
        all_numbers = [value for value in all_values if value is not None]
        if all_numbers:
            return sum(all_numbers)
    return _number_or_none(usage)


def _tool_call_count(case: Mapping[str, Any]) -> float | None:
    return _number_or_none(case.get("tool_call_count") or _advisory_metric(case, "tool_call_count"))


def _case_total_cost_usd(case: Mapping[str, Any]) -> float | None:
    direct = _number_or_none(case.get("total_cost_usd"))
    if direct is not None:
        return direct
    return _number_or_none(_advisory_metric(case, "total_cost_usd"))


def _advisory_metric(case: Mapping[str, Any], name: str) -> Any:
    score = case.get("score")
    if not isinstance(score, Mapping):
        return None

    advisory_metrics = score.get("advisory_metrics")
    if not isinstance(advisory_metrics, list):
        return None

    for metric in advisory_metrics:
        if not isinstance(metric, Mapping):
            continue
        if metric.get("name") == name:
            return metric.get("value")
    return None


def _numeric_delta(baseline: float | None, candidate: float | None) -> float | None:
    if baseline is None or candidate is None:
        return None
    return candidate - baseline


def _number_or_none(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _has_cost_fields(entry: ComparisonEntry) -> bool:
    return (
        entry.baseline_total_cost_usd is not None
        or entry.candidate_total_cost_usd is not None
        or entry.cost_delta_usd is not None
    )


def _has_stability_fields(entry: ComparisonEntry) -> bool:
    return (
        entry.baseline_stability == "flaky"
        or entry.candidate_stability == "flaky"
        or (entry.baseline_repetitions is not None and entry.baseline_repetitions > 1)
        or (entry.candidate_repetitions is not None and entry.candidate_repetitions > 1)
    )


def _has_runtime_fields(entry: ComparisonEntry) -> bool:
    return (
        entry.baseline_runtime_seconds is not None
        or entry.candidate_runtime_seconds is not None
        or entry.runtime_delta_seconds is not None
    )


def _has_token_fields(entry: ComparisonEntry) -> bool:
    return (
        entry.baseline_token_count is not None
        or entry.candidate_token_count is not None
        or entry.token_delta is not None
    )


def _has_tool_call_fields(entry: ComparisonEntry) -> bool:
    return (
        entry.baseline_tool_call_count is not None
        or entry.candidate_tool_call_count is not None
        or entry.tool_call_delta is not None
    )


def _format_metric(value: float | int | None) -> str:
    if value is None:
        return ""
    return f"{value:g}"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
