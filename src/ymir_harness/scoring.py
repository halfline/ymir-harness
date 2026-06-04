from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ymir_harness.models import ScoreMetric, ScoreReport


def load_json_file(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"{path} must contain a JSON object"
        raise ValueError(msg)
    return data


def score_case(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> ScoreReport:
    case_id = str(expected.get("case_id") or actual.get("case_id") or "")
    case_type = _string_or_none(expected.get("case_type") or actual.get("case_type"))
    normalized_actual = normalize_actual_result(actual)

    metrics = [
        _compare("case_id", expected.get("case_id"), actual.get("case_id") or case_id),
        _compare(
            "case_type",
            expected.get("case_type"),
            actual.get("case_type"),
            optional=True,
            skip_missing_actual=True,
        ),
        _compare(
            "resolution",
            _normalize_token(expected.get("resolution")),
            normalized_actual["resolution"],
        ),
        _compare("package", expected.get("package"), normalized_actual["package"]),
        _compare(
            "target_branch",
            expected.get("target_branch") or expected.get("fix_version"),
            normalized_actual["target_branch"],
            optional=True,
        ),
        _compare_list("cve_ids", expected.get("cve_ids"), normalized_actual["cve_ids"]),
        _compare_list("patch_urls", expected.get("patch_urls"), normalized_actual["patch_urls"]),
    ]

    if actual.get("error") or actual.get("crash"):
        metrics.append(
            ScoreMetric(
                name="agent_crash",
                status="fail",
                expected=None,
                actual=actual.get("error") or actual.get("crash"),
                notes="actual result contains an error/crash field",
            )
        )

    return ScoreReport(case_id=case_id, case_type=case_type, metrics=metrics)


def normalize_actual_result(actual: Mapping[str, Any]) -> dict[str, Any]:
    data = actual.get("data")
    nested = data if isinstance(data, Mapping) else {}

    return {
        "resolution": _normalize_token(actual.get("resolution")),
        "package": actual.get("package") or nested.get("package"),
        "target_branch": (
            actual.get("target_branch")
            or actual.get("fix_version")
            or actual.get("dist_git_branch")
            or nested.get("fix_version")
            or nested.get("target_branch")
            or nested.get("dist_git_branch")
        ),
        "cve_ids": _normalize_cve_ids(actual, nested),
        "patch_urls": _normalize_list(actual.get("patch_urls") or nested.get("patch_urls")),
    }


def _compare(
    name: str,
    expected: Any,
    actual: Any,
    *,
    optional: bool = False,
    skip_missing_actual: bool = False,
) -> ScoreMetric:
    if optional and (expected is None or (skip_missing_actual and actual is None)):
        return ScoreMetric(name=name, status="skipped", expected=expected, actual=actual)
    if expected == actual:
        return ScoreMetric(name=name, status="pass", expected=expected, actual=actual)
    return ScoreMetric(name=name, status="fail", expected=expected, actual=actual)


def _compare_list(name: str, expected: Any, actual: Any) -> ScoreMetric:
    if expected is None:
        return ScoreMetric(name=name, status="skipped", expected=expected, actual=actual)
    expected_values = _normalize_list(expected)
    actual_values = _normalize_list(actual)
    if expected_values == actual_values:
        return ScoreMetric(name=name, status="pass", expected=expected_values, actual=actual_values)
    return ScoreMetric(name=name, status="fail", expected=expected_values, actual=actual_values)


def _normalize_cve_ids(actual: Mapping[str, Any], nested: Mapping[str, Any]) -> list[str]:
    values = actual.get("cve_ids")
    if values is None:
        values = nested.get("cve_ids")
    if values is None:
        values = actual.get("cve_id")
    if values is None:
        values = nested.get("cve_id")
    return _normalize_list(values)


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _normalize_token(value: Any) -> str | None:
    if value is None:
        return None
    token = str(value).strip()
    if "." in token:
        token = token.rsplit(".", maxsplit=1)[-1]
    return token.lower().replace("-", "_")


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
