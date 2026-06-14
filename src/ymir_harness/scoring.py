from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ymir_harness.models import (
    AdvisoryMetric,
    ScoreMetric,
    ScoreReport,
)

ADVISORY_RESULT_FIELDS = (
    "diff_similarity",
    "rationale_quality",
    "llm_judge_notes",
    "runtime",
    "runtime_seconds",
    "token_usage",
    "iteration_count",
    "tool_call_count",
    "retry_count",
    "total_cost_usd",
)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def load_json_file(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"{path} must contain a JSON object"
        raise ValueError(msg)
    return data


def score_case(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    cases_dir: Path | None = None,
) -> ScoreReport:
    return _score_case_once(expected, actual, cases_dir=cases_dir)


def _score_case_once(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    cases_dir: Path | None,
) -> ScoreReport:
    case_id = str(expected.get("case_id") or actual.get("case_id") or "")
    case_type = _string_or_none(expected.get("case_type") or actual.get("case_type"))
    normalized_actual = normalize_actual_result(actual)

    metrics = [
        _hard_fail_gate(
            "unsafe_operations",
            _unsafe_operations(actual),
            "actual result reports attempted unsafe operations",
        ),
        _hard_fail_gate(
            "replay_violations",
            _replay_violations(actual),
            "actual result reports fixture replay violations",
        ),
        _hard_fail_gate(
            "unrelated_source_changes",
            _unrelated_source_changes(actual),
            "actual result reports unrelated source changes",
        ),
        _required_artifacts_metric(expected, actual),
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
        _compare(
            "affectedness",
            _normalize_affectedness(expected.get("affectedness")),
            _normalize_affectedness(_actual_result_field(actual, "affectedness")),
            optional=True,
        ),
        _compare("package", expected.get("package"), normalized_actual["package"]),
        _compare(
            "target_branch",
            expected.get("target_branch"),
            normalized_actual["target_branch"],
            optional=True,
        ),
        _touched_files_metric(expected, actual),
        _compare_list(
            "spec_patches",
            expected.get("spec_patches"),
            _actual_result_field(actual, "spec_patches"),
        ),
        _compare_list(
            "changelog_entries",
            expected.get("changelog_entries"),
            _actual_result_field(actual, "changelog_entries"),
        ),
        _compare(
            "build_result",
            _normalize_token(expected.get("build_result")),
            _normalize_token(_actual_result_field(actual, "build_result")),
            optional=True,
        ),
        _compare(
            "prep_result",
            _normalize_token(expected.get("prep_result")),
            _normalize_token(_actual_result_field(actual, "prep_result")),
            optional=True,
        ),
        _compare(
            "reference_patch_parse_status",
            _normalize_token(expected.get("reference_patch_parse_status")),
            _normalize_token(_actual_result_field(actual, "reference_patch_parse_status")),
            optional=True,
        ),
        _compare(
            "reference_patch_apply_status",
            _normalize_token(expected.get("reference_patch_apply_status")),
            _normalize_token(_actual_result_field(actual, "reference_patch_apply_status")),
            optional=True,
        ),
        _compare_list("cve_ids", expected.get("cve_ids"), normalized_actual["cve_ids"]),
        _compare_list(
            "dependency_issues",
            expected.get("dependency_issues"),
            _actual_result_field(actual, "dependency_issues"),
        ),
        _compare_list(
            "sibling_issues",
            expected.get("sibling_issues"),
            _actual_result_field(actual, "sibling_issues"),
        ),
        _compare_list(
            "fix_sources",
            expected.get("fix_sources"),
            _actual_result_field(actual, "fix_sources"),
            optional=True,
            skip_missing_actual=True,
        ),
        _compare(
            "backport_source",
            _normalize_token(expected.get("backport_source")),
            normalized_actual["backport_source"],
            optional=True,
        ),
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

    return ScoreReport(
        case_id=case_id,
        case_type=case_type,
        metrics=metrics,
        advisory_metrics=_advisory_metrics(actual),
    )



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
        "backport_source": _normalize_backport_source(actual, nested),
    }


def _hard_fail_gate(name: str, actual: Any, notes: str) -> ScoreMetric:
    expected: list[str] = []
    actual_values = _normalize_list(actual)
    return ScoreMetric(
        name=name,
        status="pass" if actual_values == expected else "fail",
        expected=expected,
        actual=actual_values,
        notes=notes,
    )


def _unsafe_operations(actual: Mapping[str, Any]) -> Any:
    return _actual_result_field(actual, "unsafe_operations")


def _replay_violations(actual: Mapping[str, Any]) -> Any:
    return _actual_result_field(actual, "replay_violations")


def _unrelated_source_changes(actual: Mapping[str, Any]) -> Any:
    return _actual_result_field(actual, "unrelated_source_changes")


def _required_artifacts_metric(
    expected: Mapping[str, Any], actual: Mapping[str, Any]
) -> ScoreMetric:
    required = _normalize_list(expected.get("required_artifacts"))
    generated = _normalize_list(_actual_result_field(actual, "generated_artifacts"))
    if not required:
        return ScoreMetric(
            name="required_artifacts",
            status="skipped",
            expected=required,
            actual=generated,
            notes="expected result declares no required artifacts",
        )

    missing = [artifact for artifact in required if artifact not in generated]
    return ScoreMetric(
        name="required_artifacts",
        status="pass" if not missing else "fail",
        expected=required,
        actual=generated,
        notes=f"missing required artifacts: {', '.join(missing)}" if missing else None,
    )


def _touched_files_metric(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> ScoreMetric:
    expected_files = _normalize_file_list(expected.get("touched_files"))
    actual_files = _normalize_file_list(
        _actual_result_field(actual, "touched_files")
        or _actual_result_field(actual, "changed_files")
    )
    if not expected_files:
        return ScoreMetric(
            name="touched_files",
            status="skipped",
            expected=expected_files,
            actual=actual_files,
            notes="expected result declares no touched file scope",
        )

    missing = [path for path in expected_files if path not in actual_files]
    unexpected = [path for path in actual_files if path not in expected_files]
    notes = _file_scope_notes(missing, unexpected)
    return ScoreMetric(
        name="touched_files",
        status="pass" if not notes else "fail",
        expected=expected_files,
        actual=actual_files,
        notes=notes,
    )



def _file_scope_notes(missing: list[str], unexpected: list[str]) -> str | None:
    parts = []
    if missing:
        parts.append(f"missing touched files: {', '.join(missing)}")
    if unexpected:
        parts.append(f"unexpected touched files: {', '.join(unexpected)}")
    return "; ".join(parts) if parts else None


def _actual_result_field(actual: Mapping[str, Any], name: str) -> Any:
    data = actual.get("data")
    nested = data if isinstance(data, Mapping) else {}
    if actual.get(name) is not None:
        return actual.get(name)
    return nested.get(name)


def _normalize_backport_source(
    actual: Mapping[str, Any],
    nested: Mapping[str, Any],
) -> str | None:
    explicit = _normalize_token(actual.get("backport_source") or nested.get("backport_source"))
    if explicit is not None:
        return explicit
    return _infer_backport_source_from_urls(
        _normalize_list(actual.get("patch_urls") or nested.get("patch_urls"))
    )


def _infer_backport_source_from_urls(urls: Iterable[str]) -> str | None:
    sources = {_backport_source_for_url(url) for url in urls}
    sources.discard(None)
    if not sources:
        return None
    if len(sources) == 1:
        return next(iter(sources))
    return "mixed"


def _backport_source_for_url(url: str) -> str | None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    if hostname == "gitlab.com" and (
        path.startswith("/redhat/rhel/rpms/")
        or path.startswith("/redhat/centos-stream/rpms/")
    ):
        return "distgit"
    if hostname == "src.fedoraproject.org" and path.startswith("/rpms/"):
        return "distgit"
    if parsed.scheme in {"http", "https"} and hostname:
        return "upstream"
    return None


def _advisory_metrics(actual: Mapping[str, Any]) -> list[AdvisoryMetric]:
    metrics: list[AdvisoryMetric] = []
    for name in ADVISORY_RESULT_FIELDS:
        value = _actual_result_field(actual, name)
        if value is not None:
            metrics.append(AdvisoryMetric(name=name, value=value))
    return metrics




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


def _compare_list(
    name: str,
    expected: Any,
    actual: Any,
    *,
    optional: bool = False,
    skip_missing_actual: bool = False,
) -> ScoreMetric:
    if optional and (expected is None or (skip_missing_actual and actual is None)):
        return ScoreMetric(name=name, status="skipped", expected=expected, actual=actual)
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
    normalized = _normalize_list(values)
    if normalized:
        return normalized

    cve_ids = []
    for text in _actual_result_text_values(actual, nested):
        cve_ids.extend(match.group(0).upper() for match in CVE_ID_RE.finditer(text))
    return list(dict.fromkeys(cve_ids))


def _actual_result_text_values(
    actual: Mapping[str, Any],
    nested: Mapping[str, Any],
) -> list[str]:
    return list(_walk_actual_result_text((actual, nested)))


def _walk_actual_result_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_actual_result_text(item)
        return
    if isinstance(value, list | tuple | set):
        for item in value:
            yield from _walk_actual_result_text(item)


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _normalize_file_list(value: Any) -> list[str]:
    return sorted(_normalize_list(value))


def _normalize_token(value: Any) -> str | None:
    if value is None:
        return None
    token = str(value).strip()
    if "." in token:
        token = token.rsplit(".", maxsplit=1)[-1]
    return token.lower().replace("-", "_")


def _normalize_affectedness(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "affected" if value else "not_affected"

    token = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if token in {"true", "yes", "affected", "vulnerable"}:
        return "affected"
    if token in {"false", "no", "not_affected", "unaffected", "not_vulnerable"}:
        return "not_affected"
    return token


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
