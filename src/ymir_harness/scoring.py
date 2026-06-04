from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ymir_harness.models import (
    ScoreCollectionEntry,
    ScoreCollectionReport,
    ScoreMetric,
    ScoreReport,
)


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
            expected.get("target_branch") or expected.get("fix_version"),
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

    return ScoreReport(case_id=case_id, case_type=case_type, metrics=metrics)


def score_result_directory(
    cases_dir: Path,
    actual_results_dir: Path,
    *,
    run_id: str | None = None,
    ymir_sha: str | None = None,
    variant: str | None = None,
) -> ScoreCollectionReport:
    cases_dir = cases_dir.resolve()
    actual_results_dir = actual_results_dir.resolve()
    entries = [
        _score_expected_file(expected_path, actual_results_dir)
        for expected_path in _expected_result_files(cases_dir)
    ]
    return ScoreCollectionReport(
        cases_dir=cases_dir,
        actual_results_dir=actual_results_dir,
        entries=entries,
        run_id=run_id,
        ymir_sha=ymir_sha,
        variant=variant,
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


def _score_expected_file(expected_path: Path, actual_results_dir: Path) -> ScoreCollectionEntry:
    expected = load_json_file(expected_path)
    case_id = _case_id_from_expected_path(expected_path)
    case_type = _string_or_none(expected.get("case_type"))
    case_status = _string_or_none(expected.get("case_status"))
    headline = _is_headline_case(expected)

    if case_status == "excluded":
        return ScoreCollectionEntry(
            case_id=case_id,
            case_type=case_type,
            case_status=case_status,
            expected_path=expected_path,
            actual_path=None,
            status="skipped",
            headline=False,
            reason="case_status is excluded",
        )

    actual_path = _find_actual_result_file(actual_results_dir, case_id)
    if actual_path is None:
        return ScoreCollectionEntry(
            case_id=case_id,
            case_type=case_type,
            case_status=case_status,
            expected_path=expected_path,
            actual_path=None,
            status="missing",
            headline=headline,
            reason="actual result file is missing",
        )

    score = score_case(expected, load_json_file(actual_path))
    return ScoreCollectionEntry(
        case_id=case_id,
        case_type=case_type,
        case_status=case_status,
        expected_path=expected_path,
        actual_path=actual_path,
        status="passed" if score.passed else "failed",
        headline=headline,
        score=score,
    )


def _expected_result_files(cases_dir: Path) -> list[Path]:
    return sorted((cases_dir / "expected").glob("*.expected.json"))


def _find_actual_result_file(actual_results_dir: Path, case_id: str) -> Path | None:
    for name in (f"{case_id}.actual.json", f"{case_id}.json"):
        path = actual_results_dir / name
        if path.is_file():
            return path
    return None


def _case_id_from_expected_path(expected_path: Path) -> str:
    return expected_path.name.removesuffix(".expected.json")


def _is_headline_case(expected: Mapping[str, Any]) -> bool:
    return (
        expected.get("case_status", "active") == "active"
        and expected.get("ground_truth_confidence") != "low"
        and expected.get("answer_leakage") != "explicit"
        and expected.get("network_mode") != "live_non_reproducible"
    )


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
