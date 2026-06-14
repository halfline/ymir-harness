from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ymir_harness.models import (
    ALLOWED_ANSWER_LEAKAGE,
    ALLOWED_BACKPORT_SOURCES,
    ALLOWED_CASE_STATUSES,
    ALLOWED_CASE_TYPES,
    ALLOWED_EXPECTED_BASES,
    ALLOWED_GROUND_TRUTH_CONFIDENCE,
    ALLOWED_NETWORK_MODES,
    ALLOWED_RESOLUTIONS,
    SUPPORTED_SCHEMA_VERSIONS,
    CaseValidationResult,
    ValidationIssue,
    ValidationReport,
)





def validate_case_directory(
    cases_dir: Path,
    *,
    workflow: str | None = None,
) -> ValidationReport:
    cases_dir = cases_dir.resolve()
    report = ValidationReport(cases_dir=cases_dir)
    if not cases_dir.is_dir():
        report.global_issues.append(
            ValidationIssue(
                severity="error",
                category="missing_metadata",
                message="cases directory does not exist or is not a directory",
                path=str(cases_dir),
            )
        )
        return report

    case_ids = _discover_case_ids(cases_dir)
    if not case_ids:
        report.global_issues.append(
            ValidationIssue(
                severity="error",
                category="missing_metadata",
                message="no benchmark cases found",
                path=str(cases_dir),
            )
        )
        return report

    for case_id in case_ids:
        case_result = _validate_case(cases_dir, case_id, workflow)
        case_result.finalize()
        report.cases.append(case_result)

    return report


def _validate_case(
    cases_dir: Path,
    case_id: str,
    workflow: str | None,
) -> CaseValidationResult:
    result = CaseValidationResult(case_id=case_id)
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected = _load_json_object(expected_path, result, required=True)
    mock_paths = sorted((cases_dir / "mock_data").glob(f"*/{case_id}.json"))

    if expected is not None:
        _validate_expected_metadata(expected, expected_path, result)
        result.case_type = _string_or_none(expected.get("case_type"))
        result.case_status = _string_or_none(expected.get("case_status"))


    return result


def _discover_case_ids(cases_dir: Path) -> list[str]:
    case_ids: set[str] = set()

    for path in (cases_dir / "expected").glob("*.expected.json"):
        case_ids.add(path.name.removesuffix(".expected.json"))

    for path in (cases_dir / "mock_data").glob("*/*.json"):
        case_ids.add(path.stem)

    for path in (cases_dir / "web_cache").glob("*/manifest.json"):
        case_ids.add(path.parent.name)

    for path in (cases_dir / "jiras").glob("*"):
        if path.is_dir():
            case_ids.add(path.name)

    return sorted(case_ids)


def _load_json_object(
    path: Path,
    result: CaseValidationResult,
    *,
    required: bool,
) -> dict[str, Any] | None:
    if not path.is_file():
        if required:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="missing_metadata",
                    message="required JSON file is missing",
                    case_id=result.case_id,
                    path=str(path),
                )
            )
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="schema_mismatch",
                message=f"invalid JSON: {exc.msg}",
                case_id=result.case_id,
                path=str(path),
            )
        )
        return None

    if not isinstance(data, dict):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="schema_mismatch",
                message="JSON file must contain an object",
                case_id=result.case_id,
                path=str(path),
            )
        )
        return None

    return data


def _validate_expected_metadata(
    expected: Mapping[str, Any],
    expected_path: Path,
    result: CaseValidationResult,
) -> None:
    _require_schema_metadata(expected, expected_path, result, strict=True)
    _require_equal(expected.get("case_id"), result.case_id, "case_id", expected_path, result)

    _validate_allowed_value(
        expected.get("case_type"),
        ALLOWED_CASE_TYPES,
        "case_type",
        expected_path,
        result,
        required=True,
    )
    _validate_allowed_value(
        expected.get("resolution"),
        ALLOWED_RESOLUTIONS,
        "resolution",
        expected_path,
        result,
        required=True,
    )

    _require_field(expected, "package", expected_path, result)
    if expected.get("resolution") in {"backport", "rebase", "rebuild"}:
        if expected.get("target_branch") is None and expected.get("fix_version") is None:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="missing_metadata",
                    message="expected result must include target_branch or fix_version",
                    case_id=result.case_id,
                    path=str(expected_path),
                )
            )

    _validate_allowed_value(
        expected.get("expected_basis"),
        ALLOWED_EXPECTED_BASES,
        "expected_basis",
        expected_path,
        result,
        required=True,
    )
    _validate_allowed_value(
        expected.get("ground_truth_confidence"),
        ALLOWED_GROUND_TRUTH_CONFIDENCE,
        "ground_truth_confidence",
        expected_path,
        result,
        required=True,
    )
    if expected.get("ground_truth_confidence") == "low":
        result.issues.append(
            ValidationIssue(
                severity="warning",
                category="ground_truth_ambiguous",
                message="low-confidence cases should be excluded from headline scoring",
                case_id=result.case_id,
                path=str(expected_path),
            )
        )

    _validate_allowed_value(
        expected.get("case_status"),
        ALLOWED_CASE_STATUSES,
        "case_status",
        expected_path,
        result,
        required=True,
    )
    if expected.get("case_status") in {"quarantined", "excluded"} and not expected.get(
        "case_status_reason"
    ):
        result.issues.append(
            ValidationIssue(
                severity="warning",
                category="ground_truth_ambiguous",
                message="quarantined or excluded cases should include case_status_reason",
                case_id=result.case_id,
                path=str(expected_path),
            )
        )

    _validate_allowed_value(
        expected.get("network_mode"),
        ALLOWED_NETWORK_MODES,
        "network_mode",
        expected_path,
        result,
        required=True,
    )

    _validate_allowed_value(
        expected.get("answer_leakage"),
        ALLOWED_ANSWER_LEAKAGE,
        "answer_leakage",
        expected_path,
        result,
        required=True,
    )
    if expected.get("answer_leakage") == "explicit" and expected.get("case_status") == "active":
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="ground_truth_ambiguous",
                message="explicit answer leakage cases must be quarantined or excluded",
                case_id=result.case_id,
                path=str(expected_path),
            )
        )

    _validate_allowed_value(
        expected.get("backport_source"),
        ALLOWED_BACKPORT_SOURCES,
        "backport_source",
        expected_path,
        result,
        required=False,
    )






def _require_schema_metadata(
    data: Mapping[str, Any],
    path: Path,
    result: CaseValidationResult,
    *,
    strict: bool,
) -> None:
    missing = [
        field for field in ("schema_version", "case_id", "case_type") if data.get(field) is None
    ]
    if missing:
        result.issues.append(
            ValidationIssue(
                severity="error" if strict else "warning",
                category="missing_metadata",
                message=f"missing schema metadata: {', '.join(missing)}",
                case_id=result.case_id,
                path=str(path),
            )
        )
        return

    schema_version = data.get("schema_version")
    if not isinstance(schema_version, int) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="schema_mismatch",
                message=f"unsupported schema_version: {schema_version!r}",
                case_id=result.case_id,
                path=str(path),
            )
        )


def _require_field(
    data: Mapping[str, Any],
    field: str,
    path: Path,
    result: CaseValidationResult,
    *,
    context: str | None = None,
) -> None:
    if data.get(field) is None:
        prefix = f"{context} " if context else ""
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="missing_metadata",
                message=f"{prefix}missing required field: {field}",
                case_id=result.case_id,
                path=str(path),
            )
        )


def _validate_allowed_value(
    value: Any,
    allowed: set[str],
    field: str,
    path: Path,
    result: CaseValidationResult,
    *,
    required: bool,
    missing_severity: str = "error",
) -> None:
    if value is None:
        if required:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="missing_metadata",
                    message=f"missing required field: {field}",
                    case_id=result.case_id,
                    path=str(path),
                )
            )
        elif missing_severity == "warning":
            result.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="missing_metadata",
                    message=f"missing recommended field: {field}",
                    case_id=result.case_id,
                    path=str(path),
                )
            )
        return

    if not isinstance(value, str) or value not in allowed:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="schema_mismatch",
                message=f"{field} must be one of {sorted(allowed)!r}; got {value!r}",
                case_id=result.case_id,
                path=str(path),
            )
        )


def _require_equal(
    actual: Any,
    expected: Any,
    field: str,
    path: Path,
    result: CaseValidationResult,
) -> None:
    if actual != expected:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="schema_mismatch",
                message=f"{field} mismatch: expected {expected!r}, got {actual!r}",
                case_id=result.case_id,
                path=str(path),
            )
        )


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
