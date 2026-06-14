from __future__ import annotations

import hashlib
import json
import stat
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


SOURCE_ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tzst",
    ".zip",
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
        _validate_source_cache(cases_dir, expected, expected_path, result, workflow)


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



def _validate_source_cache(
    cases_dir: Path,
    expected: Mapping[str, Any],
    expected_path: Path,
    result: CaseValidationResult,
    workflow: str | None,
) -> None:
    if not _workflow_requires_source_cache(workflow, expected):
        return

    source_cache_dir = cases_dir / "source_cache" / result.case_id
    if not source_cache_dir.is_dir():
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case must include source_cache directory",
                case_id=result.case_id,
                path=str(source_cache_dir),
            )
        )
        return

    if not any(source_cache_dir.iterdir()):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case source_cache directory is empty",
                case_id=result.case_id,
                path=str(source_cache_dir),
            )
        )

    _validate_required_source_cache_files(source_cache_dir, expected, expected_path, result)
    _validate_source_cache_checksums(source_cache_dir, expected, expected_path, result)

    upstream_dir = source_cache_dir / "upstream"
    if not upstream_dir.is_dir():
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case source_cache must include upstream directory",
                case_id=result.case_id,
                path=str(upstream_dir),
            )
        )
        return
    if not any(upstream_dir.iterdir()):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case source_cache upstream directory is empty",
                case_id=result.case_id,
                path=str(upstream_dir),
            )
        )

    if not _contains_upstream_source(upstream_dir):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message=(
                    "implementation case source_cache upstream must include "
                    "a git clone or source archive"
                ),
                case_id=result.case_id,
                path=str(upstream_dir),
            )
        )

    _validate_upstream_source_archives(upstream_dir, result)

    if expected.get("backport_source") == "distgit":
        return

    lookaside_dir = source_cache_dir / "lookaside"
    if not lookaside_dir.is_dir():
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case source_cache must include lookaside directory",
                case_id=result.case_id,
                path=str(lookaside_dir),
            )
        )
        return

    if not any(lookaside_dir.iterdir()):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case source_cache lookaside directory is empty",
                case_id=result.case_id,
                path=str(lookaside_dir),
            )
        )
        return

    if not _lookaside_artifacts(lookaside_dir):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="implementation case source_cache lookaside must include artifact files",
                case_id=result.case_id,
                path=str(lookaside_dir),
            )
        )
        return

    _validate_lookaside_artifacts(lookaside_dir, result)


def _validate_required_source_cache_files(
    source_cache_dir: Path,
    expected: Mapping[str, Any],
    expected_path: Path,
    result: CaseValidationResult,
) -> None:
    required_files = expected.get("required_source_cache_files")
    if required_files is None:
        return

    if not isinstance(required_files, list):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="required_source_cache_files must be a list",
                case_id=result.case_id,
                path=str(expected_path),
            )
        )
        return

    for relative_path in required_files:
        if not isinstance(relative_path, str) or not relative_path:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message="required_source_cache_files entries must be non-empty strings",
                    case_id=result.case_id,
                    path=str(expected_path),
                )
            )
            continue

        source_path = _source_cache_relative_path(source_cache_dir, relative_path)
        if source_path is None:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"required source cache file path escapes case directory: {relative_path}",
                    case_id=result.case_id,
                    path=str(expected_path),
                )
            )
            continue

        if not source_path.is_file():
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"required source cache file is missing: {relative_path}",
                    case_id=result.case_id,
                    path=str(source_path),
                )
            )
            continue

        if not _has_read_permission(source_path):
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"required source cache file is not readable: {relative_path}",
                    case_id=result.case_id,
                    path=str(source_path),
                )
            )


def _validate_source_cache_checksums(
    source_cache_dir: Path,
    expected: Mapping[str, Any],
    expected_path: Path,
    result: CaseValidationResult,
) -> None:
    checksums = expected.get("source_cache_checksums")
    if checksums is None:
        return

    if not isinstance(checksums, Mapping):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="source_cache_incomplete",
                message="source_cache_checksums must be an object",
                case_id=result.case_id,
                path=str(expected_path),
            )
        )
        return

    for relative_path, expected_checksum in checksums.items():
        if not isinstance(relative_path, str) or not relative_path:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message="source_cache_checksums paths must be non-empty strings",
                    case_id=result.case_id,
                    path=str(expected_path),
                )
            )
            continue

        digest = _parse_sha256_checksum(expected_checksum)
        if digest is None:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message="source_cache_checksums values must use sha256:<hex>",
                    case_id=result.case_id,
                    path=str(expected_path),
                )
            )
            continue

        source_path = _source_cache_relative_path(source_cache_dir, relative_path)
        if source_path is None:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"source cache checksum path escapes case directory: {relative_path}",
                    case_id=result.case_id,
                    path=str(expected_path),
                )
            )
            continue

        if not source_path.is_file():
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"source cache checksum file is missing: {relative_path}",
                    case_id=result.case_id,
                    path=str(source_path),
                )
            )
            continue

        if not _has_read_permission(source_path):
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"source cache checksum file is not readable: {relative_path}",
                    case_id=result.case_id,
                    path=str(source_path),
                )
            )
            continue

        actual_checksum = _sha256_file(source_path)
        if actual_checksum != digest:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message=f"source cache checksum mismatch: {relative_path}",
                    case_id=result.case_id,
                    path=str(source_path),
                )
            )


def _parse_sha256_checksum(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    prefix = "sha256:"
    if not value.startswith(prefix):
        return None

    digest = value.removeprefix(prefix).lower()
    if len(digest) != 64:
        return None
    if any(char not in "0123456789abcdef" for char in digest):
        return None
    return digest


def _source_cache_relative_path(source_cache_dir: Path, relative_path: str) -> Path | None:
    artifact_path = source_cache_dir / relative_path
    try:
        artifact_path.resolve(strict=False).relative_to(source_cache_dir.resolve(strict=False))
    except ValueError:
        return None
    return artifact_path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_upstream_source_archives(
    upstream_dir: Path,
    result: CaseValidationResult,
) -> None:
    for archive_path in _upstream_source_archives(upstream_dir):
        if not _has_read_permission(archive_path):
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message="implementation case source archive is not readable",
                    case_id=result.case_id,
                    path=str(archive_path),
                )
            )


def _validate_lookaside_artifacts(
    lookaside_dir: Path,
    result: CaseValidationResult,
) -> None:
    for artifact_path in _lookaside_artifacts(lookaside_dir):
        if not _has_read_permission(artifact_path):
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="source_cache_incomplete",
                    message="implementation case lookaside artifact is not readable",
                    case_id=result.case_id,
                    path=str(artifact_path),
                )
            )


def _lookaside_artifacts(lookaside_dir: Path) -> list[Path]:
    return [child for child in lookaside_dir.iterdir() if child.is_file()]


def _contains_upstream_source(upstream_dir: Path) -> bool:
    if _is_git_checkout(upstream_dir) or _is_bare_git_repository(upstream_dir):
        return True

    for child in upstream_dir.iterdir():
        if child.is_file() and _is_source_archive(child):
            return True
        if child.is_dir() and (_is_git_checkout(child) or _is_bare_git_repository(child)):
            return True

    return False


def _upstream_source_archives(upstream_dir: Path) -> list[Path]:
    return [
        child for child in upstream_dir.iterdir() if child.is_file() and _is_source_archive(child)
    ]


def _is_source_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in SOURCE_ARCHIVE_SUFFIXES)


def _has_read_permission(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False

    return bool(mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH))


def _is_git_checkout(path: Path) -> bool:
    return (path / ".git").exists()


def _is_bare_git_repository(path: Path) -> bool:
    return (path / "HEAD").is_file() and (path / "objects").is_dir()


def _implementation_case_requires_source_cache(expected: Mapping[str, Any]) -> bool:
    if expected.get("requires_source_cache") is False:
        return False
    return expected.get("resolution") in {"backport", "rebase", "rebuild"}


def _workflow_requires_source_cache(workflow: str | None, expected: Mapping[str, Any]) -> bool:
    if workflow == "ymir-triage":
        return False
    return _implementation_case_requires_source_cache(expected)



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
