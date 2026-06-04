from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ymir_harness.jira_mock import (
    JiraMockMaterializationError,
    build_ymir_jira_mock_issue,
    has_structured_jira_fixture,
    structured_jira_fixture_dir,
)
from ymir_harness.models import (
    ALLOWED_ANSWER_LEAKAGE,
    ALLOWED_CASE_STATUSES,
    ALLOWED_CASE_TYPES,
    ALLOWED_EXPECTED_BASES,
    ALLOWED_GROUND_TRUTH_CONFIDENCE,
    ALLOWED_NETWORK_MODES,
    ALLOWED_REFERENCE_PATCH_MODES,
    ALLOWED_RESOLUTIONS,
    SUPPORTED_SCHEMA_VERSIONS,
    CaseValidationResult,
    ValidationIssue,
    ValidationReport,
)


@dataclass(frozen=True)
class ReferencePatchTarget:
    repo_path: Path
    pre_fix_ref: str
    mock_path: Path


def validate_case_directory(cases_dir: Path, *, phase: int = 1) -> ValidationReport:
    if phase not in {1, 2}:
        msg = f"unsupported validation phase: {phase}"
        raise ValueError(msg)

    cases_dir = cases_dir.resolve()
    report = ValidationReport(cases_dir=cases_dir, phase=phase)
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
        case_result = _validate_case(cases_dir, case_id, phase)
        case_result.finalize()
        report.cases.append(case_result)

    return report


def _validate_case(cases_dir: Path, case_id: str, phase: int) -> CaseValidationResult:
    result = CaseValidationResult(case_id=case_id)
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected = _load_json_object(expected_path, result, required=True)
    mock_paths = sorted((cases_dir / "mock_data").glob(f"*/{case_id}.json"))

    if expected is not None:
        _validate_expected_metadata(expected, expected_path, result, phase)
        result.case_type = _string_or_none(expected.get("case_type"))
        result.case_status = _string_or_none(expected.get("case_status"))
        _validate_network_policy(cases_dir, expected, result, phase)
        _validate_source_cache(cases_dir, expected, result, phase)

    reference_patch_targets = _validate_mock_fixtures(mock_paths, expected, result, phase)

    if expected is not None:
        _validate_reference_patch(cases_dir, expected, result, phase, reference_patch_targets)

    if expected is not None:
        _validate_case_consistency(cases_dir, expected, result)

    _validate_ymir_jira_mock(cases_dir, result)

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
    phase: int,
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

    answer_leakage_required = phase >= 2
    _validate_allowed_value(
        expected.get("answer_leakage"),
        ALLOWED_ANSWER_LEAKAGE,
        "answer_leakage",
        expected_path,
        result,
        required=answer_leakage_required,
        missing_severity="error" if answer_leakage_required else "warning",
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

    if phase >= 2:
        reference_patch_mode_required = _implementation_case_requires_reference_patch(expected)
        _validate_allowed_value(
            expected.get("reference_patch_mode"),
            ALLOWED_REFERENCE_PATCH_MODES,
            "reference_patch_mode",
            expected_path,
            result,
            required=reference_patch_mode_required,
        )


def _validate_network_policy(
    cases_dir: Path,
    expected: Mapping[str, Any],
    result: CaseValidationResult,
    phase: int,
) -> None:
    network_mode = expected.get("network_mode")
    case_status = expected.get("case_status")

    if network_mode == "live_non_reproducible" and case_status == "active":
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="network_policy_invalid",
                message="live network cases must be quarantined or excluded",
                case_id=result.case_id,
            )
        )

    if network_mode == "replay_only":
        _validate_web_cache_manifest(cases_dir, expected, result)
    elif phase >= 2 and network_mode == "network_denied":
        web_manifest = cases_dir / "web_cache" / result.case_id / "manifest.json"
        if web_manifest.exists():
            result.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="network_policy_invalid",
                    message="network_denied case has a web cache manifest that will not be used",
                    case_id=result.case_id,
                    path=str(web_manifest),
                )
            )


def _validate_web_cache_manifest(
    cases_dir: Path,
    expected: Mapping[str, Any],
    result: CaseValidationResult,
) -> None:
    manifest_path = cases_dir / "web_cache" / result.case_id / "manifest.json"
    manifest = _load_json_object(manifest_path, result, required=True)
    if manifest is None:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="web_cache_incomplete",
                message="replay_only case must include web_cache manifest.json",
                case_id=result.case_id,
                path=str(manifest_path),
            )
        )
        return

    _require_schema_metadata(manifest, manifest_path, result, strict=True)
    _require_equal(manifest.get("case_id"), result.case_id, "case_id", manifest_path, result)
    if expected.get("case_type") is not None:
        _require_equal(
            manifest.get("case_type"),
            expected.get("case_type"),
            "case_type",
            manifest_path,
            result,
        )

    required_urls = manifest.get("required_urls")
    recorded_files = manifest.get("recorded_files")
    if not isinstance(required_urls, list):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="web_cache_incomplete",
                message="manifest required_urls must be a list",
                case_id=result.case_id,
                path=str(manifest_path),
            )
        )
        required_urls = []
    if not isinstance(recorded_files, dict):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="web_cache_incomplete",
                message="manifest recorded_files must be an object",
                case_id=result.case_id,
                path=str(manifest_path),
            )
        )
        recorded_files = {}

    for url in required_urls:
        if not isinstance(url, str) or not url:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="web_cache_incomplete",
                    message="manifest required_urls entries must be non-empty strings",
                    case_id=result.case_id,
                    path=str(manifest_path),
                )
            )
            continue
        recorded = recorded_files.get(url)
        if not isinstance(recorded, str) or not recorded:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="web_cache_incomplete",
                    message=f"required URL has no recorded file: {url}",
                    case_id=result.case_id,
                    path=str(manifest_path),
                )
            )
            continue

        recorded_path = manifest_path.parent / recorded
        if not recorded_path.is_file():
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="web_cache_incomplete",
                    message=f"recorded file is missing for URL: {url}",
                    case_id=result.case_id,
                    path=str(recorded_path),
                )
            )
            continue
        if recorded_path.stat().st_size == 0:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="web_cache_incomplete",
                    message=f"recorded file is empty for URL: {url}",
                    case_id=result.case_id,
                    path=str(recorded_path),
                )
            )


def _validate_source_cache(
    cases_dir: Path,
    expected: Mapping[str, Any],
    result: CaseValidationResult,
    phase: int,
) -> None:
    if phase < 2 or not _implementation_case_requires_source_cache(expected):
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


def _implementation_case_requires_source_cache(expected: Mapping[str, Any]) -> bool:
    if expected.get("requires_source_cache") is False:
        return False
    return expected.get("resolution") in {"backport", "rebase", "rebuild"}


def _validate_reference_patch(
    cases_dir: Path,
    expected: Mapping[str, Any],
    result: CaseValidationResult,
    phase: int,
    _source_targets: list[ReferencePatchTarget],
) -> None:
    if phase < 2 or not _implementation_case_requires_reference_patch(expected):
        return

    patch_paths = sorted(
        (cases_dir / "mock_data").glob(
            f"*/reference_patches/{result.case_id}.patch",
        )
    )
    if patch_paths:
        for patch_path in patch_paths:
            touched_paths = _validate_reference_patch_parse(patch_path, result)
            if touched_paths is not None and _reference_patch_should_apply(expected):
                _validate_reference_patch_application(patch_path, _source_targets, result)
        return

    patch_pattern = (
        cases_dir / "mock_data" / "*" / "reference_patches" / (f"{result.case_id}.patch")
    )
    result.issues.append(
        ValidationIssue(
            severity="error",
            category="reference_patch_invalid",
            message="merged_mr implementation case must include reference patch",
            case_id=result.case_id,
            path=str(patch_pattern),
        )
    )


def _implementation_case_requires_reference_patch(expected: Mapping[str, Any]) -> bool:
    if expected.get("expected_basis") != "merged_mr":
        return False
    return expected.get("resolution") in {"backport", "rebase", "rebuild"}


def _reference_patch_should_apply(expected: Mapping[str, Any]) -> bool:
    return expected.get("reference_patch_mode") == "applies"


def _validate_reference_patch_parse(
    patch_path: Path,
    result: CaseValidationResult,
) -> list[str] | None:
    if not patch_path.is_file():
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="reference_patch_invalid",
                message="reference patch path must be a file",
                case_id=result.case_id,
                path=str(patch_path),
            )
        )
        return None

    completed = subprocess.run(
        ["git", "apply", "--numstat", str(patch_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="reference_patch_invalid",
                message="reference patch must parse as a git patch",
                case_id=result.case_id,
                path=str(patch_path),
            )
        )
        return None

    touched_paths = _reference_patch_touched_paths(completed.stdout)
    if not touched_paths:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="reference_patch_invalid",
                message="reference patch touched-file list cannot be extracted",
                case_id=result.case_id,
                path=str(patch_path),
            )
        )
        return None

    return touched_paths


def _reference_patch_touched_paths(numstat_output: str) -> list[str]:
    paths: list[str] = []
    for line in numstat_output.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            return []

        path = parts[2].strip()
        if not path:
            return []

        paths.append(path)

    return paths


def _validate_reference_patch_application(
    patch_path: Path,
    source_targets: list[ReferencePatchTarget],
    result: CaseValidationResult,
) -> None:
    if not source_targets:
        return

    if any(_reference_patch_applies_to_target(patch_path, target) for target in source_targets):
        return

    result.issues.append(
        ValidationIssue(
            severity="error",
            category="reference_patch_invalid",
            message="reference patch must apply to pre-fix source tree",
            case_id=result.case_id,
            path=str(patch_path),
        )
    )


def _reference_patch_applies_to_target(
    patch_path: Path,
    target: ReferencePatchTarget,
) -> bool:
    with tempfile.TemporaryDirectory(prefix="ymir-harness-index-") as temp_dir:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(Path(temp_dir) / "index")

        read_tree = subprocess.run(
            ["git", "-C", str(target.repo_path), "read-tree", target.pre_fix_ref],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
        )
        if read_tree.returncode != 0:
            return False

        completed = subprocess.run(
            ["git", "-C", str(target.repo_path), "apply", "--check", "--cached", str(patch_path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
        )
        return completed.returncode == 0


def _validate_mock_fixtures(
    mock_paths: list[Path],
    expected: Mapping[str, Any] | None,
    result: CaseValidationResult,
    phase: int,
) -> list[ReferencePatchTarget]:
    expected_package = expected.get("package") if expected else None
    expected_case_type = expected.get("case_type") if expected else None
    expected_target_branch = None
    if expected:
        expected_target_branch = expected.get("target_branch") or expected.get("fix_version")
    packages_seen: set[str] = set()
    branches_seen: set[str] = set()
    reference_patch_targets: list[ReferencePatchTarget] = []

    if not mock_paths:
        result.issues.append(
            ValidationIssue(
                severity="warning",
                category="mock_repo_mismatch",
                message="no mock_data fixture found for case",
                case_id=result.case_id,
            )
        )
        return reference_patch_targets

    for mock_path in mock_paths:
        config = _load_json_object(mock_path, result, required=True)
        if config is None:
            continue

        _require_schema_metadata(config, mock_path, result, strict=phase >= 2)
        if config.get("case_id") is not None:
            _require_equal(config.get("case_id"), result.case_id, "case_id", mock_path, result)
        if expected_case_type is not None and config.get("case_type") is not None:
            _require_equal(
                config.get("case_type"), expected_case_type, "case_type", mock_path, result
            )
        branches_seen.update(_zstream_override_branches(config))

        repos = config.get("repos")
        if not isinstance(repos, list) or not repos:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    category="mock_repo_mismatch",
                    message="mock fixture must include a non-empty repos list",
                    case_id=result.case_id,
                    path=str(mock_path),
                )
            )
            continue

        for index, repo in enumerate(repos):
            if not isinstance(repo, dict):
                result.issues.append(
                    ValidationIssue(
                        severity="error",
                        category="mock_repo_mismatch",
                        message=f"repos[{index}] must be an object",
                        case_id=result.case_id,
                        path=str(mock_path),
                    )
                )
                continue
            packages, branches, reference_patch_target = _validate_mock_repo_entry(
                repo, index, mock_path, result
            )
            packages_seen.update(packages)
            branches_seen.update(branches)
            if reference_patch_target is not None:
                reference_patch_targets.append(reference_patch_target)

    if expected_package and packages_seen and expected_package not in packages_seen:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="mock_repo_mismatch",
                message=(
                    "expected.package does not match any mock repo package "
                    f"({expected_package!r} not in {sorted(packages_seen)!r})"
                ),
                case_id=result.case_id,
            )
        )

    if (
        phase >= 2
        and expected_target_branch
        and branches_seen
        and expected_target_branch not in branches_seen
    ):
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="mock_repo_mismatch",
                message=(
                    "expected target_branch or fix_version is not declared by any mock "
                    f"repo branch ({expected_target_branch!r} not in {sorted(branches_seen)!r})"
                ),
                case_id=result.case_id,
            )
        )

    return reference_patch_targets


def _validate_mock_repo_entry(
    repo: Mapping[str, Any],
    index: int,
    mock_path: Path,
    result: CaseValidationResult,
) -> tuple[set[str], set[str], ReferencePatchTarget | None]:
    packages_seen: set[str] = set()
    branches_seen: set[str] = set()
    reference_patch_target = None
    for field in ("package", "remote_url", "pre_fix_ref", "branch"):
        _require_field(repo, field, mock_path, result, context=f"repos[{index}]")

    package = repo.get("package")
    if isinstance(package, str) and package:
        packages_seen.add(package)

    branch = repo.get("branch")
    if isinstance(branch, str) and branch:
        branches_seen.add(branch)

    remote_url = repo.get("remote_url")
    pre_fix_ref = repo.get("pre_fix_ref")
    if isinstance(remote_url, str) and isinstance(pre_fix_ref, str):
        repo_path = _validate_local_pre_fix_ref(remote_url, pre_fix_ref, mock_path, result)
        if repo_path is not None:
            reference_patch_target = ReferencePatchTarget(
                repo_path=repo_path,
                pre_fix_ref=pre_fix_ref,
                mock_path=mock_path,
            )

    return packages_seen, branches_seen, reference_patch_target


def _zstream_override_branches(config: Mapping[str, Any]) -> set[str]:
    override = config.get("zstream_override")
    if not isinstance(override, Mapping):
        return set()
    return {value for value in override.values() if isinstance(value, str) and value}


def _validate_local_pre_fix_ref(
    remote_url: str,
    pre_fix_ref: str,
    mock_path: Path,
    result: CaseValidationResult,
) -> Path | None:
    repo_path = _local_repo_path(remote_url)
    if repo_path is None:
        result.issues.append(
            ValidationIssue(
                severity="warning",
                category="invalid_pre_fix_ref",
                message="pre_fix_ref was not checked because remote_url is not local",
                case_id=result.case_id,
                path=str(mock_path),
            )
        )
        return None

    if not repo_path.exists():
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="invalid_pre_fix_ref",
                message=f"local mock repo does not exist: {repo_path}",
                case_id=result.case_id,
                path=str(mock_path),
            )
        )
        return None

    command = ["git", "-C", str(repo_path), "cat-file", "-e", f"{pre_fix_ref}^{{commit}}"]
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="invalid_pre_fix_ref",
                message=f"pre_fix_ref does not resolve in local repo: {pre_fix_ref}",
                case_id=result.case_id,
                path=str(mock_path),
            )
        )
        return None

    return repo_path


def _local_repo_path(remote_url: str) -> Path | None:
    parsed = urlparse(remote_url)
    if parsed.scheme == "file":
        return Path(parsed.path)
    if parsed.scheme in {"http", "https", "ssh", "git"}:
        return None

    path = Path(remote_url)
    if path.is_absolute() or path.exists():
        return path
    return None


def _validate_case_consistency(
    cases_dir: Path,
    expected: Mapping[str, Any],
    result: CaseValidationResult,
) -> None:
    for json_path in _case_json_paths(cases_dir, result.case_id):
        if json_path.name.endswith(".expected.json"):
            continue
        data = _load_json_object(json_path, result, required=False)
        if data is None:
            continue
        if data.get("case_id") is not None:
            _require_equal(data.get("case_id"), result.case_id, "case_id", json_path, result)
        if data.get("case_type") is not None and expected.get("case_type") is not None:
            _require_equal(
                data.get("case_type"), expected.get("case_type"), "case_type", json_path, result
            )


def _case_json_paths(cases_dir: Path, case_id: str) -> Iterable[Path]:
    yield from (cases_dir / "mock_data").glob(f"*/{case_id}.json")
    manifest = cases_dir / "web_cache" / case_id / "manifest.json"
    if manifest.exists():
        yield manifest
    for jira_file in (cases_dir / "jiras" / case_id).glob("*.json"):
        yield jira_file


def _validate_ymir_jira_mock(cases_dir: Path, result: CaseValidationResult) -> None:
    if not has_structured_jira_fixture(cases_dir, result.case_id):
        return

    try:
        build_ymir_jira_mock_issue(cases_dir, result.case_id)
    except JiraMockMaterializationError as exc:
        result.issues.append(
            ValidationIssue(
                severity="error",
                category="jira_mock_invalid",
                message=str(exc),
                case_id=result.case_id,
                path=str(structured_jira_fixture_dir(cases_dir, result.case_id)),
            )
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
