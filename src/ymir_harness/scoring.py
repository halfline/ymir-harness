from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ymir_harness import __version__
from ymir_harness.models import (
    AdvisoryMetric,
    ScoreCollectionEntry,
    ScoreCollectionReport,
    ScoreMetric,
    ScoreReport,
)
from ymir_harness.provenance import collect_provenance

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
    "llm_judge_passed",
    "llm_judge_error",
    "llm_judge_artifact",
)
PATCH_COMMIT_RE = re.compile(r"(?m)^From ([0-9a-fA-F]{40}) ")
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
    primary = _score_case_once(expected, actual, cases_dir=cases_dir)
    if primary.passed:
        return primary

    for index, alternate in enumerate(_alternate_expected_results(expected), start=1):
        alternate_report = _score_case_once(alternate, actual, cases_dir=cases_dir)
        if alternate_report.passed:
            alternate_report.metrics.append(
                ScoreMetric(
                    name="alternate_acceptable_outcome",
                    status="pass",
                    expected=f"alternate #{index}",
                    actual="matched",
                    notes="actual result matched an alternate acceptable outcome",
                )
            )
            return alternate_report

    return primary


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
        _patch_touched_files_metric(
            expected,
            actual,
            cases_dir=cases_dir,
            case_id=case_id,
        ),
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
        _patch_urls_metric(
            expected,
            normalized_actual["patch_urls"],
            cases_dir=cases_dir,
            case_id=case_id,
        ),
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


def _alternate_expected_results(expected: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    alternates = expected.get("alternate_acceptable_outcomes")
    if not isinstance(alternates, list):
        return []

    output = []
    for alternate in alternates:
        if not isinstance(alternate, Mapping):
            continue
        merged = dict(expected)
        merged.pop("alternate_acceptable_outcomes", None)
        merged.update(alternate)
        output.append(merged)
    return output


def score_result_directory(
    cases_dir: Path,
    actual_results_dir: Path,
    *,
    run_id: str | None = None,
    ymir_sha: str | None = None,
    variant: str | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> ScoreCollectionReport:
    cases_dir = cases_dir.resolve()
    actual_results_dir = actual_results_dir.resolve()
    entries = [
        _score_expected_file(expected_path, actual_results_dir, cases_dir)
        for expected_path in _expected_result_files(cases_dir)
    ]
    return ScoreCollectionReport(
        cases_dir=cases_dir,
        actual_results_dir=actual_results_dir,
        entries=entries,
        run_id=run_id,
        ymir_sha=ymir_sha,
        variant=variant,
        harness_version=__version__,
        fixture_checksum=_fixture_checksum(cases_dir),
        provenance=collect_provenance(ymir_sha=ymir_sha, overrides=provenance),
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


def _patch_touched_files_metric(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    cases_dir: Path | None,
    case_id: str,
) -> ScoreMetric:
    expected_files = _normalize_file_list(expected.get("patch_touched_files"))
    if not expected_files and cases_dir is not None:
        expected_files = _reference_patch_touched_files(cases_dir, case_id)

    actual_files = _normalize_file_list(_actual_result_field(actual, "patch_touched_files"))
    if not actual_files:
        actual_files = _actual_generated_patch_touched_files(actual)

    if not expected_files:
        return ScoreMetric(
            name="patch_touched_files",
            status="skipped",
            expected=expected_files,
            actual=actual_files,
            notes="expected result declares no patch touched-file scope",
        )

    missing = [path for path in expected_files if path not in actual_files]
    unexpected = [path for path in actual_files if path not in expected_files]
    notes = _file_scope_notes(missing, unexpected)
    return ScoreMetric(
        name="patch_touched_files",
        status="pass" if not notes else "fail",
        expected=expected_files,
        actual=actual_files,
        notes=notes,
    )


def _patch_urls_metric(
    expected: Mapping[str, Any],
    actual: Any,
    *,
    cases_dir: Path | None,
    case_id: str,
) -> ScoreMetric:
    exact_metric = _compare_list("patch_urls", expected.get("patch_urls"), actual)
    if exact_metric.status != "fail" or cases_dir is None:
        return exact_metric

    expected_urls = _normalize_list(expected.get("patch_urls"))
    actual_urls = _normalize_list(actual)
    if _actual_patch_urls_cover_expected_commits(cases_dir, case_id, expected_urls, actual_urls):
        return ScoreMetric(
            name="patch_urls",
            status="pass",
            expected=expected_urls,
            actual=actual_urls,
            notes="actual patch URLs include the expected patch commit IDs",
        )
    return exact_metric


def _reference_patch_touched_files(cases_dir: Path, case_id: str) -> list[str]:
    paths: list[str] = []
    for patch_path in sorted(
        (cases_dir / "mock_data").glob(f"*/reference_patches/{case_id}.patch")
    ):
        nested_patch_paths = _nested_patch_touched_files(patch_path)
        if nested_patch_paths:
            paths.extend(nested_patch_paths)
            continue
        touched_paths = _patch_file_touched_paths(patch_path)
        if touched_paths is not None:
            paths.extend(touched_paths)
    return _normalize_file_list(paths)


def _actual_generated_patch_touched_files(actual: Mapping[str, Any]) -> list[str]:
    manifest_patch_artifacts = _manifest_patch_artifacts(actual)
    if manifest_patch_artifacts:
        return _patch_artifacts_touched_files(manifest_patch_artifacts)
    return _patch_artifacts_touched_files(_generated_patch_artifacts(actual))


def _manifest_patch_artifacts(actual: Mapping[str, Any]) -> list[Path]:
    manifest_path = _path_or_none(_actual_result_field(actual, "artifact_manifest"))
    if manifest_path is None:
        return []
    manifest = _load_optional_json_object(manifest_path)
    if manifest is None:
        return []
    captured_files = manifest.get("captured_files")
    if not isinstance(captured_files, Mapping):
        return []
    return [Path(path) for path in _normalize_list(captured_files.get("patch_files"))]


def _generated_patch_artifacts(actual: Mapping[str, Any]) -> list[Path]:
    artifacts = []
    for artifact in _normalize_list(_actual_result_field(actual, "generated_artifacts")):
        artifact_path = Path(artifact)
        if artifact_path.name == "commit.diff":
            continue
        if artifact_path.suffix in {".patch", ".diff"}:
            artifacts.append(artifact_path)
    return artifacts


def _patch_artifacts_touched_files(artifact_paths: list[Path]) -> list[str]:
    paths: list[str] = []
    for artifact_path in artifact_paths:
        if not artifact_path.is_file():
            continue
        touched_paths = _patch_file_touched_paths(artifact_path)
        if touched_paths is not None:
            paths.extend(touched_paths)
    return _normalize_file_list(paths)


def _patch_file_touched_paths(patch_path: Path) -> list[str] | None:
    try:
        completed = subprocess.run(
            ["git", "apply", "--numstat", str(patch_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return _numstat_touched_paths(completed.stdout)


def _nested_patch_touched_files(patch_path: Path) -> list[str]:
    paths: list[str] = []
    for patch_text in _nested_patch_texts(patch_path):
        touched_paths = _patch_text_touched_paths(patch_text)
        if touched_paths is not None:
            paths.extend(touched_paths)
    return _normalize_file_list(paths)


def _nested_patch_texts(patch_path: Path) -> list[str]:
    try:
        lines = patch_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    patch_texts = []
    current: list[str] | None = None
    in_hunk = False
    for line in lines:
        if line.startswith("diff --git "):
            if current:
                patch_texts.append("\n".join(current) + "\n")
            current = [] if _diff_git_target_is_patch(line) else None
            in_hunk = False
            continue
        if current is None:
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk or line.startswith("\\"):
            continue
        if line.startswith("+"):
            current.append(line[1:])
        elif line.startswith(" "):
            current.append(line[1:])
    if current:
        patch_texts.append("\n".join(current) + "\n")
    return patch_texts


def _diff_git_target_is_patch(line: str) -> bool:
    match = re.match(r"^diff --git a/(.+) b/(.+)$", line)
    if match is None:
        return False
    return match.group(2).endswith((".patch", ".diff"))


def _patch_text_touched_paths(patch_text: str) -> list[str] | None:
    try:
        completed = subprocess.run(
            ["git", "apply", "--numstat", "-"],
            check=False,
            input=patch_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return _numstat_touched_paths(completed.stdout)


def _numstat_touched_paths(numstat_output: str) -> list[str] | None:
    paths = []
    for line in numstat_output.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            return None
        path = parts[2].strip()
        if not path:
            return None
        paths.append(path)
    return paths


def _actual_patch_urls_cover_expected_commits(
    cases_dir: Path,
    case_id: str,
    expected_urls: list[str],
    actual_urls: list[str],
) -> bool:
    if not expected_urls or not actual_urls:
        return False

    url_commits = _recorded_patch_commits(cases_dir, case_id)
    if not url_commits:
        return False

    actual_commits = set().union(*(url_commits.get(url, set()) for url in actual_urls))
    if not actual_commits:
        return False

    expected_commits = set().union(*(url_commits.get(url, set()) for url in expected_urls))
    return bool(expected_commits) and expected_commits <= actual_commits


def _recorded_patch_commits(cases_dir: Path, case_id: str) -> dict[str, set[str]]:
    manifest_path = cases_dir / "web_cache" / case_id / "manifest.json"
    manifest = _load_optional_json_object(manifest_path)
    if manifest is None:
        return {}

    recorded_files = manifest.get("recorded_files")
    if not isinstance(recorded_files, Mapping):
        return {}

    output: dict[str, set[str]] = {}
    cache_dir = manifest_path.parent
    for url, relative_path in recorded_files.items():
        if not isinstance(url, str) or not isinstance(relative_path, str):
            continue
        recorded_path = cache_dir / relative_path
        try:
            recorded_path.resolve(strict=False).relative_to(cache_dir.resolve(strict=False))
        except ValueError:
            continue
        if not recorded_path.is_file():
            continue
        commits = {
            match.group(1).lower()
            for match in PATCH_COMMIT_RE.finditer(
                recorded_path.read_text(encoding="utf-8", errors="ignore")
            )
        }
        if commits:
            output[url] = commits
    return output


def _load_optional_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _path_or_none(value: Any) -> Path | None:
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value:
        return Path(value)
    return None


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


def _score_expected_file(
    expected_path: Path,
    actual_results_dir: Path,
    cases_dir: Path,
) -> ScoreCollectionEntry:
    expected = load_json_file(expected_path)
    case_id = _case_id_from_expected_path(expected_path)
    case_type = _string_or_none(expected.get("case_type"))
    case_status = _string_or_none(expected.get("case_status"))
    headline_reason = _headline_exclusion_reason(expected)
    headline = headline_reason is None

    if case_status == "excluded":
        return ScoreCollectionEntry(
            case_id=case_id,
            case_type=case_type,
            case_status=case_status,
            expected_path=expected_path,
            actual_path=None,
            status="skipped",
            headline=False,
            headline_reason=headline_reason,
            reason=_string_or_none(expected.get("case_status_reason")) or "case_status is excluded",
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
            headline_reason=headline_reason,
            reason="actual result file is missing",
        )

    score = score_case(expected, load_json_file(actual_path), cases_dir=cases_dir)
    return ScoreCollectionEntry(
        case_id=case_id,
        case_type=case_type,
        case_status=case_status,
        expected_path=expected_path,
        actual_path=actual_path,
        status="passed" if score.passed else "failed",
        headline=headline,
        headline_reason=headline_reason,
        score=score,
    )


def _expected_result_files(cases_dir: Path) -> list[Path]:
    return sorted((cases_dir / "expected").glob("*.expected.json"))


def _fixture_checksum(cases_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in _fixture_checksum_files(cases_dir):
        relative_path = path.relative_to(cases_dir).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _fixture_checksum_files(cases_dir: Path) -> list[Path]:
    paths: list[Path] = []
    cases_yaml = cases_dir / "cases.yaml"
    if cases_yaml.is_file():
        paths.append(cases_yaml)

    for directory_name in ("expected", "jiras", "mock_data", "web_cache", "source_cache"):
        directory = cases_dir / directory_name
        if not directory.is_dir():
            continue
        paths.extend(path for path in directory.rglob("*") if path.is_file())

    return sorted(paths, key=lambda path: path.relative_to(cases_dir).as_posix())


def _find_actual_result_file(actual_results_dir: Path, case_id: str) -> Path | None:
    for name in (f"{case_id}.actual.json", f"{case_id}.json"):
        path = actual_results_dir / name
        if path.is_file():
            return path
    return None


def _case_id_from_expected_path(expected_path: Path) -> str:
    return expected_path.name.removesuffix(".expected.json")


def _headline_exclusion_reason(expected: Mapping[str, Any]) -> str | None:
    case_status = expected.get("case_status", "active")
    if case_status == "excluded":
        return "case_status is excluded"
    if case_status == "quarantined":
        return "case_status is quarantined"
    if expected.get("ground_truth_confidence") == "low":
        return "ground_truth_confidence is low"
    if expected.get("answer_leakage") == "explicit":
        return "answer_leakage is explicit"
    if expected.get("network_mode") == "live_non_reproducible":
        return "network_mode is live_non_reproducible"
    return None


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
