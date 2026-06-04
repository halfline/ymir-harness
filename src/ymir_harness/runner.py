from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from ymir_harness import __version__
from ymir_harness.models import RunCaseResult, RunReport, ValidationIssue, ValidationReport
from ymir_harness.scoring import _fixture_checksum

RUNNER_NOT_WIRED_REASON = "workflow adapters are not wired yet"


def default_results_dir(cases_dir: Path, run_id: str) -> Path:
    return cases_dir / "reports" / "runs" / run_id


def actual_result_path(results_dir: Path, case_id: str, repetition: int) -> Path:
    return results_dir / f"repeat-{repetition}" / "actual-results" / f"{case_id}.actual.json"


def load_case_manifest(cases_dir: Path) -> tuple[list[str], list[ValidationIssue]]:
    manifest_path = cases_dir / "cases.yaml"
    if not manifest_path.is_file():
        return [], []

    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [], [_manifest_issue(manifest_path, f"invalid cases.yaml: {exc}")]

    if data is None:
        return [], []

    entries = data.get("cases") if isinstance(data, Mapping) else data
    if not isinstance(entries, list):
        return [], [_manifest_issue(manifest_path, "cases.yaml must contain a list")]

    case_ids = []
    issues = []
    for index, entry in enumerate(entries):
        case_id = _manifest_case_id(entry)
        if case_id is None:
            issues.append(
                _manifest_issue(
                    manifest_path,
                    f"cases.yaml entry {index} must be a case id or object with case_id",
                )
            )
            continue
        case_ids.append(case_id)

    return case_ids, issues


def append_global_issues(
    report: ValidationReport,
    issues: Sequence[ValidationIssue],
) -> ValidationReport:
    if not issues:
        return report
    return ValidationReport(
        cases_dir=report.cases_dir,
        phase=report.phase,
        cases=report.cases,
        global_issues=[*report.global_issues, *issues],
    )


def select_validation_cases(
    report: ValidationReport,
    case_ids: Sequence[str],
) -> ValidationReport:
    selected_ids = list(dict.fromkeys(case_ids))
    if not selected_ids:
        return report

    cases_by_id = {case.case_id: case for case in report.cases}
    selected_cases = []
    global_issues = list(report.global_issues)
    for case_id in selected_ids:
        case = cases_by_id.get(case_id)
        if case is None:
            global_issues.append(
                ValidationIssue(
                    severity="error",
                    category="missing_metadata",
                    message="requested case was not found",
                    case_id=case_id,
                )
            )
            continue
        selected_cases.append(case)

    return ValidationReport(
        cases_dir=report.cases_dir,
        phase=report.phase,
        cases=selected_cases,
        global_issues=global_issues,
    )


def _manifest_case_id(entry: Any) -> str | None:
    if isinstance(entry, str):
        case_id = entry.strip()
        return case_id or None
    if isinstance(entry, Mapping):
        value = entry.get("case_id")
        if isinstance(value, str):
            case_id = value.strip()
            return case_id or None
    return None


def _manifest_issue(path: Path, message: str) -> ValidationIssue:
    return ValidationIssue(
        severity="error",
        category="schema_mismatch",
        message=message,
        path=str(path),
    )


def build_run_report(
    cases_dir: Path,
    results_dir: Path,
    *,
    validation_report: ValidationReport,
    run_id: str,
    variant: str,
    ymir_sha: str | None = None,
    features: Sequence[str] = (),
    repeat: int = 1,
) -> RunReport:
    cases_dir = cases_dir.resolve()
    results_dir = results_dir.resolve()
    return RunReport(
        cases_dir=cases_dir,
        results_dir=results_dir,
        entries=[
            _run_case_result(
                cases_dir,
                case.case_id,
                case.case_type,
                case.status,
                repetition,
                results_dir,
            )
            for repetition in range(1, repeat + 1)
            for case in validation_report.cases
        ],
        run_id=run_id,
        variant=variant,
        ymir_sha=ymir_sha,
        harness_version=__version__,
        fixture_checksum=_fixture_checksum(cases_dir),
        features=list(features),
        repeat=repeat,
    )


def _run_case_result(
    cases_dir: Path,
    case_id: str,
    case_type: str | None,
    validation_status: str,
    repetition: int,
    results_dir: Path,
) -> RunCaseResult:
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    if validation_status == "skipped":
        return RunCaseResult(
            case_id=case_id,
            case_type=case_type,
            status="skipped",
            repetition=repetition,
            expected_path=expected_path if expected_path.is_file() else None,
            reason="case is excluded by fixture metadata",
        )

    return RunCaseResult(
        case_id=case_id,
        case_type=case_type,
        status="not_run",
        repetition=repetition,
        expected_path=expected_path if expected_path.is_file() else None,
        actual_path=actual_result_path(results_dir, case_id, repetition),
        reason=RUNNER_NOT_WIRED_REASON,
    )
