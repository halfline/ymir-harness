from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ymir_harness import __version__
from ymir_harness.models import (
    RunCaseResult,
    RunCaseStatus,
    RunReport,
    ValidationIssue,
    ValidationReport,
)
from ymir_harness.scoring import _fixture_checksum

RUNNER_NOT_WIRED_REASON = "workflow adapters are not wired yet"
NO_WRITE_ENVIRONMENT = {
    "DRY_RUN": "true",
    "MOCK_JIRA": "true",
    "JIRA_DRY_RUN": "true",
    "AUTO_CHAIN": "false",
    "SILENT_RUN": "true",
    "GIT_TERMINAL_PROMPT": "0",
}
SENSITIVE_ENVIRONMENT_NAMES = frozenset(
    {
        "GITLAB_PRIVATE_TOKEN",
        "GITLAB_TOKEN",
        "JIRA_API_TOKEN",
        "JIRA_PASSWORD",
        "JIRA_TOKEN",
        "KEYTAB_FILE",
        "KRB5CCNAME",
        "KRB5_KTNAME",
        "KOJI_CONFIG",
        "LOOKASIDE_PASSWORD",
        "LOOKASIDE_TOKEN",
    }
)
RunCaseExecutor = Callable[["RunCaseRequest"], "RunCaseExecution"]


@dataclass(frozen=True)
class RunCaseRequest:
    case_id: str
    case_type: str | None
    repetition: int
    cases_dir: Path
    results_dir: Path
    expected_path: Path
    actual_path: Path
    environment: Mapping[str, str]
    variant: str
    features: tuple[str, ...]


@dataclass(frozen=True)
class RunCaseExecution:
    status: RunCaseStatus
    actual_result: Mapping[str, Any] | None = None
    actual_path: Path | None = None
    reason: str | None = None


def default_results_dir(cases_dir: Path, run_id: str) -> Path:
    return cases_dir / "reports" / "runs" / run_id


def actual_result_path(results_dir: Path, case_id: str, repetition: int) -> Path:
    return results_dir / f"repeat-{repetition}" / "actual-results" / f"{case_id}.actual.json"


def build_no_write_environment(
    cases_dir: Path,
    results_dir: Path,
    *,
    base_env: Mapping[str, str] | None = None,
    case_id: str | None = None,
) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    for name in SENSITIVE_ENVIRONMENT_NAMES:
        env.pop(name, None)

    env.update(NO_WRITE_ENVIRONMENT)
    env["JIRA_MOCK_FILES"] = str((cases_dir / "jiras").resolve())
    env["MOCK_REPOS_DIR"] = str((cases_dir / "mock_data").resolve())
    env.setdefault("GIT_REPO_BASEPATH", str(results_dir.resolve()))
    env["YMIR_BENCHMARK_CASES_DIR"] = str(cases_dir.resolve())
    env["YMIR_BENCHMARK_RESULTS_DIR"] = str(results_dir.resolve())
    if case_id:
        env["YMIR_BENCHMARK_CASE_ID"] = case_id
    else:
        env.pop("YMIR_BENCHMARK_CASE_ID", None)
    return env


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
    executor: RunCaseExecutor | None = None,
    base_env: Mapping[str, str] | None = None,
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
                variant,
                features,
                executor,
                base_env,
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
    variant: str,
    features: Sequence[str],
    executor: RunCaseExecutor | None,
    base_env: Mapping[str, str] | None,
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

    actual_path = actual_result_path(results_dir, case_id, repetition)
    if executor is not None:
        request = RunCaseRequest(
            case_id=case_id,
            case_type=case_type,
            repetition=repetition,
            cases_dir=cases_dir,
            results_dir=results_dir,
            expected_path=expected_path,
            actual_path=actual_path,
            environment=build_no_write_environment(
                cases_dir,
                results_dir,
                base_env=base_env,
                case_id=case_id,
            ),
            variant=variant,
            features=tuple(features),
        )
        try:
            execution = executor(request)
        except Exception as exc:
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="failed",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=actual_path,
                reason=_executor_failure_reason(exc),
            )
        execution_actual_path = execution.actual_path or actual_path
        if execution.actual_result is not None:
            _write_actual_result(execution_actual_path, execution.actual_result)
        return RunCaseResult(
            case_id=case_id,
            case_type=case_type,
            status=execution.status,
            repetition=repetition,
            expected_path=expected_path if expected_path.is_file() else None,
            actual_path=execution_actual_path,
            reason=execution.reason,
        )

    return RunCaseResult(
        case_id=case_id,
        case_type=case_type,
        status="not_run",
        repetition=repetition,
        expected_path=expected_path if expected_path.is_file() else None,
        actual_path=actual_path,
        reason=RUNNER_NOT_WIRED_REASON,
    )


def _executor_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"executor failed: {type(exc).__name__}: {detail}"
    return f"executor failed: {type(exc).__name__}"


def _write_actual_result(path: Path, actual_result: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dict(actual_result), indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")
