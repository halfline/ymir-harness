from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ymir_harness import __version__
from ymir_harness.artifacts import artifact_environment
from ymir_harness.enforcement import BenchmarkBoundaryViolation, enforce_benchmark_boundaries
from ymir_harness.jira_mock import (
    JiraMockMaterializationError,
    has_structured_jira_fixture,
    materialize_ymir_jira_mock,
)
from ymir_harness.models import (
    RunCaseResult,
    RunCaseStatus,
    RunReport,
    ScoreReport,
    ValidationIssue,
    ValidationReport,
)
from ymir_harness.mock_repos import MockRepoMaterializationError, materialize_case_mock_repos
from ymir_harness.provenance import collect_provenance
from ymir_harness.safety import detect_replay_violations, detect_unsafe_operations
from ymir_harness.scoring import _fixture_checksum, load_json_file, score_case

RUNNER_NOT_WIRED_REASON = "workflow adapters are not wired yet"
MAX_ITERATIONS_OVERRIDE_ENV = "BENCHMARK_MAX_ITERATIONS_OVERRIDE"
MAX_COST_PER_RUN_ENV = "BENCHMARK_MAX_COST_PER_RUN"
COST_ALERT_THRESHOLD_ENV = "BENCHMARK_COST_ALERT_THRESHOLD"
EVENT_TRACE_FIELDS = ("events", "tool_events", "tool_calls", "trace")
NO_WRITE_ENVIRONMENT = {
    "DRY_RUN": "true",
    "MOCK_JIRA": "true",
    "JIRA_DRY_RUN": "true",
    "JIRA_EMAIL": "ymir-harness@example.invalid",
    "JIRA_TOKEN": "ymir-harness-token",
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


@dataclass(frozen=True)
class ReplayPolicy:
    network_mode: str | None
    manifest_path: Path | None
    recorded_urls: tuple[str, ...] = ()


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
    jira_mock_dir: Path | None = None,
    network_mode: str | None = None,
    replay_manifest_path: Path | None = None,
    recorded_urls: Sequence[str] = (),
) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    for name in SENSITIVE_ENVIRONMENT_NAMES:
        env.pop(name, None)

    env.update(NO_WRITE_ENVIRONMENT)
    env["JIRA_MOCK_FILES"] = str((jira_mock_dir or cases_dir / "jiras").resolve())
    env["MOCK_REPOS_DIR"] = str((cases_dir / "mock_data").resolve())
    env.setdefault("GIT_REPO_BASEPATH", str(results_dir.resolve()))
    env["YMIR_BENCHMARK_CASES_DIR"] = str(cases_dir.resolve())
    env["YMIR_BENCHMARK_RESULTS_DIR"] = str(results_dir.resolve())
    max_iterations = env.get(MAX_ITERATIONS_OVERRIDE_ENV)
    if max_iterations:
        env["BEEAI_MAX_ITERATIONS"] = max_iterations
    if network_mode:
        env["YMIR_BENCHMARK_NETWORK_MODE"] = network_mode
    else:
        env.pop("YMIR_BENCHMARK_NETWORK_MODE", None)
    if replay_manifest_path is not None:
        env["YMIR_BENCHMARK_REPLAY_MANIFEST"] = str(replay_manifest_path.resolve())
    else:
        env.pop("YMIR_BENCHMARK_REPLAY_MANIFEST", None)
    if network_mode in {"replay_only", "network_denied"} or recorded_urls:
        env["YMIR_BENCHMARK_RECORDED_URLS"] = json.dumps(list(recorded_urls))
    else:
        env.pop("YMIR_BENCHMARK_RECORDED_URLS", None)
    if case_id:
        env["YMIR_BENCHMARK_CASE_ID"] = case_id
        env["YMIR_BENCHMARK_WEB_CACHE_DIR"] = str((cases_dir / "web_cache" / case_id).resolve())
        env["YMIR_BENCHMARK_SOURCE_CACHE_DIR"] = str(
            (cases_dir / "source_cache" / case_id).resolve()
        )
    else:
        env.pop("YMIR_BENCHMARK_CASE_ID", None)
        env.pop("YMIR_BENCHMARK_WEB_CACHE_DIR", None)
        env.pop("YMIR_BENCHMARK_SOURCE_CACHE_DIR", None)
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
    provenance: Mapping[str, Any] | None = None,
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
        provenance=collect_provenance(
            base_env=base_env,
            ymir_sha=ymir_sha,
            features=features,
            overrides=provenance,
        ),
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
        expected = _load_expected_for_policy(expected_path)
        replay_policy = _replay_policy(cases_dir, case_id, expected)
        try:
            mock_repo_env = _mock_repo_environment(cases_dir, results_dir, case_id, repetition)
        except MockRepoMaterializationError as exc:
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="failed",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=actual_path,
                reason=_mock_repo_setup_failure_reason(exc),
            )
        try:
            jira_mock_dir = _jira_mock_directory(cases_dir, results_dir, case_id, repetition)
        except JiraMockMaterializationError as exc:
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="failed",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=actual_path,
                reason=_jira_mock_setup_failure_reason(exc),
            )
        environment = build_no_write_environment(
            cases_dir,
            results_dir,
            base_env=base_env,
            case_id=case_id,
            jira_mock_dir=jira_mock_dir,
            network_mode=replay_policy.network_mode,
            replay_manifest_path=replay_policy.manifest_path,
            recorded_urls=replay_policy.recorded_urls,
        )
        environment.update(artifact_environment(actual_path))
        environment.update(mock_repo_env)
        request = RunCaseRequest(
            case_id=case_id,
            case_type=case_type,
            repetition=repetition,
            cases_dir=cases_dir,
            results_dir=results_dir,
            expected_path=expected_path,
            actual_path=actual_path,
            environment=environment,
            variant=variant,
            features=tuple(features),
        )
        try:
            started_at = time.monotonic()
            with enforce_benchmark_boundaries(request.environment):
                execution = executor(request)
            runtime_seconds = time.monotonic() - started_at
        except BenchmarkBoundaryViolation as exc:
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="failed",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=actual_path,
                reason=f"benchmark boundary blocked: {exc}",
            )
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
        score = None
        actual_result = _apply_run_policies(
            cases_dir,
            case_id,
            expected,
            execution.actual_result,
        )
        if actual_result is not None:
            try:
                _write_actual_result(execution_actual_path, actual_result)
            except Exception as exc:
                return RunCaseResult(
                    case_id=case_id,
                    case_type=case_type,
                    status="failed",
                    repetition=repetition,
                    expected_path=expected_path if expected_path.is_file() else None,
                    actual_path=execution_actual_path,
                    reason=_actual_result_write_failure_reason(exc),
                )
            try:
                score = _score_actual_result(expected_path, actual_result)
            except Exception as exc:
                return RunCaseResult(
                    case_id=case_id,
                    case_type=case_type,
                    status="failed",
                    repetition=repetition,
                    expected_path=expected_path if expected_path.is_file() else None,
                    actual_path=execution_actual_path,
                    reason=_actual_result_score_failure_reason(exc),
                )
        budget_reason = _budget_guardrail_reason(request.environment, actual_result)
        return RunCaseResult(
            case_id=case_id,
            case_type=case_type,
            status="timeout" if budget_reason else _execution_status(execution, score),
            repetition=repetition,
            expected_path=expected_path if expected_path.is_file() else None,
            actual_path=execution_actual_path,
            score=score,
            runtime_seconds=runtime_seconds,
            reason=budget_reason or execution.reason or _execution_reason(execution, score),
            warnings=_budget_guardrail_warnings(request.environment, actual_result),
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
    return "executor failed: " + _exception_summary(exc)


def _exception_summary(exc: BaseException) -> str:
    detail = str(exc)
    if detail:
        summary = f"{type(exc).__name__}: {detail}"
    else:
        summary = type(exc).__name__

    if isinstance(exc, BaseExceptionGroup):
        child_summaries = "; ".join(_exception_summary(child) for child in exc.exceptions)
        if child_summaries:
            return f"{summary} [{child_summaries}]"
    return summary


def _mock_repo_setup_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"mock repo setup failed: {type(exc).__name__}: {detail}"
    return f"mock repo setup failed: {type(exc).__name__}"


def _jira_mock_setup_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"Jira mock setup failed: {type(exc).__name__}: {detail}"
    return f"Jira mock setup failed: {type(exc).__name__}"


def _mock_repo_environment(
    cases_dir: Path,
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> dict[str, str]:
    materialized = materialize_case_mock_repos(
        cases_dir,
        results_dir,
        case_id,
        repetition=repetition,
    )
    if materialized is None:
        return {}
    return materialized.to_environment()


def _jira_mock_directory(
    cases_dir: Path,
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> Path | None:
    if not has_structured_jira_fixture(cases_dir, case_id):
        return None
    return materialize_ymir_jira_mock(
        cases_dir,
        results_dir,
        case_id,
        repetition=repetition,
    )


def _actual_result_write_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"actual result write failed: {type(exc).__name__}: {detail}"
    return f"actual result write failed: {type(exc).__name__}"


def _actual_result_score_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"actual result scoring failed: {type(exc).__name__}: {detail}"
    return f"actual result scoring failed: {type(exc).__name__}"


def _score_actual_result(
    expected_path: Path,
    actual_result: Mapping[str, Any],
) -> ScoreReport:
    return score_case(load_json_file(expected_path), actual_result)


def _execution_status(
    execution: RunCaseExecution,
    score: ScoreReport | None,
) -> RunCaseStatus:
    if execution.status == "passed" and score is not None and not score.passed:
        return "failed"
    return execution.status


def _execution_reason(
    execution: RunCaseExecution,
    score: ScoreReport | None,
) -> str | None:
    if execution.status == "passed" and score is not None and not score.passed:
        return "deterministic score failed"
    return None


def _load_expected_for_policy(expected_path: Path) -> Mapping[str, Any]:
    if not expected_path.is_file():
        return {}
    try:
        return load_json_file(expected_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _replay_policy(
    cases_dir: Path,
    case_id: str,
    expected: Mapping[str, Any],
) -> ReplayPolicy:
    network_mode = expected.get("network_mode")
    if not isinstance(network_mode, str):
        network_mode = None

    manifest_path = cases_dir / "web_cache" / case_id / "manifest.json"
    if network_mode == "replay_only":
        return ReplayPolicy(
            network_mode=network_mode,
            manifest_path=manifest_path,
            recorded_urls=tuple(_recorded_urls(manifest_path)),
        )
    if network_mode == "network_denied":
        return ReplayPolicy(network_mode=network_mode, manifest_path=None)
    return ReplayPolicy(network_mode=network_mode, manifest_path=None)


def _recorded_urls(manifest_path: Path) -> list[str]:
    try:
        manifest = load_json_file(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return []

    urls = []
    required_urls = manifest.get("required_urls")
    if isinstance(required_urls, list):
        urls.extend(url for url in required_urls if isinstance(url, str) and url)

    recorded_files = manifest.get("recorded_files")
    if isinstance(recorded_files, Mapping):
        urls.extend(url for url in recorded_files if isinstance(url, str) and url)
    return list(dict.fromkeys(urls))


def _apply_run_policies(
    cases_dir: Path,
    case_id: str,
    expected: Mapping[str, Any],
    actual_result: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    if actual_result is None:
        return None

    payload = dict(actual_result)
    events = _actual_result_events(payload)
    if not events:
        return payload

    unsafe_operations = detect_unsafe_operations(events)
    if unsafe_operations:
        _append_result_values(
            payload,
            "unsafe_operations",
            [operation.to_json() for operation in unsafe_operations],
        )

    network_mode = expected.get("network_mode")
    if network_mode in {None, "replay_only", "network_denied"}:
        recorded_urls = []
        if network_mode in {None, "replay_only"}:
            recorded_urls = _recorded_urls(cases_dir / "web_cache" / case_id / "manifest.json")
        replay_violations = detect_replay_violations(events, recorded_urls=recorded_urls)
        if replay_violations:
            _append_result_values(payload, "replay_violations", replay_violations)

    return payload


def _actual_result_events(actual_result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    events = []
    for container in _event_containers(actual_result):
        for field in EVENT_TRACE_FIELDS:
            events.extend(_event_values(container.get(field)))
    return events


def _event_containers(actual_result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    containers = [actual_result]
    data = actual_result.get("data")
    if isinstance(data, Mapping):
        containers.append(data)
    return containers


def _event_values(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if not isinstance(value, list | tuple):
        return []

    events = []
    for item in value:
        if isinstance(item, Mapping):
            events.append(item)
    return events


def _append_result_values(
    payload: dict[str, Any],
    name: str,
    additions: Sequence[Any],
) -> None:
    if not additions:
        return

    values = []
    existing = payload.get(name)
    if isinstance(existing, list):
        values.extend(existing)
    elif existing is not None:
        values.append(existing)
    values.extend(additions)
    payload[name] = values


def _budget_guardrail_reason(
    environment: Mapping[str, str],
    actual_result: Mapping[str, Any] | None,
) -> str | None:
    max_cost = _float_or_none(environment.get(MAX_COST_PER_RUN_ENV))
    if max_cost is None or actual_result is None:
        return None

    total_cost = _float_or_none(_actual_result_field(actual_result, "total_cost_usd"))
    if total_cost is None or total_cost <= max_cost:
        return None

    return (
        "budget guardrail exceeded: "
        f"total_cost_usd {_format_number(total_cost)} > "
        f"{MAX_COST_PER_RUN_ENV} {_format_number(max_cost)}"
    )


def _budget_guardrail_warnings(
    environment: Mapping[str, str],
    actual_result: Mapping[str, Any] | None,
) -> list[str]:
    alert_threshold = _float_or_none(environment.get(COST_ALERT_THRESHOLD_ENV))
    if alert_threshold is None or actual_result is None:
        return []

    total_cost = _float_or_none(_actual_result_field(actual_result, "total_cost_usd"))
    max_cost = _float_or_none(environment.get(MAX_COST_PER_RUN_ENV))
    if total_cost is None or total_cost <= alert_threshold:
        return []
    if max_cost is not None and total_cost > max_cost:
        return []

    return [
        "budget alert threshold exceeded: "
        f"total_cost_usd {_format_number(total_cost)} > "
        f"{COST_ALERT_THRESHOLD_ENV} {_format_number(alert_threshold)}"
    ]


def _actual_result_field(actual_result: Mapping[str, Any], name: str) -> Any:
    data = actual_result.get("data")
    nested = data if isinstance(data, Mapping) else {}
    if actual_result.get(name) is not None:
        return actual_result.get(name)
    return nested.get(name)


def _float_or_none(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _format_number(value: float) -> str:
    return f"{value:g}"


def _write_actual_result(path: Path, actual_result: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dict(actual_result), indent=2, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")
