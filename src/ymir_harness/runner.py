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
from ymir_harness.provenance import collect_provenance
from ymir_harness.scoring import _fixture_checksum

RUNNER_NOT_WIRED_REASON = "workflow adapters are not wired yet"
DEFAULT_CHAT_MODEL = "vertexai:claude-sonnet-4-6"
MAX_ITERATIONS_OVERRIDE_ENV = "BENCHMARK_MAX_ITERATIONS_OVERRIDE"
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


def workflow_trace_dir(results_dir: Path, repetition: int) -> Path:
    return results_dir / f"repeat-{repetition}" / "workflow-trace"


def workflow_stdout_path(results_dir: Path, case_id: str, repetition: int) -> Path:
    return workflow_trace_dir(results_dir, repetition) / f"{case_id}.stdout.log"


def workflow_stderr_path(results_dir: Path, case_id: str, repetition: int) -> Path:
    return workflow_trace_dir(results_dir, repetition) / f"{case_id}.stderr.log"


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
    env.setdefault("CHAT_MODEL", DEFAULT_CHAT_MODEL)
    _normalize_model_environment(env)
    env["JIRA_MOCK_FILES"] = str((jira_mock_dir or cases_dir / "jiras").resolve())
    env["MOCK_REPOS_DIR"] = str((cases_dir / "mock_data").resolve())
    env.setdefault("GIT_REPO_BASEPATH", str(results_dir.resolve()))
    env["YMIR_BENCHMARK_CASES_DIR"] = str(cases_dir.resolve())
    env["YMIR_BENCHMARK_RESULTS_DIR"] = str(results_dir.resolve())
    if case_id:
        _install_dry_run_command_shims(env, results_dir, case_id)
    env.setdefault("GIT_AUTHOR_NAME", "Ymir Harness")
    env.setdefault("GIT_AUTHOR_EMAIL", "ymir-harness@example.invalid")
    env.setdefault("GIT_COMMITTER_NAME", "Ymir Harness")
    env.setdefault("GIT_COMMITTER_EMAIL", "ymir-harness@example.invalid")
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


def _install_dry_run_command_shims(
    environment: dict[str, str],
    results_dir: Path,
    case_id: str,
) -> None:
    shim_dir = results_dir.resolve() / f".ymir-harness-shims-{case_id}"
    shim_dir.mkdir(parents=True, exist_ok=True)
    scripts = {
        "rhpkg": _PACKAGE_TOOL_SHIM,
        "centpkg": _PACKAGE_TOOL_SHIM,
        "rpmbuild": _RPMBUILD_SHIM,
        "patch": _PATCH_SHIM,
    }
    for name, script in scripts.items():
        path = shim_dir / name
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)

    existing_path = environment.get("PATH", "")
    environment["PATH"] = (
        f"{shim_dir}{os.pathsep}{existing_path}" if existing_path else str(shim_dir)
    )
    environment["YMIR_BENCHMARK_COMMAND_SHIMS"] = str(shim_dir)


_PACKAGE_TOOL_SHIM = """#!/bin/sh
set -eu

last=
for arg in "$@"; do
    last=$arg
done

case "$last" in
    prep|sources)
        exit 0
        ;;
    srpm)
        spec=$(find . -maxdepth 1 -name '*.spec' -print | head -n 1)
        name=${spec#./}
        name=${name%.spec}
        if [ -z "$name" ]; then
            name=ymir-harness
        fi
        artifact="$(pwd)/${name}-dry-run.src.rpm"
        printf 'ymir-harness dry-run SRPM for %s\\n' "$name" > "$artifact"
        printf 'Wrote: %s\\n' "$artifact"
        exit 0
        ;;
esac

printf 'ymir-harness dry-run %s' "$(basename "$0")" >&2
for arg in "$@"; do
    printf ' %s' "$arg" >&2
done
printf '\\n' >&2
exit 0
"""


_RPMBUILD_SHIM = """#!/bin/sh
set -eu

spec=
for arg in "$@"; do
    case "$arg" in
        *.spec)
            spec=$arg
            ;;
    esac
done

name=${spec##*/}
name=${name%.spec}
if [ -z "$name" ]; then
    name=ymir-harness
fi
artifact="$(pwd)/${name}-dry-run.src.rpm"
printf 'ymir-harness dry-run SRPM for %s\\n' "$name" > "$artifact"
printf 'Wrote: %s\\n' "$artifact"
exit 0
"""


_PATCH_SHIM = """#!/bin/sh
set -eu

strip=1
check_only=false
patch_file=
for arg in "$@"; do
    case "$arg" in
        --dry-run|--check)
            check_only=true
            ;;
        -p*)
            strip=${arg#-p}
            ;;
        -*)
            ;;
        *)
            patch_file=$arg
            ;;
    esac
done

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if [ -n "$patch_file" ]; then
    cp "$patch_file" "$tmp"
else
    cat > "$tmp"
fi

if [ "$check_only" = true ]; then
    git apply --check "-p${strip}" "$tmp"
else
    git apply "-p${strip}" "$tmp"
fi
"""


def _normalize_model_environment(env: dict[str, str]) -> None:
    model_name = env.get("CHAT_MODEL", "")
    if not model_name.lower().startswith("vertexai:"):
        return

    location = env.get("GOOGLE_VERTEX_LOCATION") or env.get("CLOUD_ML_REGION")
    if location:
        env.setdefault("GOOGLE_VERTEX_LOCATION", location)
    else:
        env["GOOGLE_VERTEX_LOCATION"] = "global"

    project = (
        env.get("GOOGLE_VERTEX_PROJECT")
        or env.get("ANTHROPIC_VERTEX_PROJECT_ID")
        or env.get("GOOGLE_CLOUD_PROJECT")
    )
    if project:
        env.setdefault("GOOGLE_VERTEX_PROJECT", project)


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
    return RunCaseResult(
        case_id=case_id,
        case_type=case_type,
        status="not_run",
        repetition=repetition,
        expected_path=expected_path if expected_path.is_file() else None,
        actual_path=actual_path,
        reason=RUNNER_NOT_WIRED_REASON,
    )
