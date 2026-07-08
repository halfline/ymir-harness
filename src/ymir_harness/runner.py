from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ymir_harness import __version__
from ymir_harness.artifacts import artifact_environment
from ymir_harness.capture_missing import CaptureMissingError, blocked_urls_from_run_path
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
from ymir_harness.replay import canonicalize_replay_url
from ymir_harness.safety import detect_replay_violations, detect_unsafe_operations
from ymir_harness.scoring import _fixture_checksum, load_json_file, score_case
from ymir_harness.source_fixtures import (
    SourceFixtureError,
    materialize_case_source_cache,
    source_cache_git_rewrites,
)

RUNNER_NOT_WIRED_REASON = "workflow adapters are not wired yet"
DEFAULT_CHAT_MODEL = "vertexai:claude-sonnet-4-6"
MAX_ITERATIONS_OVERRIDE_ENV = "BENCHMARK_MAX_ITERATIONS_OVERRIDE"
MAX_COST_PER_RUN_ENV = "BENCHMARK_MAX_COST_PER_RUN"
COST_ALERT_THRESHOLD_ENV = "BENCHMARK_COST_ALERT_THRESHOLD"
FILESYSTEM_ISOLATION_ENV = "YMIR_HARNESS_FS_ISOLATION"
FILESYSTEM_ISOLATION_WORKER_ENV = "YMIR_HARNESS_WORKFLOW_WORKER"
HARNESS_WARNING_PREFIX = "ymir-harness warning: "
WORKER_CONTAINER_TOOL_ENV = "YMIR_HARNESS_CONTAINER_TOOL"
WORKER_CONTAINER_VERSION_ENV = "YMIR_HARNESS_CONTAINER_VERSION"
WORKER_IMAGE_ENV = "YMIR_HARNESS_WORKER_IMAGE"
WORKER_IMAGE_PREFIX_ENV = "YMIR_HARNESS_WORKER_IMAGE_PREFIX"
WORKER_BASE_IMAGE_PREFIX_ENV = "YMIR_HARNESS_WORKER_BASE_IMAGE_PREFIX"
AGENT_TIMEOUT_ENV = "YMIR_HARNESS_AGENT_TIMEOUT_SECONDS"
STOP_ON_REPLAY_MISS_ENV = "YMIR_HARNESS_STOP_ON_REPLAY_MISS"
EVENT_TRACE_FIELDS = ("events", "tool_events", "tool_calls", "trace")
DEFAULT_WORKER_CONTAINER_TOOL = "podman"
DEFAULT_WORKER_CONTAINER_VERSION = "c10s"
WORKER_CONTAINER_RESULTS_DIR = Path("/ymir-harness-results")
WORKER_CONTAINER_PATH = (
    "/opt/beeai-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
WORKER_CONTAINER_VERSIONS = frozenset({"c9s", "c10s"})
PACKAGE_MANAGER_SHIM_NAMES = ("dnf", "dnf5", "microdnf", "yum")
WORKER_SOURCE_FINGERPRINT_PATHS = (
    Path("src"),
    Path("VERSION"),
    Path("pyproject.toml"),
    Path("rhel-config.json"),
    Path("Containerfile.ymir-harness-worker"),
    Path("Containerfile.ymir-harness-source-worker"),
    Path("ai-workflows") / "Containerfile.c9s",
    Path("ai-workflows") / "Containerfile.c10s",
    Path("ai-workflows") / "ymir",
)
PATH_LIST_ENVIRONMENT_NAMES = frozenset(
    {
        "LD_LIBRARY_PATH",
        "PATH",
        "PYTHONPATH",
    }
)
JSON_PATH_ENVIRONMENT_NAMES = frozenset(
    {
        "YMIR_BENCHMARK_MOCK_REPOS",
    }
)
_BUILT_WORKER_IMAGES: set[tuple[str, ...]] = set()
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
MODEL_PROVIDER_CREDENTIAL_ENVIRONMENT_NAMES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_API_TOKEN",
    }
)
WRITE_CREDENTIAL_ENVIRONMENT_NAMES = frozenset(
    {
        "FREEDESKTOP_API_KEY",
        "JIRA_API_TOKEN",
        "JIRA_PASSWORD",
        "JIRA_TOKEN",
        "GITLAB_TOKEN",
        "GITHUB_TOKEN",
        "KEYTAB_FILE",
        "KRB5CCNAME",
        "KRB5_KTNAME",
        "KOJI_CONFIG",
        "LOOKASIDE_PASSWORD",
        "LOOKASIDE_TOKEN",
        "UV_PUBLISH_TOKEN",
    }
)
SENSITIVE_ENVIRONMENT_NAMES = (
    MODEL_PROVIDER_CREDENTIAL_ENVIRONMENT_NAMES | WRITE_CREDENTIAL_ENVIRONMENT_NAMES
)
PASSTHROUGH_ENVIRONMENT_NAMES = frozenset(
    {
        "AGENTIC_SKILLS_CHECKSUM",
        "AGENTIC_SKILLS_SHA",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "BEEAI_MAX_ITERATIONS",
        "BENCHMARK_MODEL_SETTINGS",
        "BENCHMARK_PROMPT_CONFIG",
        "CHAT_MODEL",
        "CHAT_MODEL_BACKPORT",
        "CHAT_MODEL_REBASE",
        "CHAT_MODEL_REBUILD",
        "CHAT_MODEL_TRIAGE",
        "CLOUD_ML_REGION",
        "CONTAINER_IMAGE_DIGEST",
        "CURL_CA_BUNDLE",
        "EXTRA_PACKAGES",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_VERTEX_LOCATION",
        "GOOGLE_VERTEX_PROJECT",
        "INTERNAL_PACKAGES",
        "INTERNAL_REPO_URL",
        "LLM_JUDGE_MODEL",
        "PATH",
        "REASONING_EFFORT",
        "REQUESTS_CA_BUNDLE",
        "RUN_LLM_JUDGE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "YMIR_HARNESS_LLM_JUDGE",
        "YMIR_HARNESS_LLM_JUDGE_MODEL",
        "YMIR_HARNESS_WORKFLOW_PROGRESS_INTERVAL",
        AGENT_TIMEOUT_ENV,
        STOP_ON_REPLAY_MISS_ENV,
        COST_ALERT_THRESHOLD_ENV,
        FILESYSTEM_ISOLATION_ENV,
        MAX_COST_PER_RUN_ENV,
        MAX_ITERATIONS_OVERRIDE_ENV,
        WORKER_BASE_IMAGE_PREFIX_ENV,
        WORKER_CONTAINER_TOOL_ENV,
        WORKER_CONTAINER_VERSION_ENV,
        WORKER_IMAGE_ENV,
        WORKER_IMAGE_PREFIX_ENV,
    }
) | MODEL_PROVIDER_CREDENTIAL_ENVIRONMENT_NAMES
PASSTHROUGH_ENVIRONMENT_PREFIXES = (
    "INTERNAL_PACKAGES_",
    "INTERNAL_REPO_URL_",
)
BUILD_ONLY_ENVIRONMENT_NAMES = frozenset(
    {
        "EXTRA_PACKAGES",
        "INTERNAL_PACKAGES",
        "INTERNAL_REPO_URL",
        WORKER_BASE_IMAGE_PREFIX_ENV,
        WORKER_CONTAINER_TOOL_ENV,
        WORKER_IMAGE_ENV,
        WORKER_IMAGE_PREFIX_ENV,
    }
)
BUILD_ONLY_ENVIRONMENT_PREFIXES = (
    "INTERNAL_PACKAGES_",
    "INTERNAL_REPO_URL_",
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


def written_actual_result_path(path: Path) -> Path | None:
    return path if path.is_file() else None


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
    source_cache_dir: Path | None = None,
) -> dict[str, str]:
    env = _passthrough_environment(base_env)
    env.update(NO_WRITE_ENVIRONMENT)
    env.setdefault("CHAT_MODEL", DEFAULT_CHAT_MODEL)
    env.setdefault(FILESYSTEM_ISOLATION_ENV, DEFAULT_WORKER_CONTAINER_TOOL)
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
            (source_cache_dir or cases_dir / "source_cache" / case_id).resolve()
        )
    else:
        env.pop("YMIR_BENCHMARK_CASE_ID", None)
        env.pop("YMIR_BENCHMARK_WEB_CACHE_DIR", None)
        env.pop("YMIR_BENCHMARK_SOURCE_CACHE_DIR", None)
    return env


def _passthrough_environment(base_env: Mapping[str, str] | None) -> dict[str, str]:
    source = os.environ if base_env is None else base_env
    env = {
        str(name): str(value)
        for name, value in source.items()
        if _passes_environment_allowlist(str(name))
    }
    _strip_environment_values(env, WRITE_CREDENTIAL_ENVIRONMENT_NAMES)
    return env


def _passes_environment_allowlist(name: str) -> bool:
    return name in PASSTHROUGH_ENVIRONMENT_NAMES or name.startswith(
        PASSTHROUGH_ENVIRONMENT_PREFIXES
    )


def _strip_environment_values(env: dict[str, str], names: frozenset[str]) -> None:
    for name in names:
        if env.get(name) != NO_WRITE_ENVIRONMENT.get(name):
            env.pop(name, None)


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
    scripts.update({name: _PACKAGE_MANAGER_SHIM for name in PACKAGE_MANAGER_SHIM_NAMES})
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

command=
for arg in "$@"; do
    case "$arg" in
        prep|sources|srpm)
            command=$arg
            ;;
    esac
done

copy_lookaside_sources() {
    source_cache=${YMIR_BENCHMARK_SOURCE_CACHE_DIR:-}
    [ -n "$source_cache" ] || return 0
    lookaside="$source_cache/lookaside"
    [ -d "$lookaside" ] || return 0
    [ -f sources ] || return 0
    sed -n -E '
        s/^[[:space:]]*[A-Za-z0-9_+.-]+[[:space:]]+\\(([^)]+)\\)[[:space:]]*=[[:space:]]*[0-9A-Fa-f]+[[:space:]]*$/\\1/p
        s/^[[:space:]]*[A-Za-z0-9_+.-]+\\(([^)]+)\\)[[:space:]]*=[[:space:]]*[0-9A-Fa-f]+[[:space:]]*$/\\1/p
        s/^[[:space:]]*[0-9A-Fa-f]+[[:space:]]+.*[[:space:]]([^[:space:]]+)[[:space:]]*$/\\1/p
    ' sources | while IFS= read -r filename; do
        [ -n "$filename" ] || continue
        source="$lookaside/$filename"
        if [ ! -f "$source" ]; then
            printf '%s was not available in the lookaside cache\n' "$filename" >&2
            return 1
        fi
        destination="$(pwd)/$(basename "$source")"
        [ -e "$destination" ] || cp -p "$source" "$destination"
    done
}

find_spec() {
    find . -maxdepth 1 -name '*.spec' -print | head -n 1
}

prep_sources() {
    copy_lookaside_sources
    spec=$(find_spec)
    if [ -z "$spec" ]; then
        printf 'ymir-harness dry-run %s prep: no spec file found\\n' "$(basename "$0")" >&2
        exit 1
    fi
    exec /usr/bin/rpmbuild -bp --nodeps \\
        --define "_topdir $(pwd)" \\
        --define "_sourcedir $(pwd)" \\
        --define "_builddir $(pwd)" \\
        --define "_specdir $(pwd)" \\
        --define "_srcrpmdir $(pwd)" \\
        --define "_rpmdir $(pwd)" \\
        "$spec"
}

case "$command" in
    sources)
        copy_lookaside_sources
        exit 0
        ;;
    prep)
        prep_sources
        ;;
    srpm)
        spec=$(find_spec)
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

printf 'ymir-harness warning: dry-run %s no-op for unsupported command:' "$(basename "$0")" >&2
for arg in "$@"; do
    printf ' %s' "$arg" >&2
done
printf '\\n' >&2
exit 0
"""


_PACKAGE_MANAGER_SHIM = """#!/bin/sh
set -eu

printf 'ymir-harness offline mode blocked %s:' "$(basename "$0")" >&2
for arg in "$@"; do
    printf ' %s' "$arg" >&2
done
printf '\\n' >&2
printf 'package-manager operations must use declared benchmark fixtures\\n' >&2
exit 1
"""


_RPMBUILD_SHIM = """#!/bin/sh
set -eu

spec=
prep=false
for arg in "$@"; do
    case "$arg" in
        -bp|-bp*)
            prep=true
            ;;
        *.spec)
            spec=$arg
            ;;
    esac
done

if $prep; then
    exec /usr/bin/rpmbuild --nodeps \\
        --define "_topdir $(pwd)" \\
        --define "_sourcedir $(pwd)" \\
        --define "_builddir $(pwd)" \\
        --define "_specdir $(pwd)" \\
        --define "_srcrpmdir $(pwd)" \\
        --define "_rpmdir $(pwd)" \\
        "$@"
fi

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
    if executor is not None:
        expected = _load_expected_for_policy(expected_path)
        replay_policy = _replay_policy(cases_dir, case_id, expected)
        try:
            source_cache_dir = _source_cache_directory(
                cases_dir,
                results_dir,
                case_id,
                repetition,
                base_env=base_env,
            )
            mock_repo_env = _mock_repo_environment(
                cases_dir,
                results_dir,
                case_id,
                repetition,
                source_cache_dir=source_cache_dir,
            )
        except SourceFixtureError as exc:
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="failed",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=actual_path,
                reason=_source_fixture_setup_failure_reason(exc),
            )
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
            source_cache_dir=source_cache_dir,
        )
        environment["YMIR_BENCHMARK_REPETITION"] = str(repetition)
        environment.update(artifact_environment(actual_path))
        environment.update(mock_repo_env)
        _apply_source_cache_git_rewrites(
            environment, source_cache_dir, results_dir, case_id, repetition
        )
        _write_gateway_gitconfig(environment, results_dir, case_id)
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
            with (
                _capture_workflow_output(results_dir, case_id, repetition),
                enforce_benchmark_boundaries(request.environment),
            ):
                execution = _execute_case_workflow(executor, request)
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
                warnings=_artifact_warnings(results_dir, case_id, repetition),
            )
        except Exception as exc:
            if timeout_failure(exc, request.environment):
                return RunCaseResult(
                    case_id=case_id,
                    case_type=case_type,
                    status="timeout",
                    repetition=repetition,
                    expected_path=expected_path if expected_path.is_file() else None,
                    actual_path=written_actual_result_path(actual_path),
                    reason=workflow_timeout_reason(
                        getattr(executor, "ymir_workflow", None),
                        request.environment,
                        exc,
                    ),
                    warnings=_artifact_warnings(results_dir, case_id, repetition),
                )
            replay_violations = _artifact_replay_violations(results_dir, case_id, repetition)
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="failed",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=actual_path,
                reason=_with_replay_violations(_executor_failure_reason(exc), replay_violations),
                warnings=_artifact_warnings(results_dir, case_id, repetition),
            )
        except BaseException as exc:
            if not timeout_failure(exc, request.environment):
                raise
            return RunCaseResult(
                case_id=case_id,
                case_type=case_type,
                status="timeout",
                repetition=repetition,
                expected_path=expected_path if expected_path.is_file() else None,
                actual_path=written_actual_result_path(actual_path),
                reason=workflow_timeout_reason(
                    getattr(executor, "ymir_workflow", None),
                    request.environment,
                    exc,
                ),
                warnings=_artifact_warnings(results_dir, case_id, repetition),
            )
        execution_actual_path = execution.actual_path or actual_path
        score = None
        replay_violations = _artifact_replay_violations(results_dir, case_id, repetition)
        replay_misses = _artifact_replay_misses(results_dir, case_id, repetition)
        actual_result = _apply_run_policies(
            cases_dir,
            case_id,
            expected,
            execution.actual_result,
            artifact_replay_violations=replay_violations,
            artifact_replay_misses=replay_misses,
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
        warnings = [
            *_artifact_warnings(results_dir, case_id, repetition),
            *_budget_guardrail_warnings(request.environment, actual_result),
        ]
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
            warnings=warnings,
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


def timeout_exception(exc: BaseException, seen: set[int] | None = None) -> bool:
    if seen is None:
        seen = set()
    if id(exc) in seen:
        return False
    seen.add(id(exc))
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(timeout_exception(child, seen) for child in exc.exceptions)
    if exc.__cause__ is not None and timeout_exception(exc.__cause__, seen):
        return True
    if exc.__context__ is not None and timeout_exception(exc.__context__, seen):
        return True
    return False


def timeout_failure(exc: BaseException, environment: Mapping[str, str]) -> bool:
    if timeout_exception(exc):
        return True
    if _positive_float_environment(environment, AGENT_TIMEOUT_ENV) is None:
        return False
    return cancelled_exception(exc)


def cancelled_exception(exc: BaseException, seen: set[int] | None = None) -> bool:
    if seen is None:
        seen = set()
    if id(exc) in seen:
        return False
    seen.add(id(exc))
    if isinstance(exc, asyncio.CancelledError):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(cancelled_exception(child, seen) for child in exc.exceptions)
    if exc.__cause__ is not None and cancelled_exception(exc.__cause__, seen):
        return True
    if exc.__context__ is not None and cancelled_exception(exc.__context__, seen):
        return True
    return False


def workflow_timeout_reason(
    workflow: object,
    environment: Mapping[str, str],
    exc: BaseException,
) -> str:
    label = f"{workflow} workflow" if isinstance(workflow, str) and workflow else "executor"
    timeout = _positive_float_environment(environment, AGENT_TIMEOUT_ENV)
    if timeout is not None:
        return f"{label} timed out after {timeout:g}s"
    return f"{label} timed out: {_exception_summary(exc)}"


def _positive_float_environment(
    environment: Mapping[str, str],
    name: str,
) -> float | None:
    raw_value = environment.get(name)
    if raw_value is None:
        return None
    try:
        value = float(raw_value)
    except ValueError:
        return None
    return value if value > 0 else None


def _with_replay_violations(reason: str, replay_violations: Sequence[str]) -> str:
    if not replay_violations:
        return reason
    return reason + "; replay violations: " + "; ".join(replay_violations[:3])


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


def _source_fixture_setup_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"source fixture setup failed: {type(exc).__name__}: {detail}"
    return f"source fixture setup failed: {type(exc).__name__}"


def _jira_mock_setup_failure_reason(exc: Exception) -> str:
    detail = str(exc)
    if detail:
        return f"Jira mock setup failed: {type(exc).__name__}: {detail}"
    return f"Jira mock setup failed: {type(exc).__name__}"


def _source_cache_directory(
    cases_dir: Path,
    results_dir: Path,
    case_id: str,
    repetition: int,
    *,
    base_env: Mapping[str, str] | None,
) -> Path:
    return materialize_case_source_cache(
        cases_dir,
        case_id,
        results_dir / f"repeat-{repetition}" / "source-cache" / case_id,
        git_env=base_env,
    )


def _execute_case_workflow(
    executor: RunCaseExecutor,
    request: RunCaseRequest,
) -> RunCaseExecution:
    workflow = getattr(executor, "ymir_workflow", None)
    if not (
        isinstance(workflow, str)
        and getattr(executor, "ymir_isolatable", False)
        and _filesystem_isolation_enabled(request.environment)
    ):
        return executor(request)
    return _execute_isolated_case_workflow(workflow, request)


def _filesystem_isolation_enabled(environment: Mapping[str, str]) -> bool:
    value = environment.get(FILESYSTEM_ISOLATION_ENV, DEFAULT_WORKER_CONTAINER_TOOL).strip().lower()
    return value not in {"", "0", "false", "no", "none", "off", "disabled"}


def _container_tool(environment: Mapping[str, str]) -> str:
    backend = (
        environment.get(FILESYSTEM_ISOLATION_ENV, DEFAULT_WORKER_CONTAINER_TOOL).strip().lower()
    )
    if backend not in {"podman", "container"}:
        raise RuntimeError(
            f"{FILESYSTEM_ISOLATION_ENV}={backend} is unsupported; "
            f"use {FILESYSTEM_ISOLATION_ENV}=podman or disable workflow isolation"
        )
    tool = environment.get(WORKER_CONTAINER_TOOL_ENV, DEFAULT_WORKER_CONTAINER_TOOL).strip()
    return tool or DEFAULT_WORKER_CONTAINER_TOOL


def _workflow_container_version(workflow: str, request: RunCaseRequest) -> str:
    override = request.environment.get(WORKER_CONTAINER_VERSION_ENV)
    if override:
        return _validate_worker_container_version(override)
    if workflow == "ymir-triage":
        return DEFAULT_WORKER_CONTAINER_VERSION
    return _branch_container_version(_request_target_branch(request))


def _validate_worker_container_version(value: str) -> str:
    version = value.strip().lower()
    if version in WORKER_CONTAINER_VERSIONS:
        return version
    allowed = ", ".join(sorted(WORKER_CONTAINER_VERSIONS))
    raise RuntimeError(f"unsupported {WORKER_CONTAINER_VERSION_ENV}={value!r}; expected {allowed}")


def _request_target_branch(request: RunCaseRequest) -> str | None:
    candidates = [
        request.cases_dir / "triage_results" / f"{request.case_id}.actual.json",
        request.expected_path,
    ]
    for path in candidates:
        payload = _load_optional_mapping(path)
        if payload is None:
            continue
        if branch := _target_branch_from_payload(payload):
            return branch
    return None


def _load_optional_mapping(path: Path) -> Mapping[str, Any] | None:
    try:
        payload = load_json_file(path)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _target_branch_from_payload(payload: Mapping[str, Any]) -> str | None:
    data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
    assert isinstance(data, Mapping)
    for source in (data, payload):
        for field in ("target_branch", "dist_git_branch", "fix_version"):
            value = source.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _branch_container_version(branch: str | None) -> str:
    if branch is None:
        return DEFAULT_WORKER_CONTAINER_VERSION
    normalized = branch.strip().lower()
    if normalized in {"c8s", "c9s"}:
        return "c9s"
    if normalized == "c10s":
        return "c10s"
    if match := re.match(r"^rhel-(\d+)(?:[.\-]|$)", normalized):
        return "c9s" if int(match.group(1)) <= 9 else "c10s"
    return DEFAULT_WORKER_CONTAINER_VERSION


def _ensure_worker_container_image(
    container_version: str,
    environment: Mapping[str, str],
) -> str:
    version = _validate_worker_container_version(container_version)
    tool = _container_tool(environment)
    if shutil.which(tool) is None:
        raise RuntimeError(
            f"{FILESYSTEM_ISOLATION_ENV}={tool} requested, but {tool} is not installed"
        )

    if worker_image := environment.get(WORKER_IMAGE_ENV):
        return worker_image

    base_image = _worker_base_image(version, environment)
    worker_image = _worker_image(version, environment)
    build_key = (tool, version, base_image, worker_image)
    if build_key in _BUILT_WORKER_IMAGES:
        return worker_image

    if _requires_prebuilt_worker_images(version, environment):
        source_image = _worker_source_image(version, environment)
        source_build_key = (tool, version, worker_image, source_image)
        if source_build_key in _BUILT_WORKER_IMAGES:
            return source_image
        if not _container_image_available(tool, source_image):
            _require_container_image(
                tool,
                worker_image,
                f"local ymir-harness {version} seed worker image",
            )
            _build_worker_source_image(tool, worker_image, source_image)
        _BUILT_WORKER_IMAGES.add(source_build_key)
        return source_image

    _build_worker_base_image(tool, version, base_image, environment)
    _build_worker_image(tool, base_image, worker_image)
    _BUILT_WORKER_IMAGES.add(build_key)
    return worker_image


def _worker_base_image(version: str, environment: Mapping[str, str]) -> str:
    prefix = environment.get(
        WORKER_BASE_IMAGE_PREFIX_ENV,
        "localhost/ymir-harness-ymir-base",
    ).rstrip(":")
    return f"{prefix}:{version}"


def _worker_image(version: str, environment: Mapping[str, str]) -> str:
    prefix = environment.get(WORKER_IMAGE_PREFIX_ENV, "localhost/ymir-harness-worker").rstrip(":")
    return f"{prefix}:{version}"


def _worker_source_image(version: str, environment: Mapping[str, str]) -> str:
    prefix = environment.get(WORKER_IMAGE_PREFIX_ENV, "localhost/ymir-harness-worker").rstrip(":")
    return f"{prefix}:{version}-source-{_worker_source_fingerprint()[:12]}"


def _worker_source_fingerprint() -> str:
    root = _harness_root()
    digest = hashlib.sha256()
    for relative_path in WORKER_SOURCE_FINGERPRINT_PATHS:
        path = root / relative_path
        if path.is_file():
            _hash_worker_source_file(digest, root, path)
            continue
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if _skip_worker_source_path(child):
                    continue
                if child.is_file():
                    _hash_worker_source_file(digest, root, child)
            continue
        raise RuntimeError(f"worker source path is missing: {path}")
    return digest.hexdigest()


def _skip_worker_source_path(path: Path) -> bool:
    return "__pycache__" in path.parts or path.name.endswith(".pyc")


def _hash_worker_source_file(digest: Any, root: Path, path: Path) -> None:
    digest.update(path.relative_to(root).as_posix().encode("utf-8"))
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")


def _requires_prebuilt_worker_images(
    version: str,
    environment: Mapping[str, str],
) -> bool:
    network_mode = environment.get("YMIR_BENCHMARK_NETWORK_MODE")
    return network_mode in {"replay_only", "network_denied"} and not _internal_repo_configured(
        version, environment
    )


def _internal_repo_configured(version: str, environment: Mapping[str, str]) -> bool:
    suffix = version.upper()
    return bool(
        environment.get(f"INTERNAL_REPO_URL_{suffix}") or environment.get("INTERNAL_REPO_URL")
    )


def _require_container_image(tool: str, image: str, description: str) -> None:
    if _container_image_available(tool, image):
        return
    raise RuntimeError(
        f"{description} {image!r} is required for replay/offline workflow runs; "
        "prebuild it before running cases, set YMIR_HARNESS_WORKER_IMAGE to a "
        "prebuilt worker image, or provide INTERNAL_REPO_URL for an explicit build"
    )


def _container_image_available(tool: str, image: str) -> bool:
    completed = subprocess.run(
        [tool, "image", "inspect", image, "--format", "{{.Id}}"],
        cwd=str(_harness_root()),
        env=_container_tool_environment(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def _build_worker_base_image(
    tool: str,
    version: str,
    image: str,
    environment: Mapping[str, str],
) -> None:
    root = _harness_root()
    context = root / "ai-workflows"
    containerfile = context / f"Containerfile.{version}"
    if not containerfile.is_file():
        raise RuntimeError(f"Ymir container definition is missing: {containerfile}")

    command = [
        tool,
        "build",
        "--pull=missing",
        "-t",
        image,
        "-f",
        str(containerfile),
        *_worker_base_build_args(version, environment),
        str(context),
    ]
    _run_container_tool(command, f"building local Ymir {version} worker base image")


def _worker_base_build_args(version: str, environment: Mapping[str, str]) -> list[str]:
    suffix = version.upper()
    build_args = []
    internal_repo = environment.get(f"INTERNAL_REPO_URL_{suffix}") or environment.get(
        "INTERNAL_REPO_URL"
    )
    extra_packages = environment.get(f"INTERNAL_PACKAGES_{suffix}") or environment.get(
        "EXTRA_PACKAGES"
    )
    if internal_repo:
        build_args.extend(["--build-arg", f"INTERNAL_REPO_URL={internal_repo}"])
    if extra_packages:
        build_args.extend(["--build-arg", f"EXTRA_PACKAGES={extra_packages}"])
    return build_args


def _build_worker_image(tool: str, base_image: str, image: str) -> None:
    root = _harness_root()
    containerfile = root / "Containerfile.ymir-harness-worker"
    if not containerfile.is_file():
        raise RuntimeError(f"harness worker container definition is missing: {containerfile}")

    command = [
        tool,
        "build",
        "--pull=never",
        "-t",
        image,
        "--build-arg",
        f"BASE_IMAGE={base_image}",
        "-f",
        str(containerfile),
        str(root),
    ]
    _run_container_tool(command, "building local ymir-harness worker image")


def _build_worker_source_image(tool: str, seed_image: str, image: str) -> None:
    root = _harness_root()
    containerfile = root / "Containerfile.ymir-harness-source-worker"
    if not containerfile.is_file():
        raise RuntimeError(f"harness source worker container definition is missing: {containerfile}")

    command = [
        tool,
        "build",
        "--pull=never",
        "-t",
        image,
        "--build-arg",
        f"BASE_IMAGE={seed_image}",
        "-f",
        str(containerfile),
        str(root),
    ]
    _run_container_tool(command, "building local ymir-harness source worker image")


def _run_container_tool(command: Sequence[str], action: str) -> None:
    completed = subprocess.run(
        list(command),
        cwd=str(_harness_root()),
        env=_container_tool_environment(),
        stdout=sys.stdout,
        stderr=sys.stderr,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{action} failed with status {completed.returncode}")


def _container_tool_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    if environment is not None:
        for name in MODEL_PROVIDER_CREDENTIAL_ENVIRONMENT_NAMES:
            value = environment.get(name)
            if value is not None:
                env[name] = value
    return env


def _execute_isolated_case_workflow(
    workflow: str,
    request: RunCaseRequest,
) -> RunCaseExecution:
    container_version = _workflow_container_version(workflow, request)
    worker_dir = request.results_dir / f"repeat-{request.repetition}" / "workflow-worker"
    worker_dir.mkdir(parents=True, exist_ok=True)
    worker_home = worker_dir / "home"
    worker_home.mkdir(parents=True, exist_ok=True)
    request_path = worker_dir / f"{request.case_id}.request.json"
    result_path = worker_dir / f"{request.case_id}.result.json"
    cases_view = _materialize_worker_cases_view(request, worker_dir)
    container_results_dir = WORKER_CONTAINER_RESULTS_DIR

    worker_environment = _isolated_worker_environment(
        request.environment,
        worker_home,
        container_version=container_version,
    )
    _translate_worker_gitconfig_result_paths(
        worker_environment,
        request.results_dir,
        container_results_dir,
    )
    worker_request = _container_worker_request(
        request,
        worker_environment,
        container_results_dir=container_results_dir,
    )
    request_path.write_text(
        json.dumps(
            {
                "workflow": workflow,
                "request": _request_payload(worker_request),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    worker_image = _ensure_worker_container_image(container_version, request.environment)
    command = _filesystem_isolation_command(
        request,
        request_path=request_path,
        result_path=result_path,
        worker_home=worker_home,
        worker_image=worker_image,
        cases_mount_source=cases_view,
        container_results_dir=container_results_dir,
    )
    _write_worker_container_artifacts(
        worker_dir,
        request=request,
        workflow=workflow,
        container_version=container_version,
        worker_image=worker_image,
        command=command,
    )
    completed = subprocess.run(
        command,
        cwd=str(_harness_root()),
        env=_container_tool_environment(request.environment),
        stdout=sys.stdout,
        stderr=sys.stderr,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"isolated {workflow} worker exited with status {completed.returncode}")
    execution = _execution_from_payload(
        json.loads(result_path.read_text(encoding="utf-8")),
        base_dir=_harness_root(),
    )
    return _host_execution_from_container(
        execution,
        host_results_dir=request.results_dir,
        container_results_dir=container_results_dir,
    )


def _isolated_worker_environment(
    environment: Mapping[str, str],
    worker_home: Path,
    *,
    container_version: str,
) -> dict[str, str]:
    env = {
        str(name): str(value)
        for name, value in environment.items()
        if not _build_only_environment_name(str(name))
    }
    _strip_environment_values(env, SENSITIVE_ENVIRONMENT_NAMES)
    env["HOME"] = str(worker_home)
    env["PATH"] = _worker_container_path(env)
    env["PYTHONPATH"] = _container_pythonpath()
    env["PYTHONUNBUFFERED"] = "1"
    env[FILESYSTEM_ISOLATION_WORKER_ENV] = "1"
    env[WORKER_CONTAINER_VERSION_ENV] = container_version
    env["CONTAINER_VERSION"] = container_version

    adc_path = _google_application_credentials_path(env)
    if adc_path is not None:
        (worker_home / ".config" / "gcloud").mkdir(parents=True, exist_ok=True)
        env["GOOGLE_APPLICATION_CREDENTIALS"] = str(
            worker_home / ".config" / "gcloud" / "application_default_credentials.json"
        )
    return env


def _build_only_environment_name(name: str) -> bool:
    return name in BUILD_ONLY_ENVIRONMENT_NAMES or name.startswith(BUILD_ONLY_ENVIRONMENT_PREFIXES)


def _worker_container_path(environment: Mapping[str, str]) -> str:
    shim_dir = environment.get("YMIR_BENCHMARK_COMMAND_SHIMS")
    return f"{shim_dir}{os.pathsep}{WORKER_CONTAINER_PATH}" if shim_dir else WORKER_CONTAINER_PATH


def _google_application_credentials_path(environment: Mapping[str, str]) -> Path | None:
    explicit = environment.get("GOOGLE_APPLICATION_CREDENTIALS")
    candidates = [Path(explicit).expanduser()] if explicit else []
    home = os.environ.get("HOME")
    if home:
        candidates.append(
            Path(home) / ".config" / "gcloud" / "application_default_credentials.json"
        )

    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def _filesystem_isolation_command(
    request: RunCaseRequest,
    *,
    request_path: Path,
    result_path: Path,
    worker_home: Path,
    worker_image: str,
    cases_mount_source: Path | None = None,
    container_results_dir: Path = WORKER_CONTAINER_RESULTS_DIR,
) -> list[str]:
    tool = _container_tool(request.environment)
    if shutil.which(tool) is None:
        raise RuntimeError(
            f"{FILESYSTEM_ISOLATION_ENV}={tool} requested, but {tool} is not installed"
        )

    command = [
        tool,
        "run",
        "--rm",
        "--pull=never",
        "--userns=keep-id",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--security-opt",
        "label=disable",
        "--workdir",
        "/opt/ymir-harness",
        "--volume",
        _container_volume(cases_mount_source or request.cases_dir, request.cases_dir, "ro"),
        "--volume",
        _container_volume(request.results_dir, container_results_dir, "rw"),
        "--env",
        "PYTHONUNBUFFERED=1",
    ]
    for volume in _package_manager_shim_volumes(request.environment):
        command.extend(["--volume", volume])

    for name in sorted(MODEL_PROVIDER_CREDENTIAL_ENVIRONMENT_NAMES):
        if name in request.environment:
            command.extend(["--env", name])

    adc_path = _google_application_credentials_path(request.environment)
    if adc_path is not None:
        command.extend(
            [
                "--volume",
                _container_volume(
                    adc_path,
                    _translate_path_under(
                        worker_home / ".config" / "gcloud" / "application_default_credentials.json",
                        request.results_dir,
                        container_results_dir,
                    ),
                    "ro",
                ),
            ]
        )

    command.extend(
        [
            worker_image,
            "python",
            "-m",
            "ymir_harness.workflow_worker",
            str(_translate_path_under(request_path, request.results_dir, container_results_dir)),
            str(_translate_path_under(result_path, request.results_dir, container_results_dir)),
        ]
    )
    return command


def _package_manager_shim_volumes(environment: Mapping[str, str]) -> list[str]:
    shim_dir_value = environment.get("YMIR_BENCHMARK_COMMAND_SHIMS")
    if not shim_dir_value:
        return []
    shim_dir = Path(shim_dir_value)
    volumes = []
    for name in PACKAGE_MANAGER_SHIM_NAMES:
        source = shim_dir / name
        if source.is_file():
            volumes.append(_container_volume(source, Path("/usr/bin") / name, "ro"))
    return volumes


def _materialize_worker_cases_view(request: RunCaseRequest, worker_dir: Path) -> Path:
    destination = worker_dir / "cases-view"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    case_id = request.case_id
    _copy_case_view_file(request.cases_dir / "cases.yaml", destination / "cases.yaml")
    _copy_case_view_file(
        request.cases_dir / "expected" / f"{case_id}.expected.json",
        destination / "expected" / f"{case_id}.expected.json",
    )
    _copy_case_view_file(
        request.cases_dir / "triage_results" / f"{case_id}.actual.json",
        destination / "triage_results" / f"{case_id}.actual.json",
    )
    _copy_case_view_tree(request.cases_dir / "jiras" / case_id, destination / "jiras" / case_id)
    _copy_case_view_tree(
        request.cases_dir / "web_cache" / case_id,
        destination / "web_cache" / case_id,
    )
    _copy_worker_source_cache_view(request.cases_dir, destination, case_id)
    _copy_worker_mock_data_view(request.cases_dir, destination, case_id)
    return destination


def _copy_worker_source_cache_view(cases_dir: Path, destination: Path, case_id: str) -> None:
    source_cache = cases_dir / "source_cache" / case_id
    _copy_case_view_tree(
        source_cache / "lookaside", destination / "source_cache" / case_id / "lookaside"
    )

    upstream = source_cache / "upstream"
    if not upstream.is_dir():
        return
    for manifest_path in sorted(upstream.glob("*.json")):
        _copy_case_view_file(
            manifest_path,
            destination / "source_cache" / case_id / "upstream" / manifest_path.name,
        )


def _copy_worker_mock_data_view(cases_dir: Path, destination: Path, case_id: str) -> None:
    mock_data = cases_dir / "mock_data"
    if not mock_data.is_dir():
        return
    for agent_dir in sorted(mock_data.iterdir()):
        if not agent_dir.is_dir():
            continue
        _copy_case_view_file(
            agent_dir / f"{case_id}.json",
            destination / "mock_data" / agent_dir.name / f"{case_id}.json",
        )
        _copy_case_view_file(
            agent_dir / "reference_patches" / f"{case_id}.patch",
            destination / "mock_data" / agent_dir.name / "reference_patches" / f"{case_id}.patch",
        )


def _copy_case_view_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        return
    for path in sorted(source.rglob("*")):
        relative_path = path.relative_to(source)
        target = destination / relative_path
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            _copy_case_view_file(path, target)


def _copy_case_view_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination, follow_symlinks=True)
    except OSError:
        shutil.copy2(source, destination, follow_symlinks=True)


def _write_worker_container_artifacts(
    worker_dir: Path,
    *,
    request: RunCaseRequest,
    workflow: str,
    container_version: str,
    worker_image: str,
    command: Sequence[str],
) -> None:
    run_script_path = worker_dir / f"{request.case_id}.container-run.sh"
    debug_script_path = worker_dir / f"{request.case_id}.container-debug-shell.sh"
    command_path = worker_dir / f"{request.case_id}.container-command.json"
    metadata_path = worker_dir / f"{request.case_id}.container.json"
    debug_command = _container_debug_shell_command(
        request,
        worker_home=worker_dir / "home",
        worker_image=worker_image,
    )

    _write_shell_command(run_script_path, command)
    _write_shell_command(debug_script_path, debug_command)
    command_path.write_text(
        json.dumps(
            {
                "cwd": str(_harness_root()),
                "run_command": list(command),
                "run_script": str(run_script_path),
                "debug_shell_command": debug_command,
                "debug_shell_script": str(debug_script_path),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    tool = command[0]
    base_image = (
        None
        if request.environment.get(WORKER_IMAGE_ENV)
        else _worker_base_image(
            container_version,
            request.environment,
        )
    )
    metadata_path.write_text(
        json.dumps(
            {
                "workflow": workflow,
                "case_id": request.case_id,
                "repetition": request.repetition,
                "container_tool": tool,
                "container_version": container_version,
                "run_as_uid": os.getuid(),
                "run_as_gid": os.getgid(),
                "worker_image": worker_image,
                "worker_image_inspect": _container_image_metadata(tool, worker_image),
                "base_image": base_image,
                "base_image_inspect": (
                    _container_image_metadata(tool, base_image) if base_image else None
                ),
                "harness_source": _git_source_metadata(_harness_root()),
                "ymir_source": _git_source_metadata(_harness_root() / "ai-workflows"),
                "command_file": str(command_path),
                "run_script": str(run_script_path),
                "debug_shell_script": str(debug_script_path),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _container_debug_shell_command(
    request: RunCaseRequest,
    *,
    worker_home: Path,
    worker_image: str,
) -> list[str]:
    container_results_dir = WORKER_CONTAINER_RESULTS_DIR
    container_home = _translate_path_under(
        worker_home,
        request.results_dir,
        container_results_dir,
    )
    container_path = _translate_environment_value(
        "PATH",
        _worker_container_path(request.environment),
        request.results_dir,
        container_results_dir,
    )
    command = _filesystem_isolation_command(
        request,
        request_path=Path("/dev/null"),
        result_path=Path("/dev/null"),
        worker_home=worker_home,
        worker_image=worker_image,
        container_results_dir=container_results_dir,
    )
    image_index = command.index(worker_image)
    return [
        *command[:image_index],
        "--interactive",
        "--tty",
        "--env",
        f"HOME={container_home}",
        "--env",
        f"PYTHONPATH={_container_pythonpath()}",
        "--env",
        f"PATH={container_path}",
        worker_image,
        "bash",
        "-l",
    ]


def _write_shell_command(path: Path, command: Sequence[str]) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        f"cd {shlex.quote(str(_harness_root()))}\n"
        f"exec {_shell_command(command)}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _shell_command(command: Sequence[str]) -> str:
    return " \\\n  ".join(shlex.quote(str(part)) for part in command)


def _container_image_metadata(tool: str, image: str) -> dict[str, Any]:
    completed = subprocess.run(
        [tool, "image", "inspect", image, "--format", "{{json .}}"],
        cwd=str(_harness_root()),
        env=_container_tool_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return {
            "inspect_status": completed.returncode,
            "inspect_stderr": completed.stderr.strip(),
        }

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"inspect_stdout": completed.stdout.strip()}

    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    if not isinstance(payload, Mapping):
        return {"inspect_payload": payload}
    return {
        "id": payload.get("Id"),
        "digest": payload.get("Digest"),
        "repo_digests": payload.get("RepoDigests") or [],
        "created": payload.get("Created"),
    }


def _git_source_metadata(path: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {"path": str(path)}
    head = _git_output(path, "rev-parse", "HEAD")
    if head:
        metadata["head"] = head
    dirty = _git_output(path, "status", "--porcelain")
    if dirty is not None:
        metadata["dirty"] = bool(dirty.strip())
    return metadata


def _git_output(path: Path, *args: str) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(path), *args],
        cwd=str(_harness_root()),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _ro_bind_path(source: Path, destination: Path) -> list[str]:
    return ["--ro-bind", str(source), str(destination)]


def _bind_path(source: Path, destination: Path) -> list[str]:
    return ["--bind", str(source), str(destination)]


def _container_volume(source: Path, destination: Path, mode: str) -> str:
    return f"{source}:{destination}:{mode}"


def _container_pythonpath() -> str:
    return "/opt/ymir-harness/src:/home/beeai"


def _container_worker_request(
    request: RunCaseRequest,
    environment: Mapping[str, str],
    *,
    container_results_dir: Path,
) -> RunCaseRequest:
    return RunCaseRequest(
        case_id=request.case_id,
        case_type=request.case_type,
        repetition=request.repetition,
        cases_dir=request.cases_dir,
        results_dir=container_results_dir,
        expected_path=request.expected_path,
        actual_path=_translate_path_under(
            request.actual_path,
            request.results_dir,
            container_results_dir,
        ),
        environment=_translate_environment_result_paths(
            environment,
            request.results_dir,
            container_results_dir,
        ),
        variant=request.variant,
        features=request.features,
    )


def _translate_environment_result_paths(
    environment: Mapping[str, str],
    host_results_dir: Path,
    container_results_dir: Path,
) -> dict[str, str]:
    return {
        name: _translate_environment_value(
            name,
            value,
            host_results_dir,
            container_results_dir,
        )
        for name, value in environment.items()
    }


def _translate_environment_value(
    name: str,
    value: str,
    host_results_dir: Path,
    container_results_dir: Path,
) -> str:
    if name in PATH_LIST_ENVIRONMENT_NAMES:
        return os.pathsep.join(
            _translate_path_string(part, host_results_dir, container_results_dir)
            for part in value.split(os.pathsep)
        )
    if name in JSON_PATH_ENVIRONMENT_NAMES:
        return _translate_json_path_value(value, host_results_dir, container_results_dir)
    return _translate_path_string(value, host_results_dir, container_results_dir)


def _translate_worker_gitconfig_result_paths(
    environment: Mapping[str, str],
    host_results_dir: Path,
    container_results_dir: Path,
) -> None:
    paths: list[Path] = []
    for name in ("GIT_CONFIG_GLOBAL", "YMIR_BENCHMARK_GITCONFIG"):
        value = environment.get(name)
        if not value:
            continue
        paths.append(Path(value))
    paths.extend(sorted(host_results_dir.glob(".mock_gitconfig*")))

    seen: set[Path] = set()
    for path in paths:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        content = path.read_text(encoding="utf-8")
        translated = content.replace(str(host_results_dir), str(container_results_dir))
        if translated != content:
            path.write_text(translated, encoding="utf-8")


def _translate_json_path_value(
    value: str,
    source_root: Path,
    destination_root: Path,
) -> str:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return value
    translated = _translate_result_paths_in_json(payload, source_root, destination_root)
    return json.dumps(translated, sort_keys=True)


def _translate_path_string(
    value: str,
    source_root: Path,
    destination_root: Path,
) -> str:
    path = Path(value)
    if not path.is_absolute():
        return value
    translated = _translate_path_under(path, source_root, destination_root)
    return str(translated)


def _translate_path_under(path: Path, source_root: Path, destination_root: Path) -> Path:
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        return path
    return destination_root / relative


def _host_execution_from_container(
    execution: RunCaseExecution,
    *,
    host_results_dir: Path,
    container_results_dir: Path,
) -> RunCaseExecution:
    actual_path = (
        _translate_path_under(execution.actual_path, container_results_dir, host_results_dir)
        if execution.actual_path is not None
        else None
    )
    actual_result = (
        _translate_result_paths_in_json(
            execution.actual_result,
            container_results_dir,
            host_results_dir,
        )
        if execution.actual_result is not None
        else None
    )
    return RunCaseExecution(
        status=execution.status,
        actual_result=actual_result if isinstance(actual_result, Mapping) else None,
        actual_path=actual_path,
        reason=execution.reason,
    )


def _translate_result_paths_in_json(
    value: Any,
    source_root: Path,
    destination_root: Path,
) -> Any:
    if isinstance(value, str):
        return _translate_path_string(value, source_root, destination_root)
    if isinstance(value, list):
        return [
            _translate_result_paths_in_json(item, source_root, destination_root)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _translate_result_paths_in_json(item, source_root, destination_root)
            for key, item in value.items()
        }
    return value


def _request_payload(request: RunCaseRequest) -> dict[str, Any]:
    return {
        "case_id": request.case_id,
        "case_type": request.case_type,
        "repetition": request.repetition,
        "cases_dir": str(request.cases_dir),
        "results_dir": str(request.results_dir),
        "expected_path": str(request.expected_path),
        "actual_path": str(request.actual_path),
        "environment": dict(request.environment),
        "variant": request.variant,
        "features": list(request.features),
    }


def request_from_payload(payload: Mapping[str, Any]) -> RunCaseRequest:
    return RunCaseRequest(
        case_id=str(payload["case_id"]),
        case_type=payload.get("case_type") if isinstance(payload.get("case_type"), str) else None,
        repetition=int(payload["repetition"]),
        cases_dir=Path(str(payload["cases_dir"])),
        results_dir=Path(str(payload["results_dir"])),
        expected_path=Path(str(payload["expected_path"])),
        actual_path=Path(str(payload["actual_path"])),
        environment={
            str(key): str(value) for key, value in dict(payload.get("environment") or {}).items()
        },
        variant=str(payload["variant"]),
        features=tuple(str(feature) for feature in payload.get("features") or ()),
    )


def execution_to_payload(execution: RunCaseExecution) -> dict[str, Any]:
    return {
        "status": execution.status,
        "actual_result": execution.actual_result,
        "actual_path": str(execution.actual_path) if execution.actual_path is not None else None,
        "reason": execution.reason,
    }


def _execution_from_payload(
    payload: Mapping[str, Any],
    *,
    base_dir: Path,
) -> RunCaseExecution:
    actual_path_value = payload.get("actual_path")
    actual_result = payload.get("actual_result")
    return RunCaseExecution(
        status=str(payload["status"]),  # type: ignore[arg-type]
        actual_result=actual_result if isinstance(actual_result, Mapping) else None,
        actual_path=Path(str(actual_path_value)) if actual_path_value is not None else None,
        reason=payload.get("reason") if isinstance(payload.get("reason"), str) else None,
    )


def _harness_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mock_repo_environment(
    cases_dir: Path,
    results_dir: Path,
    case_id: str,
    repetition: int,
    *,
    source_cache_dir: Path,
) -> dict[str, str]:
    materialized = materialize_case_mock_repos(
        cases_dir,
        results_dir,
        case_id,
        repetition=repetition,
        source_cache_dir=source_cache_dir,
    )
    if materialized is None:
        return {}
    return materialized.to_environment()


def _apply_source_cache_git_rewrites(
    environment: dict[str, str],
    source_cache_dir: Path,
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> None:
    rewrites = source_cache_git_rewrites(source_cache_dir)
    if not rewrites:
        return

    gitconfig_value = environment.get("GIT_CONFIG_GLOBAL")
    gitconfig_path = (
        Path(gitconfig_value)
        if gitconfig_value
        else results_dir / f"repeat-{repetition}" / "source-cache-gitconfig"
    )
    _append_gitconfig_rewrites(gitconfig_path, rewrites)
    environment["GIT_CONFIG_GLOBAL"] = str(gitconfig_path)
    environment["YMIR_BENCHMARK_GITCONFIG"] = str(gitconfig_path)

    blocked_urls = [
        canonicalize_replay_url(url)
        for url in environment.get("MOCK_BLOCKED_URLS", "").splitlines()
    ]
    blocked_urls.extend(canonicalize_replay_url(original) for original, _local in rewrites)
    environment["MOCK_BLOCKED_URLS"] = "\n".join(dict.fromkeys(url for url in blocked_urls if url))


def _write_gateway_gitconfig(environment: dict[str, str], results_dir: Path, case_id: str) -> None:
    gitconfig_value = environment.get("GIT_CONFIG_GLOBAL")
    if not gitconfig_value:
        return

    source = Path(gitconfig_value)
    if not source.is_file():
        return

    base = Path(environment.get("GIT_REPO_BASEPATH", str(results_dir.resolve())))
    destination = base / f".mock_gitconfig_{case_id}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.resolve(strict=False) == source.resolve(strict=False):
        return
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")


def _append_gitconfig_rewrites(path: Path, rewrites: Sequence[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    existing_instead_of = _existing_gitconfig_instead_of_values(existing)
    lines = []
    for original_url, local_url in dict.fromkeys(rewrites):
        if original_url in existing_instead_of:
            continue
        section = f'[url "{local_url}"]\n\tinsteadOf = {original_url}\n'
        if section not in existing:
            lines.append(section)
    if not lines:
        return
    prefix = existing.rstrip()
    content = ("\n\n".join([prefix, *lines]) if prefix else "\n\n".join(lines)).rstrip()
    path.write_text(content + "\n", encoding="utf-8")


def _existing_gitconfig_instead_of_values(content: str) -> set[str]:
    values = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("insteadOf = "):
            continue
        value = stripped.removeprefix("insteadOf = ").strip()
        if value:
            values.add(value)
    return values


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
    cases_dir = expected_path.parent.parent if expected_path.parent.name == "expected" else None
    return score_case(load_json_file(expected_path), actual_result, cases_dir=cases_dir)


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
        urls.extend(
            canonicalize_replay_url(url)
            for url in required_urls
            if isinstance(url, str) and canonicalize_replay_url(url)
        )

    recorded_files = manifest.get("recorded_files")
    if isinstance(recorded_files, Mapping):
        urls.extend(
            canonicalize_replay_url(url)
            for url in recorded_files
            if isinstance(url, str) and canonicalize_replay_url(url)
        )
    return list(dict.fromkeys(urls))


def _apply_run_policies(
    cases_dir: Path,
    case_id: str,
    expected: Mapping[str, Any],
    actual_result: Mapping[str, Any] | None,
    artifact_replay_violations: Sequence[str] = (),
    artifact_replay_misses: Sequence[str] = (),
) -> Mapping[str, Any] | None:
    if actual_result is None:
        return None

    payload = dict(actual_result)
    if artifact_replay_violations:
        _append_result_values(payload, "replay_violations", artifact_replay_violations)
    if artifact_replay_misses:
        _append_result_values(payload, "replay_misses", artifact_replay_misses)

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
            target = "replay_misses" if network_mode == "replay_only" else "replay_violations"
            _append_result_values(payload, target, replay_violations)

    return payload


@contextmanager
def _capture_workflow_output(
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> Iterator[None]:
    stdout_path = workflow_stdout_path(results_dir, case_id, repetition)
    stderr_path = workflow_stderr_path(results_dir, case_id, repetition)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        stdout = stack.enter_context(stdout_path.open("w", encoding="utf-8"))
        stderr = stack.enter_context(stderr_path.open("w", encoding="utf-8"))
        stack.enter_context(redirect_stdout(stdout))
        stack.enter_context(redirect_stderr(stderr))
        yield


def _artifact_replay_violations(
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> list[str]:
    return [
        blocked.to_replay_violation()
        for blocked in _artifact_blocked_urls(results_dir, case_id, repetition)
        if blocked.reason != "replay miss"
    ]


def _artifact_replay_misses(
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> list[str]:
    return [
        blocked.to_replay_violation()
        for blocked in _artifact_blocked_urls(results_dir, case_id, repetition)
        if blocked.reason == "replay miss"
    ]


def _artifact_warnings(
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> list[str]:
    warnings: list[str] = []
    for path in (
        workflow_stdout_path(results_dir, case_id, repetition),
        workflow_stderr_path(results_dir, case_id, repetition),
    ):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(HARNESS_WARNING_PREFIX):
                warnings.append(stripped.removeprefix(HARNESS_WARNING_PREFIX))
    return list(dict.fromkeys(warnings))


def _artifact_blocked_urls(
    results_dir: Path,
    case_id: str,
    repetition: int,
):
    artifact_root = results_dir / f"repeat-{repetition}"
    if not artifact_root.exists():
        return []
    blocked = []
    for path in _case_artifact_paths(results_dir, case_id, repetition):
        try:
            blocked.extend(blocked_urls_from_run_path(path))
        except CaptureMissingError:
            continue
    return list({entry.to_replay_violation(): entry for entry in blocked}.values())


def _case_artifact_paths(
    results_dir: Path,
    case_id: str,
    repetition: int,
) -> list[Path]:
    artifact_root = results_dir / f"repeat-{repetition}"
    paths = [
        workflow_stdout_path(results_dir, case_id, repetition),
        workflow_stderr_path(results_dir, case_id, repetition),
        artifact_root / "mcp-gateway" / f"{case_id}.stdout.log",
        artifact_root / "mcp-gateway" / f"{case_id}.stderr.log",
        artifact_root / "mcp-gateway" / f"{case_id}.debug.log",
        artifact_root / "artifacts" / case_id,
        artifact_root / "jira-mock" / case_id,
    ]

    worker_dir = artifact_root / "workflow-worker"
    if worker_dir.is_dir():
        paths.extend(sorted(worker_dir.glob(f"{case_id}.*")))

    return [path for path in paths if path.exists()]


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
