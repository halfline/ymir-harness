from __future__ import annotations

import asyncio
import importlib
import inspect
import os
import socket
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from ymir_harness.artifacts import merge_artifact_fields
from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.runner import RunCaseExecution, RunCaseRequest
from ymir_harness.scoring import load_json_file

AsyncWorkflow = Callable[..., Awaitable[Any]]
AgentFactory = Callable[..., Any]
MCP_GATEWAY_URL_ENV = "MCP_GATEWAY_URL"
GATEWAY_START_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class BackportInputs:
    package: str
    dist_git_branch: str
    upstream_patches: tuple[str, ...]
    jira_issue: str
    cve_id: str | None
    justification: str | None
    fix_version: str | None


@dataclass(frozen=True)
class RebaseInputs:
    package: str
    dist_git_branch: str
    version: str
    jira_issue: str
    justification: str | None


@dataclass(frozen=True)
class RebuildInputs:
    package: str
    dist_git_branch: str
    jira_issue: str
    justification: str | None
    dependency_issue: str | None
    dependency_component: str | None
    consolidated_issues: tuple[Mapping[str, Any], ...]
    consolidation_summary: str | None


def make_ymir_triage_executor(
    *,
    workflow: AsyncWorkflow | None = None,
    agent_factory: AgentFactory | None = None,
) -> Callable[[RunCaseRequest], RunCaseExecution]:
    def executor(request: RunCaseRequest) -> RunCaseExecution:
        return asyncio.run(
            _run_ymir_triage(
                request,
                workflow=workflow,
                agent_factory=agent_factory,
            )
        )

    return executor


def make_ymir_backport_executor(
    *,
    workflow: AsyncWorkflow | None = None,
    agent_factory: AgentFactory | None = None,
) -> Callable[[RunCaseRequest], RunCaseExecution]:
    def executor(request: RunCaseRequest) -> RunCaseExecution:
        return asyncio.run(
            _run_ymir_backport(
                request,
                workflow=workflow,
                agent_factory=agent_factory,
            )
        )

    return executor


def make_ymir_rebase_executor(
    *,
    workflow: AsyncWorkflow | None = None,
) -> Callable[[RunCaseRequest], RunCaseExecution]:
    def executor(request: RunCaseRequest) -> RunCaseExecution:
        return asyncio.run(
            _run_ymir_rebase(
                request,
                workflow=workflow,
            )
        )

    return executor


def make_ymir_rebuild_executor(
    *,
    workflow: AsyncWorkflow | None = None,
) -> Callable[[RunCaseRequest], RunCaseExecution]:
    def executor(request: RunCaseRequest) -> RunCaseExecution:
        return asyncio.run(
            _run_ymir_rebuild(
                request,
                workflow=workflow,
            )
        )

    return executor


async def _run_ymir_triage(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> RunCaseExecution:
    workflow_runner, default_agent_factory = _triage_dependencies(workflow, agent_factory)

    with _workflow_environment(request, workflow=workflow) as effective_request:
        state = await workflow_runner(
            effective_request.case_id,
            True,
            default_agent_factory,
            auto_chain=False,
            silent_run=True,
        )

    triage_result = getattr(state, "triage_result", None)
    if triage_result is None:
        return RunCaseExecution(
            status="failed",
            reason="ymir triage workflow returned no triage result",
        )

    return RunCaseExecution(
        status="passed",
        actual_result=_triage_actual_result(request, state, triage_result),
    )


async def _run_ymir_backport(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> RunCaseExecution:
    inputs = _backport_inputs(request)
    if isinstance(inputs, RunCaseExecution):
        return inputs

    workflow_runner, default_agent_factory = _backport_dependencies(workflow, agent_factory)

    with _workflow_environment(request, workflow=workflow):
        state = await workflow_runner(
            package=inputs.package,
            dist_git_branch=inputs.dist_git_branch,
            upstream_patches=list(inputs.upstream_patches),
            jira_issue=inputs.jira_issue,
            cve_id=inputs.cve_id,
            justification=inputs.justification,
            fix_version=inputs.fix_version,
            dry_run=True,
            backport_agent_factory=default_agent_factory,
        )

    backport_result = getattr(state, "backport_result", None)
    if backport_result is None:
        return RunCaseExecution(
            status="failed",
            reason="ymir backport workflow returned no backport result",
        )

    return RunCaseExecution(
        status="passed",
        actual_result=_backport_actual_result(request, inputs, state, backport_result),
    )


async def _run_ymir_rebase(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
) -> RunCaseExecution:
    inputs = _rebase_inputs(request)
    if isinstance(inputs, RunCaseExecution):
        return inputs

    workflow_runner = _rebase_dependencies(workflow)

    with _workflow_environment(request, workflow=workflow):
        state = await workflow_runner(
            package=inputs.package,
            dist_git_branch=inputs.dist_git_branch,
            version=inputs.version,
            jira_issue=inputs.jira_issue,
            justification=inputs.justification,
            redis_conn=None,
        )

    rebase_result = getattr(state, "rebase_result", None)
    if rebase_result is None:
        return RunCaseExecution(
            status="failed",
            reason="ymir rebase workflow returned no rebase result",
        )

    return RunCaseExecution(
        status="passed",
        actual_result=_rebase_actual_result(request, inputs, state, rebase_result),
    )


async def _run_ymir_rebuild(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
) -> RunCaseExecution:
    inputs = _rebuild_inputs(request)
    if isinstance(inputs, RunCaseExecution):
        return inputs

    workflow_runner = _rebuild_dependencies(workflow)

    with _workflow_environment(request, workflow=workflow):
        state = await workflow_runner(
            package=inputs.package,
            dist_git_branch=inputs.dist_git_branch,
            jira_issue=inputs.jira_issue,
            justification=inputs.justification,
            dependency_issue=inputs.dependency_issue,
            dependency_component=inputs.dependency_component,
            consolidated_issues=list(inputs.consolidated_issues),
            consolidation_summary=inputs.consolidation_summary,
        )

    if not hasattr(state, "rebuild_success"):
        return RunCaseExecution(
            status="failed",
            reason="ymir rebuild workflow returned no rebuild result",
        )

    return RunCaseExecution(
        status="passed",
        actual_result=_rebuild_actual_result(request, inputs, state),
    )


@contextmanager
def _workflow_environment(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
) -> Any:
    if workflow is not None or _string_or_none(request.environment.get(MCP_GATEWAY_URL_ENV)):
        with _request_environment(request):
            yield request
        return

    with _managed_mcp_gateway(request) as gateway_url:
        effective_request = _request_with_environment(
            request,
            {
                **request.environment,
                MCP_GATEWAY_URL_ENV: gateway_url,
            },
        )
        with _request_environment(effective_request):
            yield effective_request


@contextmanager
def _managed_mcp_gateway(request: RunCaseRequest) -> Any:
    port = _available_local_port()
    gateway_dir = request.results_dir / f"repeat-{request.repetition}" / "mcp-gateway"
    gateway_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = gateway_dir / f"{request.case_id}.stdout.log"
    stderr_path = gateway_dir / f"{request.case_id}.stderr.log"
    gateway_url = f"http://127.0.0.1:{port}/sse"

    env = {
        **request.environment,
        "MCP_TRANSPORT": "sse",
        "SSE_PORT": str(port),
        "PYTHONUNBUFFERED": "1",
        "JIRA_URL": request.environment.get("JIRA_URL", "https://redhat.atlassian.net"),
        "DEBUG_FILE": str(gateway_dir / f"{request.case_id}.debug.log"),
    }

    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-m", "ymir_harness.ymir_gateway"],
            stdout=stdout,
            stderr=stderr,
            env=env,
        )
        try:
            _wait_for_gateway(process, port, stderr_path)
            yield gateway_url
        finally:
            _terminate_gateway(process)


def _available_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _wait_for_gateway(
    process: subprocess.Popen[bytes],
    port: int,
    stderr_path: Path,
) -> None:
    deadline = time.monotonic() + GATEWAY_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                "managed MCP gateway exited before accepting connections"
                + _gateway_log_excerpt(stderr_path)
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)

    raise RuntimeError(
        f"managed MCP gateway did not accept connections within "
        f"{GATEWAY_START_TIMEOUT_SECONDS:g}s" + _gateway_log_excerpt(stderr_path)
    )


def _terminate_gateway(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _gateway_log_excerpt(stderr_path: Path) -> str:
    try:
        text = stderr_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    if not text:
        return ""
    lines = text.splitlines()[-8:]
    return ": " + " | ".join(lines)


def _request_with_environment(
    request: RunCaseRequest,
    environment: Mapping[str, str],
) -> RunCaseRequest:
    return RunCaseRequest(
        case_id=request.case_id,
        case_type=request.case_type,
        repetition=request.repetition,
        cases_dir=request.cases_dir,
        results_dir=request.results_dir,
        expected_path=request.expected_path,
        actual_path=request.actual_path,
        environment=environment,
        variant=request.variant,
        features=request.features,
    )


def _triage_dependencies(
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> tuple[AsyncWorkflow, AgentFactory]:
    if workflow is not None and agent_factory is not None:
        return workflow, agent_factory

    from ymir.agents.triage_agent import (  # type: ignore[import-not-found]
        create_triage_agent,
        run_workflow,
    )

    return workflow or run_workflow, agent_factory or create_triage_agent


def _backport_dependencies(
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> tuple[AsyncWorkflow, AgentFactory]:
    if workflow is not None and agent_factory is not None:
        return workflow, agent_factory

    from ymir.agents.backport_agent import (  # type: ignore[import-not-found]
        create_backport_agent,
        run_workflow,
    )

    return workflow or run_workflow, agent_factory or create_backport_agent


def _rebase_dependencies(workflow: AsyncWorkflow | None) -> AsyncWorkflow:
    if workflow is not None:
        return workflow

    return _agent_class_workflow(
        "ymir.agents.rebase_agent",
        class_names=("RebaseAgent", "RebaseWorkflow"),
    )


def _rebuild_dependencies(workflow: AsyncWorkflow | None) -> AsyncWorkflow:
    if workflow is not None:
        return workflow

    return _agent_class_workflow(
        "ymir.agents.rebuild_agent",
        class_names=("RebuildAgent", "RebuildWorkflow"),
    )


def _agent_class_workflow(
    module_name: str,
    *,
    class_names: tuple[str, ...],
) -> AsyncWorkflow:
    module = importlib.import_module(module_name)

    for class_name in class_names:
        workflow_class = getattr(module, class_name, None)
        if inspect.isclass(workflow_class) and callable(
            getattr(workflow_class, "run_workflow", None)
        ):
            return _bind_class_workflow(module_name, class_name, workflow_class)

    candidates = [
        name
        for name, value in vars(module).items()
        if inspect.isclass(value) and callable(getattr(value, "run_workflow", None))
    ]
    if len(candidates) == 1:
        class_name = candidates[0]
        return _bind_class_workflow(module_name, class_name, getattr(module, class_name))

    if not candidates:
        raise ImportError(f"{module_name} does not define an agent class with run_workflow")

    joined = ", ".join(sorted(candidates))
    raise ImportError(f"{module_name} defines multiple agent classes with run_workflow: {joined}")


def _bind_class_workflow(module_name: str, class_name: str, workflow_class: type) -> AsyncWorkflow:
    descriptor = inspect.getattr_static(workflow_class, "run_workflow", None)
    if descriptor is None:
        raise ImportError(f"{module_name}.{class_name} does not define run_workflow")

    if isinstance(descriptor, staticmethod | classmethod):
        workflow = descriptor.__get__(None, workflow_class)
    else:
        try:
            workflow = getattr(workflow_class(), "run_workflow")
        except TypeError as exc:
            raise ImportError(
                f"{module_name}.{class_name} must be instantiable without arguments "
                "or define run_workflow as a staticmethod/classmethod"
            ) from exc

    if not callable(workflow):
        raise ImportError(f"{module_name}.{class_name}.run_workflow is not callable")

    return workflow


def _triage_actual_result(
    request: RunCaseRequest,
    state: Any,
    triage_result: Any,
) -> dict[str, Any]:
    payload = _model_payload(triage_result)
    data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
    actual: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "workflow": "ymir-triage",
        **payload,
    }

    for name in (
        "package",
        "patch_urls",
        "cve_id",
        "fix_version",
        "version",
        "dependency_issue",
        "dependency_component",
    ):
        if name in data and data[name] is not None:
            actual[name] = data[name]

    if "package" not in actual:
        expected = load_json_file(request.expected_path)
        pkg = expected.get("package")
        if pkg:
            actual["package"] = pkg

    target_branch = getattr(state, "target_branch", None)
    if target_branch:
        actual["target_branch"] = target_branch

    actual.update(_state_diagnostics(state))
    return actual


def _backport_inputs(request: RunCaseRequest) -> BackportInputs | RunCaseExecution:
    expected = load_json_file(request.expected_path)
    upstream_patches = tuple(
        _string_list(expected.get("patch_urls")) or _string_list(expected.get("fix_sources"))
    )
    values = {
        "package": _string_or_none(expected.get("package")),
        "dist_git_branch": _string_or_none(
            expected.get("dist_git_branch")
            or expected.get("target_branch")
            or expected.get("fix_version")
        ),
        "upstream_patches": upstream_patches,
        "jira_issue": _string_or_none(expected.get("jira_issue") or expected.get("case_id"))
        or request.case_id,
    }
    missing = [
        name for name, value in values.items() if value is None or value == () or value == ""
    ]
    if missing:
        return RunCaseExecution(
            status="failed",
            reason=f"ymir backport workflow missing expected {', '.join(missing)}",
        )

    return BackportInputs(
        package=values["package"],
        dist_git_branch=values["dist_git_branch"],
        upstream_patches=upstream_patches,
        jira_issue=values["jira_issue"],
        cve_id=_first_string(expected.get("cve_id"), expected.get("cve_ids")),
        justification=_string_or_none(
            expected.get("justification") or expected.get("rationale") or expected.get("notes")
        ),
        fix_version=_string_or_none(expected.get("fix_version")),
    )


def _rebase_inputs(request: RunCaseRequest) -> RebaseInputs | RunCaseExecution:
    expected = load_json_file(request.expected_path)
    values = {
        "package": _string_or_none(expected.get("package")),
        "dist_git_branch": _string_or_none(
            expected.get("dist_git_branch")
            or expected.get("target_branch")
            or expected.get("fix_version")
        ),
        "version": _string_or_none(expected.get("version") or expected.get("target_version")),
        "jira_issue": _string_or_none(expected.get("jira_issue") or expected.get("case_id"))
        or request.case_id,
    }
    missing = [name for name, value in values.items() if value is None or value == ""]
    if missing:
        return RunCaseExecution(
            status="failed",
            reason=f"ymir rebase workflow missing expected {', '.join(missing)}",
        )

    return RebaseInputs(
        package=values["package"],
        dist_git_branch=values["dist_git_branch"],
        version=values["version"],
        jira_issue=values["jira_issue"],
        justification=_string_or_none(
            expected.get("justification") or expected.get("rationale") or expected.get("notes")
        ),
    )


def _rebuild_inputs(request: RunCaseRequest) -> RebuildInputs | RunCaseExecution:
    expected = load_json_file(request.expected_path)
    dependency_issue = _first_string(
        expected.get("dependency_issue"),
        expected.get("dependency_issues"),
    )
    dependency_component = _first_string(
        expected.get("dependency_component"),
        expected.get("dependency_components"),
    )
    values = {
        "package": _string_or_none(expected.get("package")),
        "dist_git_branch": _string_or_none(
            expected.get("dist_git_branch")
            or expected.get("target_branch")
            or expected.get("fix_version")
        ),
        "jira_issue": _string_or_none(expected.get("jira_issue") or expected.get("case_id"))
        or request.case_id,
    }
    missing = [name for name, value in values.items() if value is None or value == ""]
    if missing:
        return RunCaseExecution(
            status="failed",
            reason=f"ymir rebuild workflow missing expected {', '.join(missing)}",
        )

    return RebuildInputs(
        package=values["package"],
        dist_git_branch=values["dist_git_branch"],
        jira_issue=values["jira_issue"],
        justification=_string_or_none(
            expected.get("justification") or expected.get("rationale") or expected.get("notes")
        ),
        dependency_issue=dependency_issue,
        dependency_component=dependency_component,
        consolidated_issues=tuple(
            _expected_consolidated_issues(
                expected,
                dependency_issue=dependency_issue,
                dependency_component=dependency_component,
            )
        ),
        consolidation_summary=_string_or_none(expected.get("consolidation_summary")),
    )


def _backport_actual_result(
    request: RunCaseRequest,
    inputs: BackportInputs,
    state: Any,
    backport_result: Any,
) -> dict[str, Any]:
    payload = _model_payload(backport_result)
    package = getattr(state, "package", None) or inputs.package
    dist_git_branch = getattr(state, "dist_git_branch", None) or inputs.dist_git_branch
    upstream_patches = getattr(state, "upstream_patches", None) or inputs.upstream_patches
    cve_id = getattr(state, "cve_id", None) or inputs.cve_id
    srpm_path = payload.get("srpm_path")

    actual: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "workflow": "ymir-backport",
        "resolution": "backport",
        "package": package,
        "target_branch": dist_git_branch,
        "patch_urls": _string_list(upstream_patches),
        "cve_ids": [cve_id] if cve_id else [],
        "build_result": "passed" if payload.get("success") else "failed",
        "backport_status": payload.get("status"),
        "backport_error": payload.get("error"),
        "data": payload,
    }
    if srpm_path:
        actual["generated_artifacts"] = [str(srpm_path)]

    merge_artifact_fields(
        actual,
        request_artifact_dir=_request_artifact_dir(request),
        state=state,
        payload=payload,
    )
    actual.update(_state_diagnostics(state))
    return actual


def _rebase_actual_result(
    request: RunCaseRequest,
    inputs: RebaseInputs,
    state: Any,
    rebase_result: Any,
) -> dict[str, Any]:
    payload = _model_payload(rebase_result)
    package = getattr(state, "package", None) or inputs.package
    dist_git_branch = getattr(state, "dist_git_branch", None) or inputs.dist_git_branch
    version = getattr(state, "version", None) or inputs.version
    srpm_path = payload.get("srpm_path")
    files_to_git_add = _string_list(payload.get("files_to_git_add"))

    actual: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "workflow": "ymir-rebase",
        "resolution": "rebase",
        "package": package,
        "target_branch": dist_git_branch,
        "version": version,
        "build_result": "passed" if payload.get("success") else "failed",
        "rebase_status": payload.get("status"),
        "rebase_error": payload.get("error"),
        "data": payload,
    }
    if srpm_path:
        actual["generated_artifacts"] = [str(srpm_path)]
    if files_to_git_add:
        actual["touched_files"] = files_to_git_add

    merge_artifact_fields(
        actual,
        request_artifact_dir=_request_artifact_dir(request),
        state=state,
        payload=payload,
    )
    actual.update(_state_diagnostics(state))
    return actual


def _rebuild_actual_result(
    request: RunCaseRequest,
    inputs: RebuildInputs,
    state: Any,
) -> dict[str, Any]:
    success = bool(getattr(state, "rebuild_success"))
    package = getattr(state, "package", None) or inputs.package
    dist_git_branch = getattr(state, "dist_git_branch", None) or inputs.dist_git_branch
    dependency_issue = getattr(state, "dependency_issue", None) or inputs.dependency_issue
    dependency_component = (
        getattr(state, "dependency_component", None) or inputs.dependency_component
    )
    consolidated_issues = _consolidated_issue_payloads(
        getattr(state, "consolidated_issues", None) or inputs.consolidated_issues
    )
    dependency_issues = _unique_strings(
        [
            dependency_issue,
            *[issue.get("dependency_issue") for issue in consolidated_issues],
        ]
    )
    dependency_components = _unique_strings(
        [
            dependency_component,
            *[issue.get("dependency_component") for issue in consolidated_issues],
        ]
    )
    sibling_issues = _unique_strings(issue.get("issue_key") for issue in consolidated_issues)
    merge_request_url = _string_or_none(getattr(state, "merge_request_url", None))
    rebuild_error = _string_or_none(getattr(state, "rebuild_error", None))
    consolidation_summary = (
        _string_or_none(getattr(state, "consolidation_summary", None))
        or inputs.consolidation_summary
    )
    status = "rebuilt" if success else "failed"
    data: dict[str, Any] = {
        "success": success,
        "status": status,
        "merge_request_url": merge_request_url,
        "error": rebuild_error,
        "dependency_issues": dependency_issues,
        "dependency_components": dependency_components,
        "sibling_issues": sibling_issues,
        "consolidated_issues": consolidated_issues,
        "consolidation_summary": consolidation_summary,
    }
    actual: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "workflow": "ymir-rebuild",
        "resolution": "rebuild",
        "package": package,
        "target_branch": dist_git_branch,
        "build_result": "passed" if success else "failed",
        "rebuild_status": status,
        "rebuild_error": rebuild_error,
        "data": data,
    }
    if merge_request_url:
        actual["merge_request_url"] = merge_request_url
    if dependency_issues:
        actual["dependency_issues"] = dependency_issues
    if dependency_components:
        actual["dependency_components"] = dependency_components
    if sibling_issues:
        actual["sibling_issues"] = sibling_issues

    merge_artifact_fields(
        actual,
        request_artifact_dir=_request_artifact_dir(request),
        state=state,
        payload=data,
    )
    actual.update(_state_diagnostics(state))
    return actual


def _request_artifact_dir(request: RunCaseRequest) -> Path | None:
    artifact_dir = request.environment.get("YMIR_BENCHMARK_ARTIFACT_DIR")
    return Path(artifact_dir) if artifact_dir else None


def _model_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        payload = {}

    if not isinstance(payload, dict):
        return {}
    return payload


def _state_diagnostics(state: Any) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {}

    usage = _diagnostic_payload(getattr(state, "usage", None))
    if usage is not None:
        diagnostics["token_usage"] = usage

    iteration_count = _int_or_none(
        _field_value(state, "iteration_count") or _field_value(state, "iteration")
    )
    if iteration_count is not None:
        diagnostics["iteration_count"] = iteration_count

    tool_call_count = _tool_call_count(state)
    if tool_call_count is not None:
        diagnostics["tool_call_count"] = tool_call_count

    total_cost_usd = _total_cost_usd(state)
    if total_cost_usd is not None:
        diagnostics["total_cost_usd"] = total_cost_usd

    return diagnostics


def _diagnostic_payload(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return _compact_mapping(value)
    if is_dataclass(value):
        return _compact_mapping(asdict(value))
    if hasattr(value, "model_dump"):
        try:
            payload = value.model_dump(mode="json")
        except TypeError:
            payload = value.model_dump()
        if isinstance(payload, Mapping):
            return _compact_mapping(payload)
        return payload
    return _number_or_none(value)


def _compact_mapping(value: Mapping[str, Any]) -> dict[str, Any] | None:
    payload = {str(key): item for key, item in value.items() if item is not None}
    return payload or None


def _tool_call_count(state: Any) -> int | None:
    direct = _int_or_none(_field_value(state, "tool_call_count"))
    if direct is not None:
        return direct

    tool_calls = _field_value(state, "tool_calls")
    if isinstance(tool_calls, list | tuple):
        return len(tool_calls)

    steps = _field_value(state, "steps")
    if isinstance(steps, list | tuple):
        return len(steps)

    return None


def _total_cost_usd(state: Any) -> float | None:
    direct = _number_or_none(_field_value(state, "total_cost_usd"))
    if direct is not None:
        return direct

    cost = _field_value(state, "cost")
    if cost is None:
        return None

    for name in ("total_cost_usd", "total_usd", "usd", "total"):
        value = _number_or_none(_field_value(cost, name))
        if value is not None:
            return value

    payload = _diagnostic_payload(cost)
    if isinstance(payload, Mapping):
        for name in ("total_cost_usd", "total_usd", "usd", "total"):
            value = _number_or_none(payload.get(name))
            if value is not None:
                return value

    return _number_or_none(cost)


def _string_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        string = value.strip()
        return [string] if string else []
    if isinstance(value, tuple | list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _first_string(*values: Any) -> str | None:
    for value in values:
        if string := _string_or_none(value):
            return string
        strings = _string_list(value)
        if strings:
            return strings[0]
    return None


def _expected_consolidated_issues(
    expected: Mapping[str, Any],
    *,
    dependency_issue: str | None,
    dependency_component: str | None,
) -> list[Mapping[str, Any]]:
    payloads = _consolidated_issue_payloads(expected.get("consolidated_issues"))
    if payloads:
        return payloads

    return [
        {
            "issue_key": issue,
            "dependency_issue": dependency_issue,
            "dependency_component": dependency_component,
        }
        for issue in _string_list(expected.get("sibling_issues"))
    ]


def _consolidated_issue_payloads(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list | tuple):
        return []
    payloads = []
    for item in value:
        payload = _consolidated_issue_payload(item)
        if payload is not None:
            payloads.append(payload)
    return payloads


def _consolidated_issue_payload(value: Any) -> dict[str, Any] | None:
    issue_key = _string_or_none(_field_value(value, "issue_key"))
    if issue_key is None:
        return None
    return {
        "issue_key": issue_key,
        "dependency_issue": _string_or_none(_field_value(value, "dependency_issue")),
        "dependency_component": _string_or_none(_field_value(value, "dependency_component")),
    }


def _field_value(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _number_or_none(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _unique_strings(values: Any) -> list[str]:
    seen = set()
    strings = []
    for value in values:
        string = _string_or_none(value)
        if string is None or string in seen:
            continue
        seen.add(string)
        strings.append(string)
    return strings


@contextmanager
def _request_environment(request: RunCaseRequest):
    original = os.environ.copy()
    env = dict(request.environment)
    for feature in request.features:
        env[feature] = "true"

    os.environ.clear()
    os.environ.update(env)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)
