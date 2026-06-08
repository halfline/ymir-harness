from __future__ import annotations

import asyncio
import importlib
import inspect
import os
from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.runner import RunCaseExecution, RunCaseRequest
from ymir_harness.scoring import load_json_file

AsyncWorkflow = Callable[..., Awaitable[Any]]
AgentFactory = Callable[..., Any]


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


async def _run_ymir_triage(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> RunCaseExecution:
    workflow_runner, default_agent_factory = _triage_dependencies(workflow, agent_factory)

    with _request_environment(request):
        state = await workflow_runner(
            request.case_id,
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

    with _request_environment(request):
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

    with _request_environment(request):
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

    target_branch = getattr(state, "target_branch", None)
    if target_branch:
        actual["target_branch"] = target_branch

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

    return actual


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
