from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager
from typing import Any

from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.runner import RunCaseExecution, RunCaseRequest

AsyncWorkflow = Callable[..., Awaitable[Any]]
AgentFactory = Callable[..., Any]


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
