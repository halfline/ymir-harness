from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from ymir_harness.artifacts import capture_backport_artifacts, merge_artifact_fields
from ymir_harness.llm_judge import evaluate_backport_llm_judge
from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.replay_metadata import (
    install_specfile_changelog_replay,
    replay_metadata_environment,
)
from ymir_harness.runner import DEFAULT_CHAT_MODEL, RunCaseExecution, RunCaseRequest
from ymir_harness.scoring import load_json_file
from ymir_harness.source_fixtures import find_source_cache_repository
from ymir_harness.ymir_source import ensure_ymir_source_path

AsyncWorkflow = Callable[..., Awaitable[Any]]
AgentFactory = Callable[..., Any]
MCP_GATEWAY_URL_ENV = "MCP_GATEWAY_URL"
CHAT_MODEL_ENV = "CHAT_MODEL"
GATEWAY_START_TIMEOUT_SECONDS = 10.0
WORKFLOW_PROGRESS_INTERVAL_SECONDS = 30.0


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

    executor.ymir_workflow = "ymir-triage"  # type: ignore[attr-defined]
    executor.ymir_isolatable = workflow is None and agent_factory is None  # type: ignore[attr-defined]
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

    executor.ymir_workflow = "ymir-backport"  # type: ignore[attr-defined]
    executor.ymir_isolatable = workflow is None and agent_factory is None  # type: ignore[attr-defined]
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

    executor.ymir_workflow = "ymir-rebase"  # type: ignore[attr-defined]
    executor.ymir_isolatable = workflow is None  # type: ignore[attr-defined]
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

    executor.ymir_workflow = "ymir-rebuild"  # type: ignore[attr-defined]
    executor.ymir_isolatable = workflow is None  # type: ignore[attr-defined]
    return executor


async def _run_ymir_triage(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> RunCaseExecution:
    missing_dependency = _live_workflow_dependency_failure(
        request,
        workflow=workflow,
        workflow_name="triage",
    )
    if missing_dependency is not None:
        return missing_dependency

    workflow_runner, default_agent_factory = _triage_dependencies(workflow, agent_factory)
    if workflow is None:
        default_agent_factory = _instrument_sync_agent_factory(
            default_agent_factory,
            request=request,
            agent_name="triage",
        )

    with _workflow_environment(request, workflow=workflow) as effective_request:
        state = await _await_workflow(
            effective_request,
            "triage",
            workflow_runner(
                effective_request.case_id,
                True,
                default_agent_factory,
                auto_chain=False,
                silent_run=True,
            ),
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

    missing_dependency = _live_workflow_dependency_failure(
        request,
        workflow=workflow,
        workflow_name="backport",
    )
    if missing_dependency is not None:
        return missing_dependency

    workflow_runner, default_agent_factory = _backport_dependencies(workflow, agent_factory)
    if workflow is None:
        default_agent_factory = _wrap_backport_replay_agent_factory(
            default_agent_factory,
            request=request,
        )
        default_agent_factory = _instrument_agent_factory(
            default_agent_factory,
            request=request,
            agent_name="backport",
        )

    with _workflow_environment(request, workflow=workflow):
        state = await _await_workflow(
            request,
            "backport",
            workflow_runner(
                package=inputs.package,
                dist_git_branch=inputs.dist_git_branch,
                upstream_patches=list(inputs.upstream_patches),
                jira_issue=inputs.jira_issue,
                cve_id=inputs.cve_id,
                justification=inputs.justification,
                fix_version=inputs.fix_version,
                dry_run=True,
                backport_agent_factory=default_agent_factory,
            ),
        )

    backport_result = getattr(state, "backport_result", None)
    if backport_result is None:
        return RunCaseExecution(
            status="failed",
            reason="ymir backport workflow returned no backport result",
        )

    actual_result = _backport_actual_result(request, inputs, state, backport_result)
    judge_advisory = await evaluate_backport_llm_judge(
        actual_result=actual_result,
        cases_dir=request.cases_dir,
        environment=request.environment,
    )
    if judge_advisory:
        actual_result.update(judge_advisory)
        judge_artifact = judge_advisory.get("llm_judge_artifact")
        if isinstance(judge_artifact, str) and judge_artifact:
            actual_result["generated_artifacts"] = _unique_strings(
                [*_string_list(actual_result.get("generated_artifacts")), judge_artifact]
            )

    return RunCaseExecution(
        status="passed",
        actual_result=actual_result,
    )


async def _run_ymir_rebase(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
) -> RunCaseExecution:
    inputs = _rebase_inputs(request)
    if isinstance(inputs, RunCaseExecution):
        return inputs

    missing_dependency = _live_workflow_dependency_failure(
        request,
        workflow=workflow,
        workflow_name="rebase",
    )
    if missing_dependency is not None:
        return missing_dependency

    workflow_runner = _rebase_dependencies(workflow)

    with _workflow_environment(request, workflow=workflow):
        state = await _await_workflow(
            request,
            "rebase",
            workflow_runner(
                package=inputs.package,
                dist_git_branch=inputs.dist_git_branch,
                version=inputs.version,
                jira_issue=inputs.jira_issue,
                justification=inputs.justification,
                redis_conn=None,
            ),
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

    missing_dependency = _live_workflow_dependency_failure(
        request,
        workflow=workflow,
        workflow_name="rebuild",
    )
    if missing_dependency is not None:
        return missing_dependency

    workflow_runner = _rebuild_dependencies(workflow)

    with _workflow_environment(request, workflow=workflow):
        state = await _await_workflow(
            request,
            "rebuild",
            workflow_runner(
                package=inputs.package,
                dist_git_branch=inputs.dist_git_branch,
                jira_issue=inputs.jira_issue,
                justification=inputs.justification,
                dependency_issue=inputs.dependency_issue,
                dependency_component=inputs.dependency_component,
                consolidated_issues=list(inputs.consolidated_issues),
                consolidation_summary=inputs.consolidation_summary,
            ),
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


def _live_workflow_dependency_failure(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
    workflow_name: str,
) -> RunCaseExecution | None:
    if workflow is not None or _string_or_none(request.environment.get(CHAT_MODEL_ENV)):
        return None

    return RunCaseExecution(
        status="failed",
        reason=(
            f"ymir {workflow_name} workflow missing {CHAT_MODEL_ENV}; "
            f"set CHAT_MODEL in the run environment, e.g. {DEFAULT_CHAT_MODEL}"
        ),
    )


@contextmanager
def _workflow_environment(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
) -> Any:
    request = _request_with_replay_metadata_environment(request)
    if workflow is not None or _string_or_none(request.environment.get(MCP_GATEWAY_URL_ENV)):
        _workflow_debug(request, "workflow_environment", mode="external_gateway_or_injected")
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
            _workflow_debug(
                effective_request,
                "workflow_environment",
                mode="managed_gateway",
                gateway_url=gateway_url,
            )
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
        _workflow_debug(
            request,
            "gateway_starting",
            stderr_path=str(stderr_path),
            stdout_path=str(stdout_path),
            port=port,
        )
        process = subprocess.Popen(
            [sys.executable, "-m", "ymir_harness.ymir_gateway"],
            stdout=stdout,
            stderr=stderr,
            env=env,
        )
        try:
            _wait_for_gateway(process, port, stderr_path)
            _workflow_debug(request, "gateway_ready", gateway_url=gateway_url, pid=process.pid)
            yield gateway_url
        finally:
            _workflow_debug(request, "gateway_stopping", pid=process.pid)
            _terminate_gateway(process)
            _workflow_debug(request, "gateway_stopped", returncode=process.returncode)


async def _await_workflow(
    request: RunCaseRequest,
    workflow_name: str,
    awaitable: Awaitable[Any],
) -> Any:
    started_at = time.monotonic()
    _workflow_debug(request, "workflow_started", workflow=workflow_name)
    task = asyncio.create_task(awaitable)
    interval = _workflow_progress_interval(request)

    try:
        if interval <= 0:
            result = await task
        else:
            while not task.done():
                done, _pending = await asyncio.wait({task}, timeout=interval)
                if done:
                    break
                _workflow_debug(
                    request,
                    "workflow_waiting",
                    workflow=workflow_name,
                    elapsed_seconds=round(time.monotonic() - started_at, 3),
                )
            result = await task
    except BaseException as exc:
        _workflow_debug(
            request,
            "workflow_errored",
            workflow=workflow_name,
            elapsed_seconds=round(time.monotonic() - started_at, 3),
            error_type=type(exc).__name__,
            error=str(exc),
            error_detail="".join(traceback.format_exception(exc)),
        )
        raise

    _workflow_debug(
        request,
        "workflow_finished",
        workflow=workflow_name,
        elapsed_seconds=round(time.monotonic() - started_at, 3),
        state_type=type(result).__name__,
    )
    return result


def _workflow_progress_interval(request: RunCaseRequest) -> float:
    raw_value = request.environment.get("YMIR_HARNESS_WORKFLOW_PROGRESS_INTERVAL")
    if raw_value is None:
        return WORKFLOW_PROGRESS_INTERVAL_SECONDS
    try:
        return float(raw_value)
    except ValueError:
        return WORKFLOW_PROGRESS_INTERVAL_SECONDS


def _agent_timeout_seconds(request: RunCaseRequest) -> float | None:
    raw_value = request.environment.get("YMIR_HARNESS_AGENT_TIMEOUT_SECONDS")
    if raw_value is None:
        return None
    try:
        value = float(raw_value)
    except ValueError:
        return None
    return value if value > 0 else None


def _instrument_agent_factory(
    agent_factory: AgentFactory,
    *,
    request: RunCaseRequest,
    agent_name: str,
) -> AgentFactory:
    async def factory(*args: Any, **kwargs: Any) -> Any:
        result = agent_factory(*args, **kwargs)
        agent = await result if inspect.isawaitable(result) else result
        return _instrument_agent(agent, request=request, agent_name=agent_name)

    return factory


def _instrument_sync_agent_factory(
    agent_factory: AgentFactory,
    *,
    request: RunCaseRequest,
    agent_name: str,
) -> AgentFactory:
    def factory(*args: Any, **kwargs: Any) -> Any:
        result = agent_factory(*args, **kwargs)
        if inspect.isawaitable(result):
            return _instrument_agent_awaitable(result, request=request, agent_name=agent_name)
        return _instrument_agent(result, request=request, agent_name=agent_name)

    return factory


async def _instrument_agent_awaitable(
    awaitable: Awaitable[Any],
    *,
    request: RunCaseRequest,
    agent_name: str,
) -> Any:
    agent = await awaitable
    return _instrument_agent(agent, request=request, agent_name=agent_name)


def _instrument_agent(agent: Any, *, request: RunCaseRequest, agent_name: str) -> Any:
    _instrument_agent_llm(agent, request=request, agent_name=agent_name)
    return _InstrumentedAgent(agent, request=request, agent_name=agent_name)


def _instrument_agent_llm(agent: Any, *, request: RunCaseRequest, agent_name: str) -> None:
    llm = getattr(agent, "_llm", None)
    if llm is None or isinstance(llm, _InstrumentedChatModel):
        return
    try:
        setattr(agent, "_llm", _InstrumentedChatModel(llm, request=request, agent_name=agent_name))
    except (AttributeError, TypeError):
        _workflow_debug(
            request,
            "chat_model_instrumentation_skipped",
            agent=agent_name,
            agent_type=type(agent).__name__,
            chat_model_type=type(llm).__name__,
        )


class _InstrumentedChatModel:
    def __init__(self, model: Any, *, request: RunCaseRequest, agent_name: str) -> None:
        self._model = model
        self._request = request
        self._agent_name = agent_name

    def __getattr__(self, name: str) -> Any:
        return getattr(self._model, name)

    def run(self, messages: Any, **options: Any) -> Any:
        _workflow_debug(
            self._request,
            "chat_model_run_start",
            agent=self._agent_name,
            chat_model_type=type(self._model).__name__,
            message_count=_safe_len(messages),
            message_summary=_message_summary(messages),
            option_keys=sorted(options),
        )
        run = self._model.run(messages, **options)
        _workflow_debug(
            self._request,
            "chat_model_run_created",
            agent=self._agent_name,
            run_type=type(run).__name__,
        )
        return _InstrumentedChatModelRun(run, request=self._request, agent_name=self._agent_name)


class _InstrumentedChatModelRun:
    def __init__(self, run: Any, *, request: RunCaseRequest, agent_name: str) -> None:
        self._run = run
        self._request = request
        self._agent_name = agent_name

    def __getattr__(self, name: str) -> Any:
        return getattr(self._run, name)

    def middleware(self, *args: Any, **kwargs: Any) -> Awaitable[Any]:
        _workflow_debug(
            self._request,
            "chat_model_middleware_start",
            agent=self._agent_name,
            middleware_count=len(args) + len(kwargs),
        )
        awaitable = self._run.middleware(*args, **kwargs)
        _workflow_debug(
            self._request,
            "chat_model_awaitable_created",
            agent=self._agent_name,
            awaitable_type=type(awaitable).__name__,
        )
        return self._log_awaitable(awaitable)

    async def _log_awaitable(self, awaitable: Awaitable[Any]) -> Any:
        started_at = time.monotonic()
        _workflow_debug(
            self._request,
            "chat_model_await_start",
            agent=self._agent_name,
        )
        try:
            result = await awaitable
        except BaseException as exc:
            _workflow_debug(
                self._request,
                "chat_model_await_errored",
                agent=self._agent_name,
                elapsed_seconds=round(time.monotonic() - started_at, 3),
                error_type=type(exc).__name__,
                error=str(exc),
                error_detail="".join(traceback.format_exception(exc)),
            )
            raise
        _workflow_debug(
            self._request,
            "chat_model_await_finished",
            agent=self._agent_name,
            elapsed_seconds=round(time.monotonic() - started_at, 3),
            result_type=type(result).__name__,
        )
        return result


class _InstrumentedAgent:
    def __init__(self, agent: Any, *, request: RunCaseRequest, agent_name: str) -> None:
        self._agent = agent
        self._request = request
        self._agent_name = agent_name

    def __getattr__(self, name: str) -> Any:
        return getattr(self._agent, name)

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        started_at = time.monotonic()
        timeout = _agent_timeout_seconds(self._request)
        _workflow_debug(
            self._request,
            "agent_run_start",
            agent=self._agent_name,
            agent_type=type(self._agent).__name__,
            timeout_seconds=timeout,
            chat_model=self._request.environment.get(CHAT_MODEL_ENV),
        )
        try:
            awaitable = self._agent.run(*args, **kwargs)
            _workflow_debug(
                self._request,
                "agent_run_awaitable_created",
                agent=self._agent_name,
                awaitable_type=type(awaitable).__name__,
                args_summary=_agent_args_summary(args, kwargs),
            )
            if timeout is None:
                result = await awaitable
            else:
                result = await asyncio.wait_for(awaitable, timeout=timeout)
        except BaseException as exc:
            _workflow_debug(
                self._request,
                "agent_run_errored",
                agent=self._agent_name,
                elapsed_seconds=round(time.monotonic() - started_at, 3),
                error_type=type(exc).__name__,
                error=str(exc),
                error_detail="".join(traceback.format_exception(exc)),
            )
            raise
        _workflow_debug(
            self._request,
            "agent_run_finished",
            agent=self._agent_name,
            elapsed_seconds=round(time.monotonic() - started_at, 3),
            result_type=type(result).__name__,
        )
        return result


def _safe_len(value: Any) -> int | None:
    try:
        return len(value)
    except TypeError:
        return None


def _agent_args_summary(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "arg_count": len(args),
        "kwarg_keys": sorted(str(key) for key in kwargs),
    }
    if args:
        first = args[0]
        if isinstance(first, str):
            summary["first_arg_chars"] = len(first)
            summary["first_arg_head"] = first[:200]
        else:
            summary["first_arg_type"] = type(first).__name__
    expected_output = kwargs.get("expected_output")
    if expected_output is not None:
        summary["expected_output"] = getattr(
            expected_output, "__name__", type(expected_output).__name__
        )
    return summary


def _message_summary(messages: Any) -> dict[str, Any]:
    if not isinstance(messages, Sequence) or isinstance(messages, str | bytes):
        return {"type": type(messages).__name__}
    total_chars = 0
    summaries: list[dict[str, Any]] = []
    for message in messages[-3:]:
        text = _message_text(message)
        total_chars += len(text)
        summaries.append(
            {
                "type": type(message).__name__,
                "chars": len(text),
                "head": text[:160],
            }
        )
    return {
        "recent": summaries,
        "recent_total_chars": total_chars,
    }


def _message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    text = getattr(message, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence) and not isinstance(content, str | bytes):
        return "\n".join(_message_text(item) for item in content)
    return str(message)


def _request_from_environment() -> RunCaseRequest:
    return RunCaseRequest(
        case_id=os.getenv("YMIR_BENCHMARK_CASE_ID", "unknown"),
        case_type=None,
        expected_path=Path(os.devnull),
        actual_path=Path(os.devnull),
        cases_dir=Path(os.getenv("YMIR_BENCHMARK_CASES_DIR", ".")),
        results_dir=Path(os.getenv("YMIR_BENCHMARK_RESULTS_DIR", ".")),
        repetition=_environment_int("YMIR_BENCHMARK_REPETITION", default=0),
        variant="debug",
        features=(),
        environment=dict(os.environ),
    )


def _workflow_state_snapshot(state: Any) -> dict[str, Any]:
    names = (
        "package",
        "dist_git_branch",
        "jira_issue",
        "attempts_remaining",
        "incremental_fix_attempts_remaining",
        "build_error",
        "abandon_autorelease",
        "used_cherry_pick_workflow",
    )
    snapshot = {
        name: _json_safe_value(getattr(state, name)) for name in names if hasattr(state, name)
    }
    backport_result = getattr(state, "backport_result", None)
    if backport_result is not None:
        payload = _model_payload(backport_result)
        snapshot["backport_result"] = {
            key: _json_safe_value(payload.get(key))
            for key in ("success", "status", "error", "srpm_path")
            if key in payload
        }
    upstream_patches = getattr(state, "upstream_patches", None)
    if upstream_patches is not None:
        snapshot["upstream_patch_count"] = _safe_len(upstream_patches)
    local_clone = getattr(state, "local_clone", None)
    if local_clone is not None:
        snapshot["local_clone"] = str(local_clone)
    unpacked_sources = getattr(state, "unpacked_sources", None)
    if unpacked_sources is not None:
        snapshot["unpacked_sources"] = str(unpacked_sources)
    return snapshot


def _environment_int(name: str, *, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _json_safe_value(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [_json_safe_value(item) for item in value[:10]]
    if isinstance(value, Mapping):
        return {str(key): _json_safe_value(item) for key, item in list(value.items())[:10]}
    return str(value)


def _workflow_debug(
    request: RunCaseRequest,
    event: str,
    **fields: Any,
) -> None:
    payload: dict[str, Any] = {
        "event": event,
        "case_id": request.case_id,
        "repetition": request.repetition,
        **fields,
    }
    sys.stderr.write("ymir-harness workflow: ")
    sys.stderr.write(json.dumps(payload, sort_keys=True))
    sys.stderr.write("\n")
    sys.stderr.flush()


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


def _request_with_replay_metadata_environment(request: RunCaseRequest) -> RunCaseRequest:
    replay_env = replay_metadata_environment(request.cases_dir, request.case_id)
    if not replay_env:
        return request
    environment = dict(request.environment)
    environment.update(replay_env)
    return _request_with_environment(request, environment)


def _triage_dependencies(
    workflow: AsyncWorkflow | None,
    agent_factory: AgentFactory | None,
) -> tuple[AsyncWorkflow, AgentFactory]:
    if workflow is not None and agent_factory is not None:
        return workflow, agent_factory

    ensure_ymir_source_path()
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

    ensure_ymir_source_path()
    from ymir.agents import backport_agent as backport_module  # type: ignore[import-not-found]

    _patch_backport_no_write_subprocesses(backport_module)
    _patch_backport_workflow_step_logging(backport_module)
    _patch_backport_source_changelog(backport_module)
    _patch_fixture_duckduckgo_search(backport_module)
    _patch_no_write_candidate_build_lookup()

    return (
        workflow or backport_module.run_workflow,
        agent_factory or backport_module.create_backport_agent,
    )


def _wrap_backport_replay_agent_factory(
    agent_factory: AgentFactory,
    *,
    request: RunCaseRequest,
) -> AgentFactory:
    def factory(*args: Any, **kwargs: Any) -> Any:
        result = agent_factory(*args, **kwargs)
        if inspect.isawaitable(result):
            return _wrap_backport_replay_agent_awaitable(result, request=request)
        return _wrap_backport_replay_agent(result, request=request)

    return factory


async def _wrap_backport_replay_agent_awaitable(
    awaitable: Awaitable[Any],
    *,
    request: RunCaseRequest,
) -> Any:
    agent = await awaitable
    return _wrap_backport_replay_agent(agent, request=request)


def _wrap_backport_replay_agent(agent: Any, *, request: RunCaseRequest) -> Any:
    if request.environment.get("YMIR_BENCHMARK_NETWORK_MODE") not in {
        "replay_only",
        "network_denied",
    }:
        return agent

    tools = getattr(agent, "_tools", None)
    if not isinstance(tools, list):
        return agent

    wrapped_tools = []
    changed = False
    for tool in tools:
        if getattr(tool, "name", None) == "clone_upstream_repository":
            wrapped_tools.append(_replay_safe_clone_upstream_tool(tool, request=request))
            changed = True
        else:
            wrapped_tools.append(tool)

    if changed:
        setattr(agent, "_tools", wrapped_tools)
    return agent


def _replay_safe_clone_upstream_tool(tool: Any, *, request: RunCaseRequest) -> Any:
    from beeai_framework.tools import ToolError
    from ymir.tools.unprivileged.upstream_tools import (  # type: ignore[import-not-found]
        CloneUpstreamRepositoryTool,
    )

    class HarnessReplayCloneUpstreamRepositoryTool(CloneUpstreamRepositoryTool):
        description = (
            CloneUpstreamRepositoryTool.description
            + "\n\nIn harness replay, this tool uses only source-cache-backed repositories. "
            "If the upstream repository is not cached, use the pre-downloaded patch files "
            "and the git-am fallback workflow."
        )

        async def _run(self, tool_input: Any, options: Any, context: Any) -> Any:
            source_cache = request.environment.get("YMIR_BENCHMARK_SOURCE_CACHE_DIR")
            if source_cache and find_source_cache_repository(
                Path(source_cache), tool_input.repo_url
            ):
                return await super()._run(tool_input, options, context)
            repo_url = str(getattr(tool_input, "repo_url", ""))
            raise ToolError(
                f"external subprocess URL blocked: {repo_url}\n"
                "Upstream repository is not available in the harness source cache. "
                "Use the pre-downloaded patch files and git-am fallback workflow."
            )

    return HarnessReplayCloneUpstreamRepositoryTool(options=getattr(tool, "options", None))


def _patch_backport_no_write_subprocesses(backport_module: Any) -> None:
    if getattr(backport_module, "_ymir_harness_check_subprocess_patched", False):
        return

    original_check_subprocess = backport_module.check_subprocess
    original_get_unpacked_sources = backport_module.tasks.get_unpacked_sources

    async def harness_check_subprocess(
        cmd: str | list[str],
        shell: bool = False,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str | None, str | None]:
        if (
            os.getenv("DRY_RUN", "False").lower() == "true"
            and cwd is not None
            and _is_package_prep_command(cmd)
        ):
            source_dir = _materialize_replay_unpacked_sources(cwd)
            if source_dir is None:
                raise RuntimeError(f"replay source archive is missing for {cwd}")
            return "", ""
        return await original_check_subprocess(cmd, shell=shell, cwd=cwd, env=env)

    def harness_get_unpacked_sources(local_clone: Path, package: str) -> Path:
        if os.getenv("DRY_RUN", "False").lower() == "true":
            source_dir = _materialize_replay_unpacked_sources(local_clone)
            if source_dir is not None:
                return source_dir
        return original_get_unpacked_sources(local_clone, package)

    backport_module.check_subprocess = harness_check_subprocess
    backport_module.tasks.get_unpacked_sources = harness_get_unpacked_sources
    backport_module._ymir_harness_check_subprocess_patched = True


def _patch_backport_workflow_step_logging(backport_module: Any) -> None:
    if getattr(backport_module, "_ymir_harness_workflow_step_logging_patched", False):
        return

    workflow_class = getattr(backport_module, "Workflow", None)
    if workflow_class is None:
        return

    original_add_step = workflow_class.add_step

    def harness_add_step(self: Any, step_name: Any, runnable: Any) -> Any:
        if os.getenv("DRY_RUN", "False").lower() != "true":
            return original_add_step(self, step_name, runnable)

        async def logged_step(state: Any) -> Any:
            request = _request_from_environment()
            started_at = time.monotonic()
            if str(step_name) == "update_release":
                _restore_backport_release_from_head(state)
            _workflow_debug(
                request,
                "ymir_step_start",
                workflow="backport",
                step=str(step_name),
                state=_workflow_state_snapshot(state),
            )
            try:
                result = await _maybe_await(runnable(state))
            except BaseException as exc:
                _workflow_debug(
                    request,
                    "ymir_step_errored",
                    workflow="backport",
                    step=str(step_name),
                    elapsed_seconds=round(time.monotonic() - started_at, 3),
                    error_type=type(exc).__name__,
                    error=str(exc),
                    error_detail="".join(traceback.format_exception(exc)),
                    state=_workflow_state_snapshot(state),
                )
                raise
            _workflow_debug(
                request,
                "ymir_step_finished",
                workflow="backport",
                step=str(step_name),
                next_step=str(result),
                elapsed_seconds=round(time.monotonic() - started_at, 3),
                state=_workflow_state_snapshot(state),
            )
            return result

        return original_add_step(self, step_name, logged_step)

    workflow_class.add_step = harness_add_step
    backport_module._ymir_harness_workflow_step_logging_patched = True


def _patch_backport_source_changelog(backport_module: Any) -> None:
    if getattr(backport_module, "_ymir_harness_source_changelog_patched", False):
        return

    original_extract_source_changelog = backport_module.extract_source_changelog

    async def harness_extract_source_changelog(
        local_clone: Path,
        upstream_patches: list[str],
        package: str,
    ) -> str | None:
        source_changelog = await _maybe_await(
            original_extract_source_changelog(local_clone, upstream_patches, package)
        )
        if source_changelog or os.getenv("DRY_RUN", "False").lower() != "true":
            return source_changelog
        return _source_changelog_from_replay_patch_files(local_clone, package)

    backport_module.extract_source_changelog = harness_extract_source_changelog
    backport_module._ymir_harness_source_changelog_patched = True


def _restore_backport_release_from_head(state: Any) -> None:
    if os.getenv("DRY_RUN", "False").lower() != "true":
        return

    local_clone = _field_value(state, "local_clone")
    package = _string_or_none(_field_value(state, "package"))
    if not isinstance(local_clone, Path) or package is None:
        return

    spec_path = local_clone / f"{package}.spec"
    if not spec_path.is_file():
        return

    baseline_text = _git_show_text(local_clone, f"HEAD:{package}.spec")
    if baseline_text is None:
        return

    baseline_release = _release_line(baseline_text)
    current_text = spec_path.read_text(encoding="utf-8", errors="replace")
    current_release = _release_line(current_text)
    if baseline_release is None or current_release is None or baseline_release == current_release:
        return

    restored_text = _replace_release_line(current_text, baseline_release)
    if restored_text is not None:
        spec_path.write_text(restored_text, encoding="utf-8")


def _git_show_text(repo_path: Path, revision_path: str) -> str | None:
    completed = subprocess.run(
        ["git", "show", revision_path],
        cwd=repo_path,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _release_line(text: str) -> str | None:
    for line in text.splitlines():
        if re.match(r"^\s*Release:\s*", line):
            return line
    return None


def _replace_release_line(text: str, release_line: str) -> str | None:
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if not re.match(r"^\s*Release:\s*", line):
            continue
        newline = line[len(line.rstrip("\r\n")) :]
        lines[index] = release_line + newline
        return "".join(lines)
    return None


def _source_changelog_from_replay_patch_files(local_clone: Path, package: str) -> str | None:
    case_id = os.getenv("YMIR_BENCHMARK_CASE_ID")
    if not case_id:
        return None

    collected: list[str] = []
    seen: set[str] = set()
    for patch_path in sorted(local_clone.glob(f"{case_id}-*.patch")):
        try:
            patch_text = patch_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in _source_changelog_from_patch_text(patch_text, package):
            if line in seen:
                continue
            seen.add(line)
            collected.append(line)

    return "\n".join(collected) if collected else None


def _source_changelog_from_patch_text(patch_text: str, package: str) -> list[str]:
    spec_name = f"{package}.spec"
    in_spec_diff = False
    in_changelog = False
    collecting_entry = False
    collected: list[str] = []

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            in_spec_diff = _diff_git_mentions_file(line, spec_name)
            in_changelog = False
            collecting_entry = False
            continue
        if not in_spec_diff:
            continue
        if line.startswith("+++ "):
            in_spec_diff = line == f"+++ b/{spec_name}" or line.endswith(f"/{spec_name}")
            continue

        content = line[1:] if line[:1] in {" ", "+", "-"} else line
        if content.strip() == "%changelog":
            in_changelog = True
            collecting_entry = False
            continue
        if not in_changelog:
            continue

        if line.startswith("+* "):
            collecting_entry = True
            continue
        if collecting_entry and line.startswith("+"):
            entry_line = line[1:].rstrip()
            if entry_line:
                collected.append(entry_line)
            continue
        if collecting_entry and line.startswith(" ") and line[1:].startswith("* "):
            break

    return collected


def _diff_git_mentions_file(line: str, file_name: str) -> bool:
    return f" a/{file_name} " in line and f" b/{file_name}" in line


def _patch_fixture_duckduckgo_search(agent_module: Any) -> None:
    if getattr(agent_module, "_ymir_harness_duckduckgo_patched", False):
        return

    original_tool = getattr(agent_module, "DuckDuckGoSearchTool", None)
    if original_tool is None:
        return

    try:
        from beeai_framework.tools.search.duckduckgo.duckduckgo import (
            DuckDuckGoSearchToolOutput,
            DuckDuckGoSearchToolResult,
        )
    except ImportError:
        return

    class HarnessDuckDuckGoSearchTool(original_tool):  # type: ignore[misc, valid-type]
        async def _run(self, input: Any, options: Any, context: Any) -> Any:
            if os.getenv("DRY_RUN", "False").lower() != "true":
                return await super()._run(input, options, context)

            request = _request_from_environment()
            query = str(getattr(input, "query", ""))
            results = [
                DuckDuckGoSearchToolResult(
                    title=result["title"],
                    description=result["description"],
                    url=result["url"],
                )
                for result in _fixture_search_results(request, query, max_results=self.max_results)
            ]
            _workflow_debug(
                request,
                "duckduckgo_replay",
                query=query,
                result_count=len(results),
                urls=[result.url for result in results],
            )
            return DuckDuckGoSearchToolOutput(results)

    agent_module.DuckDuckGoSearchTool = HarnessDuckDuckGoSearchTool
    agent_module._ymir_harness_duckduckgo_patched = True


def _fixture_search_results(
    request: RunCaseRequest,
    query: str,
    *,
    max_results: int,
) -> list[dict[str, str]]:
    query_terms = _search_terms(query)
    candidates = _fixture_search_candidates(request)
    scored: list[tuple[int, int, dict[str, str]]] = []
    for index, candidate in enumerate(candidates):
        haystack = " ".join(
            (candidate.get("title", ""), candidate.get("description", ""), candidate.get("url", ""))
        )
        score = _search_score(query_terms, haystack)
        if score > 0:
            scored.append((score, -index, candidate))
    scored.sort(reverse=True)
    return [candidate for _score, _index, candidate in scored[:max_results]]


def _fixture_search_candidates(request: RunCaseRequest) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    historical_replay = _fixture_search_as_of(request) is not None

    def add(url: str, title: str, description: str) -> None:
        url = _normalize_fixture_url(url)
        if not url or url in seen_urls:
            return
        seen_urls.add(url)
        candidates.append({"url": url, "title": title or url, "description": description})

    jira_dir = request.cases_dir / "jiras" / request.case_id
    if not historical_replay:
        for link in _json_list(jira_dir / "links.json", "links"):
            obj = link.get("object") if isinstance(link, Mapping) else None
            if not isinstance(obj, Mapping):
                continue
            url = _string_value(obj.get("url"))
            title = _string_value(obj.get("title")) or url
            add(url, title, "Known Jira remote link.")

    jira_sources = (
        (jira_dir / "starting-issue.json",)
        if historical_replay
        else (
            jira_dir / "starting-issue.json",
            jira_dir / "issue.json",
            jira_dir / "comments.json",
        )
    )
    for path in jira_sources:
        _add_urls_from_json(path, add, "Known Jira issue content.")
    for path in sorted((jira_dir / "linked").glob("*/starting-issue.json")):
        _add_urls_from_json(path, add, "Known linked Jira issue content.")

    if not historical_replay:
        manifest_path = request.cases_dir / "web_cache" / request.case_id / "manifest.json"
        manifest = _read_json_object(manifest_path)
        recorded_files = manifest.get("recorded_files")
        if isinstance(recorded_files, Mapping):
            for url in recorded_files:
                add(str(url), str(url), "Recorded fixture URL.")
        required_urls = manifest.get("required_urls")
        if isinstance(required_urls, Sequence) and not isinstance(required_urls, str | bytes):
            for url in required_urls:
                add(str(url), str(url), "Required fixture URL.")

    source_cache = request.cases_dir / "source_cache" / request.case_id / "upstream"
    for manifest_path in sorted(source_cache.glob("*.json")):
        manifest = _read_json_object(manifest_path)
        url = _string_value(manifest.get("remote_url"))
        if url:
            add(url, url, "Cached source fixture.")

    return candidates


def _fixture_search_as_of(request: RunCaseRequest) -> str | None:
    reconstruction = _read_json_object(
        request.cases_dir / "jiras" / request.case_id / "reconstruction.json"
    )
    return _string_value(reconstruction.get("as_of")) or None


def _add_urls_from_json(path: Path, add: Callable[[str, str, str], None], description: str) -> None:
    data = _read_json_value(path)
    for url in _urls_from_value(data):
        add(url, url, description)


def _json_list(path: Path, key: str) -> list[Any]:
    data = _read_json_object(path)
    value = data.get(key)
    if isinstance(value, list):
        return value
    return []


def _read_json_object(path: Path) -> dict[str, Any]:
    data = _read_json_value(path)
    if isinstance(data, dict):
        return data
    return {}


def _read_json_value(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _urls_from_value(value: Any) -> list[str]:
    urls: list[str] = []
    if isinstance(value, str):
        urls.extend(
            _normalize_fixture_url(match.group(0))
            for match in re.finditer(r"https?://[^\s\"'<>]+", value)
        )
    elif isinstance(value, Mapping):
        for item in value.values():
            urls.extend(_urls_from_value(item))
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for item in value:
            urls.extend(_urls_from_value(item))
    return list(dict.fromkeys(urls))


def _normalize_fixture_url(url: str) -> str:
    return url.split("|", 1)[0].rstrip(").,|]")


def _search_score(query_terms: set[str], text: str) -> int:
    if not query_terms:
        return 0
    text_terms = _search_terms(text)
    return len(query_terms & text_terms)


def _search_terms(text: str) -> set[str]:
    stop_words = {
        "and",
        "for",
        "from",
        "https",
        "http",
        "the",
        "www",
    }
    return {
        token
        for token in re.findall(r"[a-z0-9]+", text.lower())
        if len(token) >= 3 and token not in stop_words
    }


def _string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _patch_no_write_candidate_build_lookup() -> None:
    try:
        from ymir.common import utils as utils_module  # type: ignore[import-not-found]
        from ymir.tools.unprivileged import specfile as specfile_module  # type: ignore[import-not-found]
        from ymir_harness.koji_replay import recorded_candidate_build_from_environment
    except ImportError:
        return

    if not getattr(specfile_module, "_ymir_harness_candidate_build_patched", False):
        original_specfile_get_latest_candidate_build = specfile_module.get_latest_candidate_build
        original_utils_get_latest_candidate_build = utils_module.get_latest_candidate_build

        async def harness_get_latest_candidate_build(
            package: str,
            dist_git_branch: str,
        ) -> tuple[Any, str]:
            if os.getenv("DRY_RUN", "False").lower() != "true":
                return await original_utils_get_latest_candidate_build(package, dist_git_branch)

            return recorded_candidate_build_from_environment(package, dist_git_branch)

        specfile_module.get_latest_candidate_build = harness_get_latest_candidate_build
        utils_module.get_latest_candidate_build = harness_get_latest_candidate_build
        specfile_module._ymir_harness_candidate_build_patched = True
        specfile_module._ymir_harness_original_get_latest_candidate_build = (
            original_specfile_get_latest_candidate_build
        )


def _is_package_prep_command(cmd: str | list[str]) -> bool:
    if isinstance(cmd, str):
        parts = cmd.split()
    else:
        parts = [str(part) for part in cmd]
    if not parts or parts[-1] != "prep":
        return False
    program = Path(parts[0]).name
    return program in {"rhpkg", "centpkg"}


def _materialize_replay_unpacked_sources(cwd: Path) -> Path | None:
    source_dir = _expected_unpacked_sources_dir(cwd)
    if source_dir is None:
        return None
    if _has_materialized_source_content(source_dir):
        return source_dir

    archive = _primary_source_archive(cwd)
    if archive is None:
        return None

    if source_dir.exists() and not _has_materialized_source_content(source_dir):
        shutil.rmtree(source_dir)

    extracted = _extract_source_archive(archive, cwd)
    if extracted is None:
        return None
    if extracted == source_dir:
        return source_dir
    if source_dir.exists():
        shutil.rmtree(source_dir)
    if extracted.exists():
        extracted.rename(source_dir)
        return source_dir
    return None


def _expected_unpacked_sources_dir(cwd: Path) -> Path | None:
    spec_path = next(cwd.glob("*.spec"), None)
    if spec_path is None:
        return None

    text = spec_path.read_text(encoding="utf-8", errors="replace")
    explicit_setup = re.search(r"^%(?:auto)?setup\b[^\n]*\s-n\s+(\S+)", text, re.MULTILINE)
    if explicit_setup is not None:
        return cwd / explicit_setup.group(1)

    name = _rpm_tag_value(text, "Name")
    version = _rpm_tag_value(text, "Version")
    if name is not None and version is not None:
        return cwd / f"{name}-{version}"
    return None


def _has_materialized_source_content(source_dir: Path) -> bool:
    if not source_dir.is_dir():
        return False
    return any(child.name != ".git" for child in source_dir.iterdir())


def _primary_source_archive(cwd: Path) -> Path | None:
    spec_path = next(cwd.glob("*.spec"), None)
    if spec_path is None:
        return None

    text = spec_path.read_text(encoding="utf-8", errors="replace")
    name = _rpm_tag_value(text, "Name")
    version = _rpm_tag_value(text, "Version")
    source_filename = _source0_filename(text, name=name, version=version)
    if source_filename is not None:
        candidate = cwd / source_filename
        if candidate.is_file():
            return candidate

    for filename in _sources_file_filenames(cwd / "sources"):
        candidate = cwd / filename
        if candidate.is_file():
            return candidate
    return None


def _source0_filename(text: str, *, name: str | None, version: str | None) -> str | None:
    source = _rpm_source_tag_value(text, "Source0") or _rpm_source_tag_value(text, "Source")
    if source is None:
        return None
    if name is not None:
        source = source.replace("%{name}", name).replace("%{?name}", name)
    if version is not None:
        source = source.replace("%{version}", version).replace("%{?version}", version)
    return Path(source).name


def _rpm_source_tag_value(text: str, tag: str) -> str | None:
    match = re.search(rf"^{re.escape(tag)}:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
    if match is None:
        return None
    value = match.group(1).strip()
    return value or None


def _sources_file_filenames(path: Path) -> tuple[str, ...]:
    if not path.is_file():
        return ()
    filenames = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"\(([^)]+)\)", line)
        if match is not None:
            filenames.append(match.group(1).strip())
            continue
        parts = line.split()
        if parts:
            filenames.append(parts[-1])
    return tuple(dict.fromkeys(filename for filename in filenames if filename))


def _extract_source_archive(archive: Path, cwd: Path) -> Path | None:
    before = {child.resolve() for child in cwd.iterdir()}
    try:
        shutil.unpack_archive(str(archive), str(cwd))
        return _single_new_directory(cwd, before)
    except (shutil.ReadError, ValueError, OSError):
        pass

    rpm_uncompress = Path("/usr/lib/rpm/rpmuncompress")
    if rpm_uncompress.exists():
        completed = subprocess.run(
            [str(rpm_uncompress), "-x", str(archive)],
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode == 0:
            return _single_new_directory(cwd, before)
    return None


def _single_new_directory(cwd: Path, before: set[Path]) -> Path | None:
    new_directories = [
        child for child in cwd.iterdir() if child.resolve() not in before and child.is_dir()
    ]
    if len(new_directories) == 1:
        return new_directories[0]
    return None


def _rpm_tag_value(text: str, tag: str) -> str | None:
    match = re.search(rf"^{re.escape(tag)}:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
    if match is None:
        return None
    value = match.group(1).strip()
    if not value or "%" in value:
        return None
    return value


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
    ensure_ymir_source_path()
    module = importlib.import_module(module_name)
    _patch_no_write_candidate_build_lookup()

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
    expected = load_json_file(request.expected_path) if request.expected_path.is_file() else {}
    actual: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "workflow": "ymir-triage",
        **payload,
    }

    for name in (
        "package",
        "jira_issue",
        "patch_urls",
        "cve_id",
        "fix_version",
        "version",
        "dependency_issue",
        "dependency_component",
    ):
        if name in data and data[name] is not None:
            actual[name] = data[name]

    if "jira_issue" not in actual:
        actual["jira_issue"] = request.case_id

    if "package" not in actual:
        pkg = expected.get("package")
        if pkg:
            actual["package"] = pkg

    if "cve_id" not in actual and "cve_ids" not in actual:
        cve_ids = _string_list(expected.get("cve_ids") or expected.get("cve_id"))
        if cve_ids:
            actual["cve_ids"] = cve_ids

    target_branch = getattr(state, "target_branch", None)
    if target_branch:
        actual["target_branch"] = target_branch

    actual.update(_state_diagnostics(state))
    return actual


def _backport_inputs(request: RunCaseRequest) -> BackportInputs | RunCaseExecution:
    expected = load_json_file(request.expected_path)
    triage_inputs = _backport_inputs_from_triage_result(request)
    if triage_inputs is not None:
        return triage_inputs

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


def _backport_inputs_from_triage_result(
    request: RunCaseRequest,
) -> BackportInputs | RunCaseExecution | None:
    triage_result_path = _backport_triage_result_path(request)
    if triage_result_path is None:
        return None

    triage_result = load_json_file(triage_result_path)
    resolution = _string_or_none(triage_result.get("resolution"))
    if resolution is None or resolution.replace("-", "_") != "backport":
        return RunCaseExecution(
            status="failed",
            reason=f"ymir backport workflow triage result is not backport: {resolution!r}",
        )

    data = triage_result.get("data") if isinstance(triage_result.get("data"), Mapping) else {}
    assert isinstance(data, Mapping)
    upstream_patches = tuple(
        _string_list(data.get("patch_urls"))
        or _string_list(triage_result.get("patch_urls"))
        or _string_list(data.get("fix_sources"))
        or _string_list(triage_result.get("fix_sources"))
    )
    package = _string_or_none(data.get("package") or triage_result.get("package"))
    values = {
        "package": package,
        "dist_git_branch": _backport_triage_dist_git_branch(
            request,
            triage_result,
            package=package,
        ),
        "upstream_patches": upstream_patches,
        "jira_issue": _string_or_none(
            data.get("jira_issue")
            or triage_result.get("jira_issue")
            or triage_result.get("case_id")
        )
        or request.case_id,
    }
    missing = [
        name for name, value in values.items() if value is None or value == () or value == ""
    ]
    if missing:
        return RunCaseExecution(
            status="failed",
            reason=(
                "ymir backport workflow missing triage result "
                f"{', '.join(missing)} from {triage_result_path}"
            ),
        )

    return BackportInputs(
        package=values["package"],
        dist_git_branch=values["dist_git_branch"],
        upstream_patches=upstream_patches,
        jira_issue=values["jira_issue"],
        cve_id=_first_string(
            data.get("cve_id"), triage_result.get("cve_id"), triage_result.get("cve_ids")
        ),
        justification=_string_or_none(
            data.get("justification")
            or triage_result.get("justification")
            or data.get("rationale")
            or triage_result.get("rationale")
            or data.get("notes")
            or triage_result.get("notes")
        ),
        fix_version=_string_or_none(data.get("fix_version") or triage_result.get("fix_version")),
    )


def _backport_triage_result_path(request: RunCaseRequest) -> Path | None:
    path = request.cases_dir / "triage_results" / f"{request.case_id}.actual.json"
    return path if path.is_file() else None


def _backport_triage_dist_git_branch(
    request: RunCaseRequest,
    triage_result: Mapping[str, Any],
    *,
    package: str | None,
) -> str | None:
    data = triage_result.get("data") if isinstance(triage_result.get("data"), Mapping) else {}
    assert isinstance(data, Mapping)
    return (
        _string_or_none(data.get("target_branch"))
        or _string_or_none(triage_result.get("target_branch"))
        or _string_or_none(data.get("fix_version"))
        or _string_or_none(triage_result.get("fix_version"))
        or _mock_repo_branch(request, package=package)
    )


def _mock_repo_branch(request: RunCaseRequest, *, package: str | None) -> str | None:
    for path in sorted((request.cases_dir / "mock_data").glob(f"*/{request.case_id}.json")):
        config = load_json_file(path)
        repos = config.get("repos")
        if not isinstance(repos, list):
            continue
        for repo in repos:
            if not isinstance(repo, Mapping):
                continue
            repo_package = _string_or_none(repo.get("package"))
            if package is not None and repo_package not in {None, package}:
                continue
            if branch := _string_or_none(repo.get("branch")):
                return branch
    return None


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
        "jira_issue": inputs.jira_issue,
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

    capture = capture_backport_artifacts(
        case_id=request.case_id,
        package=package,
        state=state,
        payload=payload,
        request_artifact_dir=_request_artifact_dir(request),
    )
    if capture.generated_artifacts:
        actual["generated_artifacts"] = [
            *actual.get("generated_artifacts", []),
            *capture.generated_artifacts,
        ]
    if capture.touched_files:
        actual["touched_files"] = [*actual.get("touched_files", []), *capture.touched_files]
    if capture.uncommitted_files:
        actual["uncommitted_files"] = [
            *actual.get("uncommitted_files", []),
            *capture.uncommitted_files,
        ]
    if capture.patch_touched_files:
        actual["patch_touched_files"] = [
            *actual.get("patch_touched_files", []),
            *capture.patch_touched_files,
        ]
    if capture.spec_patches:
        actual["spec_patches"] = [*actual.get("spec_patches", []), *capture.spec_patches]
    if capture.unrelated_source_changes:
        actual["unrelated_source_changes"] = [
            *actual.get("unrelated_source_changes", []),
            *capture.unrelated_source_changes,
        ]
    if capture.manifest_path is not None:
        actual["artifact_manifest"] = str(capture.manifest_path)

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
        "jira_issue": inputs.jira_issue,
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
        "jira_issue": inputs.jira_issue,
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
    install_specfile_changelog_replay()
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)
