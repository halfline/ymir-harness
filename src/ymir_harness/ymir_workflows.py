from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any

from ymir_harness.models import SCHEMA_VERSION

from ymir_harness.runner import DEFAULT_CHAT_MODEL, RunCaseExecution, RunCaseRequest
from ymir_harness.scoring import load_json_file
from ymir_harness.ymir_source import ensure_ymir_source_path

AsyncWorkflow = Callable[..., Awaitable[Any]]
AgentFactory = Callable[..., Any]
MCP_GATEWAY_URL_ENV = "MCP_GATEWAY_URL"
CHAT_MODEL_ENV = "CHAT_MODEL"
GATEWAY_START_TIMEOUT_SECONDS = 10.0
WORKFLOW_PROGRESS_INTERVAL_SECONDS = 30.0







def _workflow_environment(
    request: RunCaseRequest,
    *,
    workflow: AsyncWorkflow | None,
) -> Any:
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
        _instrument_agent_llm(agent, request=request, agent_name=agent_name)
        return _InstrumentedAgent(agent, request=request, agent_name=agent_name)

    return factory


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
