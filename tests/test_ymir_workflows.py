from __future__ import annotations

import asyncio
import json
import os
import sys
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

import ymir_harness.ymir_workflows as workflow_module
from ymir_harness.runner import DEFAULT_CHAT_MODEL, RunCaseRequest
from ymir_harness.ymir_workflows import (
    _instrument_agent_factory,
    _patch_no_write_candidate_build_lookup,
    make_ymir_triage_executor,
)



def test_ymir_triage_executor_runs_workflow_with_no_write_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OUTER_ONLY", "kept")
    calls = []

    async def workflow(jira_issue, dry_run, agent_factory, **kwargs):
        calls.append(
            {
                "jira_issue": jira_issue,
                "dry_run": dry_run,
                "agent_factory": agent_factory,
                "kwargs": kwargs,
                "dry_run_env": os.environ["DRY_RUN"],
                "feature_env": os.environ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
                "outer_only": os.environ.get("OUTER_ONLY"),
            }
        )
        return _State(
            triage_result=_TriageResult(
                {
                    "resolution": "backport",
                    "data": {
                        "package": "dnsmasq",
                        "patch_urls": ["https://example.invalid/fix.patch"],
                        "cve_id": "CVE-2026-0001",
                        "fix_version": "rhel-8.10.z",
                    },
                }
            ),
            target_branch="rhel-8.10.z",
            usage={"input_tokens": 1200, "output_tokens": 300},
            iteration=9,
            steps=[object(), object(), object()],
            cost=_State(total=4.25),
        )

    def agent_factory(_gateway_tools, _local_tool_options):
        return object()

    executor = make_ymir_triage_executor(
        workflow=workflow,
        agent_factory=agent_factory,
    )

    execution = executor(
        _request(
            tmp_path,
            environment={
                "PATH": "/usr/bin",
                "DRY_RUN": "true",
            },
            features=("YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK",),
        )
    )

    assert os.environ["OUTER_ONLY"] == "kept"
    assert execution.status == "passed"
    assert execution.actual_result == {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "workflow": "ymir-triage",
        "resolution": "backport",
        "data": {
            "package": "dnsmasq",
            "patch_urls": ["https://example.invalid/fix.patch"],
            "cve_id": "CVE-2026-0001",
            "fix_version": "rhel-8.10.z",
        },
        "package": "dnsmasq",
        "patch_urls": ["https://example.invalid/fix.patch"],
        "cve_id": "CVE-2026-0001",
        "fix_version": "rhel-8.10.z",
        "target_branch": "rhel-8.10.z",
        "token_usage": {"input_tokens": 1200, "output_tokens": 300},
        "iteration_count": 9,
        "tool_call_count": 3,
        "total_cost_usd": 4.25,
    }
    assert calls == [
        {
            "jira_issue": "RHEL-12345",
            "dry_run": True,
            "agent_factory": agent_factory,
            "kwargs": {"auto_chain": False, "silent_run": True},
            "dry_run_env": "true",
            "feature_env": "true",
            "outer_only": None,
        }
    ]


def test_ymir_triage_executor_reports_missing_triage_result(tmp_path: Path) -> None:
    async def workflow(*_args, **_kwargs):
        return _State(triage_result=None, target_branch=None)

    executor = make_ymir_triage_executor(
        workflow=workflow,
        agent_factory=lambda _gateway_tools, _local_tool_options: object(),
    )

    execution = executor(_request(tmp_path))

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == "ymir triage workflow returned no triage result"


def test_ymir_triage_executor_logs_workflow_progress(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def workflow(*_args, **_kwargs):
        await workflow_module.asyncio.sleep(0.01)
        return _State(
            triage_result=_TriageResult(
                {
                    "resolution": "not_affected",
                    "data": {
                        "jira_issue": "RHEL-12345",
                        "package": "dnsmasq",
                    },
                }
            )
        )

    executor = make_ymir_triage_executor(
        workflow=workflow,
        agent_factory=lambda _gateway_tools, _local_tool_options: object(),
    )

    execution = executor(
        _request(
            tmp_path,
            environment={
                "DRY_RUN": "true",
                "YMIR_HARNESS_WORKFLOW_PROGRESS_INTERVAL": "0.001",
            },
        )
    )

    assert execution.status == "passed"
    stderr = capsys.readouterr().err
    assert '"event": "workflow_started"' in stderr
    assert '"event": "workflow_waiting"' in stderr
    assert '"event": "workflow_finished"' in stderr


@pytest.mark.parametrize(
    ("executor_factory", "case_type", "expected", "reason"),
    [
        (
            make_ymir_triage_executor,
            "cve_backport",
            None,
            "ymir triage workflow missing CHAT_MODEL; "
            f"set CHAT_MODEL in the run environment, e.g. {DEFAULT_CHAT_MODEL}",
        ),
    ],
)
def test_live_ymir_executors_report_missing_chat_model(
    tmp_path: Path,
    executor_factory,
    case_type: str,
    expected: dict[str, object] | None,
    reason: str,
) -> None:
    request = _request(tmp_path, case_type=case_type)
    if expected is not None:
        _write_expected(request, expected)

    execution = executor_factory()(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == reason


def test_ymir_triage_executor_starts_managed_gateway_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    gateway_requests = []
    calls = []

    @contextmanager
    def managed_gateway(request):
        gateway_requests.append(request)
        yield "http://127.0.0.1:18080/sse"

    async def workflow(jira_issue, dry_run, agent_factory, **kwargs):
        calls.append(
            {
                "jira_issue": jira_issue,
                "dry_run": dry_run,
                "agent_factory": agent_factory,
                "kwargs": kwargs,
                "gateway_url": os.environ["MCP_GATEWAY_URL"],
            }
        )
        return _State(
            triage_result=_TriageResult(
                {
                    "resolution": "not_affected",
                    "data": {
                        "jira_issue": "RHEL-12345",
                        "package": "dnsmasq",
                    },
                }
            )
        )

    def agent_factory(_gateway_tools, _local_tool_options):
        return object()

    monkeypatch.setattr(workflow_module, "_managed_mcp_gateway", managed_gateway)
    monkeypatch.setattr(
        workflow_module,
        "_triage_dependencies",
        lambda _workflow, _agent_factory: (workflow, agent_factory),
    )

    executor = make_ymir_triage_executor()
    execution = executor(
        _request(
            tmp_path,
            environment={
                "CHAT_MODEL": "gemini:gemini-2.5-pro",
                "DRY_RUN": "true",
            },
        )
    )

    assert execution.status == "passed"
    assert execution.actual_result is not None
    assert execution.actual_result["resolution"] == "not_affected"
    assert len(gateway_requests) == 1
    assert gateway_requests[0].environment["DRY_RUN"] == "true"
    assert "MCP_GATEWAY_URL" not in gateway_requests[0].environment
    assert calls == [
        {
            "jira_issue": "RHEL-12345",
            "dry_run": True,
            "agent_factory": agent_factory,
            "kwargs": {"auto_chain": False, "silent_run": True},
            "gateway_url": "http://127.0.0.1:18080/sse",
        }
    ]



def test_patch_no_write_candidate_build_lookup_replays_brewhub(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    from ymir.common import utils as utils_module
    from ymir.tools.unprivileged import specfile as specfile_module

    async def fail_lookup(_package: str, _dist_git_branch: str):
        raise AssertionError("live candidate build lookup should not run")

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "recorded_files": {},
                "koji_candidate_builds": {
                    "redis|rhel-9.6.0": {
                        "evr": {
                            "epoch": 1,
                            "version": "6.2.20",
                            "release": "3.el9",
                        },
                        "source_ref": "real-source-ref",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("YMIR_BENCHMARK_REPLAY_MANIFEST", str(manifest_path))
    monkeypatch.delattr(specfile_module, "_ymir_harness_candidate_build_patched", raising=False)
    monkeypatch.setattr(specfile_module, "get_latest_candidate_build", fail_lookup)
    monkeypatch.setattr(utils_module, "get_latest_candidate_build", fail_lookup)

    _patch_no_write_candidate_build_lookup()

    evr, source_ref = asyncio.run(specfile_module.get_latest_candidate_build("redis", "rhel-9.6.0"))

    assert evr.epoch == 1
    assert evr.version == "6.2.20"
    assert evr.release == "3.el9"
    assert source_ref == "real-source-ref"



def test_instrument_agent_factory_logs_agent_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request(
        tmp_path,
        environment={
            "CHAT_MODEL": "vertexai:claude-sonnet-4-6",
        },
    )

    class Agent:
        async def run(self) -> str:
            return "done"

    async def run_agent() -> str:
        factory = _instrument_agent_factory(lambda *_args: Agent(), request=request, agent_name="x")
        agent = await factory([], {})
        return await agent.run()

    assert asyncio.run(run_agent()) == "done"
    stderr = capsys.readouterr().err
    assert '"event": "agent_run_start"' in stderr
    assert '"event": "agent_run_finished"' in stderr
    assert '"chat_model": "vertexai:claude-sonnet-4-6"' in stderr


def test_instrument_agent_factory_logs_chat_model_boundary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request(tmp_path)

    class ModelRun:
        def middleware(self, _middleware) -> object:
            async def await_response() -> str:
                return "model response"

            return await_response()

    class Model:
        def run(self, messages, **options) -> ModelRun:
            assert messages == ["hello"]
            assert options == {"temperature": 0.6}
            return ModelRun()

    class Agent:
        def __init__(self) -> None:
            self._llm = Model()

        async def run(self) -> str:
            return await self._llm.run(["hello"], temperature=0.6).middleware(object())

    async def run_agent() -> str:
        factory = _instrument_agent_factory(lambda *_args: Agent(), request=request, agent_name="x")
        agent = await factory([], {})
        return await agent.run()

    assert asyncio.run(run_agent()) == "model response"
    stderr = capsys.readouterr().err
    assert '"event": "chat_model_run_start"' in stderr
    assert '"message_count": 1' in stderr
    assert '"option_keys": ["temperature"]' in stderr
    assert '"event": "chat_model_run_created"' in stderr
    assert '"event": "chat_model_middleware_start"' in stderr
    assert '"event": "chat_model_awaitable_created"' in stderr
    assert '"event": "chat_model_await_start"' in stderr
    assert '"event": "chat_model_await_finished"' in stderr


def test_instrument_agent_factory_times_out_agent_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request(
        tmp_path,
        environment={
            "YMIR_HARNESS_AGENT_TIMEOUT_SECONDS": "0.01",
        },
    )

    class Agent:
        async def run(self) -> str:
            await asyncio.sleep(1)
            return "done"

    async def run_agent() -> None:
        factory = _instrument_agent_factory(lambda *_args: Agent(), request=request, agent_name="x")
        agent = await factory([], {})
        await agent.run()

    with pytest.raises(TimeoutError):
        asyncio.run(run_agent())

    stderr = capsys.readouterr().err
    assert '"event": "agent_run_errored"' in stderr
    assert '"error_type": "TimeoutError"' in stderr





def _request(
    tmp_path: Path,
    *,
    case_type: str | None = "cve_backport",
    environment: dict[str, str] | None = None,
    features: tuple[str, ...] = (),
) -> RunCaseRequest:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    return RunCaseRequest(
        case_id="RHEL-12345",
        case_type=case_type,
        repetition=1,
        cases_dir=cases_dir,
        results_dir=results_dir,
        expected_path=cases_dir / "expected" / "RHEL-12345.expected.json",
        actual_path=results_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        environment=environment or {},
        variant="baseline",
        features=features,
    )


def _write_expected(request: RunCaseRequest, payload: dict[str, object]) -> None:
    request.expected_path.parent.mkdir(parents=True, exist_ok=True)
    request.expected_path.write_text(json.dumps(payload), encoding="utf-8")


def _install_fake_ymir_agent(
    monkeypatch,
    module_basename: str,
    *,
    workflow_class: type | None = None,
    module_run_workflow=None,
) -> None:
    ymir_module = types.ModuleType("ymir")
    ymir_module.__path__ = []
    agents_module = types.ModuleType("ymir.agents")
    agents_module.__path__ = []
    agent_module = types.ModuleType(f"ymir.agents.{module_basename}")

    if workflow_class is not None:
        setattr(agent_module, workflow_class.__name__, workflow_class)
    if module_run_workflow is not None:
        agent_module.run_workflow = module_run_workflow

    ymir_module.agents = agents_module
    setattr(agents_module, module_basename, agent_module)

    monkeypatch.setitem(sys.modules, "ymir", ymir_module)
    monkeypatch.setitem(sys.modules, "ymir.agents", agents_module)
    monkeypatch.setitem(sys.modules, f"ymir.agents.{module_basename}", agent_module)


class _State:
    def __init__(self, **attributes):
        for name, value in attributes.items():
            setattr(self, name, value)


class _TriageResult:
    def __init__(self, payload: dict[str, object]):
        self._payload = payload

    def model_dump(self, *, mode: str):
        assert mode == "json"
        return self._payload
