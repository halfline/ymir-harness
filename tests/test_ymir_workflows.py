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
