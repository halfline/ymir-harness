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
