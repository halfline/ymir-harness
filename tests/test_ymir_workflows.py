from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

from ymir_harness.runner import RunCaseRequest
from ymir_harness.ymir_workflows import (
    make_ymir_backport_executor,
    make_ymir_rebuild_executor,
    make_ymir_rebase_executor,
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


def test_ymir_backport_executor_runs_workflow_with_expected_inputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OUTER_ONLY", "kept")
    request = _request(
        tmp_path,
        environment={
            "PATH": "/usr/bin",
            "DRY_RUN": "true",
        },
        features=("YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK",),
    )
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "patch_urls": ["https://example.invalid/fix.patch"],
            "cve_ids": ["CVE-2026-0001"],
            "rationale": "Merged upstream fix",
            "fix_version": "rhel-8.10.z",
        },
    )
    calls = []

    async def workflow(**kwargs):
        calls.append(
            {
                **kwargs,
                "dry_run_env": os.environ["DRY_RUN"],
                "feature_env": os.environ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
                "outer_only": os.environ.get("OUTER_ONLY"),
            }
        )
        return _State(
            backport_result=_BackportResult(
                {
                    "success": True,
                    "status": "built",
                    "error": None,
                    "srpm_path": "/tmp/build/dnsmasq.src.rpm",
                }
            ),
            usage={"input_tokens": 2200, "output_tokens": 500},
            iteration_count=17,
            tool_call_count=8,
            total_cost_usd=9.75,
        )

    def agent_factory(_gateway_tools, _local_tool_options):
        return object()

    executor = make_ymir_backport_executor(
        workflow=workflow,
        agent_factory=agent_factory,
    )

    execution = executor(request)

    assert os.environ["OUTER_ONLY"] == "kept"
    assert execution.status == "passed"
    assert execution.actual_result == {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "workflow": "ymir-backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "patch_urls": ["https://example.invalid/fix.patch"],
        "cve_ids": ["CVE-2026-0001"],
        "build_result": "passed",
        "backport_status": "built",
        "backport_error": None,
        "data": {
            "success": True,
            "status": "built",
            "error": None,
            "srpm_path": "/tmp/build/dnsmasq.src.rpm",
        },
        "generated_artifacts": ["/tmp/build/dnsmasq.src.rpm"],
        "token_usage": {"input_tokens": 2200, "output_tokens": 500},
        "iteration_count": 17,
        "tool_call_count": 8,
        "total_cost_usd": 9.75,
    }
    assert calls == [
        {
            "package": "dnsmasq",
            "dist_git_branch": "rhel-8.10.z",
            "upstream_patches": ["https://example.invalid/fix.patch"],
            "jira_issue": "RHEL-12345",
            "cve_id": "CVE-2026-0001",
            "justification": "Merged upstream fix",
            "fix_version": "rhel-8.10.z",
            "dry_run": True,
            "backport_agent_factory": agent_factory,
            "dry_run_env": "true",
            "feature_env": "true",
            "outer_only": None,
        }
    ]


def test_ymir_backport_executor_reports_missing_expected_inputs(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )
    calls = []

    async def workflow(**kwargs):
        calls.append(kwargs)
        return _State(backport_result={})

    executor = make_ymir_backport_executor(
        workflow=workflow,
        agent_factory=lambda _gateway_tools, _local_tool_options: object(),
    )

    execution = executor(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == (
        "ymir backport workflow missing expected dist_git_branch, upstream_patches"
    )
    assert calls == []


def test_ymir_backport_executor_reports_missing_backport_result(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    )

    async def workflow(**_kwargs):
        return _State(backport_result=None)

    executor = make_ymir_backport_executor(
        workflow=workflow,
        agent_factory=lambda _gateway_tools, _local_tool_options: object(),
    )

    execution = executor(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == "ymir backport workflow returned no backport result"


def test_ymir_rebase_executor_runs_workflow_with_expected_inputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OUTER_ONLY", "kept")
    request = _request(
        tmp_path,
        case_type="rebase",
        environment={
            "PATH": "/usr/bin",
            "DRY_RUN": "true",
        },
        features=("YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK",),
    )
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "rebase",
            "resolution": "rebase",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "version": "2.91",
            "rationale": "Maintainer requested rebase",
        },
    )
    calls = []

    async def workflow(**kwargs):
        calls.append(
            {
                **kwargs,
                "dry_run_env": os.environ["DRY_RUN"],
                "feature_env": os.environ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
                "outer_only": os.environ.get("OUTER_ONLY"),
            }
        )
        return _State(
            rebase_result=_RebaseResult(
                {
                    "success": True,
                    "status": "rebased to 2.91",
                    "error": None,
                    "srpm_path": "/tmp/build/dnsmasq.src.rpm",
                    "files_to_git_add": ["dnsmasq.spec", "dnsmasq-2.91.patch"],
                }
            )
        )

    executor = make_ymir_rebase_executor(workflow=workflow)

    execution = executor(request)

    assert os.environ["OUTER_ONLY"] == "kept"
    assert execution.status == "passed"
    assert execution.actual_result == {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "rebase",
        "workflow": "ymir-rebase",
        "resolution": "rebase",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "version": "2.91",
        "build_result": "passed",
        "rebase_status": "rebased to 2.91",
        "rebase_error": None,
        "data": {
            "success": True,
            "status": "rebased to 2.91",
            "error": None,
            "srpm_path": "/tmp/build/dnsmasq.src.rpm",
            "files_to_git_add": ["dnsmasq.spec", "dnsmasq-2.91.patch"],
        },
        "generated_artifacts": ["/tmp/build/dnsmasq.src.rpm"],
        "touched_files": ["dnsmasq.spec", "dnsmasq-2.91.patch"],
    }
    assert calls == [
        {
            "package": "dnsmasq",
            "dist_git_branch": "rhel-8.10.z",
            "version": "2.91",
            "jira_issue": "RHEL-12345",
            "justification": "Maintainer requested rebase",
            "redis_conn": None,
            "dry_run_env": "true",
            "feature_env": "true",
            "outer_only": None,
        }
    ]


def test_ymir_rebase_executor_reports_missing_expected_inputs(tmp_path: Path) -> None:
    request = _request(tmp_path, case_type="rebase")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "rebase",
            "resolution": "rebase",
            "package": "dnsmasq",
        },
    )
    calls = []

    async def workflow(**kwargs):
        calls.append(kwargs)
        return _State(rebase_result={})

    executor = make_ymir_rebase_executor(workflow=workflow)

    execution = executor(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == "ymir rebase workflow missing expected dist_git_branch, version"
    assert calls == []


def test_ymir_rebase_executor_reports_missing_rebase_result(tmp_path: Path) -> None:
    request = _request(tmp_path, case_type="rebase")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "rebase",
            "resolution": "rebase",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "version": "2.91",
        },
    )

    async def workflow(**_kwargs):
        return _State(rebase_result=None)

    executor = make_ymir_rebase_executor(workflow=workflow)

    execution = executor(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == "ymir rebase workflow returned no rebase result"


def test_ymir_rebase_executor_uses_class_workflow_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request = _request(tmp_path, case_type="rebase")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "rebase",
            "resolution": "rebase",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "version": "2.91",
        },
    )
    calls = []

    async def stale_module_workflow(**_kwargs):
        raise AssertionError("module-level run_workflow must not be used")

    class RebaseWorkflow:
        @classmethod
        async def run_workflow(cls, **kwargs):
            calls.append({"class": cls.__name__, **kwargs})
            return _State(
                rebase_result={
                    "success": True,
                    "status": "rebased",
                    "error": None,
                }
            )

    _install_fake_ymir_agent(
        monkeypatch,
        "rebase_agent",
        workflow_class=RebaseWorkflow,
        module_run_workflow=stale_module_workflow,
    )

    executor = make_ymir_rebase_executor()

    execution = executor(request)

    assert execution.status == "passed"
    assert calls == [
        {
            "class": "RebaseWorkflow",
            "package": "dnsmasq",
            "dist_git_branch": "rhel-8.10.z",
            "version": "2.91",
            "jira_issue": "RHEL-12345",
            "justification": None,
            "redis_conn": None,
        }
    ]


def test_ymir_rebase_executor_rejects_module_level_workflow_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request = _request(tmp_path, case_type="rebase")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "rebase",
            "resolution": "rebase",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "version": "2.91",
        },
    )

    async def stale_module_workflow(**_kwargs):
        return _State(rebase_result={})

    _install_fake_ymir_agent(
        monkeypatch,
        "rebase_agent",
        module_run_workflow=stale_module_workflow,
    )

    executor = make_ymir_rebase_executor()

    with pytest.raises(ImportError, match="agent class with run_workflow"):
        executor(request)


def test_ymir_rebuild_executor_runs_workflow_with_expected_inputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OUTER_ONLY", "kept")
    request = _request(
        tmp_path,
        case_type="dependency_rebuild",
        environment={
            "PATH": "/usr/bin",
            "DRY_RUN": "true",
        },
        features=("YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK",),
    )
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "dependency_rebuild",
            "resolution": "rebuild",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
            "rationale": "Dependency update requires a rebuild",
            "dependency_issues": ["RHEL-23456"],
            "dependency_component": "golang",
            "sibling_issues": ["RHEL-34567"],
            "consolidation_summary": "Rebuild siblings share the same dependency",
        },
    )
    calls = []

    async def workflow(**kwargs):
        calls.append(
            {
                **kwargs,
                "dry_run_env": os.environ["DRY_RUN"],
                "feature_env": os.environ["YMIR_ENABLE_CVE_AFFECTED_VERSION_CHECK"],
                "outer_only": os.environ.get("OUTER_ONLY"),
            }
        )
        return _State(
            package="dnsmasq",
            dist_git_branch="rhel-8.10.z",
            rebuild_success=True,
            rebuild_error=None,
            merge_request_url="https://gitlab.example.invalid/dnsmasq/-/merge_requests/1",
            dependency_issue="RHEL-23456",
            dependency_component="golang",
            consolidated_issues=[
                _State(
                    issue_key="RHEL-34567",
                    dependency_issue="RHEL-23456",
                    dependency_component="golang",
                )
            ],
            consolidation_summary="Rebuild siblings share the same dependency",
        )

    executor = make_ymir_rebuild_executor(workflow=workflow)

    execution = executor(request)

    assert os.environ["OUTER_ONLY"] == "kept"
    assert execution.status == "passed"
    assert execution.actual_result == {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "workflow": "ymir-rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "build_result": "passed",
        "rebuild_status": "rebuilt",
        "rebuild_error": None,
        "data": {
            "success": True,
            "status": "rebuilt",
            "merge_request_url": "https://gitlab.example.invalid/dnsmasq/-/merge_requests/1",
            "error": None,
            "dependency_issues": ["RHEL-23456"],
            "dependency_components": ["golang"],
            "sibling_issues": ["RHEL-34567"],
            "consolidated_issues": [
                {
                    "issue_key": "RHEL-34567",
                    "dependency_issue": "RHEL-23456",
                    "dependency_component": "golang",
                }
            ],
            "consolidation_summary": "Rebuild siblings share the same dependency",
        },
        "merge_request_url": "https://gitlab.example.invalid/dnsmasq/-/merge_requests/1",
        "dependency_issues": ["RHEL-23456"],
        "dependency_components": ["golang"],
        "sibling_issues": ["RHEL-34567"],
    }
    assert calls == [
        {
            "package": "dnsmasq",
            "dist_git_branch": "rhel-8.10.z",
            "jira_issue": "RHEL-12345",
            "justification": "Dependency update requires a rebuild",
            "dependency_issue": "RHEL-23456",
            "dependency_component": "golang",
            "consolidated_issues": [
                {
                    "issue_key": "RHEL-34567",
                    "dependency_issue": "RHEL-23456",
                    "dependency_component": "golang",
                }
            ],
            "consolidation_summary": "Rebuild siblings share the same dependency",
            "dry_run_env": "true",
            "feature_env": "true",
            "outer_only": None,
        }
    ]


def test_ymir_rebuild_executor_reports_missing_expected_inputs(tmp_path: Path) -> None:
    request = _request(tmp_path, case_type="dependency_rebuild")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "dependency_rebuild",
            "resolution": "rebuild",
            "package": "dnsmasq",
        },
    )
    calls = []

    async def workflow(**kwargs):
        calls.append(kwargs)
        return _State(rebuild_success=True)

    executor = make_ymir_rebuild_executor(workflow=workflow)

    execution = executor(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == "ymir rebuild workflow missing expected dist_git_branch"
    assert calls == []


def test_ymir_rebuild_executor_reports_missing_rebuild_result(tmp_path: Path) -> None:
    request = _request(tmp_path, case_type="dependency_rebuild")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "dependency_rebuild",
            "resolution": "rebuild",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
        },
    )

    async def workflow(**_kwargs):
        return _State()

    executor = make_ymir_rebuild_executor(workflow=workflow)

    execution = executor(request)

    assert execution.status == "failed"
    assert execution.actual_result is None
    assert execution.reason == "ymir rebuild workflow returned no rebuild result"


def test_ymir_rebuild_executor_uses_class_workflow_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request = _request(tmp_path, case_type="dependency_rebuild")
    _write_expected(
        request,
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "dependency_rebuild",
            "resolution": "rebuild",
            "package": "dnsmasq",
            "target_branch": "rhel-8.10.z",
        },
    )
    calls = []

    async def stale_module_workflow(**_kwargs):
        raise AssertionError("module-level run_workflow must not be used")

    class RebuildAgent:
        async def run_workflow(self, **kwargs):
            calls.append(kwargs)
            return _State(rebuild_success=True, rebuild_error=None)

    _install_fake_ymir_agent(
        monkeypatch,
        "rebuild_agent",
        workflow_class=RebuildAgent,
        module_run_workflow=stale_module_workflow,
    )

    executor = make_ymir_rebuild_executor()

    execution = executor(request)

    assert execution.status == "passed"
    assert calls == [
        {
            "package": "dnsmasq",
            "dist_git_branch": "rhel-8.10.z",
            "jira_issue": "RHEL-12345",
            "justification": None,
            "dependency_issue": None,
            "dependency_component": None,
            "consolidated_issues": [],
            "consolidation_summary": None,
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


class _BackportResult:
    def __init__(self, payload: dict[str, object]):
        self._payload = payload

    def model_dump(self, *, mode: str):
        assert mode == "json"
        return self._payload


class _RebaseResult:
    def __init__(self, payload: dict[str, object]):
        self._payload = payload

    def model_dump(self, *, mode: str):
        assert mode == "json"
        return self._payload
