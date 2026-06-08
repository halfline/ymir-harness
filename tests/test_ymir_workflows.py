from __future__ import annotations

import json
import os
from pathlib import Path

from ymir_harness.runner import RunCaseRequest
from ymir_harness.ymir_workflows import make_ymir_backport_executor, make_ymir_triage_executor


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
            )
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


def _request(
    tmp_path: Path,
    *,
    environment: dict[str, str] | None = None,
    features: tuple[str, ...] = (),
) -> RunCaseRequest:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    return RunCaseRequest(
        case_id="RHEL-12345",
        case_type="cve_backport",
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
