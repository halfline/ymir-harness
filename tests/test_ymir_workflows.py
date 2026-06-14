from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tarfile
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

import ymir_harness.ymir_workflows as workflow_module
from ymir_harness.runner import DEFAULT_CHAT_MODEL, RunCaseRequest
from ymir_harness.ymir_workflows import (
    _fallback_update_release_text,
    _fixture_search_results,
    _instrument_agent_factory,
    _is_package_prep_command,
    _materialize_replay_unpacked_sources,
    _patch_no_write_candidate_build_lookup,
    _recover_backport_stage_changes,
    make_ymir_backport_executor,
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


def _source_patch_text(path: str = "source.c") -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        "index 5d308e1..85c3040 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )


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


def test_fixture_search_results_returns_known_jira_links(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    jira_dir = cases_dir / "jiras" / "RHEL-12345"
    jira_dir.mkdir(parents=True)
    (jira_dir / "links.json").write_text(
        json.dumps(
            {
                "links": [
                    {
                        "object": {
                            "title": "Redis security advisory",
                            "url": "https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4",
                        }
                    },
                    {
                        "object": {
                            "title": "Unrelated link",
                            "url": "https://example.invalid/unrelated",
                        }
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (jira_dir / "comments.json").write_text(
        json.dumps(
            [
                {
                    "body": (
                        "MR: [https://gitlab.example/pkg/-/merge_requests/7|"
                        "https://gitlab.example/pkg/-/merge_requests/7|smart-link]"
                    )
                }
            ]
        ),
        encoding="utf-8",
    )

    results = _fixture_search_results(
        _request(tmp_path),
        "CVE-2026-25243 redis security advisory merge request",
        max_results=10,
    )

    assert [result["url"] for result in results] == [
        "https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4",
        "https://gitlab.example/pkg/-/merge_requests/7",
    ]


def test_fixture_search_results_includes_recorded_urls_and_source_remotes(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    web_cache = cases_dir / "web_cache" / "RHEL-12345"
    web_cache.mkdir(parents=True)
    (web_cache / "manifest.json").write_text(
        json.dumps(
            {
                "recorded_files": {
                    "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/abc.patch": "patches/abc.patch"
                }
            }
        ),
        encoding="utf-8",
    )
    source_repo = cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "redis.git"
    source_repo.mkdir(parents=True)
    (source_repo / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/redis/redis.git\n',
        encoding="utf-8",
    )

    results = _fixture_search_results(
        _request(tmp_path),
        "redis upstream commit fix",
        max_results=10,
    )

    assert [result["url"] for result in results] == [
        "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/abc.patch",
        "https://github.com/redis/redis.git",
    ]


def test_fixture_search_results_returns_empty_for_unknown_query(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    jira_dir = cases_dir / "jiras" / "RHEL-12345"
    jira_dir.mkdir(parents=True)
    (jira_dir / "links.json").write_text(
        json.dumps(
            {
                "links": [
                    {
                        "object": {
                            "title": "Redis security advisory",
                            "url": "https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4",
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        _fixture_search_results(
            _request(tmp_path),
            "postgres kerberos regression",
            max_results=10,
        )
        == []
    )

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
        (
            make_ymir_backport_executor,
            "cve_backport",
            {
                "schema_version": 1,
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
                "target_branch": "rhel-8.10.z",
                "patch_urls": ["https://example.invalid/fix.patch"],
            },
            "ymir backport workflow missing CHAT_MODEL; "
            f"set CHAT_MODEL in the run environment, e.g. {DEFAULT_CHAT_MODEL}",
        ),
    ],
)
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


def test_is_package_prep_command_detects_rhpkg_and_centpkg() -> None:
    assert _is_package_prep_command(["rhpkg", "--release=rhel-9.6.0", "prep"])
    assert _is_package_prep_command("centpkg --release=c9s prep")
    assert not _is_package_prep_command(["git", "status"])
    assert not _is_package_prep_command(["rhpkg", "sources"])


def test_materialize_replay_unpacked_sources_extracts_source0_archive(tmp_path: Path) -> None:
    (tmp_path / "redis.spec").write_text(
        "Name: redis\nVersion: 6.2.20\nSource0: %{name}-%{version}.tar.gz\n%prep\n%autosetup -p1\n",
        encoding="utf-8",
    )
    source_tree = tmp_path / "archive" / "redis-6.2.20"
    source_tree.mkdir(parents=True)
    (source_tree / "README").write_text("real source\n", encoding="utf-8")
    with tarfile.open(tmp_path / "redis-6.2.20.tar.gz", "w:gz") as archive:
        archive.add(source_tree, arcname="redis-6.2.20")

    source_dir = _materialize_replay_unpacked_sources(tmp_path)

    assert source_dir == tmp_path / "redis-6.2.20"
    assert (tmp_path / "redis-6.2.20" / "README").read_text(encoding="utf-8") == "real source\n"


def test_materialize_replay_unpacked_sources_uses_sources_file_fallback(
    tmp_path: Path,
) -> None:
    (tmp_path / "pkg.spec").write_text(
        "Name: pkg\nVersion: 1.0\n%prep\n%autosetup -n custom-source -p1\n",
        encoding="utf-8",
    )
    (tmp_path / "sources").write_text("SHA512 (custom.tar.gz) = abc123\n", encoding="utf-8")
    source_tree = tmp_path / "archive" / "upstream-name"
    source_tree.mkdir(parents=True)
    (source_tree / "source.c").write_text("real source\n", encoding="utf-8")
    with tarfile.open(tmp_path / "custom.tar.gz", "w:gz") as archive:
        archive.add(source_tree, arcname="upstream-name")

    source_dir = _materialize_replay_unpacked_sources(tmp_path)

    assert source_dir == tmp_path / "custom-source"
    assert (tmp_path / "custom-source" / "source.c").read_text(encoding="utf-8") == "real source\n"


def test_fallback_update_release_text_bumps_stream_release(tmp_path: Path) -> None:
    spec_path = tmp_path / "dnsmasq.spec"
    spec_path.write_text(
        "Name:           dnsmasq\n"
        "Version:        2.79\n"
        "Release:        31%{?extraversion:.%{extraversion}}%{?dist}\n",
        encoding="utf-8",
    )

    _fallback_update_release_text(
        spec_path,
        rebase=False,
        dist_git_branch="c8s",
        abandon_autorelease=False,
    )

    assert (
        "Release:        32%{?extraversion:.%{extraversion}}%{?dist}\n"
        in spec_path.read_text(encoding="utf-8")
    )


def test_recover_backport_stage_changes_stages_spec_patch_files_from_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_path = tmp_path / "dist-git"
    repo_path.mkdir()
    subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "ymir-harness@example.invalid"],
        cwd=repo_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Ymir Harness"],
        cwd=repo_path,
        check=True,
    )
    spec_path = repo_path / "dnsmasq.spec"
    spec_path.write_text("Name: dnsmasq\nVersion: 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "dnsmasq.spec"], cwd=repo_path, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo_path, check=True)

    spec_path.write_text(
        "Name: dnsmasq\nVersion: 1\nPatch0001: fix.patch\n",
        encoding="utf-8",
    )
    (repo_path / "fix.patch").write_text(_source_patch_text(), encoding="utf-8")
    state = _State(
        local_clone=repo_path,
        package="dnsmasq",
        backport_result=_State(
            success=False,
            error="Could not stage changes: rpm.expandMacro requires system RPM bindings",
        ),
        log_result=None,
    )
    monkeypatch.setenv("DRY_RUN", "true")

    next_step = _recover_backport_stage_changes("stage_changes", state, "comment_in_jira")

    assert next_step == "run_log_agent"
    assert state.backport_result.success is True
    assert state.backport_result.error is None
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=repo_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert staged == ["dnsmasq.spec", "fix.patch"]


def test_materialize_replay_unpacked_sources_reports_missing_archive(tmp_path: Path) -> None:
    (tmp_path / "redis.spec").write_text(
        "Name: redis\nVersion: 6.2.20\nSource0: %{name}-%{version}.tar.gz\n",
        encoding="utf-8",
    )

    assert _materialize_replay_unpacked_sources(tmp_path) is None
    assert not (tmp_path / "redis-6.2.20").exists()

def test_ymir_backport_executor_collects_artifacts_and_scope(tmp_path: Path) -> None:
    request = _request(
        tmp_path,
        environment={
            "DRY_RUN": "true",
            "YMIR_BENCHMARK_ARTIFACT_DIR": str(tmp_path / "artifacts" / "RHEL-12345"),
        },
    )
    artifact_path = Path(request.environment["YMIR_BENCHMARK_ARTIFACT_DIR"]) / "fix.patch"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_text("diff --git a/source.c b/source.c\n", encoding="utf-8")
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
        return _State(
            backport_result=_BackportResult(
                {
                    "success": True,
                    "status": "built",
                    "srpm_path": "/tmp/build/dnsmasq.src.rpm",
                    "touched_files": ["SOURCES/fix.patch"],
                    "spec_patches": ["Patch0001: fix.patch"],
                    "changelog_entries": ["- Resolves: RHEL-12345"],
                }
            ),
        )

    executor = make_ymir_backport_executor(
        workflow=workflow,
        agent_factory=lambda _gateway_tools, _local_tool_options: object(),
    )

    execution = executor(request)

    assert execution.status == "passed"
    assert execution.actual_result is not None
    assert execution.actual_result["generated_artifacts"] == [
        "/tmp/build/dnsmasq.src.rpm",
        str(artifact_path),
    ]
    assert execution.actual_result["touched_files"] == ["SOURCES/fix.patch"]
    assert execution.actual_result["spec_patches"] == ["Patch0001: fix.patch"]
    assert execution.actual_result["changelog_entries"] == ["- Resolves: RHEL-12345"]
class _BackportResult:
    def __init__(self, payload: dict[str, object]):
        self._payload = payload

    def model_dump(self, *, mode: str):
        assert mode == "json"
        return self._payload
