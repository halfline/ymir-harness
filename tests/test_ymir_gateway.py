from __future__ import annotations

import asyncio
import builtins
import json
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from ymir_harness.jira_replay import (
    load_jira_search_response,
    parse_jira_replay_misses,
    write_jira_search_fixture,
)
from ymir_harness.ymir_gateway import (
    _install_optional_gateway_shims,
    _patch_no_write_gateway_tools,
    _patch_ymir_jira_mock_remote_links,
)


def test_install_optional_gateway_shims_adds_requests_gssapi_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def import_without_requests_gssapi(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "requests_gssapi" and name not in sys.modules:
            raise ImportError(name)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "requests_gssapi", raising=False)
    monkeypatch.setattr(builtins, "__import__", import_without_requests_gssapi)

    _install_optional_gateway_shims()

    from requests_gssapi import HTTPSPNEGOAuth

    with pytest.raises(RuntimeError, match="Errata tools are unavailable"):
        HTTPSPNEGOAuth(opportunistic_auth=True)


def test_patch_ymir_jira_mock_remote_links_returns_link_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def read_jira_mock(issue_key: str, remote_link: bool = False) -> object:
        assert issue_key == "RHEL-12345"
        if remote_link:
            return [{"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}]
        return {"key": issue_key}

    class BaseSession:
        remote_link_get_regex = re.compile(
            r"https://jira.example/rest/api/3/issue/([A-Z0-9-]+)/remotelink"
        )

        @asynccontextmanager
        async def get(self, *_args: object, **_kwargs: object):
            yield SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"key": "RHEL-12345"},
            )

    mock_module = SimpleNamespace(
        aiohttpClientSessionMock=BaseSession,
        _read_jira_mock=read_jira_mock,
        flexmock=lambda **attrs: SimpleNamespace(**attrs),
    )
    jira_module = SimpleNamespace(aiohttpClientSession=BaseSession)

    monkeypatch.setenv("MOCK_JIRA", "true")
    monkeypatch.setitem(
        __import__("sys").modules,
        "ymir.tools.privileged.aiohttp_client_session_mock",
        mock_module,
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "ymir.tools.privileged.jira",
        jira_module,
    )

    _patch_ymir_jira_mock_remote_links()

    async def read_remote_links() -> object:
        session = jira_module.aiohttpClientSession()
        async with session.get(
            "https://jira.example/rest/api/3/issue/RHEL-12345/remotelink"
        ) as response:
            assert response.status == 200
            response.raise_for_status()
            return await response.json()

    assert asyncio.run(read_remote_links()) == [
        {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
    ]


def test_patch_no_write_gateway_tools_replays_zstream_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    monkeypatch.setenv("DRY_RUN", "true")

    _patch_no_write_gateway_tools()

    from ymir.tools.privileged.distgit import CreateZstreamBranchTool

    async def run_tool():
        return await CreateZstreamBranchTool().run(
            input={"package": "redis", "branch": "rhel-9.6.z"},
        )

    result = asyncio.run(run_tool())

    assert result.result == "Z-Stream branch rhel-9.6.z already exists, no need to create it"


def test_patch_no_write_gateway_tools_replays_fork_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("FORK_NAMESPACE", "redhat/rhel/bot-branches")

    _patch_no_write_gateway_tools()

    from ymir.tools.privileged.gitlab import ForkRepositoryTool

    async def run_tool():
        return await ForkRepositoryTool().run(
            input={"repository": "https://gitlab.com/redhat/rhel/rpms/redis"}
        )

    result = asyncio.run(run_tool())

    assert result.result == "https://gitlab.com/redhat/rhel/bot-branches/redis.git"


def test_patch_no_write_gateway_tools_replays_lookaside(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    source_cache = tmp_path / "source_cache"
    lookaside = source_cache / "lookaside"
    lookaside.mkdir(parents=True)
    (lookaside / "redis-6.2.20.tar.gz").write_text("archive\n", encoding="utf-8")
    (lookaside / "redis-6.2.22.tar.gz").write_text("future archive\n", encoding="utf-8")
    (tmp_path / "sources").write_text(
        "SHA512 (redis-6.2.20.tar.gz) = deadbeef\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("YMIR_BENCHMARK_SOURCE_CACHE_DIR", str(source_cache))

    _patch_no_write_gateway_tools()

    from ymir.tools.privileged.lookaside import DownloadSourcesTool, PrepSourcesTool

    async def run_tools():
        input_data = {
            "dist_git_path": tmp_path,
            "package": "redis",
            "dist_git_branch": "rhel-9.6.0",
        }
        download = await DownloadSourcesTool().run(input=input_data)
        prep = await PrepSourcesTool().run(input=input_data)
        return download.result, prep.result

    assert asyncio.run(run_tools()) == (
        "Successfully downloaded sources from replay cache (1 file(s))",
        "Successfully prepped sources from replay cache",
    )
    assert (tmp_path / "redis-6.2.20.tar.gz").read_text(encoding="utf-8") == "archive\n"
    assert not (tmp_path / "redis-6.2.22.tar.gz").exists()


def test_patch_no_write_gateway_tools_replays_patch_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    patch_url = "https://gitlab.example/group/pkg/-/commit/abc123.patch"
    cache_dir = tmp_path / "web_cache"
    patch_path = cache_dir / "jira" / "patches" / "001.patch"
    patch_path.parent.mkdir(parents=True)
    patch_path.write_text("diff --git a/source.c b/source.c\n", encoding="utf-8")
    (cache_dir / "manifest.json").write_text(
        json.dumps(
            {
                "recorded_files": {patch_url: "jira/patches/001.patch"},
                "required_urls": [patch_url],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("YMIR_BENCHMARK_REPLAY_MANIFEST", str(cache_dir / "manifest.json"))

    _patch_no_write_gateway_tools()

    from ymir.tools.privileged.gitlab import GetPatchFromUrlTool

    async def run_tool():
        return await GetPatchFromUrlTool().run(input={"patch_url": patch_url})

    assert asyncio.run(run_tool()).result == "diff --git a/source.c b/source.c\n"


def test_patch_no_write_gateway_tools_does_not_truncate_patch_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    patch_url = "https://gitlab.example/group/pkg/-/commit/abc123.patch"
    patch_text = "diff --git a/source.c b/source.c\n" + ("+source line\n" * 250)
    cache_dir = tmp_path / "web_cache"
    patch_path = cache_dir / "jira" / "patches" / "001.patch"
    patch_path.parent.mkdir(parents=True)
    patch_path.write_text(patch_text, encoding="utf-8")
    (cache_dir / "manifest.json").write_text(
        json.dumps(
            {
                "recorded_files": {patch_url: "jira/patches/001.patch"},
                "required_urls": [patch_url],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("YMIR_BENCHMARK_REPLAY_MANIFEST", str(cache_dir / "manifest.json"))

    _patch_no_write_gateway_tools()

    from ymir.tools.privileged.gitlab import GetPatchFromUrlTool

    async def run_tool():
        return await GetPatchFromUrlTool().run(input={"patch_url": patch_url})

    assert asyncio.run(run_tool()).result == patch_text


def test_patch_no_write_gateway_tools_replays_build_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ymir")
    srpm_path = tmp_path / "redis-dry-run.src.rpm"
    srpm_path.write_text("dry-run srpm\n", encoding="utf-8")
    monkeypatch.setenv("DRY_RUN", "true")

    _patch_no_write_gateway_tools()

    from ymir.tools.privileged.copr import BuildPackageTool

    async def run_tool():
        return await BuildPackageTool().run(
            input={
                "srpm_path": srpm_path,
                "dist_git_branch": "rhel-9.6.0",
                "jira_issue": "RHEL-178386",
            }
        )

    result = asyncio.run(run_tool()).result

    assert result.success is True
    assert result.artifacts_urls == [
        "ymir-harness://build/RHEL-178386/rhel-9.6.0/redis-dry-run.src.rpm"
    ]


def test_patch_ymir_jira_mock_replays_cached_search(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    payload = {
        "jql": 'component = "glib2"',
        "fields": ["fixVersions"],
        "maxResults": 50,
    }
    expected_response = {
        "issues": [
            {
                "key": "RHEL-4139",
                "id": "10001",
                "fields": {"fixVersions": [{"name": "rhel-9.8"}]},
            }
        ]
    }
    write_jira_search_fixture(
        cases_dir,
        "RHEL-114059",
        url="https://jira.example/rest/api/3/search/jql",
        payload=payload,
        response=expected_response,
        as_of="2025-09-12T09:46:42Z",
        overwrite=True,
    )

    class BaseSession:
        remote_link_get_regex = re.compile(
            r"https://jira.example/rest/api/3/issue/([A-Z0-9-]+)/remotelink"
        )
        search_post_regex = re.compile(r"https://jira.example/rest/api/3/search/jql")

        @asynccontextmanager
        async def get(self, *_args: object, **_kwargs: object):
            yield SimpleNamespace(raise_for_status=lambda: None, json=lambda: {})

        @asynccontextmanager
        async def post(self, *_args: object, **_kwargs: object):
            yield SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"issues": []})

    async def read_jira_mock(issue_key: str, remote_link: bool = False) -> object:
        return {"key": issue_key, "remote_link": remote_link}

    mock_module = SimpleNamespace(
        aiohttpClientSessionMock=BaseSession,
        _read_jira_mock=read_jira_mock,
        flexmock=lambda **attrs: SimpleNamespace(**attrs),
    )
    jira_module = SimpleNamespace(aiohttpClientSession=BaseSession)

    monkeypatch.setenv("MOCK_JIRA", "true")
    monkeypatch.setenv("YMIR_BENCHMARK_CASES_DIR", str(cases_dir))
    monkeypatch.setenv("YMIR_BENCHMARK_CASE_ID", "RHEL-114059")
    monkeypatch.setitem(
        sys.modules,
        "ymir.tools.privileged.aiohttp_client_session_mock",
        mock_module,
    )
    monkeypatch.setitem(sys.modules, "ymir.tools.privileged.jira", jira_module)

    _patch_ymir_jira_mock_remote_links()

    async def search() -> object:
        session = jira_module.aiohttpClientSession()
        async with session.post(
            "https://jira.example/rest/api/3/search/jql",
            json=payload,
        ) as response:
            assert response.status == 200
            response.raise_for_status()
            return await response.json()

    assert asyncio.run(search()) == expected_response


def test_jira_search_replay_synthesizes_from_issue_corpus(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    jira_dir = cases_dir / "jiras" / "RHEL-167675"
    linked_dir = jira_dir / "linked" / "RHEL-169930"
    linked_dir.mkdir(parents=True)
    (jira_dir / "reconstruction.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": "RHEL-167675",
                "as_of": "2026-04-27T17:13:39.101999Z",
            }
        ),
        encoding="utf-8",
    )
    (jira_dir / "issue.json").write_text(
        json.dumps(
            {
                "id": "1",
                "key": "RHEL-167675",
                "fields": {
                    "summary": "CVE-2026-32283 butane issue [rhel-9.8.z]",
                    "components": [{"name": "butane"}],
                    "fixVersions": [{"name": "rhel-9.8.z"}],
                    "labels": ["CVE-2026-32283"],
                    "created": "2026-04-13T11:08:58.333+0000",
                },
            }
        ),
        encoding="utf-8",
    )
    (linked_dir / "issue.json").write_text(
        json.dumps(
            {
                "id": "2",
                "key": "RHEL-169930",
                "fields": {
                    "summary": "Update Go to version 1.26.2+2 [rhel-9.8.z]",
                    "components": [{"name": "golang"}],
                    "fixVersions": [{"name": "rhel-9.8.z"}],
                    "issuetype": {"name": "Story"},
                    "status": {"name": "Closed"},
                    "customfield_10578": "golang-1.26.2-1.el9_8",
                    "created": "2026-04-21T18:37:25.322+0000",
                },
                "changelog": {
                    "histories": [
                        {
                            "created": "2026-05-01T10:00:00.000+0000",
                            "items": [
                                {
                                    "field": "status",
                                    "fieldId": "status",
                                    "fromString": "New",
                                    "toString": "Closed",
                                }
                            ],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    response = load_jira_search_response(
        cases_dir,
        "RHEL-167675",
        {
            "jql": (
                'project = RHEL AND component = "golang" '
                'AND fixVersion in ("rhel-9.8.z", "rhel-9.9") '
                'AND summary ~ "Go 1.26"'
            ),
            "fields": [
                "key",
                "summary",
                "fixVersions",
                "status",
                "components",
                "customfield_10578",
            ],
            "maxResults": 10,
        },
    )

    assert response is not None
    assert response["total"] == 1
    assert response["issues"][0]["key"] == "RHEL-169930"
    assert response["issues"][0]["fields"] == {
        "summary": "Update Go to version 1.26.2+2 [rhel-9.8.z]",
        "fixVersions": [{"name": "rhel-9.8.z"}],
        "status": {"name": "New"},
        "components": [{"name": "golang"}],
        "customfield_10578": "golang-1.26.2-1.el9_8",
    }


def test_patch_ymir_jira_mock_reports_missing_issue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class BaseSession:
        issue_get_regex = re.compile(r"https://jira.example/rest/api/3/issue/([A-Z0-9-]+)")
        remote_link_get_regex = re.compile(
            r"https://jira.example/rest/api/3/issue/([A-Z0-9-]+)/remotelink"
        )

        @asynccontextmanager
        async def get(self, *_args: object, **_kwargs: object):
            yield SimpleNamespace(raise_for_status=lambda: None, json=lambda: {})

    async def read_jira_mock(issue_key: str, remote_link: bool = False) -> object:
        raise FileNotFoundError(issue_key)

    mock_module = SimpleNamespace(
        aiohttpClientSessionMock=BaseSession,
        _read_jira_mock=read_jira_mock,
        flexmock=lambda **attrs: SimpleNamespace(**attrs),
    )
    jira_module = SimpleNamespace(aiohttpClientSession=BaseSession)

    monkeypatch.setenv("MOCK_JIRA", "true")
    monkeypatch.setitem(
        sys.modules,
        "ymir.tools.privileged.aiohttp_client_session_mock",
        mock_module,
    )
    monkeypatch.setitem(sys.modules, "ymir.tools.privileged.jira", jira_module)

    _patch_ymir_jira_mock_remote_links()

    async def read_missing_issue() -> None:
        session = jira_module.aiohttpClientSession()
        async with session.get("https://jira.example/rest/api/3/issue/RHEL-99999") as response:
            assert response.status == 200
            response.raise_for_status()
            with pytest.raises(FileNotFoundError):
                await response.json()

    asyncio.run(read_missing_issue())

    misses = parse_jira_replay_misses(capsys.readouterr().err)
    assert len(misses) == 1
    assert misses[0].kind == "jira_issue"
    assert misses[0].method == "GET"
    assert misses[0].payload == {"issue_key": "RHEL-99999"}


def test_patch_ymir_jira_mock_serves_dev_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_dir = tmp_path / "jira-mock"
    mock_dir.mkdir()
    (mock_dir / "RHEL-4139").write_text(
        json.dumps(
            {
                "id": "10001",
                "key": "RHEL-4139",
                "fields": {"summary": "Fixed issue"},
                "dev_status": {
                    "summary": {"repository": {"byInstanceType": {"GitLab": {"count": 1}}}},
                    "details": {
                        "GitLab:repository": [
                            {
                                "repositories": [
                                    {
                                        "url": "https://gitlab.example/group/pkg",
                                        "commits": [
                                            {"url": "https://gitlab.example/group/pkg/-/commit/1"}
                                        ],
                                    }
                                ]
                            }
                        ]
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    class BaseSession:
        remote_link_get_regex = re.compile(
            r"https://jira.example/rest/api/3/issue/([A-Z0-9-]+)/remotelink"
        )
        search_post_regex = re.compile(r"https://jira.example/rest/api/3/search/jql")

        @asynccontextmanager
        async def get(self, *_args: object, **_kwargs: object):
            yield SimpleNamespace(raise_for_status=lambda: None, json=lambda: {})

        @asynccontextmanager
        async def post(self, *_args: object, **_kwargs: object):
            yield SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"issues": []})

    async def read_jira_mock(issue_key: str, remote_link: bool = False) -> object:
        return {"key": issue_key, "remote_link": remote_link}

    mock_module = SimpleNamespace(
        aiohttpClientSessionMock=BaseSession,
        _read_jira_mock=read_jira_mock,
        flexmock=lambda **attrs: SimpleNamespace(**attrs),
    )
    jira_module = SimpleNamespace(aiohttpClientSession=BaseSession)

    monkeypatch.setenv("MOCK_JIRA", "true")
    monkeypatch.setenv("JIRA_MOCK_FILES", str(mock_dir))
    monkeypatch.setitem(
        sys.modules,
        "ymir.tools.privileged.aiohttp_client_session_mock",
        mock_module,
    )
    monkeypatch.setitem(sys.modules, "ymir.tools.privileged.jira", jira_module)

    _patch_ymir_jira_mock_remote_links()

    async def read_detail() -> object:
        session = jira_module.aiohttpClientSession()
        async with session.get(
            "https://jira.example/rest/dev-status/1.0/issue/detail"
            "?issueId=10001&applicationType=GitLab&dataType=repository"
        ) as response:
            assert response.status == 200
            response.raise_for_status()
            return await response.json()

    assert asyncio.run(read_detail()) == {
        "detail": [
            {
                "repositories": [
                    {
                        "url": "https://gitlab.example/group/pkg",
                        "commits": [{"url": "https://gitlab.example/group/pkg/-/commit/1"}],
                    }
                ]
            }
        ]
    }
