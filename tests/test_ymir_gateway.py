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

from ymir_harness.jira_replay import write_jira_search_fixture
from ymir_harness.ymir_gateway import (
    _install_optional_gateway_shims,
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
            response.raise_for_status()
            return await response.json()

    assert asyncio.run(read_remote_links()) == [
        {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
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
            response.raise_for_status()
            return await response.json()

    assert asyncio.run(search()) == expected_response


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
