from __future__ import annotations

import asyncio
import builtins
import re
import sys
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

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
