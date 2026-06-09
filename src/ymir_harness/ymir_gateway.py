from __future__ import annotations

import os
import json
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs, urlparse

from ymir_harness.enforcement import enforce_benchmark_boundaries
from ymir_harness.jira_replay import (
    jira_issue_replay_miss,
    jira_search_replay_miss,
    load_jira_search_response,
)
from ymir_harness.ymir_source import ensure_ymir_source_path


def main() -> None:
    ensure_ymir_source_path()
    _install_optional_gateway_shims()
    from ymir.tools.privileged.gateway import main as gateway_main  # type: ignore[import-not-found]

    _patch_ymir_jira_mock_remote_links()
    with enforce_benchmark_boundaries(os.environ):
        gateway_main()


def _install_optional_gateway_shims() -> None:
    try:
        __import__("requests_gssapi")
        return
    except ImportError:
        pass

    module = ModuleType("requests_gssapi")

    class HTTPSPNEGOAuth:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError(
                "requests-gssapi is not installed; Errata tools are unavailable in "
                "turnkey ymir-harness runs"
            )

    module.HTTPSPNEGOAuth = HTTPSPNEGOAuth
    sys.modules["requests_gssapi"] = module


def _patch_ymir_jira_mock_remote_links() -> None:
    if os.getenv("MOCK_JIRA", "False").lower() != "true":
        return

    try:
        from ymir.tools.privileged import aiohttp_client_session_mock as mock_module
        from ymir.tools.privileged import jira as jira_module
    except ImportError:
        return

    base_session = getattr(mock_module, "aiohttpClientSessionMock", None)
    read_jira_mock = getattr(mock_module, "_read_jira_mock", None)
    flexmock_factory = getattr(mock_module, "flexmock", None)
    if base_session is None or read_jira_mock is None or flexmock_factory is None:
        return

    class HarnessAiohttpClientSessionMock(base_session):  # type: ignore[misc, valid-type]
        @asynccontextmanager
        async def get(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            url = args[0] if args else None
            issue_get_regex = getattr(self, "issue_get_regex", None)
            if (
                isinstance(url, str)
                and issue_get_regex is not None
                and (match_data := issue_get_regex.fullmatch(url))
            ):
                issue_key = match_data.group(1)
                yield flexmock_factory(
                    raise_for_status=lambda: None,
                    json=partial(
                        _read_jira_mock_with_miss,
                        read_jira_mock,
                        url,
                        issue_key,
                        remote_link=False,
                    ),
                )
                return
            if isinstance(url, str) and (match_data := self.remote_link_get_regex.fullmatch(url)):
                issue_key = match_data.group(1)
                yield flexmock_factory(
                    raise_for_status=lambda: None,
                    json=partial(
                        _read_jira_mock_with_miss,
                        read_jira_mock,
                        url,
                        issue_key,
                        remote_link=True,
                    ),
                )
                return
            if isinstance(url, str) and "/rest/dev-status/1.0/issue/summary" in url:
                query = parse_qs(urlparse(url).query)
                issue_id = (query.get("issueId") or [""])[0]
                yield flexmock_factory(
                    raise_for_status=lambda: None,
                    json=partial(_jira_dev_status_summary, issue_id),
                )
                return
            if isinstance(url, str) and "/rest/dev-status/1.0/issue/detail" in url:
                query = parse_qs(urlparse(url).query)
                issue_id = (query.get("issueId") or [""])[0]
                app_type = (query.get("applicationType") or [""])[0]
                data_type = (query.get("dataType") or [""])[0]
                yield flexmock_factory(
                    raise_for_status=lambda: None,
                    json=partial(_jira_dev_status_detail, issue_id, app_type, data_type),
                )
                return

            async with super().get(*args, **kwargs) as response:
                yield response

        @asynccontextmanager
        async def post(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            url = args[0] if args else None
            if isinstance(url, str) and self.search_post_regex.fullmatch(url):
                payload = kwargs.get("json") or {}
                response = _jira_search_response(url, payload)
                yield flexmock_factory(
                    raise_for_status=lambda: None,
                    json=partial(_async_payload, response),
                )
                return

            async with super().post(*args, **kwargs) as response:
                yield response

    jira_module.aiohttpClientSession = HarnessAiohttpClientSessionMock


def _jira_search_response(url: str, payload: Mapping[str, Any] | dict[str, Any]) -> dict[str, Any]:
    cases_dir = os.getenv("YMIR_BENCHMARK_CASES_DIR")
    case_id = os.getenv("YMIR_BENCHMARK_CASE_ID")
    if cases_dir and case_id:
        cached = load_jira_search_response(Path(cases_dir), case_id, payload)
        if cached is not None:
            return cached

    print(jira_search_replay_miss(url, payload), file=sys.stderr)
    return {"issues": []}


async def _jira_dev_status_summary(issue_id: str) -> dict[str, Any]:
    issue = await _mock_jira_issue_by_id(issue_id)
    if issue is None:
        return {"summary": {}}
    dev_status = issue.get("dev_status")
    if not isinstance(dev_status, dict):
        return {"summary": {}}
    summary = dev_status.get("summary")
    return {"summary": summary if isinstance(summary, dict) else {}}


async def _jira_dev_status_detail(
    issue_id: str,
    app_type: str,
    data_type: str,
) -> dict[str, Any]:
    issue = await _mock_jira_issue_by_id(issue_id)
    if issue is None:
        return {"detail": []}
    dev_status = issue.get("dev_status")
    if not isinstance(dev_status, dict):
        return {"detail": []}
    details = dev_status.get("details")
    if not isinstance(details, dict):
        return {"detail": []}
    key = f"{app_type}:{data_type}"
    detail = details.get(key, details.get(data_type, []))
    return {"detail": detail if isinstance(detail, list) else []}


async def _mock_jira_issue_by_id(issue_id: str) -> dict[str, Any] | None:
    for issue in await _all_mock_jira_issues():
        if str(issue.get("id") or "") == issue_id:
            return issue
    return None


async def _all_mock_jira_issues() -> list[dict[str, Any]]:
    root = os.getenv("JIRA_MOCK_FILES")
    if not root:
        return []
    issues = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file():
            continue
        try:
            data = json.loads(Path(entry.path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            issues.append(data)
    return issues


async def _async_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return payload


async def _read_jira_mock_with_miss(
    read_jira_mock: Any,
    url: str,
    issue_key: str,
    *,
    remote_link: bool,
) -> Any:
    try:
        return await read_jira_mock(issue_key=issue_key, remote_link=remote_link)
    except Exception:
        print(jira_issue_replay_miss(url, issue_key), file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
