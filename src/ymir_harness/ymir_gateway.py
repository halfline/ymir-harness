from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from types import ModuleType
from typing import Any

from ymir_harness.enforcement import enforce_benchmark_boundaries
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
            if isinstance(url, str) and (match_data := self.remote_link_get_regex.fullmatch(url)):
                yield flexmock_factory(
                    raise_for_status=lambda: None,
                    json=partial(
                        read_jira_mock,
                        issue_key=match_data.group(1),
                        remote_link=True,
                    ),
                )
                return

            async with super().get(*args, **kwargs) as response:
                yield response

    jira_module.aiohttpClientSession = HarnessAiohttpClientSessionMock


if __name__ == "__main__":
    main()
