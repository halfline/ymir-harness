from __future__ import annotations

import os
import json
import re
import shutil
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs, urlparse

from ymir_harness.enforcement import enforce_benchmark_boundaries
from ymir_harness.replay import ReplayCacheError
from ymir_harness.jira_replay import (
    jira_issue_replay_miss,
    jira_search_replay_miss,
    load_jira_search_response,
)
from ymir_harness.ymir_source import ensure_ymir_source_path


def main() -> None:
    ensure_ymir_source_path()
    _install_optional_gateway_shims()
    _patch_no_write_gateway_tools()
    from ymir.tools.privileged.gateway import main as gateway_main  # type: ignore[import-not-found]

    _patch_ymir_jira_mock_remote_links()
    with enforce_benchmark_boundaries(os.environ):
        gateway_main()


def _patch_no_write_gateway_tools() -> None:
    if os.getenv("DRY_RUN", "False").lower() != "true":
        return

    try:
        from beeai_framework.context import RunContext
        from beeai_framework.emitter import Emitter
        from beeai_framework.tools import StringToolOutput, ToolError, ToolRunOptions
        from pydantic import BaseModel, Field
        from ymir.tools.base import CloneableTool as Tool
        from ymir.tools.privileged import distgit as distgit_module
        from ymir.tools.privileged import gitlab as gitlab_module
        from ymir.tools.privileged import lookaside as lookaside_module
        from ymir.tools.privileged import copr as copr_module
        from ymir_harness.replay import ReplayCache, ReplayCacheError
    except ImportError:
        return

    class HarnessCreateZstreamBranchToolInput(BaseModel):
        package: str = Field(description="Package name")
        branch: str = Field(description="Name of the branch to create")

    class HarnessCreateZstreamBranchTool(
        Tool[HarnessCreateZstreamBranchToolInput, ToolRunOptions, StringToolOutput]
    ):
        name = "create_zstream_branch"
        description = "Replays Z-Stream branch creation without mutating dist-git."
        input_schema = HarnessCreateZstreamBranchToolInput

        def _create_emitter(self) -> Emitter:
            return Emitter.root().child(
                namespace=["tool", "distgit", self.name],
                creator=self,
            )

        async def _run(
            self,
            tool_input: HarnessCreateZstreamBranchToolInput,
            options: ToolRunOptions | None,
            context: RunContext,
        ) -> StringToolOutput:
            del options, context
            return StringToolOutput(
                result=(f"Z-Stream branch {tool_input.branch} already exists, no need to create it")
            )

    class HarnessLookasideToolInput(BaseModel):
        dist_git_path: Path = Field(description="Absolute path to cloned dist-git repository")
        package: str = Field(description="Package name")
        dist_git_branch: str = Field(description="dist-git branch")

    class HarnessDownloadSourcesTool(
        Tool[HarnessLookasideToolInput, ToolRunOptions, StringToolOutput]
    ):
        name = "download_sources"
        description = "Replays lookaside source download without Kerberos or rhpkg."
        input_schema = HarnessLookasideToolInput

        def _create_emitter(self) -> Emitter:
            return Emitter.root().child(
                namespace=["tool", "lookaside", self.name],
                creator=self,
            )

        async def _run(
            self,
            tool_input: HarnessLookasideToolInput,
            options: ToolRunOptions | None,
            context: RunContext,
        ) -> StringToolOutput:
            del options, context
            try:
                copied = _copy_replay_lookaside_sources(tool_input.dist_git_path)
            except ReplayCacheError as exc:
                raise ToolError(f"Failed to download sources from replay cache: {exc}") from exc
            detail = f" ({copied} file(s))" if copied else ""
            return StringToolOutput(
                result=f"Successfully downloaded sources from replay cache{detail}"
            )

    class HarnessPrepSourcesTool(Tool[HarnessLookasideToolInput, ToolRunOptions, StringToolOutput]):
        name = "prep_sources"
        description = "Replays source prep without Kerberos or rhpkg."
        input_schema = HarnessLookasideToolInput

        def _create_emitter(self) -> Emitter:
            return Emitter.root().child(
                namespace=["tool", "lookaside", self.name],
                creator=self,
            )

        async def _run(
            self,
            tool_input: HarnessLookasideToolInput,
            options: ToolRunOptions | None,
            context: RunContext,
        ) -> StringToolOutput:
            del tool_input, options, context
            return StringToolOutput(result="Successfully prepped sources from replay cache")

    class HarnessGetPatchFromUrlToolInput(BaseModel):
        patch_url: str = Field(description="URL to a patch or diff file")

    class HarnessGetPatchFromUrlTool(
        Tool[HarnessGetPatchFromUrlToolInput, ToolRunOptions, StringToolOutput]
    ):
        name = "get_patch_from_url"
        description = "Replays patch fetches from the harness web cache."
        input_schema = HarnessGetPatchFromUrlToolInput

        def _create_emitter(self) -> Emitter:
            return Emitter.root().child(
                namespace=["tool", "gitlab", self.name],
                creator=self,
            )

        async def _run(
            self,
            tool_input: HarnessGetPatchFromUrlToolInput,
            options: ToolRunOptions | None,
            context: RunContext,
        ) -> StringToolOutput:
            del options, context
            try:
                cache = ReplayCache.from_environment(os.environ)
                body = cache.read_bytes(tool_input.patch_url)
            except ReplayCacheError as exc:
                raise ToolError(
                    f"Failed to fetch patch from {tool_input.patch_url}: {exc}"
                ) from exc
            return StringToolOutput(result=body.decode("utf-8", errors="replace"))

    class HarnessForkRepositoryTool(
        Tool[gitlab_module.ForkRepositoryToolInput, ToolRunOptions, StringToolOutput]
    ):
        name = "fork_repository"
        description = "Replays GitLab fork creation without GitLab API writes."
        input_schema = gitlab_module.ForkRepositoryToolInput

        def _create_emitter(self) -> Emitter:
            return Emitter.root().child(
                namespace=["tool", "gitlab", self.name],
                creator=self,
            )

        async def _run(
            self,
            tool_input: gitlab_module.ForkRepositoryToolInput,
            options: ToolRunOptions | None,
            context: RunContext,
        ) -> StringToolOutput:
            del options, context
            fork_namespace = os.getenv("FORK_NAMESPACE", "ymir-harness")
            repository = tool_input.repository.rstrip("/")
            name = repository.rsplit("/", 1)[-1].removesuffix(".git")
            return StringToolOutput(result=f"https://gitlab.com/{fork_namespace}/{name}.git")

    class HarnessBuildPackageTool(
        Tool[
            copr_module.BuildPackageToolInput,
            ToolRunOptions,
            copr_module.BuildPackageToolOutput,
        ]
    ):
        name = "build_package"
        description = "Replays package build submission without Copr."
        input_schema = copr_module.BuildPackageToolInput

        def _create_emitter(self) -> Emitter:
            return Emitter.root().child(
                namespace=["tool", "copr", self.name],
                creator=self,
            )

        async def _run(
            self,
            tool_input: copr_module.BuildPackageToolInput,
            options: ToolRunOptions | None,
            context: RunContext,
        ) -> copr_module.BuildPackageToolOutput:
            del options, context
            if not tool_input.srpm_path.is_file():
                raise ToolError(f"SRPM does not exist: {tool_input.srpm_path}")
            artifact_url = (
                "ymir-harness://build/"
                f"{tool_input.jira_issue}/{tool_input.dist_git_branch}/"
                f"{tool_input.srpm_path.name}"
            )
            return copr_module.BuildPackageToolOutput(
                result=copr_module.BuildResult(
                    success=True,
                    artifacts_urls=[artifact_url],
                )
            )

    distgit_module.CreateZstreamBranchTool = HarnessCreateZstreamBranchTool
    copr_module.BuildPackageTool = HarnessBuildPackageTool
    gitlab_module.ForkRepositoryTool = HarnessForkRepositoryTool
    gitlab_module.GetPatchFromUrlTool = HarnessGetPatchFromUrlTool
    lookaside_module.DownloadSourcesTool = HarnessDownloadSourcesTool
    lookaside_module.PrepSourcesTool = HarnessPrepSourcesTool


def _copy_replay_lookaside_sources(dist_git_path: Path) -> int:
    source_cache = os.environ.get("YMIR_BENCHMARK_SOURCE_CACHE_DIR")
    if not source_cache:
        raise ReplayCacheError("YMIR_BENCHMARK_SOURCE_CACHE_DIR is not set")

    lookaside_dir = Path(source_cache) / "lookaside"
    if not lookaside_dir.is_dir():
        raise ReplayCacheError(f"lookaside source cache is missing: {lookaside_dir}")

    sources_file = dist_git_path / "sources"
    source_names = _sources_file_names(sources_file)
    copied = 0
    for source_name in source_names:
        source = lookaside_dir / source_name
        if not source.is_file():
            raise ReplayCacheError(
                f"{source_name} was not available in the lookaside cache"
            )
        destination = dist_git_path / source.name
        if destination.exists():
            continue
        shutil.copy2(source, destination)
        copied += 1
    if copied == 0 and not any(child.is_file() for child in lookaside_dir.iterdir()):
        raise ReplayCacheError(f"lookaside source cache is empty: {lookaside_dir}")
    return copied


def _sources_file_names(path: Path) -> tuple[str, ...]:
    if not path.is_file():
        return ()
    names: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name = _parse_sources_file_name(line)
        if name:
            names.append(name)
    return tuple(dict.fromkeys(names))


def _parse_sources_file_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    modern = re.fullmatch(r"[A-Za-z0-9_+.-]+\s+\(([^)]+)\)\s+=\s*[0-9A-Fa-f]+", stripped)
    if modern is not None:
        return modern.group(1).strip()
    tagged = re.fullmatch(r"[A-Za-z0-9_+.-]+\(([^)]+)\)\s*=\s*[0-9A-Fa-f]+", stripped)
    if tagged is not None:
        return tagged.group(1).strip()
    legacy = stripped.split()
    if len(legacy) >= 2 and re.fullmatch(r"[0-9A-Fa-f]+", legacy[0]):
        return legacy[-1].strip()
    return None


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
