from __future__ import annotations

import base64
import configparser
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from ymir_harness.jira_replay import (
    JiraReplayMiss,
    derive_as_of,
    filter_comments_as_of,
    filter_dev_status_as_of,
    filter_search_response_as_of,
    jira_search_fixture_path,
    parse_jira_replay_misses,
    write_jira_dev_status_fixture,
    write_jira_search_fixture,
)
from ymir_harness.koji_replay import (
    KOJI_CANDIDATE_BUILDS_MANIFEST_KEY,
    candidate_build_key,
    fetch_candidate_build,
)
from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.replay import canonicalize_replay_url, subprocess_command_key
from ymir_harness.scoring import load_json_file
from ymir_harness.source_fixtures import (
    git_refs,
    git_symbolic_ref,
    is_git_worktree,
    source_fixture_name,
    write_source_fixture_from_repository,
)


DEFAULT_ALLOWED_HOSTS = (
    "gitlab.com",
    "gitlab.gnome.org",
    "github.com",
    "issues.redhat.com",
    "metacpan.org",
    "pkgs.devel.redhat.com",
    "redhat.atlassian.net",
    "sources.stream.centos.org",
    "src.fedoraproject.org",
)
MISSING_URL_PATTERNS = (
    (
        "replay miss",
        re.compile(
            r"replay miss:\s*"
            r"(?:URL is not (?:recorded|available) in replay cache:\s*)?"
            r"(https?://[^\s\"'<>]+)"
        ),
    ),
    (
        "unrecorded replay URL blocked",
        re.compile(r"unrecorded replay URL blocked:\s*(https?://[^\s\"'<>]+)"),
    ),
    (
        "external subprocess URL blocked",
        re.compile(r"external subprocess URL blocked:\s*(https?://[^\s\"'<>]+)"),
    ),
    (
        "external network access blocked",
        re.compile(r"external network access blocked:\s*(https?://[^\s\"'<>]+)"),
    ),
    (
        "tool HTTP 404",
        re.compile(r"Failed to fetch patch from\s+(https?://[^\s\"'<>]+):\s*HTTP 404"),
    ),
    (
        "tool replay miss",
        re.compile(
            r"Failed to fetch patch from\s+(https?://[^\s\"'<>]+):\s*"
            r"URL is not (?:recorded|available) in replay cache"
        ),
    ),
    ("unrecorded URL", re.compile(r"unrecorded URL:\s*(https?://[^\s\"'<>]+)")),
)
MISSING_LOOKASIDE_PATTERN = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._+-]*"
    r"(?:\.tar(?:\.[A-Za-z0-9]+)?|\.tgz|\.tbz2|\.txz|\.zip)) "
    r"(?:(?:tarball|archive|source|file)\s+)?"
    r"(?:was\s+)?not\s+(?:found|available)\s+in\s+(?:the\s+)?lookaside cache"
)
LOOKASIDE_CACHE_MISS_PATTERN = re.compile(r"lookaside source cache is missing:\s*([^\s\"')]+)")
LOOKASIDE_TOOL_INPUT_PATTERN = re.compile(
    r"HarnessLookasideToolInput\("
    r"dist_git_path=PosixPath\('(?P<clone_path>[^']+)'\),\s*"
    r"package='(?P<package>[^']+)',\s*"
    r"dist_git_branch='(?P<branch>[^']+)'\)"
)
KOJI_CANDIDATE_BUILD_MISS_PATTERN = re.compile(
    r"Koji candidate build replay miss:\s*"
    r"package=(?P<package>[A-Za-z0-9._+-]+)\s+"
    r"dist_git_branch=(?P<branch>[A-Za-z0-9._+-]+)"
)
TEXT_SUFFIXES = {".json", ".log", ".md", ".out", ".txt"}


class CaptureMissingError(RuntimeError):
    """Raised when missing replay evidence cannot be captured."""


@dataclass(frozen=True)
class BlockedUrl:
    reason: str
    url: str

    def to_replay_violation(self) -> str:
        return f"{self.reason}: {self.url}"


@dataclass(frozen=True)
class CaptureMissingRequest:
    cases_dir: Path
    run_path: Path
    case_id: str
    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS
    gitlab_token_env: str = "GITLAB_TOKEN"
    jira_token_env: str = "JIRA_TOKEN"
    jira_token_file: Path | None = None
    jira_email: str | None = None
    as_of: str | None = None
    http_timeout: float = 30.0
    dry_run: bool = False
    overwrite: bool = False


@dataclass(frozen=True)
class CapturedResponse:
    url: str
    relative_path: str
    status: int

    def to_json(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "relative_path": self.relative_path,
            "status": self.status,
        }


@dataclass(frozen=True)
class CapturedJiraRequest:
    kind: str
    method: str
    url: str
    relative_path: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "method": self.method,
            "url": self.url,
            "relative_path": self.relative_path,
        }


@dataclass(frozen=True)
class CapturedSource:
    kind: str
    url: str
    relative_path: str

    def to_json(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "url": self.url,
            "relative_path": self.relative_path,
        }


@dataclass(frozen=True)
class LookasideSourceReplayMiss:
    filename: str
    url: str


@dataclass(frozen=True)
class CapturedGitFailure:
    url: str
    returncode: int
    stderr: str

    def to_json(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "returncode": self.returncode,
            "stderr": self.stderr,
        }


@dataclass(frozen=True)
class CapturedSubprocess:
    command: str
    returncode: int

    def to_json(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
        }


@dataclass(frozen=True)
class CapturedKojiCandidateBuild:
    package: str
    dist_git_branch: str
    key: str
    relative_path: str

    def to_json(self) -> dict[str, str]:
        return {
            "package": self.package,
            "dist_git_branch": self.dist_git_branch,
            "key": self.key,
            "relative_path": self.relative_path,
        }


@dataclass(frozen=True)
class _LookasideSource:
    filename: str
    algorithm: str
    checksum: str


@dataclass(frozen=True)
class _MissingLookasideSource:
    filename: str
    package: str
    branch: str
    url: str
    source: _LookasideSource


@dataclass(frozen=True)
class _LookasideCacheMiss:
    package: str
    branch: str
    clone_path: Path


@dataclass(frozen=True)
class _MissingKojiCandidateBuild:
    package: str
    dist_git_branch: str

    @property
    def key(self) -> str:
        return candidate_build_key(self.package, self.dist_git_branch)

    @property
    def display_url(self) -> str:
        return f"koji-candidate-build:{self.key}"


@dataclass(frozen=True)
class CaptureFailure:
    url: str
    reason: str

    def to_json(self) -> dict[str, str]:
        return {"url": self.url, "reason": self.reason}


@dataclass
class CaptureMissingResult:
    case_id: str
    cases_dir: Path
    run_path: Path
    candidate_urls: list[str] = field(default_factory=list)
    candidate_jira_requests: list[dict[str, Any]] = field(default_factory=list)
    captured: list[CapturedResponse] = field(default_factory=list)
    captured_jira: list[CapturedJiraRequest] = field(default_factory=list)
    captured_source: list[CapturedSource] = field(default_factory=list)
    captured_git_failures: list[CapturedGitFailure] = field(default_factory=list)
    captured_subprocesses: list[CapturedSubprocess] = field(default_factory=list)
    captured_koji_candidate_builds: list[CapturedKojiCandidateBuild] = field(default_factory=list)
    skipped: list[CaptureFailure] = field(default_factory=list)
    failed: list[CaptureFailure] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "cases_dir": str(self.cases_dir),
            "run_path": str(self.run_path),
            "candidate_urls": self.candidate_urls,
            "candidate_jira_requests": self.candidate_jira_requests,
            "captured": [capture.to_json() for capture in self.captured],
            "captured_jira": [capture.to_json() for capture in self.captured_jira],
            "captured_source": [capture.to_json() for capture in self.captured_source],
            "captured_git_failures": [capture.to_json() for capture in self.captured_git_failures],
            "captured_subprocesses": [capture.to_json() for capture in self.captured_subprocesses],
            "captured_koji_candidate_builds": [
                capture.to_json() for capture in self.captured_koji_candidate_builds
            ],
            "skipped": [skip.to_json() for skip in self.skipped],
            "failed": [failure.to_json() for failure in self.failed],
        }


@dataclass(frozen=True)
class _FetchedResponse:
    body: bytes
    status: int
    headers: Mapping[str, str]
    capture_error: str | None = None


@dataclass(frozen=True)
class _CapturedCommand:
    returncode: int
    stdout: str
    stderr: str


def capture_missing(request: CaptureMissingRequest) -> CaptureMissingResult:
    cases_dir = request.cases_dir.resolve()
    run_path = request.run_path.resolve()
    result = CaptureMissingResult(
        case_id=request.case_id,
        cases_dir=cases_dir,
        run_path=run_path,
    )
    blocked_urls = blocked_urls_from_run_path(run_path)
    urls = list(dict.fromkeys(blocked.url for blocked in blocked_urls))
    url_reasons = _blocked_url_reasons(blocked_urls)
    result.candidate_urls.extend(urls)
    jira_requests = _blocked_jira_requests_from_run_path(run_path)
    result.candidate_jira_requests.extend(miss.to_json() for miss in jira_requests)

    manifest_path = cases_dir / "web_cache" / request.case_id / "manifest.json"
    manifest = _load_or_create_manifest(cases_dir, request.case_id, manifest_path)
    required_urls = _manifest_list(manifest.get("required_urls"))
    recorded_files = _manifest_mapping(manifest.get("recorded_files"))
    response_metadata = _manifest_mapping(manifest.get("response_metadata"))
    git_failures = _manifest_mapping(manifest.get("git_failures"))
    subprocess_replays = _manifest_raw_mapping(manifest.get("subprocess_replays"))
    koji_candidate_builds = manifest.setdefault(KOJI_CANDIDATE_BUILDS_MANIFEST_KEY, {})
    if not isinstance(koji_candidate_builds, dict):
        koji_candidate_builds = None
    git_discovery_commands = _git_discovery_commands_from_run_path(run_path, urls)
    git_command_urls = _git_command_urls(git_discovery_commands)
    non_discovery_git_command_urls = _non_discovery_git_command_urls_from_run_path(run_path, urls)
    as_of = request.as_of or derive_as_of(cases_dir, request.case_id)
    captured_source_remotes: set[str] = set()

    for command in git_discovery_commands:
        command_key = subprocess_command_key(command)
        command_urls = _command_urls(command)
        if command_key in subprocess_replays and not request.overwrite:
            for url in command_urls:
                result.skipped.append(
                    CaptureFailure(url=url, reason="subprocess command is already recorded")
                )
            continue
        denied_url = next(
            (url for url in command_urls if not _allowed_url(url, request.allowed_hosts)),
            None,
        )
        if denied_url is not None:
            result.skipped.append(CaptureFailure(url=denied_url, reason="host is not allowed"))
            continue
        if request.dry_run:
            continue
        try:
            captured = _capture_git_discovery_command(command, request, as_of=as_of)
        except CaptureMissingError as exc:
            for url in command_urls:
                result.failed.append(CaptureFailure(url=url, reason=str(exc)))
            continue
        subprocess_replays[command_key] = {
            "returncode": captured.returncode,
            "stdout": captured.stdout,
            "stderr": captured.stderr,
        }
        result.captured_subprocesses.append(
            CapturedSubprocess(command=command, returncode=captured.returncode)
        )

    for url in urls:
        reasons = url_reasons.get(url, ())
        project_url = _git_source_project_url(url)
        should_capture_source = project_url is not None and (
            "external subprocess URL blocked" in reasons or "replay miss" in reasons
        )
        if (
            should_capture_source
            and url in git_command_urls
            and url not in non_discovery_git_command_urls
        ):
            result.skipped.append(CaptureFailure(url=url, reason="subprocess command is recorded"))
            continue
        if should_capture_source and project_url is not None:
            if not _allowed_url(project_url, request.allowed_hosts):
                result.skipped.append(CaptureFailure(url=url, reason="host is not allowed"))
                continue
            remote_url = _git_clone_url(project_url)
            if remote_url in captured_source_remotes:
                result.skipped.append(
                    CaptureFailure(url=url, reason="source repo is already captured")
                )
                if "external subprocess URL blocked" in reasons:
                    continue
                should_capture_source = False
            if not should_capture_source:
                continue
            if _git_failure_is_recorded(git_failures, url) and not request.overwrite:
                result.skipped.append(
                    CaptureFailure(url=url, reason="git failure is already recorded")
                )
                continue
            if request.dry_run:
                continue
            try:
                captured = _capture_git_source_repo(project_url, cases_dir, request, as_of=as_of)
            except CaptureMissingError as exc:
                captured_failure = _record_git_failure(git_failures, url, project_url, str(exc))
                result.captured_git_failures.append(captured_failure)
                continue
            if captured is None:
                result.skipped.append(
                    CaptureFailure(url=url, reason="source repo is already recorded")
                )
            else:
                _clear_git_failure(git_failures, url, project_url)
                result.captured_source.append(captured)
                captured_source_remotes.add(remote_url)
            if "external subprocess URL blocked" in reasons:
                continue

        if not _allowed_url(url, request.allowed_hosts):
            result.skipped.append(CaptureFailure(url=url, reason="host is not allowed"))
            continue
        if url in recorded_files and not request.overwrite:
            result.skipped.append(CaptureFailure(url=url, reason="URL is already recorded"))
            continue
        if request.dry_run:
            continue

        try:
            fetched = _fetch_url(url, request, record_errors=True)
        except OSError as exc:
            result.failed.append(CaptureFailure(url=url, reason=str(exc)))
            continue
        if url in recorded_files and fetched.status >= 400:
            result.skipped.append(
                CaptureFailure(url=url, reason="URL is already recorded with successful content")
            )
            continue

        relative_path = _relative_capture_path(url)
        destination = manifest_path.parent / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(fetched.body)

        recorded_files[url] = relative_path
        response_metadata[url] = _response_metadata(fetched)
        if url not in required_urls:
            required_urls.append(url)
        result.captured.append(
            CapturedResponse(url=url, relative_path=relative_path, status=fetched.status)
        )

    for miss in jira_requests:
        if miss.kind == "jira_issue":
            if miss.method != "GET":
                result.skipped.append(
                    CaptureFailure(url=miss.url, reason=f"unsupported Jira method {miss.method}")
                )
                continue
            if not _allowed_url(miss.url, request.allowed_hosts):
                result.skipped.append(CaptureFailure(url=miss.url, reason="host is not allowed"))
                continue
            issue_key = _jira_issue_key_from_miss(miss)
            if issue_key is None:
                result.skipped.append(CaptureFailure(url=miss.url, reason="Jira issue key missing"))
                continue
            jira_dir = _jira_fixture_dir(cases_dir, request.case_id, issue_key)
            if (jira_dir / "issue.json").is_file() and not request.overwrite:
                result.skipped.append(
                    CaptureFailure(url=miss.url, reason="Jira issue is already recorded")
                )
                continue
            if request.dry_run:
                continue
            captured_dir = _capture_jira_issue_fixture(
                miss.url,
                issue_key,
                cases_dir,
                request.case_id,
                as_of,
                request,
                result,
            )
            if captured_dir is not None:
                result.captured_jira.append(
                    CapturedJiraRequest(
                        kind=miss.kind,
                        method=miss.method,
                        url=miss.url,
                        relative_path=str(
                            (captured_dir / "issue.json").relative_to(
                                cases_dir / "jiras" / request.case_id
                            )
                        ),
                    )
                )
            continue

        if miss.kind != "jira_search":
            result.skipped.append(
                CaptureFailure(url=miss.url, reason=f"unsupported Jira miss {miss.kind}")
            )
            continue
        if miss.method != "POST":
            result.skipped.append(
                CaptureFailure(url=miss.url, reason=f"unsupported Jira method {miss.method}")
            )
            continue
        if not _allowed_url(miss.url, request.allowed_hosts):
            result.skipped.append(CaptureFailure(url=miss.url, reason="host is not allowed"))
            continue
        search_path = jira_search_fixture_path(cases_dir, request.case_id, miss.payload)
        if search_path.is_file() and not request.overwrite:
            try:
                existing = load_json_file(search_path)
            except (OSError, json.JSONDecodeError):
                existing = {}
            if existing.get("response"):
                result.skipped.append(
                    CaptureFailure(url=miss.url, reason="Jira search is already recorded")
                )
                continue
        if request.dry_run:
            continue

        try:
            fetched = _post_json(miss.url, miss.payload, request)
            response = _json_object_from_body(fetched.body, miss.url)
        except (OSError, CaptureMissingError) as exc:
            result.failed.append(CaptureFailure(url=miss.url, reason=str(exc)))
            continue
        issue_details = _fetch_search_issue_details(
            miss.url,
            response,
            request,
            result,
            as_of=as_of,
            jql=str(miss.payload.get("jql") or ""),
        )
        filtered_response = filter_search_response_as_of(
            response,
            as_of=as_of,
            issue_details=issue_details,
            jql=str(miss.payload.get("jql") or ""),
        )
        _capture_related_jira_from_search(
            miss.url,
            filtered_response,
            cases_dir,
            request.case_id,
            as_of,
            request,
            result,
        )
        path = write_jira_search_fixture(
            cases_dir,
            request.case_id,
            url=miss.url,
            payload=miss.payload,
            response=filtered_response,
            as_of=as_of,
            overwrite=True,
        )
        result.captured_jira.append(
            CapturedJiraRequest(
                kind=miss.kind,
                method=miss.method,
                url=miss.url,
                relative_path=str(path.relative_to(cases_dir / "jiras" / request.case_id)),
            )
        )

    _capture_missing_koji_candidate_builds(
        request,
        result,
        manifest_path=manifest_path,
        records=koji_candidate_builds,
        as_of=as_of,
    )

    _capture_missing_lookaside_sources(cases_dir, request, result)

    manifest_changed = bool(
        result.captured
        or result.captured_source
        or result.captured_git_failures
        or result.captured_subprocesses
        or result.captured_koji_candidate_builds
    )
    if not request.dry_run and manifest_changed:
        manifest["required_urls"] = required_urls
        manifest["recorded_files"] = recorded_files
        manifest["response_metadata"] = response_metadata
        if koji_candidate_builds is not None:
            manifest[KOJI_CANDIDATE_BUILDS_MANIFEST_KEY] = koji_candidate_builds
        if git_failures:
            manifest["git_failures"] = git_failures
        else:
            manifest.pop("git_failures", None)
        if subprocess_replays:
            manifest["subprocess_replays"] = subprocess_replays
        else:
            manifest.pop("subprocess_replays", None)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return result


def _blocked_urls_from_run_path(run_path: Path) -> list[str]:
    return list(dict.fromkeys(blocked.url for blocked in blocked_urls_from_run_path(run_path)))


def _blocked_url_reasons(blocked_urls: Sequence[BlockedUrl]) -> dict[str, tuple[str, ...]]:
    reasons: dict[str, list[str]] = {}
    for blocked in blocked_urls:
        reasons.setdefault(blocked.url, []).append(blocked.reason)
    return {url: tuple(dict.fromkeys(url_reasons)) for url, url_reasons in reasons.items()}


def _blocked_jira_requests_from_run_path(run_path: Path) -> list[JiraReplayMiss]:
    return list(
        {
            json.dumps(miss.to_json(), sort_keys=True): miss
            for miss in jira_requests_from_run_path(run_path)
        }.values()
    )


def _capture_missing_koji_candidate_builds(
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
    *,
    manifest_path: Path,
    records: dict[str, Any] | None,
    as_of: str | None,
) -> None:
    misses = _missing_koji_candidate_builds_from_run_path(request.run_path)
    if not misses:
        return
    if records is None:
        for miss in misses:
            result.failed.append(
                CaptureFailure(
                    url=miss.display_url,
                    reason=f"{KOJI_CANDIDATE_BUILDS_MANIFEST_KEY} is not an object",
                )
            )
        return

    for miss in misses:
        if miss.key in records and not request.overwrite:
            result.skipped.append(
                CaptureFailure(
                    url=miss.display_url, reason="Koji candidate build is already recorded"
                )
            )
            continue
        if request.dry_run:
            continue
        try:
            records[miss.key] = fetch_candidate_build(
                miss.package,
                miss.dist_git_branch,
                as_of=as_of,
                timeout=request.http_timeout,
            )
        except Exception as exc:
            result.failed.append(CaptureFailure(url=miss.display_url, reason=str(exc)))
            continue
        result.captured_koji_candidate_builds.append(
            CapturedKojiCandidateBuild(
                package=miss.package,
                dist_git_branch=miss.dist_git_branch,
                key=miss.key,
                relative_path=str(manifest_path.relative_to(request.cases_dir.resolve())),
            )
        )


def _missing_koji_candidate_builds_from_run_path(
    run_path: Path,
) -> tuple[_MissingKojiCandidateBuild, ...]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(path for path in run_path.rglob("*") if _looks_like_text_artifact(path))
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    misses: list[_MissingKojiCandidateBuild] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in KOJI_CANDIDATE_BUILD_MISS_PATTERN.finditer(text):
            misses.append(
                _MissingKojiCandidateBuild(
                    package=match.group("package"),
                    dist_git_branch=match.group("branch"),
                )
            )
    return tuple({miss.key: miss for miss in misses}.values())


def _git_discovery_commands_from_run_path(
    run_path: Path,
    urls: Sequence[str],
) -> list[str]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(path for path in run_path.rglob("*") if _looks_like_text_artifact(path))
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    target_urls = set(urls)
    commands: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for command in _json_command_strings(text):
            command_urls = set(_command_urls(command))
            if not command_urls or not command_urls & target_urls:
                continue
            if not _git_ls_remote_invocations(command):
                continue
            commands.append(command)
    return list(dict.fromkeys(commands))


def _non_discovery_git_command_urls_from_run_path(
    run_path: Path,
    urls: Sequence[str],
) -> set[str]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(path for path in run_path.rglob("*") if _looks_like_text_artifact(path))
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    target_urls = set(urls)
    output: set[str] = set()
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for command in _json_command_strings(text):
            command_urls = set(_command_urls(command))
            matched_urls = command_urls & target_urls
            if not matched_urls:
                continue
            if _is_non_discovery_git_subprocess_command(command):
                output.update(matched_urls)
    return output


def _json_command_strings(text: str) -> list[str]:
    commands: list[str] = []
    for match in re.finditer(r'"command"\s*:\s*"((?:\\.|[^"\\])*)"', text):
        try:
            command = json.loads(f'"{match.group(1)}"')
        except json.JSONDecodeError:
            continue
        if isinstance(command, str) and command.strip():
            commands.append(command)
    return commands


def _git_command_urls(commands: Sequence[str]) -> set[str]:
    return {url for command in commands for url in _command_urls(command)}


def _command_urls(command: str) -> tuple[str, ...]:
    urls = []
    for match in re.finditer(r"https?://[^\s\"'<>]+", command):
        url = _clean_url(match.group(0))
        if url:
            urls.append(url)
    return tuple(dict.fromkeys(urls))


def _capture_git_discovery_command(
    command: str,
    request: CaptureMissingRequest,
    *,
    as_of: str | None,
) -> _CapturedCommand:
    invocations = _git_ls_remote_invocations(command)
    if not invocations:
        raise CaptureMissingError("unsupported git discovery command")
    completions = (
        _run_git_ls_remote(url, line_limit, request, as_of=as_of) for url, line_limit in invocations
    )
    completed = tuple(completions)
    if not completed:
        raise CaptureMissingError("unsupported git discovery command")
    return _CapturedCommand(
        returncode=completed[-1].returncode,
        stdout="".join(item.stdout for item in completed),
        stderr="".join(item.stderr for item in completed),
    )


def _run_git_ls_remote(
    url: str,
    line_limit: int | None,
    request: CaptureMissingRequest,
    *,
    as_of: str | None,
) -> _CapturedCommand:
    if as_of is not None:
        return _run_git_ls_remote_as_of(url, line_limit, request, as_of)

    completed = subprocess.run(
        ["git", "ls-remote", url],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=request.http_timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return _CapturedCommand(
        returncode=completed.returncode,
        stdout=_limit_lines(completed.stdout, line_limit),
        stderr=_limit_lines(completed.stderr, line_limit),
    )


def _run_git_ls_remote_as_of(
    url: str,
    line_limit: int | None,
    request: CaptureMissingRequest,
    as_of: str,
) -> _CapturedCommand:
    with tempfile.TemporaryDirectory(prefix="ymir-harness-ls-remote-") as tmp:
        mirror = Path(tmp) / _git_source_cache_name(url)
        _run_git(["clone", "--mirror", "--quiet", url, str(mirror)], Path(tmp))
        refs = git_refs(mirror, as_of=as_of)
        refs_by_name = dict(refs)
        lines = []
        head_ref = git_symbolic_ref(mirror, "HEAD")
        if head_ref is not None and head_ref in refs_by_name:
            lines.append(f"{refs_by_name[head_ref]}\tHEAD\n")
        lines.extend(f"{object_name}\t{ref_name}\n" for ref_name, object_name in refs)
    return _CapturedCommand(
        returncode=0,
        stdout=_limit_lines("".join(lines), line_limit),
        stderr="",
    )


def _git_ls_remote_invocations(command: str) -> tuple[tuple[str, int | None], ...]:
    invocations: list[tuple[str, int | None]] = []
    for chunk in _shell_command_chunks(command):
        url = _git_ls_remote_url(chunk)
        if url is not None:
            invocations.append((url, _head_line_limit(chunk)))
    return tuple(invocations)


def _is_non_discovery_git_subprocess_command(command: str) -> bool:
    for chunk in _shell_command_chunks(command):
        if _git_ls_remote_url(chunk) is not None:
            continue
        tokens = _command_tokens(chunk)
        for segment in _shell_command_segments(tokens):
            command_tokens = _tokens_after_env(segment)
            if command_tokens and Path(command_tokens[0]).name == "git":
                return True
    return False


def _git_ls_remote_url(command: str) -> str | None:
    tokens = _command_tokens(command)
    for segment in _shell_command_segments(tokens):
        command_tokens = _tokens_after_env(segment)
        if not command_tokens or Path(command_tokens[0]).name != "git":
            continue
        subcommand_index = _git_subcommand_index(command_tokens)
        if subcommand_index is None or command_tokens[subcommand_index] != "ls-remote":
            continue
        return _git_ls_remote_remote_arg(command_tokens[subcommand_index + 1 :])
    return None


def _git_subcommand_index(tokens: Sequence[str]) -> int | None:
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
            index += 2
            continue
        if any(
            token.startswith(f"{option}=")
            for option in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
        ):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return index
    return None


def _git_ls_remote_remote_arg(tokens: Sequence[str]) -> str | None:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"|", "&&", "||", ";"}:
            return None
        if token == "--":
            index += 1
            continue
        if token in {"--upload-pack", "--server-option", "-o"}:
            index += 2
            continue
        if token.startswith(("--upload-pack=", "--server-option=")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        url = _clean_url(token)
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return url
        return None
    return None


def _strip_shell_comment_lines(command: str) -> str:
    return "\n".join(line for line in command.splitlines() if not line.lstrip().startswith("#"))


def _shell_command_chunks(command: str) -> tuple[str, ...]:
    return tuple(
        chunk.strip()
        for chunk in re.split(r"[;\n]+", _strip_shell_comment_lines(command))
        if chunk.strip()
    )


def _command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _shell_command_segments(tokens: Sequence[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in {"&&", "||", ";", "|"}:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _tokens_after_env(tokens: Sequence[str]) -> list[str]:
    output = list(tokens)
    if output and Path(output[0]).name == "env":
        output = output[1:]
        while output and output[0].startswith("-"):
            option = output.pop(0)
            if option in {"-i", "--ignore-environment", "-0", "--null"}:
                continue
            if option in {"-u", "--unset"} and output:
                output.pop(0)
                continue
            if option.startswith(("-u=", "--unset=")):
                continue
            break
    while output and _is_env_assignment(output[0]):
        output.pop(0)
    return output


def _is_env_assignment(token: str) -> bool:
    name, separator, _value = token.partition("=")
    if not separator or not name:
        return False
    return all(char == "_" or char.isalnum() for char in name)


def _head_line_limit(command: str) -> int | None:
    match = re.search(r"(?:^|\|)\s*head(?:\s+-n)?\s+-(\d+)\b", command)
    if match:
        return int(match.group(1))
    match = re.search(r"(?:^|\|)\s*head\s+(\d+)\b", command)
    if match:
        return int(match.group(1))
    return None


def _limit_lines(value: str, limit: int | None) -> str:
    if limit is None:
        return value
    lines = value.splitlines(keepends=True)
    return "".join(lines[:limit])


def jira_requests_from_run_path(run_path: Path) -> list[JiraReplayMiss]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(path for path in run_path.rglob("*") if _looks_like_text_artifact(path))
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    misses: list[JiraReplayMiss] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        misses.extend(parse_jira_replay_misses(text))
    return misses


def lookaside_source_requests_from_run_path(
    run_path: Path,
    case_id: str,
) -> list[LookasideSourceReplayMiss]:
    return [
        LookasideSourceReplayMiss(filename=missing.filename, url=missing.url)
        for missing in _missing_lookaside_sources_from_run_path(run_path, case_id)
    ]


def blocked_urls_from_run_path(run_path: Path) -> list[BlockedUrl]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(
            path
            for path in run_path.rglob("*")
            if _looks_like_text_artifact(path) and not _is_worker_case_view_artifact(run_path, path)
        )
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    blocked_urls: list[BlockedUrl] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for reason, pattern in MISSING_URL_PATTERNS:
            for match in pattern.finditer(text):
                url = _clean_url(match.group(1))
                if url:
                    blocked_urls.append(BlockedUrl(reason=reason, url=url))
    return list({blocked.to_replay_violation(): blocked for blocked in blocked_urls}.values())


def _looks_like_text_artifact(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in TEXT_SUFFIXES


def _is_worker_case_view_artifact(root: Path, path: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return False
    for index in range(len(relative_parts) - 1):
        if relative_parts[index : index + 2] == ("workflow-worker", "cases-view"):
            return True
    return False


def _clean_url(url: str) -> str:
    return canonicalize_replay_url(url)


def _load_or_create_manifest(
    cases_dir: Path,
    case_id: str,
    manifest_path: Path,
) -> dict[str, Any]:
    if manifest_path.is_file():
        return load_json_file(manifest_path)

    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected = load_json_file(expected_path) if expected_path.is_file() else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "case_type": expected.get("case_type"),
        "required_urls": [],
        "recorded_files": {},
    }


def _manifest_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        canonical for item in value if isinstance(item, str) and (canonical := _clean_url(item))
    ]


def _manifest_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {
        canonical: item
        for key, item in value.items()
        if isinstance(key, str) and (canonical := _clean_url(key))
    }


def _manifest_raw_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str) and key}


def _allowed_url(url: str, allowed_hosts: Sequence[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return False
    hostname = parsed.hostname.lower()
    return any(
        hostname == allowed.lower() or hostname.endswith(f".{allowed.lower()}")
        for allowed in allowed_hosts
    )


def _fetch_url(
    url: str,
    request: CaptureMissingRequest,
    *,
    record_errors: bool = False,
) -> _FetchedResponse:
    http_request = Request(url, headers=_headers_for_url(url, request), method="GET")
    try:
        with urlopen(http_request, timeout=request.http_timeout) as response:
            body = response.read()
            status = getattr(response, "status", None) or getattr(response, "code", 200)
            headers = _selected_headers(dict(response.headers.items()))
    except HTTPError as exc:
        body = exc.read()
        status = exc.code
        headers = _selected_headers(dict(exc.headers.items()))
    except OSError as exc:
        if not record_errors:
            raise
        return _transport_error_response(url, exc)
    return _FetchedResponse(body=body, status=int(status), headers=headers)


def _transport_error_response(url: str, exc: OSError) -> _FetchedResponse:
    reason = f"{type(exc).__name__}: {exc}".rstrip(": ")
    body = (f"ymir-harness captured fetch error\nurl: {url}\nerror: {reason}\n").encode("utf-8")
    return _FetchedResponse(
        body=body,
        status=599,
        headers={"Content-Type": "text/plain"},
        capture_error=reason,
    )


def _post_json(
    url: str,
    payload: Mapping[str, Any],
    request: CaptureMissingRequest,
) -> _FetchedResponse:
    body = json.dumps(payload).encode("utf-8")
    headers = _headers_for_url(url, request)
    headers["Content-Type"] = "application/json"
    http_request = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(http_request, timeout=request.http_timeout) as response:
            response_body = response.read()
            status = getattr(response, "status", None) or getattr(response, "code", 200)
            response_headers = _selected_headers(dict(response.headers.items()))
    except HTTPError as exc:
        response_body = exc.read()
        status = exc.code
        response_headers = _selected_headers(dict(exc.headers.items()))
    return _FetchedResponse(body=response_body, status=int(status), headers=response_headers)


def _json_object_from_body(body: bytes, url: str) -> dict[str, Any]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureMissingError(f"failed to decode JSON response from {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise CaptureMissingError(f"JSON response from {url} must be an object")
    return data


def _fetch_search_issue_details(
    search_url: str,
    response: Mapping[str, Any],
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
    *,
    as_of: str | None,
    jql: str,
) -> dict[str, Mapping[str, Any]]:
    details = {}
    issues = response.get("issues")
    if not isinstance(issues, list):
        return details
    needs_historical_detail = as_of is not None

    for issue in issues:
        if not isinstance(issue, Mapping):
            continue
        key = issue.get("key")
        if not isinstance(key, str) or not key:
            continue
        if not needs_historical_detail and _has_field(issue, "created"):
            continue
        url = (
            _jira_issue_with_changelog_url(search_url, key)
            if needs_historical_detail
            else _jira_issue_detail_url(search_url, key)
        )
        try:
            fetched = _fetch_url(url, request)
            detail = _json_object_from_body(fetched.body, url)
        except (OSError, CaptureMissingError) as exc:
            result.failed.append(CaptureFailure(url=url, reason=str(exc)))
            continue
        details[key] = detail
    return details


def _capture_related_jira_from_search(
    search_url: str,
    response: Mapping[str, Any],
    cases_dir: Path,
    case_id: str,
    as_of: str | None,
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
) -> None:
    issues = response.get("issues")
    if not isinstance(issues, list):
        return

    for issue in issues:
        if not isinstance(issue, Mapping):
            continue
        issue_key = issue.get("key")
        if not isinstance(issue_key, str) or not issue_key:
            continue
        _capture_jira_issue_fixture(
            search_url,
            issue_key,
            cases_dir,
            case_id,
            as_of,
            request,
            result,
        )


def _capture_jira_issue_fixture(
    source_url: str,
    issue_key: str,
    cases_dir: Path,
    case_id: str,
    as_of: str | None,
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
) -> Path | None:
    jira_dir = _jira_fixture_dir(cases_dir, case_id, issue_key)
    if (jira_dir / "issue.json").is_file() and not request.overwrite:
        return None

    issue_url = _jira_issue_url(source_url, issue_key)
    issue_fetch_url = _jira_issue_with_changelog_url(source_url, issue_key)
    try:
        issue_payload = _json_object_from_body(
            _fetch_url(issue_fetch_url, request).body,
            issue_fetch_url,
        )
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=issue_fetch_url, reason=str(exc)))
        return None

    comments_url = f"{issue_url}/comment"
    links_url = f"{issue_url}/remotelink"
    try:
        comments_payload = _json_object_from_body(
            _fetch_url(comments_url, request).body,
            comments_url,
        )
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=comments_url, reason=str(exc)))
        comments_payload = {"comments": []}
    try:
        links_payload = _json_value_from_body(_fetch_url(links_url, request).body, links_url)
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=links_url, reason=str(exc)))
        links_payload = []

    filtered_comments = filter_comments_as_of(comments_payload, as_of=as_of)
    _write_json(jira_dir / "issue.json", issue_payload, overwrite=request.overwrite)
    _write_json(jira_dir / "comments.json", filtered_comments, overwrite=request.overwrite)
    _write_json(
        jira_dir / "links.json",
        {"schema_version": SCHEMA_VERSION, "case_id": issue_key, "links": links_payload},
        overwrite=request.overwrite,
    )
    _write_linked_starting_issue(
        jira_dir,
        issue_key,
        issue_payload,
        filtered_comments,
        as_of,
        overwrite=request.overwrite,
    )
    _capture_dev_status(
        source_url,
        cases_dir,
        case_id,
        issue_key,
        issue_payload,
        as_of,
        request,
        result,
    )
    return jira_dir


def _jira_fixture_dir(cases_dir: Path, case_id: str, issue_key: str) -> Path:
    if issue_key == case_id:
        return cases_dir / "jiras" / case_id
    return cases_dir / "jiras" / case_id / "linked" / issue_key


def _jira_issue_key_from_miss(miss: JiraReplayMiss) -> str | None:
    issue_key = miss.payload.get("issue_key")
    if isinstance(issue_key, str) and issue_key:
        return issue_key
    match = re.search(r"/issue/([A-Z][A-Z0-9]+-\d+)(?:/|$)", miss.url)
    return match.group(1) if match else None


def _write_linked_starting_issue(
    jira_dir: Path,
    issue_key: str,
    issue_payload: Mapping[str, Any],
    comments_payload: Mapping[str, Any],
    as_of: str | None,
    *,
    overwrite: bool,
) -> None:
    from ymir_harness.collect_case import _build_starting_jira_issue

    starting = _build_starting_jira_issue(
        issue_payload,
        comments_payload,
        case_id=issue_key,
        case_type=None,
        as_of=as_of,
    )
    _write_json(jira_dir / "starting-issue.json", starting, overwrite=overwrite)
    if as_of is not None:
        _write_json(
            jira_dir / "reconstruction.json",
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": issue_key,
                "as_of": as_of,
                "method": "captured_from_search_result",
            },
            overwrite=overwrite,
        )


def _capture_dev_status(
    search_url: str,
    cases_dir: Path,
    case_id: str,
    issue_key: str,
    issue_payload: Mapping[str, Any],
    as_of: str | None,
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
) -> None:
    issue_id = issue_payload.get("id")
    if not isinstance(issue_id, str) or not issue_id:
        return
    summary_url = _jira_dev_status_summary_url(search_url, issue_id)
    try:
        summary_payload = _json_object_from_body(_fetch_url(summary_url, request).body, summary_url)
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=summary_url, reason=str(exc)))
        return

    summary = summary_payload.get("summary")
    if not isinstance(summary, Mapping):
        summary = {}
    details: dict[str, Any] = {}
    repository_summary = summary.get("repository")
    by_instance = (
        repository_summary.get("byInstanceType")
        if isinstance(repository_summary, Mapping)
        else None
    )
    if isinstance(by_instance, Mapping):
        for app_type in by_instance:
            if not isinstance(app_type, str) or not app_type:
                continue
            detail_url = _jira_dev_status_detail_url(
                search_url,
                issue_id,
                application_type=app_type,
                data_type="repository",
            )
            try:
                detail_payload = _json_object_from_body(
                    _fetch_url(detail_url, request).body, detail_url
                )
            except (OSError, CaptureMissingError) as exc:
                result.failed.append(CaptureFailure(url=detail_url, reason=str(exc)))
                continue
            detail = detail_payload.get("detail")
            if isinstance(detail, list):
                details[f"{app_type}:repository"] = detail

    filtered_summary, filtered_details = filter_dev_status_as_of(
        summary,
        details,
        as_of=as_of,
    )
    write_jira_dev_status_fixture(
        cases_dir,
        case_id,
        issue_key,
        summary=filtered_summary,
        details=filtered_details,
        as_of=as_of,
        overwrite=request.overwrite,
    )


def _has_field(issue: Mapping[str, Any], field: str) -> bool:
    fields = issue.get("fields")
    return isinstance(fields, Mapping) and fields.get(field) is not None


def _jira_issue_url(search_url: str, issue_key: str) -> str:
    parsed = urlparse(search_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return f"{origin}/rest/api/2/issue/{quote(issue_key)}"


def _jira_issue_with_changelog_url(search_url: str, issue_key: str) -> str:
    return f"{_jira_issue_url(search_url, issue_key)}?expand=changelog"


def _jira_issue_detail_url(search_url: str, issue_key: str) -> str:
    return f"{_jira_issue_url(search_url, issue_key).replace('/rest/api/2/', '/rest/api/3/')}?fields=created,updated"


def _jira_dev_status_summary_url(search_url: str, issue_id: str) -> str:
    parsed = urlparse(search_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return f"{origin}/rest/dev-status/1.0/issue/summary?issueId={quote(issue_id)}"


def _jira_dev_status_detail_url(
    search_url: str,
    issue_id: str,
    *,
    application_type: str,
    data_type: str,
) -> str:
    parsed = urlparse(search_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return (
        f"{origin}/rest/dev-status/1.0/issue/detail?issueId={quote(issue_id)}"
        f"&applicationType={quote(application_type)}&dataType={quote(data_type)}"
    )


def _json_value_from_body(body: bytes, url: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureMissingError(f"failed to decode JSON response from {url}: {exc}") from exc


def _write_json(path: Path, data: object, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _headers_for_url(url: str, request: CaptureMissingRequest) -> dict[str, str]:
    headers = {"Accept": "*/*"}
    hostname = (urlparse(url).hostname or "").lower()
    if "gitlab" in hostname:
        token = os.environ.get(request.gitlab_token_env)
        if token:
            headers["PRIVATE-TOKEN"] = token
    if "jira" in hostname or "atlassian" in hostname:
        token = _jira_token(request)
        if token:
            headers["Authorization"] = _jira_authorization(token, request.jira_email)
            headers["Accept"] = "application/json"
    return headers


def _jira_token(request: CaptureMissingRequest) -> str | None:
    if request.jira_token_file is not None:
        try:
            return request.jira_token_file.expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            return None
    token = os.environ.get(request.jira_token_env)
    return token.strip() if token else None


def _jira_authorization(token: str, email: str | None) -> str:
    lowered = token.lower()
    if lowered.startswith("bearer ") or lowered.startswith("basic "):
        return token
    basic_email = email or os.environ.get("JIRA_EMAIL") or os.environ.get("ATLASSIAN_EMAIL")
    if basic_email:
        raw = f"{basic_email}:{token}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")
    return f"Bearer {token}"


def _selected_headers(headers: Mapping[str, str]) -> dict[str, str]:
    output = {}
    for name, value in headers.items():
        if name.lower() == "content-type":
            output["Content-Type"] = value
    return output


def _response_metadata(fetched: _FetchedResponse) -> dict[str, Any]:
    metadata: dict[str, Any] = {"status": fetched.status}
    if fetched.headers:
        metadata["headers"] = dict(fetched.headers)
    if fetched.capture_error:
        metadata["capture_error"] = fetched.capture_error
    return metadata


def _relative_capture_path(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown-host"
    suffix = _path_suffix(parsed.path)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return f"captured/{host}/{digest}{suffix}"


def _capture_missing_lookaside_sources(
    cases_dir: Path,
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
) -> None:
    if request.dry_run:
        return
    for missing in _missing_lookaside_sources_from_run_path(request.run_path, request.case_id):
        if not _allowed_url(missing.url, request.allowed_hosts):
            result.skipped.append(CaptureFailure(url=missing.url, reason="host is not allowed"))
            continue
        destination = cases_dir / "source_cache" / request.case_id / "lookaside" / missing.filename
        if destination.is_file() and not request.overwrite:
            result.skipped.append(
                CaptureFailure(url=missing.url, reason="lookaside source is already recorded")
            )
            continue
        try:
            body = _fetch_lookaside_source(missing, timeout=request.http_timeout)
        except CaptureMissingError as exc:
            result.failed.append(CaptureFailure(url=missing.url, reason=str(exc)))
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        result.captured_source.append(
            CapturedSource(
                kind="lookaside",
                url=missing.url,
                relative_path=str(destination.relative_to(cases_dir)),
            )
        )


def _missing_lookaside_sources_from_run_path(
    run_path: Path,
    case_id: str,
) -> tuple[_MissingLookasideSource, ...]:
    candidates: list[_MissingLookasideSource] = []
    seen: set[tuple[str, str]] = set()

    def add_candidate(
        *,
        filename: str,
        package: str,
        branch: str,
        url: str,
        source: _LookasideSource,
    ) -> None:
        key = (filename, url)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            _MissingLookasideSource(
                filename=filename,
                package=package,
                branch=branch,
                url=url,
                source=source,
            )
        )

    for actual_path in sorted(run_path.glob("repeat-*/actual-results/*.actual.json")):
        try:
            actual = load_json_file(actual_path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        filenames = _missing_lookaside_filenames(actual)
        if not filenames:
            continue
        package = _string_value(actual.get("package"))
        branch = _string_value(actual.get("target_branch"))
        if package is None or branch is None:
            continue
        base_url = _lookaside_base_url(branch)
        if base_url is None:
            continue
        for local_clone in _actual_local_clones(actual, run_path, case_id):
            entries = _lookaside_entries_for_missing(local_clone, filenames)
            for filename in filenames:
                source = entries.get(filename)
                if source is None:
                    continue
                url = _lookaside_source_url(base_url, package, source)
                add_candidate(
                    filename=filename,
                    package=package,
                    branch=branch,
                    url=url,
                    source=source,
                )

    for miss in _lookaside_cache_misses_from_run_path(run_path, case_id):
        base_url = _lookaside_base_url(miss.branch)
        if base_url is None:
            continue
        for source in _sources_file_entries(miss.clone_path / "sources"):
            url = _lookaside_source_url(base_url, miss.package, source)
            add_candidate(
                filename=source.filename,
                package=miss.package,
                branch=miss.branch,
                url=url,
                source=source,
            )
    return tuple(candidates)


def _lookaside_cache_misses_from_run_path(
    run_path: Path,
    case_id: str,
) -> tuple[_LookasideCacheMiss, ...]:
    candidates: list[_LookasideCacheMiss] = []
    seen: set[tuple[str, str, Path]] = set()
    for path in _run_text_artifacts(run_path):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if LOOKASIDE_CACHE_MISS_PATTERN.search(text) is None:
            continue
        for match in LOOKASIDE_TOOL_INPUT_PATTERN.finditer(text):
            clone_path = _host_run_path(Path(match.group("clone_path")), run_path)
            package = match.group("package")
            branch = match.group("branch")
            clone_paths = (
                (clone_path,)
                if clone_path.is_dir()
                else _mock_repo_lookaside_clone_paths(run_path, case_id, package)
            )
            for candidate_path in clone_paths:
                key = (package, branch, candidate_path)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    _LookasideCacheMiss(package=package, branch=branch, clone_path=candidate_path)
                )
    return tuple(candidates)


def _mock_repo_lookaside_clone_paths(
    run_path: Path,
    case_id: str,
    package: str,
) -> tuple[Path, ...]:
    return tuple(
        source_path.parent
        for source_path in sorted(run_path.glob(f"repeat-*/mock-repos/{case_id}/*/sources"))
        if _mock_repo_dir_matches_package(source_path.parent, package)
    )


def _mock_repo_dir_matches_package(path: Path, package: str) -> bool:
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in package)
    return path.name == safe or path.name.endswith(f"-{safe}")


def _run_text_artifacts(run_path: Path) -> tuple[Path, ...]:
    if run_path.is_file():
        return (run_path,) if _looks_like_text_artifact(run_path) else ()
    if not run_path.is_dir():
        return ()
    return tuple(
        sorted(
            path
            for path in run_path.rglob("*")
            if _looks_like_text_artifact(path) and not _is_worker_case_view_artifact(run_path, path)
        )
    )


def _host_run_path(path: Path, run_path: Path) -> Path:
    if path.is_absolute():
        try:
            return run_path / path.relative_to("/ymir-harness-results")
        except ValueError:
            return path
    return run_path / path


def _lookaside_entries_for_missing(
    local_clone: Path, filenames: Sequence[str]
) -> dict[str, _LookasideSource]:
    entries = {entry.filename: entry for entry in _sources_file_entries(local_clone / "sources")}
    missing = [filename for filename in filenames if filename not in entries]
    if missing:
        entries.update(_sources_file_entries_from_distgit_patches(local_clone, missing))
    return entries


def _sources_file_entries_from_distgit_patches(
    local_clone: Path, filenames: Sequence[str]
) -> dict[str, _LookasideSource]:
    needed = set(filenames)
    entries: dict[str, _LookasideSource] = {}
    for patch_path in sorted((*local_clone.glob("*.patch"), *local_clone.glob("*.diff"))):
        try:
            lines = patch_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.startswith("+") or line.startswith("+++"):
                continue
            entry = _parse_sources_file_line(line[1:])
            if entry is not None and entry.filename in needed:
                entries[entry.filename] = entry
    return entries


def _missing_lookaside_filenames(actual: Mapping[str, Any]) -> tuple[str, ...]:
    texts = []
    for name in ("backport_error", "backport_status", "error", "status"):
        value = actual.get(name)
        if isinstance(value, str):
            texts.append(value)
    data = actual.get("data")
    if isinstance(data, Mapping):
        for name in ("error", "status"):
            value = data.get(name)
            if isinstance(value, str):
                texts.append(value)
    filenames: list[str] = []
    for text in texts:
        filenames.extend(MISSING_LOOKASIDE_PATTERN.findall(text))
    return tuple(dict.fromkeys(filenames))


def _actual_local_clones(
    actual: Mapping[str, Any], run_path: Path, case_id: str
) -> tuple[Path, ...]:
    paths: list[Path] = []
    manifest_path = _string_value(actual.get("artifact_manifest"))
    if manifest_path is not None:
        try:
            manifest = load_json_file(Path(manifest_path))
        except (OSError, json.JSONDecodeError, ValueError):
            manifest = {}
        source_paths = manifest.get("source_paths")
        if isinstance(source_paths, Mapping):
            local_clone = _string_value(source_paths.get("local_clone"))
            if local_clone is not None:
                paths.append(Path(local_clone))
    if not paths:
        paths.extend(path.parent for path in sorted((run_path / case_id).glob("*/sources")))
    return tuple(dict.fromkeys(path for path in paths if path.is_dir()))


def _fetch_lookaside_source(missing: _MissingLookasideSource, *, timeout: float) -> bytes:
    request = Request(missing.url, headers={"User-Agent": "ymir-harness"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read()
    except OSError as exc:
        raise CaptureMissingError(str(exc)) from exc
    if not _lookaside_checksum_matches(body, missing.source):
        raise CaptureMissingError(f"lookaside checksum mismatch for {missing.filename}")
    return body


def _sources_file_entries(path: Path) -> tuple[_LookasideSource, ...]:
    if not path.is_file():
        return ()
    entries = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = _parse_sources_file_line(line)
        if entry is not None:
            entries.append(entry)
    return tuple({entry.filename: entry for entry in entries}.values())


def _parse_sources_file_line(line: str) -> _LookasideSource | None:
    line = line.strip()
    if not line:
        return None
    modern = re.fullmatch(r"([A-Za-z0-9_+.-]+)\s+\(([^)]+)\)\s+=\s*([0-9A-Fa-f]+)", line)
    if modern is not None:
        return _LookasideSource(
            filename=modern.group(2).strip(),
            algorithm=modern.group(1).strip(),
            checksum=modern.group(3).strip(),
        )
    tagged = re.fullmatch(
        r"([A-Za-z0-9_+.-]+)\s*\(([^)]+)\)\s*=\s*([0-9A-Fa-f]+)",
        line,
    )
    if tagged is not None:
        return _LookasideSource(
            filename=tagged.group(2).strip(),
            algorithm=tagged.group(1).strip(),
            checksum=tagged.group(3).strip(),
        )
    legacy = line.split()
    if len(legacy) >= 2 and re.fullmatch(r"[0-9A-Fa-f]+", legacy[0]):
        algorithm = "sha512" if len(legacy[0]) == 128 else "md5"
        return _LookasideSource(
            filename=legacy[-1].strip(),
            algorithm=algorithm,
            checksum=legacy[0].strip(),
        )
    return None


def _lookaside_base_url(branch: str) -> str | None:
    tool = "centpkg" if _is_cs_branch(branch) else "rhpkg"
    config_path = Path("/etc/rpkg") / f"{tool}.conf"
    if not config_path.is_file():
        return None
    parser = configparser.ConfigParser()
    parser.read(config_path)
    try:
        return parser[tool]["lookaside"].rstrip("/")
    except KeyError:
        return None


def _lookaside_source_url(
    base_url: str,
    package: str,
    source: _LookasideSource,
) -> str:
    filename = quote(source.filename, safe="")
    package_path = quote(package, safe="")
    checksum = quote(source.checksum, safe="")
    algorithm = quote(source.algorithm.lower(), safe="")
    return f"{base_url}/rpms/{package_path}/{filename}/{algorithm}/{checksum}/{filename}"


def _lookaside_checksum_matches(body: bytes, source: _LookasideSource) -> bool:
    try:
        digest = hashlib.new(source.algorithm.lower())
    except ValueError:
        return False
    digest.update(body)
    return digest.hexdigest().lower() == source.checksum.lower()


def _is_cs_branch(branch: str) -> bool:
    return re.fullmatch(r"c\d+s", branch) is not None


def _string_value(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _capture_git_source_repo(
    project_url: str,
    cases_dir: Path,
    request: CaptureMissingRequest,
    *,
    as_of: str | None,
) -> CapturedSource | None:
    remote_url = _git_clone_url(project_url)
    fixture_path = (
        cases_dir
        / "source_cache"
        / request.case_id
        / "upstream"
        / f"{source_fixture_name(remote_url)}.json"
    )
    if fixture_path.exists() and not request.overwrite:
        return None

    if not is_git_worktree(cases_dir):
        raise CaptureMissingError(f"cases directory is not a git worktree: {cases_dir}")

    with tempfile.TemporaryDirectory(prefix="ymir-harness-source-fixture-") as tmp:
        mirror = Path(tmp) / _git_source_cache_name(remote_url)
        _run_git(["clone", "--mirror", "--quiet", remote_url, str(mirror)], Path(tmp))
        manifest_path = write_source_fixture_from_repository(
            cases_dir,
            request.case_id,
            mirror,
            remote_url=remote_url,
            as_of=as_of,
            overwrite=request.overwrite,
        )
    return CapturedSource(
        kind="source_fixture",
        url=project_url,
        relative_path=str(manifest_path.relative_to(cases_dir)),
    )


def _record_git_failure(
    git_failures: dict[str, Any],
    url: str,
    project_url: str,
    reason: str,
) -> CapturedGitFailure:
    stderr = reason if reason.endswith("\n") else f"{reason}\n"
    failure = {
        "returncode": 128,
        "stdout": "",
        "stderr": stderr,
    }
    for alias in _git_failure_aliases(url, project_url):
        git_failures[alias] = failure
    return CapturedGitFailure(url=url, returncode=128, stderr=stderr)


def _clear_git_failure(git_failures: dict[str, Any], url: str, project_url: str) -> None:
    for alias in _git_failure_aliases(url, project_url):
        git_failures.pop(alias, None)


def _git_failure_is_recorded(git_failures: Mapping[str, Any], url: str) -> bool:
    return any(alias in git_failures for alias in _git_failure_aliases(url, url))


def _git_failure_aliases(url: str, project_url: str) -> tuple[str, ...]:
    aliases: list[str] = []
    for value in (url, project_url, _git_clone_url(project_url)):
        canonical = canonicalize_replay_url(value)
        if not canonical:
            continue
        aliases.append(canonical)
        if canonical.endswith(".git"):
            aliases.append(canonical.removesuffix(".git"))
        else:
            aliases.append(f"{canonical}.git")
    return tuple(dict.fromkeys(aliases))


def _git_source_project_url(url: str) -> str | None:
    parsed = urlparse(canonicalize_replay_url(url))
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.query or parsed.fragment:
        return None

    hostname = parsed.hostname.lower()
    path = parsed.path.strip("/").removesuffix(".git")
    parts = [part for part in path.split("/") if part]
    if hostname == "github.com" and len(parts) == 2:
        return f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts)}"
    if hostname in {"gitlab.com", "gitlab.gnome.org"} or (
        hostname.startswith("gitlab.") and url.endswith(".git")
    ):
        if len(parts) < 2 or parts[0] == "api" or "/-/" in f"/{path}/":
            return None
        return f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts)}"
    if (
        hostname == "src.fedoraproject.org"
        and len(parts) == 2
        and parts[0]
        in {
            "modules",
            "rpms",
        }
    ):
        return f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts)}"
    return None


def _git_clone_url(project_url: str) -> str:
    return project_url if project_url.endswith(".git") else f"{project_url}.git"


def _git_source_cache_name(remote_url: str) -> str:
    parsed = urlparse(remote_url)
    source = parsed.path.rstrip("/").rsplit("/", 1)[-1] if parsed.path else "repo"
    source = source.removesuffix(".git")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in source)
    digest = hashlib.sha256(remote_url.encode("utf-8")).hexdigest()[:12]
    return f"{safe or 'repo'}-{digest}.git"


def _run_git(command: Sequence[str], cwd: Path) -> None:
    completed = subprocess.run(
        ["git", *command],
        cwd=cwd if cwd.is_dir() else None,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode == 0:
        return
    detail = (completed.stderr or completed.stdout or "").strip()
    if detail:
        raise CaptureMissingError(f"git {' '.join(command)} failed: {detail}")
    raise CaptureMissingError(f"git {' '.join(command)} failed with exit {completed.returncode}")


def _path_suffix(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in {".diff", ".html", ".json", ".md", ".patch", ".txt"}:
        return suffix
    return ".bin"
