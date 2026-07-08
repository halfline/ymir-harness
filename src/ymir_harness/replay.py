from __future__ import annotations

import html
import io
import json
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.response import addinfourl


class ReplayCacheError(RuntimeError):
    """Raised when replay cache data cannot satisfy a requested URL."""


def allows_empty_recorded_body(status: Any) -> bool:
    if isinstance(status, bool) or not isinstance(status, int):
        return False
    return 100 <= status < 200 or status in {202, 204, 205, 304}


class ReplayResponse:
    def __init__(
        self,
        url: str,
        body: bytes,
        *,
        headers: Mapping[str, str] | None = None,
        status: int = 200,
    ):
        self.url = url
        self.status = status
        self.status_code = status
        self.headers = dict(headers or {})
        self._body = body

    async def __aenter__(self) -> "ReplayResponse":
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        return None

    async def read(self) -> bytes:
        return self._body

    async def text(self, encoding: str = "utf-8") -> str:
        return self._body.decode(encoding)

    async def json(self) -> Any:
        return json.loads(await self.text())


@dataclass(frozen=True)
class _SourcePatchRequest:
    project_url: str
    commit: str
    output: str


@dataclass(frozen=True)
class _SourceFileRequest:
    project_url: str
    ref: str
    file_path: str


@dataclass(frozen=True)
class _SourceLogRequest:
    project_url: str
    package: str
    ref: str


@dataclass(frozen=True)
class _SourceRefsRequest:
    project_url: str
    package: str


@dataclass(frozen=True)
class _SourceGitLabBranchesRequest:
    project_identifier: str


@dataclass(frozen=True)
class _SourcePatchResponse:
    body: bytes
    status: int
    headers: Mapping[str, str]


@dataclass(frozen=True)
class GitFailureReplay:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class SubprocessReplay:
    returncode: int
    stdout: bytes
    stderr: bytes


TRAILING_ESCAPED_URL_GARBAGE_RE = re.compile(r"(?:\\+[nrt]|\\+)+$", re.IGNORECASE)


def canonicalize_replay_url(value: Any) -> str:
    url = value if isinstance(value, str) else str(value)
    url = url.strip()
    if not url:
        return url

    url = re.split(r"\\+[nrt]", url, maxsplit=1, flags=re.IGNORECASE)[0]
    split = re.split(r"[\s\"'<>]", url, maxsplit=1)
    url = split[0] if split else url
    previous = None
    while previous != url:
        previous = url
        url = url.rstrip(".,;:)]}\"'")
        url = TRAILING_ESCAPED_URL_GARBAGE_RE.sub("", url)
        url = url.strip()
    return url


def subprocess_command_key(command: Any) -> str:
    if isinstance(command, str):
        return command.strip()
    if isinstance(command, (list, tuple)):
        return json.dumps([str(part) for part in command], separators=(",", ":"))
    return str(command).strip()


class ReplayCache:
    def __init__(self, manifest_path: Path, *, source_cache_dir: Path | None = None):
        self.manifest_path = manifest_path
        self.cache_dir = manifest_path.parent
        self.source_cache_dir = source_cache_dir
        self._recorded_files = self._load_recorded_files(manifest_path)
        self._response_metadata = self._load_response_metadata(manifest_path)
        self._git_failures = self._load_git_failures(manifest_path)
        self._subprocess_replays = self._load_subprocess_replays(manifest_path)
        self._as_of = self._load_case_as_of(manifest_path)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> "ReplayCache | None":
        manifest = environment.get("YMIR_BENCHMARK_REPLAY_MANIFEST")
        if not manifest:
            return None
        source_cache_dir = environment.get("YMIR_BENCHMARK_SOURCE_CACHE_DIR")
        return cls(
            Path(manifest),
            source_cache_dir=Path(source_cache_dir) if source_cache_dir else None,
        )

    @property
    def recorded_urls(self) -> tuple[str, ...]:
        return tuple(self._recorded_files)

    def has_url(self, url: Any) -> bool:
        url = _url_text(url)
        return url in self._recorded_files or self._source_repo_for_url(url) is not None

    def git_failure_for_urls(self, urls: list[str]) -> GitFailureReplay | None:
        failures = [self._git_failure_for_url(url) for url in urls]
        if not failures or any(failure is None for failure in failures):
            return None

        replay_failures = [failure for failure in failures if failure is not None]
        return GitFailureReplay(
            returncode=next(
                (failure.returncode for failure in replay_failures if failure.returncode != 0),
                replay_failures[0].returncode,
            ),
            stdout=b"".join(failure.stdout for failure in replay_failures),
            stderr=b"".join(failure.stderr for failure in replay_failures),
        )

    def subprocess_replay_for_command(self, command: Any) -> SubprocessReplay | None:
        return self._subprocess_replays.get(subprocess_command_key(command))

    def read_bytes(self, url: Any) -> bytes:
        url = _url_text(url)
        source_response = self._source_response(url)
        if source_response is not None:
            return source_response.body

        path = self.path_for_url(url)
        try:
            body = path.read_bytes()
        except OSError as exc:
            raise ReplayCacheError(f"recorded file cannot be read for URL {url}: {path}") from exc
        return self._filter_recorded_body(url, body)

    def open_urllib_response(self, url: Any) -> addinfourl:
        url = _url_text(url)
        body = self.read_bytes(url)
        status = self.status_code(url)
        headers = self.response_headers(url, body)
        if status >= 400:
            raise HTTPError(url, status, "Recorded response", headers, io.BytesIO(body))
        response = addinfourl(
            io.BytesIO(body),
            headers=headers,
            url=url,
            code=status,
        )
        response.msg = "Recorded response"
        return response

    def open_aiohttp_response(self, url: Any) -> ReplayResponse:
        url = _url_text(url)
        body = self.read_bytes(url)
        return ReplayResponse(
            url,
            body,
            headers=self.response_headers(url, body),
            status=self.status_code(url),
        )

    def response_headers(self, url: Any, body: bytes | None = None) -> dict[str, str]:
        url = _url_text(url)
        source_response = self._source_response(url)
        if source_response is not None:
            return dict(source_response.headers)

        body = self.read_bytes(url) if body is None else body
        path = self.path_for_url(url)
        metadata = self._response_metadata.get(url, {})
        headers = metadata.get("headers") if isinstance(metadata, Mapping) else None
        output = {
            str(name): str(value)
            for name, value in (headers or {}).items()
            if isinstance(name, str) and isinstance(value, str)
        }
        output.setdefault("Content-Type", _content_type_for(path, body))
        return output

    def status_code(self, url: Any) -> int:
        url = _url_text(url)
        source_response = self._source_response(url)
        if source_response is not None:
            return source_response.status

        metadata = self._response_metadata.get(url, {})
        status = metadata.get("status") if isinstance(metadata, Mapping) else None
        if isinstance(status, int):
            return status
        return 200

    def path_for_url(self, url: Any) -> Path:
        url = _url_text(url)
        recorded = self._recorded_files.get(url)
        if recorded is None:
            raise ReplayCacheError(f"URL is not recorded in replay cache: {url}")
        path = self.cache_dir / recorded
        try:
            path.resolve(strict=False).relative_to(self.cache_dir.resolve(strict=False))
        except ValueError as exc:
            raise ReplayCacheError(f"recorded file escapes cache directory for URL {url}") from exc
        if not path.is_file():
            raise ReplayCacheError(f"recorded file is missing for URL {url}: {path}")
        if path.stat().st_size == 0 and not allows_empty_recorded_body(self.status_code(url)):
            raise ReplayCacheError(f"recorded file is empty for URL {url}: {path}")
        return path

    def _load_recorded_files(self, manifest_path: Path) -> dict[str, str]:
        manifest = self._load_manifest(manifest_path)
        recorded_files = manifest.get("recorded_files")
        if not isinstance(recorded_files, Mapping):
            raise ReplayCacheError(
                f"replay manifest recorded_files must be an object: {manifest_path}"
            )
        output = {
            canonicalize_replay_url(url): recorded
            for url, recorded in recorded_files.items()
            if isinstance(url, str)
            and canonicalize_replay_url(url)
            and isinstance(recorded, str)
            and recorded
        }
        return output

    def _filter_recorded_body(self, url: str, body: bytes) -> bytes:
        if self._as_of is None or _source_gitlab_branches_request(url) is None:
            return body
        return _filter_gitlab_branches_body_as_of(body, self._as_of)

    def _load_case_as_of(self, manifest_path: Path) -> datetime | None:
        case_id = manifest_path.parent.name
        cases_dir = manifest_path.parent.parent.parent
        reconstruction_path = cases_dir / "jiras" / case_id / "reconstruction.json"
        try:
            reconstruction = json.loads(reconstruction_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(reconstruction, Mapping):
            return None
        return _parse_replay_timestamp(reconstruction.get("as_of"))

    def _load_response_metadata(self, manifest_path: Path) -> dict[str, Mapping[str, Any]]:
        manifest = self._load_manifest(manifest_path)
        response_metadata = manifest.get("response_metadata")
        if not isinstance(response_metadata, Mapping):
            return {}
        return {
            canonicalize_replay_url(url): metadata
            for url, metadata in response_metadata.items()
            if isinstance(url, str)
            and canonicalize_replay_url(url)
            and isinstance(metadata, Mapping)
        }

    def _load_git_failures(self, manifest_path: Path) -> dict[str, GitFailureReplay]:
        manifest = self._load_manifest(manifest_path)
        git_failures = manifest.get("git_failures")
        if not isinstance(git_failures, Mapping):
            return {}

        output: dict[str, GitFailureReplay] = {}
        for url, payload in git_failures.items():
            canonical_url = canonicalize_replay_url(url) if isinstance(url, str) else ""
            if not canonical_url or not isinstance(payload, Mapping):
                continue
            returncode = payload.get("returncode")
            stdout = payload.get("stdout")
            stderr = payload.get("stderr")
            output[canonical_url] = GitFailureReplay(
                returncode=returncode if isinstance(returncode, int) else 128,
                stdout=stdout.encode("utf-8") if isinstance(stdout, str) else b"",
                stderr=stderr.encode("utf-8") if isinstance(stderr, str) else b"",
            )
        return output

    def _load_subprocess_replays(self, manifest_path: Path) -> dict[str, SubprocessReplay]:
        manifest = self._load_manifest(manifest_path)
        subprocess_replays = manifest.get("subprocess_replays")
        if not isinstance(subprocess_replays, Mapping):
            return {}

        output: dict[str, SubprocessReplay] = {}
        for command, payload in subprocess_replays.items():
            command_key = command if isinstance(command, str) else ""
            if not command_key or not isinstance(payload, Mapping):
                continue
            returncode = payload.get("returncode")
            stdout = payload.get("stdout")
            stderr = payload.get("stderr")
            output[command_key] = SubprocessReplay(
                returncode=returncode if isinstance(returncode, int) else 1,
                stdout=stdout.encode("utf-8") if isinstance(stdout, str) else b"",
                stderr=stderr.encode("utf-8") if isinstance(stderr, str) else b"",
            )
        return output

    def _load_manifest(self, manifest_path: Path) -> Mapping[str, Any]:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReplayCacheError(f"cannot read replay manifest: {manifest_path}") from exc
        if not isinstance(manifest, Mapping):
            raise ReplayCacheError(f"replay manifest must contain an object: {manifest_path}")
        return manifest

    def _git_failure_for_url(self, url: str) -> GitFailureReplay | None:
        for alias in _git_url_aliases(url):
            failure = self._git_failures.get(alias)
            if failure is not None:
                return failure
        return None

    def _source_response(self, url: str) -> _SourcePatchResponse | None:
        patch_response = self._source_patch_response(url)
        if patch_response is not None:
            return patch_response
        file_response = self._source_file_response(url)
        if file_response is not None:
            return file_response
        log_response = self._source_log_response(url)
        if log_response is not None:
            return log_response
        refs_response = self._source_refs_response(url)
        if refs_response is not None:
            return refs_response
        return self._source_gitlab_branches_response(url)

    def _source_patch_response(self, url: str) -> _SourcePatchResponse | None:
        request = _source_patch_request(url)
        if request is None:
            return None

        repo_path = self._source_repo_for_project(request.project_url)
        if repo_path is None:
            return None

        if not _git_commit_exists(repo_path, request.commit) or not _git_commit_advertised(
            repo_path, request.commit
        ):
            return _SourcePatchResponse(
                body=f"commit {request.commit} is not available in source cache\n".encode("utf-8"),
                status=404,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )

        body = (
            _git_format_patch(repo_path, request.commit)
            if request.output == "patch"
            else _git_format_diff(repo_path, request.commit)
        )
        return _SourcePatchResponse(
            body=body,
            status=200,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    def _source_file_response(self, url: str) -> _SourcePatchResponse | None:
        request = _source_file_request(url)
        if request is None:
            return None

        repo_path = self._source_repo_for_project(request.project_url)
        if repo_path is None:
            return None

        if _looks_like_git_object(request.ref) and not _git_commit_advertised(
            repo_path, request.ref
        ):
            return _SourcePatchResponse(
                body=(
                    f"{request.ref}:{request.file_path} is not available in source cache\n"
                ).encode("utf-8"),
                status=404,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )

        body = _git_show_file(repo_path, request.ref, request.file_path)
        if body is None:
            return _SourcePatchResponse(
                body=(
                    f"{request.ref}:{request.file_path} is not available in source cache\n"
                ).encode("utf-8"),
                status=404,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )
        return _SourcePatchResponse(
            body=body,
            status=200,
            headers={"Content-Type": _content_type_for(Path(request.file_path), body)},
        )

    def _source_log_response(self, url: str) -> _SourcePatchResponse | None:
        request = _source_log_request(url)
        if request is None:
            return None

        repo_path = self._source_repo_for_project(request.project_url)
        if repo_path is None:
            return None

        body = _git_cgit_log_html(repo_path, request.package, request.ref)
        if body is None:
            return _SourcePatchResponse(
                body=f"{request.ref} is not available in source cache\n".encode("utf-8"),
                status=404,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )
        return _SourcePatchResponse(
            body=body,
            status=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

    def _source_refs_response(self, url: str) -> _SourcePatchResponse | None:
        request = _source_refs_request(url)
        if request is None:
            return None

        repo_path = self._source_repo_for_project(request.project_url)
        if repo_path is None:
            return None

        return _SourcePatchResponse(
            body=_git_cgit_refs_html(repo_path, request.package),
            status=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

    def _source_gitlab_branches_response(self, url: str) -> _SourcePatchResponse | None:
        request = _source_gitlab_branches_request(url)
        if request is None:
            return None

        project_url = self._gitlab_api_project_url(request.project_identifier)
        if project_url is None:
            return None
        repo_path = self._source_repo_for_project(project_url)
        if repo_path is None:
            return None

        body = json.dumps(
            _gitlab_branch_payloads(repo_path, project_url),
            separators=(",", ":"),
        ).encode("utf-8")
        return _SourcePatchResponse(
            body=body,
            status=200,
            headers={"Content-Type": "application/json"},
        )

    def _source_repo_for_url(self, url: str) -> Path | None:
        patch_request = _source_patch_request(url)
        if patch_request is not None:
            return self._source_repo_for_project(patch_request.project_url)
        file_request = _source_file_request(url)
        if file_request is not None:
            return self._source_repo_for_project(file_request.project_url)
        log_request = _source_log_request(url)
        if log_request is not None:
            return self._source_repo_for_project(log_request.project_url)
        refs_request = _source_refs_request(url)
        if refs_request is not None:
            return self._source_repo_for_project(refs_request.project_url)
        branches_request = _source_gitlab_branches_request(url)
        if branches_request is not None:
            project_url = self._gitlab_api_project_url(branches_request.project_identifier)
            return self._source_repo_for_project(project_url) if project_url is not None else None
        return None

    def _source_repo_for_project(self, project_url: str) -> Path | None:
        if self.source_cache_dir is None:
            return None
        upstream_dir = self.source_cache_dir / "upstream"
        if not upstream_dir.is_dir():
            return None

        repositories = _source_git_repositories(upstream_dir)
        matching = [
            repository
            for repository in repositories
            if _same_or_aliased_git_project(_git_remote_url(repository), project_url)
        ]
        if matching:
            return matching[0]
        return None

    def _gitlab_api_project_url(self, project_identifier: str) -> str | None:
        decoded = unquote(project_identifier).strip("/")
        if not decoded:
            return None
        if "/" in decoded:
            return f"https://gitlab.com/{decoded}"

        for url, relative_path in self._recorded_files.items():
            parsed = urlparse(url)
            if parsed.hostname is None or parsed.hostname.lower() != "gitlab.com":
                continue
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) != 4 or parts[:3] != ["api", "v4", "projects"]:
                continue
            project = self._load_recorded_json(relative_path)
            if not isinstance(project, Mapping):
                continue
            recorded_identifier = unquote(parts[3]).strip("/")
            metadata_id = project.get("id")
            if recorded_identifier != decoded and str(metadata_id or "") != decoded:
                continue
            project_url = _gitlab_project_url_from_metadata(project)
            if project_url is not None:
                return project_url
        return None

    def _load_recorded_json(self, relative_path: str) -> Any:
        path = self.cache_dir / relative_path
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None


def _content_type_for(path: Path, body: bytes) -> str:
    stripped = body.lstrip()
    if stripped.startswith((b"{", b"[")):
        return "application/json"
    if path.suffix.lower() in {".diff", ".md", ".patch", ".txt"}:
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def _url_text(url: Any) -> str:
    return canonicalize_replay_url(url)


def _source_patch_request(url: Any) -> _SourcePatchRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None

    cgit_request = _cgit_source_patch_request(parsed)
    if cgit_request is not None:
        return cgit_request

    markers = ("/-/commit/", "/commit/")
    marker = next((candidate for candidate in markers if candidate in parsed.path), None)
    if marker is None:
        return None

    project_path, commit_part = parsed.path.split(marker, 1)
    commit = commit_part.strip("/").split("/", 1)[0].removesuffix(".patch").removesuffix(".diff")
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        return None

    suffix = Path(parsed.path).suffix.lower()
    query = parse_qs(parsed.query)
    if suffix == ".patch" or query.get("format") == [".patch"]:
        output = "patch"
    elif suffix == ".diff" or query.get("format") == [".diff"]:
        output = "diff"
    else:
        return None

    project_url = f"{parsed.scheme}://{parsed.netloc}{project_path.rstrip('/')}"
    return _SourcePatchRequest(project_url=project_url, commit=commit, output=output)


def _cgit_source_patch_request(parsed) -> _SourcePatchRequest | None:
    if parsed.hostname is None or parsed.hostname.lower() != "pkgs.devel.redhat.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 4 or parts[:2] != ["cgit", "rpms"] or parts[3] != "patch":
        return None

    commit = (parse_qs(parsed.query).get("id") or [""])[0]
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        return None

    package = parts[2]
    project_url = f"{parsed.scheme}://gitlab.com/redhat/rhel/rpms/{package}"
    return _SourcePatchRequest(project_url=project_url, commit=commit, output="patch")


def _source_file_request(url: Any) -> _SourceFileRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None

    cgit_request = _cgit_source_file_request(parsed)
    if cgit_request is not None:
        return cgit_request

    if parsed.hostname.lower() != "src.fedoraproject.org":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 6 or parts[0] != "rpms" or parts[2] != "raw" or parts[4] != "f":
        return None

    ref = parts[3]
    file_path = "/".join(parts[5:])
    project_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts[:2])}"
    return _SourceFileRequest(project_url=project_url, ref=ref, file_path=file_path)


def _cgit_source_file_request(parsed) -> _SourceFileRequest | None:
    if parsed.hostname is None or parsed.hostname.lower() != "pkgs.devel.redhat.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 5 or parts[:2] != ["cgit", "rpms"] or parts[3] != "plain":
        return None

    package = parts[2]
    file_path = "/".join(parts[4:])
    ref = _cgit_query_ref(parsed)
    project_url = f"{parsed.scheme}://gitlab.com/redhat/rhel/rpms/{package}"
    return _SourceFileRequest(project_url=project_url, ref=ref, file_path=file_path)


def _source_log_request(url: Any) -> _SourceLogRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.hostname.lower() != "pkgs.devel.redhat.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 4 or parts[:2] != ["cgit", "rpms"] or parts[3] != "log":
        return None

    package = parts[2]
    project_url = f"{parsed.scheme}://gitlab.com/redhat/rhel/rpms/{package}"
    return _SourceLogRequest(
        project_url=project_url,
        package=package,
        ref=_cgit_query_ref(parsed),
    )


def _source_refs_request(url: Any) -> _SourceRefsRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.hostname.lower() != "pkgs.devel.redhat.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 4 or parts[:2] != ["cgit", "rpms"] or parts[3] != "refs":
        return None

    package = parts[2]
    project_url = f"{parsed.scheme}://gitlab.com/redhat/rhel/rpms/{package}"
    return _SourceRefsRequest(project_url=project_url, package=package)


def _source_gitlab_branches_request(url: Any) -> _SourceGitLabBranchesRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.hostname.lower() != "gitlab.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 6 or parts[:3] != ["api", "v4", "projects"]:
        return None
    if parts[4:] != ["repository", "branches"]:
        return None
    return _SourceGitLabBranchesRequest(project_identifier=parts[3])


def _cgit_query_ref(parsed) -> str:
    ref = (parse_qs(parsed.query).get("h") or ["HEAD"])[0].strip()
    return ref or "HEAD"


def _source_git_repositories(upstream_dir: Path) -> tuple[Path, ...]:
    candidates = [upstream_dir, *sorted(upstream_dir.iterdir())]
    repositories = [
        candidate
        for candidate in candidates
        if candidate.is_dir()
        and (_is_git_checkout(candidate) or _is_bare_git_repository(candidate))
    ]
    return tuple(dict.fromkeys(repositories))


def _is_git_checkout(path: Path) -> bool:
    return (path / ".git").exists()


def _is_bare_git_repository(path: Path) -> bool:
    return (path / "HEAD").is_file() and (path / "objects").is_dir()


def _git_remote_url(repo_path: Path) -> str | None:
    completed = subprocess.run(
        _git_command(repo_path, ["config", "--get", "remote.origin.url"]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        return None
    remote_url = completed.stdout.decode("utf-8", errors="ignore").strip()
    return remote_url or None


def _git_commit_exists(repo_path: Path, commit: str) -> bool:
    completed = subprocess.run(
        _git_command(repo_path, ["cat-file", "-e", f"{commit}^{{commit}}"]),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _git_commit_advertised(repo_path: Path, commit: str) -> bool:
    refs = _git_advertised_refs(repo_path)
    if not refs:
        return _git_commit_exists(repo_path, commit)
    return any(_git_commit_reachable(repo_path, commit, ref) for ref in refs)


def _git_advertised_refs(repo_path: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        _git_command(repo_path, ["for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags"]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    refs = [
        line.strip()
        for line in completed.stdout.splitlines()
        if completed.returncode == 0 and line.strip()
    ]
    head = subprocess.run(
        _git_command(repo_path, ["rev-parse", "--verify", "HEAD^{commit}"]),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if head.returncode == 0:
        refs.append("HEAD")
    return tuple(dict.fromkeys(refs))


def _git_commit_reachable(repo_path: Path, commit: str, ref: str) -> bool:
    completed = subprocess.run(
        _git_command(repo_path, ["merge-base", "--is-ancestor", commit, ref]),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _looks_like_git_object(value: str) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]{7,64}", value) is not None


def _git_cgit_log_html(repo_path: Path, package: str, ref: str) -> bytes | None:
    start = _git_resolve_commit(repo_path, ref)
    if start is None:
        return None

    completed = subprocess.run(
        _git_command(
            repo_path,
            [
                "log",
                "--max-count=50",
                "--date=iso-strict",
                "--pretty=format:%H%x00%an%x00%ad%x00%s",
                start,
            ],
        ),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None

    ref_text = html.escape(ref)
    rows = []
    for line in completed.stdout.splitlines():
        parts = line.split("\0")
        if len(parts) != 4:
            continue
        commit, author, authored_date, subject = parts
        commit_text = html.escape(commit)
        rows.append(
            "<tr>"
            "<td><a href='/cgit/rpms/"
            f"{html.escape(package)}/commit/?h={quote(ref)}&amp;id={commit_text}'>"
            f"{html.escape(subject)}</a></td>"
            f"<td>{html.escape(author)}</td>"
            f"<td>{html.escape(authored_date)}</td>"
            "</tr>"
        )
    body = (
        "<!doctype html><html><head>"
        f"<title>{html.escape(package)} log</title>"
        "</head><body>"
        f"<h1>{html.escape(package)} log for {ref_text}</h1>"
        "<table class='list nowrap'>"
        "<tr><th>Commit message</th><th>Author</th><th>Date</th></tr>"
        + "".join(rows)
        + "</table></body></html>\n"
    )
    return body.encode("utf-8")


def _git_cgit_refs_html(repo_path: Path, package: str) -> bytes:
    completed = subprocess.run(
        _git_command(
            repo_path,
            [
                "for-each-ref",
                "--format=%(refname:strip=2)%00%(objectname)%00%(subject)%00%(authordate:iso-strict)",
                "refs/heads",
            ],
        ),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    rows = []
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            parts = line.split("\0")
            if len(parts) != 4:
                continue
            ref, commit, subject, authored_date = parts
            ref_text = html.escape(ref)
            commit_text = html.escape(commit)
            rows.append(
                "<tr>"
                f"<td><a href='/cgit/rpms/{html.escape(package)}/log/?h={quote(ref)}'>"
                f"{ref_text}</a></td>"
                "<td><a href='/cgit/rpms/"
                f"{html.escape(package)}/commit/?h={quote(ref)}&amp;id={commit_text}'>"
                f"{html.escape(subject)}</a></td>"
                f"<td>{commit_text}</td>"
                f"<td>{html.escape(authored_date)}</td>"
                "</tr>"
            )
    body = (
        "<!doctype html><html><head>"
        f"<title>{html.escape(package)} refs</title>"
        "</head><body>"
        f"<h1>{html.escape(package)} refs</h1>"
        "<table class='list nowrap'>"
        "<tr><th>Branch</th><th>Commit</th><th>Object</th><th>Date</th></tr>"
        + "".join(rows)
        + "</table></body></html>\n"
    )
    return body.encode("utf-8")


def _gitlab_branch_payloads(repo_path: Path, project_url: str) -> list[dict[str, Any]]:
    completed = subprocess.run(
        _git_command(
            repo_path,
            [
                "for-each-ref",
                "--format=%(refname:strip=2)%00%(objectname)",
                "refs/heads",
            ],
        ),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return []

    branches = []
    default_branch = _git_symbolic_branch(repo_path, "HEAD")
    for line in completed.stdout.splitlines():
        parts = line.split("\0")
        if len(parts) != 2:
            continue
        branch, commit = parts
        commit_payload = _gitlab_commit_payload(repo_path, project_url, commit)
        branches.append(
            {
                "name": branch,
                "commit": commit_payload,
                "merged": False,
                "protected": False,
                "developers_can_push": False,
                "developers_can_merge": False,
                "can_push": False,
                "default": branch == default_branch,
                "web_url": f"{project_url}/-/tree/{quote(branch)}",
            }
        )
    return branches


def _filter_gitlab_branches_body_as_of(body: bytes, as_of: datetime) -> bytes:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(payload, list):
        return body

    branches = []
    for branch in payload:
        if not isinstance(branch, Mapping):
            branches.append(branch)
            continue
        if _gitlab_branch_is_after(branch, as_of):
            continue
        branches.append(branch)
    return json.dumps(branches, separators=(",", ":")).encode("utf-8")


def _gitlab_branch_is_after(branch: Mapping[str, Any], as_of: datetime) -> bool:
    name = branch.get("name")
    if isinstance(name, str) and _text_contains_date_after(name, as_of):
        return True
    commit = branch.get("commit")
    return isinstance(commit, Mapping) and _gitlab_commit_is_after(commit, as_of)


def _gitlab_commit_is_after(commit: Mapping[str, Any], as_of: datetime) -> bool:
    for field_name in ("committed_date", "authored_date", "created_at"):
        timestamp = _parse_replay_timestamp(commit.get(field_name))
        if timestamp is not None:
            return timestamp > as_of
    return False


def _text_contains_date_after(value: str, as_of: datetime) -> bool:
    for match in re.finditer(r"\d{4}[-_]\d{2}[-_]\d{2}", value):
        candidate = match.group(0).replace("_", "-")
        try:
            date = datetime.fromisoformat(candidate).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if date > as_of:
            return True
    return False


def _parse_replay_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    if len(candidate) >= 5 and candidate[-5] in {"+", "-"} and candidate[-3] != ":":
        candidate = f"{candidate[:-2]}:{candidate[-2:]}"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _gitlab_commit_payload(repo_path: Path, project_url: str, commit: str) -> dict[str, Any]:
    completed = subprocess.run(
        _git_command(
            repo_path,
            [
                "show",
                "-s",
                "--date=iso-strict",
                "--format=%H%x00%h%x00%aI%x00%cI%x00%an%x00%ae%x00%cn%x00%ce%x00%s%x00%B",
                commit,
            ],
        ),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return {
            "id": commit,
            "short_id": commit[:8],
            "web_url": f"{project_url}/-/commit/{commit}",
        }
    parts = completed.stdout.split("\0", 9)
    if len(parts) != 10:
        return {
            "id": commit,
            "short_id": commit[:8],
            "web_url": f"{project_url}/-/commit/{commit}",
        }
    (
        full_id,
        short_id,
        authored_date,
        committed_date,
        author_name,
        author_email,
        committer_name,
        committer_email,
        title,
        message,
    ) = parts
    return {
        "id": full_id,
        "short_id": short_id,
        "created_at": committed_date,
        "parent_ids": _git_parent_ids(repo_path, full_id),
        "title": title,
        "message": message,
        "author_name": author_name,
        "author_email": author_email,
        "authored_date": authored_date,
        "committer_name": committer_name,
        "committer_email": committer_email,
        "committed_date": committed_date,
        "trailers": {},
        "extended_trailers": {},
        "web_url": f"{project_url}/-/commit/{full_id}",
    }


def _git_parent_ids(repo_path: Path, commit: str) -> list[str]:
    completed = subprocess.run(
        _git_command(repo_path, ["show", "-s", "--format=%P", commit]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return []
    return [parent for parent in completed.stdout.strip().split() if parent]


def _git_symbolic_branch(repo_path: Path, ref: str) -> str | None:
    symbolic_ref = subprocess.run(
        _git_command(repo_path, ["symbolic-ref", "-q", "--short", ref]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if symbolic_ref.returncode != 0:
        return None
    value = symbolic_ref.stdout.strip()
    return value.removeprefix("heads/") or None


def _git_resolve_commit(repo_path: Path, ref: str) -> str | None:
    completed = subprocess.run(
        _git_command(repo_path, ["rev-parse", "--verify", f"{ref}^{{commit}}"]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    commit = completed.stdout.strip()
    return commit if commit else None


def _git_format_patch(repo_path: Path, commit: str) -> bytes:
    completed = subprocess.run(
        _git_command(repo_path, ["format-patch", "-1", commit, "--stdout"]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="ignore").strip()
        detail = f": {stderr}" if stderr else ""
        raise ReplayCacheError(f"source cache cannot format patch for {commit}{detail}")
    return completed.stdout


def _git_format_diff(repo_path: Path, commit: str) -> bytes:
    completed = subprocess.run(
        _git_command(repo_path, ["show", "--format=", "--patch", commit]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="ignore").strip()
        detail = f": {stderr}" if stderr else ""
        raise ReplayCacheError(f"source cache cannot format diff for {commit}{detail}")
    return completed.stdout


def _git_show_file(repo_path: Path, ref: str, file_path: str) -> bytes | None:
    completed = subprocess.run(
        _git_command(repo_path, ["show", f"{ref}:{file_path}"]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _git_command(repo_path: Path, args: list[str]) -> list[str]:
    if _is_bare_git_repository(repo_path):
        return ["git", f"--git-dir={repo_path}", *args]
    return ["git", "-C", str(repo_path), *args]


def _same_or_aliased_git_project(first: str | None, second: str) -> bool:
    if first is None:
        return False
    target = _normalized_git_project(second)
    return target in {_normalized_git_project(alias) for alias in _source_project_aliases(first)}


def _gitlab_project_url_from_metadata(project: Mapping[str, Any]) -> str | None:
    for field in ("http_url_to_repo", "web_url"):
        value = project.get(field)
        if isinstance(value, str) and value:
            parsed = urlparse(value)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                path = parsed.path.removesuffix(".git").rstrip("/")
                return f"{parsed.scheme}://{parsed.netloc}{path}"
    namespace = project.get("path_with_namespace")
    if isinstance(namespace, str) and namespace:
        return f"https://gitlab.com/{namespace.strip('/').removesuffix('.git')}"
    return None


def _source_project_aliases(remote_url: str) -> tuple[str, ...]:
    aliases = [remote_url]
    parsed = urlparse(remote_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return tuple(dict.fromkeys(aliases))

    parts = [part for part in parsed.path.strip("/").removesuffix(".git").split("/") if part]
    if len(parts) >= 2 and parts[-2] == "rpms":
        aliases.append(f"https://src.fedoraproject.org/rpms/{parts[-1]}.git")
    if parsed.hostname.lower() == "gitlab.gnome.org" and len(parts) >= 2:
        aliases.append(f"https://github.com/{'/'.join(parts)}.git")
    return tuple(dict.fromkeys(aliases))


def _normalized_git_project(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.netloc.lower()}/{_normalized_git_path(parsed.path)}"
    return _normalized_git_path(url)


def _normalized_git_path(path: str) -> str:
    value = path.strip().rstrip("/")
    if value.endswith(".git"):
        value = value.removesuffix(".git")
    return value.strip("/").lower()


def _git_url_aliases(url: str) -> tuple[str, ...]:
    url = canonicalize_replay_url(url)
    aliases = [url]
    if url.endswith(".git"):
        aliases.append(url.removesuffix(".git"))
    else:
        aliases.append(f"{url}.git")
    return tuple(dict.fromkeys(alias for alias in aliases if alias))


def request_url(value: Any, args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str | None:
    if isinstance(value, str):
        return canonicalize_replay_url(value)
    if hasattr(value, "full_url"):
        url = getattr(value, "full_url")
        return canonicalize_replay_url(url) if isinstance(url, str) else None
    if args:
        first = args[0]
        if isinstance(first, str):
            return canonicalize_replay_url(first)
    url = kwargs.get("url")
    return canonicalize_replay_url(url) if isinstance(url, str) else None
