from __future__ import annotations

import io
import json
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.error import HTTPError
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from urllib.response import addinfourl


class ReplayCacheError(RuntimeError):
    """Raised when replay cache data cannot satisfy a requested URL."""


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
class _SourcePatchResponse:
    body: bytes
    status: int
    headers: Mapping[str, str]


TRAILING_ESCAPED_URL_GARBAGE_RE = re.compile(r"(?:\\+[nrt]|\\+)+$", re.IGNORECASE)


def canonicalize_replay_url(value: Any) -> str:
    url = value if isinstance(value, str) else str(value)
    url = url.strip()
    if not url:
        return url

    split = re.split(r"[\s\"'<>]", url, maxsplit=1)
    url = split[0] if split else url
    previous = None
    while previous != url:
        previous = url
        url = url.rstrip(".,;:)]}\"'")
        url = TRAILING_ESCAPED_URL_GARBAGE_RE.sub("", url)
        url = url.strip()
    return url


class ReplayCache:
    def __init__(self, manifest_path: Path, *, source_cache_dir: Path | None = None):
        self.manifest_path = manifest_path
        self.cache_dir = manifest_path.parent
        self.source_cache_dir = source_cache_dir
        self._recorded_files = self._load_recorded_files(manifest_path)
        self._response_metadata = self._load_response_metadata(manifest_path)

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

    def read_bytes(self, url: Any) -> bytes:
        url = _url_text(url)
        if url not in self._recorded_files:
            source_response = self._source_response(url)
            if source_response is not None:
                return source_response.body

        path = self.path_for_url(url)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ReplayCacheError(f"recorded file cannot be read for URL {url}: {path}") from exc

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
        if url not in self._recorded_files:
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
        if url not in self._recorded_files:
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
        if path.stat().st_size == 0:
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

    def _load_response_metadata(self, manifest_path: Path) -> dict[str, Mapping[str, Any]]:
        manifest = self._load_manifest(manifest_path)
        response_metadata = manifest.get("response_metadata")
        if not isinstance(response_metadata, Mapping):
            return {}
        return {
            canonicalize_replay_url(url): metadata
            for url, metadata in response_metadata.items()
            if isinstance(url, str) and canonicalize_replay_url(url) and isinstance(metadata, Mapping)
        }

    def _load_manifest(self, manifest_path: Path) -> Mapping[str, Any]:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReplayCacheError(f"cannot read replay manifest: {manifest_path}") from exc
        if not isinstance(manifest, Mapping):
            raise ReplayCacheError(f"replay manifest must contain an object: {manifest_path}")
        return manifest

    def _source_response(self, url: str) -> _SourcePatchResponse | None:
        patch_response = self._source_patch_response(url)
        if patch_response is not None:
            return patch_response
        return self._source_file_response(url)

    def _source_patch_response(self, url: str) -> _SourcePatchResponse | None:
        request = _source_patch_request(url)
        if request is None:
            return None

        repo_path = self._source_repo_for_project(request.project_url, commit=request.commit)
        if repo_path is None:
            return None

        if not _git_commit_exists(repo_path, request.commit):
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

    def _source_repo_for_url(self, url: str) -> Path | None:
        patch_request = _source_patch_request(url)
        if patch_request is not None:
            return self._source_repo_for_project(
                patch_request.project_url,
                commit=patch_request.commit,
            )
        file_request = _source_file_request(url)
        if file_request is not None:
            return self._source_repo_for_project(file_request.project_url)
        return None

    def _source_repo_for_project(
        self, project_url: str, *, commit: str | None = None
    ) -> Path | None:
        if self.source_cache_dir is None:
            return None
        upstream_dir = self.source_cache_dir / "upstream"
        if not upstream_dir.is_dir():
            return None

        repositories = _source_git_repositories(upstream_dir)
        matching = [
            repository
            for repository in repositories
            if _same_git_project(_git_remote_url(repository), project_url)
        ]
        if matching:
            return matching[0]

        related = [
            repository
            for repository in repositories
            if _related_git_project(_git_remote_url(repository), project_url)
        ]
        if related:
            return related[0]

        if commit is None:
            return None
        for repository in repositories:
            if _git_commit_exists(repository, commit):
                return repository
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


def _source_file_request(url: Any) -> _SourceFileRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.hostname.lower() != "src.fedoraproject.org":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 6 or parts[0] != "rpms" or parts[2] != "raw" or parts[4] != "f":
        return None

    ref = parts[3]
    file_path = "/".join(parts[5:])
    project_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts[:2])}"
    return _SourceFileRequest(project_url=project_url, ref=ref, file_path=file_path)


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


def _same_git_project(first: str | None, second: str) -> bool:
    if first is None:
        return False
    return _normalized_git_project(first) == _normalized_git_project(second)


def _related_git_project(first: str | None, second: str) -> bool:
    if first is None:
        return False
    first_path = _normalized_git_path(_git_project_path(first))
    second_path = _normalized_git_path(_git_project_path(second))
    return first_path == second_path or first_path.endswith(f"/{second_path}")


def _normalized_git_project(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.netloc.lower()}/{_normalized_git_path(parsed.path)}"
    return _normalized_git_path(url)


def _git_project_path(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path if parsed.scheme and parsed.netloc else url


def _normalized_git_path(path: str) -> str:
    value = path.strip().rstrip("/")
    if value.endswith(".git"):
        value = value.removesuffix(".git")
    return value.strip("/").lower()


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
