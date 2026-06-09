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


@dataclass(frozen=True)
class _SourcePatchResponse:
    body: bytes
    status: int
    headers: Mapping[str, str]


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
        return url in self._recorded_files or self._source_patch_repo_for(url) is not None

    def read_bytes(self, url: Any) -> bytes:
        url = _url_text(url)
        if url not in self._recorded_files:
            source_patch = self._source_patch_response(url)
            if source_patch is not None:
                return source_patch.body

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
            source_patch = self._source_patch_response(url)
            if source_patch is not None:
                return dict(source_patch.headers)

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
            source_patch = self._source_patch_response(url)
            if source_patch is not None:
                return source_patch.status

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
            url: recorded
            for url, recorded in recorded_files.items()
            if isinstance(url, str) and url and isinstance(recorded, str) and recorded
        }
        return output

    def _load_response_metadata(self, manifest_path: Path) -> dict[str, Mapping[str, Any]]:
        manifest = self._load_manifest(manifest_path)
        response_metadata = manifest.get("response_metadata")
        if not isinstance(response_metadata, Mapping):
            return {}
        return {
            url: metadata
            for url, metadata in response_metadata.items()
            if isinstance(url, str) and isinstance(metadata, Mapping)
        }

    def _load_manifest(self, manifest_path: Path) -> Mapping[str, Any]:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReplayCacheError(f"cannot read replay manifest: {manifest_path}") from exc
        if not isinstance(manifest, Mapping):
            raise ReplayCacheError(f"replay manifest must contain an object: {manifest_path}")
        return manifest

    def _source_patch_response(self, url: str) -> _SourcePatchResponse | None:
        repo_path = self._source_patch_repo_for(url)
        if repo_path is None:
            return None

        request = _source_patch_request(url)
        if request is None:
            return None

        if not _git_commit_exists(repo_path, request.commit):
            return _SourcePatchResponse(
                body=f"commit {request.commit} is not available in source cache\n".encode("utf-8"),
                status=404,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )

        body = _git_format_patch(repo_path, request.commit)
        return _SourcePatchResponse(
            body=body,
            status=200,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    def _source_patch_repo_for(self, url: str) -> Path | None:
        request = _source_patch_request(url)
        if request is None or self.source_cache_dir is None:
            return None

        upstream_dir = self.source_cache_dir / "upstream"
        if not upstream_dir.is_dir():
            return None

        repositories = _source_git_repositories(upstream_dir)
        matching = [
            repository
            for repository in repositories
            if _same_git_project(_git_remote_url(repository), request.project_url)
        ]
        if matching:
            return matching[0]

        for repository in repositories:
            if _git_commit_exists(repository, request.commit):
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
    return url if isinstance(url, str) else str(url)


def _source_patch_request(url: str) -> _SourcePatchRequest | None:
    url = _url_text(url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None

    marker = "/-/commit/"
    if marker not in parsed.path:
        return None

    project_path, commit_part = parsed.path.split(marker, 1)
    commit = commit_part.strip("/").split("/", 1)[0].removesuffix(".patch")
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        return None

    query = parse_qs(parsed.query)
    if not parsed.path.endswith(".patch") and query.get("format") != [".patch"]:
        return None

    project_url = f"{parsed.scheme}://{parsed.netloc}{project_path.rstrip('/')}"
    return _SourcePatchRequest(project_url=project_url, commit=commit)


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


def _git_command(repo_path: Path, args: list[str]) -> list[str]:
    if _is_bare_git_repository(repo_path):
        return ["git", f"--git-dir={repo_path}", *args]
    return ["git", "-C", str(repo_path), *args]


def _same_git_project(first: str | None, second: str) -> bool:
    if first is None:
        return False
    return _normalized_git_project(first) == _normalized_git_project(second)


def _normalized_git_project(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        path = parsed.path
        return f"{parsed.netloc.lower()}/{_normalized_git_path(path)}"
    return _normalized_git_path(url)


def _normalized_git_path(path: str) -> str:
    value = path.strip().rstrip("/")
    if value.endswith(".git"):
        value = value.removesuffix(".git")
    return value.strip("/").lower()


def request_url(value: Any, args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str | None:
    if isinstance(value, str):
        return value
    if hasattr(value, "full_url"):
        url = getattr(value, "full_url")
        return url if isinstance(url, str) else None
    if args:
        first = args[0]
        if isinstance(first, str):
            return first
    url = kwargs.get("url")
    return url if isinstance(url, str) else None
