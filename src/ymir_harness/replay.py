from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
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


class ReplayCache:
    def __init__(self, manifest_path: Path):
        self.manifest_path = manifest_path
        self.cache_dir = manifest_path.parent
        self._recorded_files = self._load_recorded_files(manifest_path)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> "ReplayCache | None":
        manifest = environment.get("YMIR_BENCHMARK_REPLAY_MANIFEST")
        if not manifest:
            return None
        return cls(Path(manifest))

    @property
    def recorded_urls(self) -> tuple[str, ...]:
        return tuple(self._recorded_files)

    def has_url(self, url: str) -> bool:
        return url in self._recorded_files

    def read_bytes(self, url: str) -> bytes:
        path = self.path_for_url(url)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ReplayCacheError(f"recorded file cannot be read for URL {url}: {path}") from exc

    def open_urllib_response(self, url: str) -> addinfourl:
        body = self.read_bytes(url)
        response = addinfourl(
            io.BytesIO(body),
            headers=self.response_headers(url, body),
            url=url,
            code=200,
        )
        response.msg = "OK"
        return response

    def open_aiohttp_response(self, url: str) -> ReplayResponse:
        body = self.read_bytes(url)
        return ReplayResponse(url, body, headers=self.response_headers(url, body))

    def response_headers(self, url: str, body: bytes | None = None) -> dict[str, str]:
        body = self.read_bytes(url) if body is None else body
        path = self.path_for_url(url)
        return {"Content-Type": _content_type_for(path, body)}

    def path_for_url(self, url: str) -> Path:
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
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReplayCacheError(f"cannot read replay manifest: {manifest_path}") from exc
        if not isinstance(manifest, Mapping):
            raise ReplayCacheError(f"replay manifest must contain an object: {manifest_path}")
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


def _content_type_for(path: Path, body: bytes) -> str:
    stripped = body.lstrip()
    if stripped.startswith((b"{", b"[")):
        return "application/json"
    if path.suffix.lower() in {".diff", ".md", ".patch", ".txt"}:
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


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
