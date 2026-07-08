from __future__ import annotations

import json
from pathlib import Path

import pytest

from ymir_harness.replay import ReplayCache, ReplayCacheError


def test_replay_cache_rejects_unexpected_empty_recorded_file(tmp_path: Path) -> None:
    url = "https://example.invalid/challenge"
    manifest_path = _write_manifest(tmp_path, url, status=200)
    (manifest_path.parent / "captured" / "challenge.html").write_bytes(b"")
    cache = ReplayCache(manifest_path)

    with pytest.raises(ReplayCacheError, match="recorded file is empty"):
        cache.read_bytes(url)


def test_replay_cache_accepts_empty_recorded_file_for_recorded_empty_status(
    tmp_path: Path,
) -> None:
    url = "https://example.invalid/challenge"
    manifest_path = _write_manifest(tmp_path, url, status=202)
    (manifest_path.parent / "captured" / "challenge.html").write_bytes(b"")
    cache = ReplayCache(manifest_path)

    assert cache.status_code(url) == 202
    assert cache.read_bytes(url) == b""


def _write_manifest(tmp_path: Path, url: str, *, status: int) -> Path:
    manifest_path = tmp_path / "web_cache" / "RHEL-12345" / "manifest.json"
    recorded_path = manifest_path.parent / "captured" / "challenge.html"
    recorded_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "required_urls": [url],
                "recorded_files": {url: "captured/challenge.html"},
                "response_metadata": {url: {"status": status}},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest_path
