from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path

import pytest

from ymir_harness.enforcement import BenchmarkBoundaryViolation, enforce_benchmark_boundaries


def test_enforcement_serves_recorded_urllib_response(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(
        tmp_path,
        {"https://example.invalid/advisory": "advisories/advisory.txt"},
    )
    (manifest_path.parent / "advisories").mkdir()
    (manifest_path.parent / "advisories" / "advisory.txt").write_text(
        "cached advisory\n",
        encoding="utf-8",
    )

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        response = urllib.request.urlopen("https://example.invalid/advisory")

    assert response.read() == b"cached advisory\n"


def test_enforcement_blocks_unrecorded_urllib_response(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(BenchmarkBoundaryViolation, match="unrecorded replay URL"):
            urllib.request.urlopen("https://example.invalid/missing")


def test_enforcement_blocks_unsafe_subprocess_command() -> None:
    with enforce_benchmark_boundaries({"YMIR_BENCHMARK_NETWORK_MODE": "network_denied"}):
        with pytest.raises(BenchmarkBoundaryViolation, match="unsafe operation blocked"):
            subprocess.run(["git", "push", "origin", "HEAD"], check=False)


def test_enforcement_replays_recorded_shell_download(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(
        tmp_path,
        {"https://example.invalid/fix.patch": "commits/fix.patch"},
    )
    (manifest_path.parent / "commits").mkdir()
    (manifest_path.parent / "commits" / "fix.patch").write_text(
        "cached patch\n",
        encoding="utf-8",
    )

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        completed = subprocess.run(
            ["curl", "https://example.invalid/fix.patch"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )

    assert completed.stdout == "cached patch\n"


def test_enforcement_blocks_external_subprocess_url(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(BenchmarkBoundaryViolation, match="external subprocess URL"):
            subprocess.run(
                ["git", "clone", "https://example.invalid/repo.git"],
                check=False,
            )


def _environment(manifest_path: Path) -> dict[str, str]:
    return {
        "YMIR_BENCHMARK_NETWORK_MODE": "replay_only",
        "YMIR_BENCHMARK_REPLAY_MANIFEST": str(manifest_path),
        "YMIR_BENCHMARK_RECORDED_URLS": json.dumps(
            list(json.loads(manifest_path.read_text(encoding="utf-8"))["recorded_files"])
        ),
    }


def _write_replay_manifest(tmp_path: Path, recorded_files: dict[str, str]) -> Path:
    manifest_path = tmp_path / "web_cache" / "RHEL-12345" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "required_urls": list(recorded_files),
                "recorded_files": recorded_files,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest_path
