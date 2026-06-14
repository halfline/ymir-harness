from __future__ import annotations

import asyncio
import json
import shlex
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from ymir_harness.enforcement import BenchmarkBoundaryViolation, enforce_benchmark_boundaries
from ymir_harness.replay import ReplayCache

def test_enforcement_blocks_unsafe_subprocess_command() -> None:
    with enforce_benchmark_boundaries({"YMIR_BENCHMARK_NETWORK_MODE": "network_denied"}):
        with pytest.raises(BenchmarkBoundaryViolation, match="unsafe operation blocked"):
            subprocess.run(["git", "push", "origin", "HEAD"], check=False)


def test_enforcement_blocks_env_wrapped_unsafe_subprocess_command() -> None:
    environment = {
        "YMIR_BENCHMARK_NETWORK_MODE": "network_denied",
        "MOCK_BLOCKED_URLS": "https://example.invalid/repo.git",
    }
    with enforce_benchmark_boundaries(environment):
        with pytest.raises(BenchmarkBoundaryViolation, match="unsafe operation blocked"):
            subprocess.run(
                [
                    "env",
                    "GIT_TERMINAL_PROMPT=0",
                    "git",
                    "push",
                    "https://example.invalid/repo",
                    "HEAD",
                ],
                check=False,
            )


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


def test_enforcement_returns_replay_miss_for_unrecorded_shell_download(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/missing.patch"

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        completed = subprocess.run(
            ["curl", url],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )

    assert completed.returncode == 0
    assert completed.stdout == f"replay miss: URL is not recorded in replay cache: {url}\n"


def test_enforcement_returns_replay_miss_for_popen_shell_download(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/missing.patch"

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        process = subprocess.Popen(
            ["curl", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()

    assert process.returncode == 0
    assert stdout == f"replay miss: URL is not recorded in replay cache: {url}\n"
    assert stderr == ""


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


def _create_git_repo(tmp_path: Path) -> tuple[Path, str]:
    repo_path = tmp_path / "source-repo"
    repo_path.mkdir()
    subprocess.run(["git", "-C", str(repo_path), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo_path), "config", "user.email", "dev@example.com"], check=True
    )
    subprocess.run(["git", "-C", str(repo_path), "config", "user.name", "Dev"], check=True)
    (repo_path / "source.c").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_path), "add", "source.c"], check=True)
    subprocess.run(["git", "-C", str(repo_path), "commit", "-q", "-m", "initial"], check=True)
    (repo_path / "source.c").write_text("after\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_path), "commit", "-am", "fix", "-q"], check=True)
    commit_sha = subprocess.check_output(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    return repo_path, commit_sha
