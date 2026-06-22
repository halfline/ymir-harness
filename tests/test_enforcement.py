from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from ymir_harness.enforcement import BenchmarkBoundaryViolation, enforce_benchmark_boundaries
from ymir_harness.replay import ReplayCache


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


def test_enforcement_returns_replay_miss_for_unrecorded_urllib_response(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen("https://example.invalid/missing")

    assert exc_info.value.code == 404
    assert exc_info.value.read() == (
        b"replay miss: URL is not recorded in replay cache: https://example.invalid/missing\n"
    )


def test_enforcement_blocks_network_denied_urllib_response() -> None:
    with enforce_benchmark_boundaries({"YMIR_BENCHMARK_NETWORK_MODE": "network_denied"}):
        with pytest.raises(BenchmarkBoundaryViolation, match="external network access blocked"):
            urllib.request.urlopen("https://example.invalid/missing")


def test_enforcement_serves_recorded_requests_json_response(tmp_path: Path) -> None:
    requests = pytest.importorskip("requests")
    url = "https://gitlab.example/api/v4/projects/group%2Fpkg"
    manifest_path = _write_replay_manifest(tmp_path, {url: "gitlab/project.json"})
    (manifest_path.parent / "gitlab").mkdir()
    (manifest_path.parent / "gitlab" / "project.json").write_text(
        json.dumps({"id": 42, "path_with_namespace": "group/pkg"}) + "\n",
        encoding="utf-8",
    )

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        response = requests.get(url)

    assert response.headers["Content-Type"] == "application/json"
    assert response.json() == {"id": 42, "path_with_namespace": "group/pkg"}


def test_enforcement_returns_replay_miss_for_unrecorded_requests_response(
    tmp_path: Path,
) -> None:
    requests = pytest.importorskip("requests")
    url = "https://gitlab.example/api/v4/projects/group%2Fmissing"
    manifest_path = _write_replay_manifest(tmp_path, {})

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        response = requests.get(url)

    assert response.status_code == 404
    assert response.text == f"replay miss: URL is not recorded in replay cache: {url}\n"


def test_enforcement_blocks_unsafe_requests_write(tmp_path: Path) -> None:
    requests = pytest.importorskip("requests")
    manifest_path = _write_replay_manifest(tmp_path, {})

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(BenchmarkBoundaryViolation, match="unsafe operation blocked"):
            requests.post("https://redhat.atlassian.net/rest/api/3/issue", json={})


def test_replay_cache_accepts_url_objects(tmp_path: Path) -> None:
    yarl = pytest.importorskip("yarl")
    manifest_path = _write_replay_manifest(tmp_path, {})

    cache = ReplayCache(manifest_path)

    assert not cache.has_url(yarl.URL("https://generativelanguage.googleapis.com/v1beta/models"))


def test_enforcement_allows_configured_model_provider_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    calls = []

    class Response:
        def read(self) -> bytes:
            return b"model response\n"

    def fake_urlopen(url: str, *_args: Any, **_kwargs: Any) -> Response:
        calls.append(url)
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    environment = {
        **_environment(manifest_path),
        "CHAT_MODEL": "gemini:gemini-2.5-pro",
    }
    with enforce_benchmark_boundaries(environment):
        response = urllib.request.urlopen(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"
        )

    assert response.read() == b"model response\n"
    assert calls == [
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"
    ]


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


def test_enforcement_replays_recorded_compound_shell_download(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(
        tmp_path,
        {"https://example.invalid/archive.tar.gz": "archives/source.tar.gz"},
    )
    (manifest_path.parent / "archives").mkdir()
    (manifest_path.parent / "archives" / "source.tar.gz").write_bytes(
        b"\x1f\x8b\x08\x00binary replay body"
    )

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        completed = subprocess.run(
            "cd /tmp && curl -sL https://example.invalid/archive.tar.gz | tar xz",
            check=True,
            capture_output=True,
            text=True,
        )

    assert completed.stdout == ""
    assert completed.stderr == ""


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


def test_enforcement_replays_gitlab_commit_patch_from_source_cache(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    source_repo, commit_sha = _create_git_repo(tmp_path)
    cached_repo = tmp_path / "source_cache" / "RHEL-12345" / "upstream" / "pkg.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            "https://gitlab.gnome.org/group/pkg.git",
        ],
        check=True,
    )

    url = f"https://gitlab.gnome.org/group/pkg/-/commit/{commit_sha}.patch"
    environment = {
        **_environment(manifest_path),
        "YMIR_BENCHMARK_SOURCE_CACHE_DIR": str(cached_repo.parent.parent),
    }

    with enforce_benchmark_boundaries(environment):
        response = urllib.request.urlopen(url)
        diff_response = urllib.request.urlopen(
            f"https://gitlab.gnome.org/group/pkg/-/commit/{commit_sha}.diff"
        )
        github_response = urllib.request.urlopen(
            f"https://github.com/group/pkg/commit/{commit_sha}.patch"
        )
        completed = subprocess.run(
            ["curl", url],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )

    body = response.read()
    assert b"Subject: [PATCH] fix" in body
    assert b"diff --git" in diff_response.read()
    assert b"Subject: [PATCH] fix" in github_response.read()
    assert "Subject: [PATCH] fix" in completed.stdout


def test_enforcement_replays_pkgs_devel_cgit_patch_from_source_cache(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    source_repo, commit_sha = _create_git_repo(tmp_path)
    cached_repo = tmp_path / "source_cache" / "RHEL-12345" / "upstream" / "pkg.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            "https://gitlab.com/redhat/rhel/rpms/pkg.git",
        ],
        check=True,
    )

    patch_url = (
        "https://pkgs.devel.redhat.com/cgit/rpms/pkg/patch/"
        f"?h=rhel-9.2.0&id={commit_sha}"
    )
    commit_url = (
        "https://pkgs.devel.redhat.com/cgit/rpms/pkg/commit/"
        f"?h=rhel-9.2.0&id={commit_sha}"
    )
    environment = {
        **_environment(manifest_path),
        "YMIR_BENCHMARK_SOURCE_CACHE_DIR": str(cached_repo.parent.parent),
    }

    cache = ReplayCache(manifest_path, source_cache_dir=cached_repo.parent.parent)
    assert cache.has_url(patch_url)
    assert not cache.has_url(commit_url)

    with enforce_benchmark_boundaries(environment):
        response = urllib.request.urlopen(patch_url)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(commit_url)

    assert b"Subject: [PATCH] fix" in response.read()
    assert exc_info.value.code == 404


def test_enforcement_returns_404_for_missing_source_cache_commit(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    source_repo, _commit_sha = _create_git_repo(tmp_path)
    cached_repo = tmp_path / "source_cache" / "RHEL-12345" / "upstream" / "pkg.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            "https://gitlab.gnome.org/group/pkg.git",
        ],
        check=True,
    )

    missing_sha = "f" * 40
    environment = {
        **_environment(manifest_path),
        "YMIR_BENCHMARK_SOURCE_CACHE_DIR": str(cached_repo.parent.parent),
    }

    with enforce_benchmark_boundaries(environment):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                f"https://gitlab.gnome.org/group/pkg/-/commit/{missing_sha}.patch"
            )
        with pytest.raises(urllib.error.HTTPError) as diff_exc_info:
            urllib.request.urlopen(
                f"https://gitlab.gnome.org/group/pkg/-/commit/{missing_sha}.diff"
            )
        with pytest.raises(urllib.error.HTTPError) as github_exc_info:
            urllib.request.urlopen(f"https://github.com/group/pkg/commit/{missing_sha}.patch")

    assert exc_info.value.code == 404
    assert exc_info.value.read() == (
        f"commit {missing_sha} is not available in source cache\n".encode("utf-8")
    )
    assert diff_exc_info.value.code == 404
    assert github_exc_info.value.code == 404


def test_enforcement_returns_404_for_unadvertised_source_cache_commit(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    source_repo, branch, pre_fix_ref, future_ref = _create_dated_git_repo(tmp_path)
    cached_repo = tmp_path / "source_cache" / "RHEL-12345" / "upstream" / "pkg.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        ["git", f"--git-dir={cached_repo}", "update-ref", f"refs/heads/{branch}", pre_fix_ref],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            "https://gitlab.gnome.org/group/pkg.git",
        ],
        check=True,
    )

    environment = {
        **_environment(manifest_path),
        "YMIR_BENCHMARK_SOURCE_CACHE_DIR": str(cached_repo.parent.parent),
    }

    with enforce_benchmark_boundaries(environment):
        ok_response = urllib.request.urlopen(
            f"https://gitlab.gnome.org/group/pkg/-/commit/{pre_fix_ref}.patch"
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                f"https://gitlab.gnome.org/group/pkg/-/commit/{future_ref}.patch"
            )

    assert b"Subject: [PATCH] initial" in ok_response.read()
    assert exc_info.value.code == 404
    assert exc_info.value.read() == (
        f"commit {future_ref} is not available in source cache\n".encode("utf-8")
    )


def test_enforcement_does_not_replay_unaliased_same_path_source_cache_url(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    source_repo, commit_sha = _create_git_repo(tmp_path)
    cached_repo = tmp_path / "source_cache" / "RHEL-12345" / "upstream" / "kea.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            "https://github.com/isc-projects/kea.git",
        ],
        check=True,
    )

    url = f"https://gitlab.isc.org/isc-projects/kea/-/commit/{commit_sha}.patch"
    environment = {
        **_environment(manifest_path),
        "YMIR_BENCHMARK_SOURCE_CACHE_DIR": str(cached_repo.parent.parent),
    }

    cache = ReplayCache(manifest_path, source_cache_dir=cached_repo.parent.parent)
    assert not cache.has_url(url)

    with enforce_benchmark_boundaries(environment):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(url)

    assert exc_info.value.code == 404
    assert exc_info.value.read() == (
        f"replay miss: URL is not recorded in replay cache: {url}\n".encode("utf-8")
    )


def test_enforcement_replays_fedora_raw_url_from_source_cache(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    source_repo, _commit_sha = _create_git_repo(tmp_path)
    cached_repo = tmp_path / "source_cache" / "RHEL-12345" / "upstream" / "pkg.git"
    cached_repo.parent.mkdir(parents=True)
    subprocess.run(
        ["git", "clone", "--mirror", "--quiet", str(source_repo), str(cached_repo)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={cached_repo}",
            "config",
            "remote.origin.url",
            "https://gitlab.com/redhat/centos-stream/rpms/pkg.git",
        ],
        check=True,
    )
    environment = {
        **_environment(manifest_path),
        "YMIR_BENCHMARK_SOURCE_CACHE_DIR": str(cached_repo.parent.parent),
    }

    with enforce_benchmark_boundaries(environment):
        response = urllib.request.urlopen(
            "https://src.fedoraproject.org/rpms/pkg/raw/HEAD/f/source.c"
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                "https://src.fedoraproject.org/rpms/pkg/raw/main/f/missing.patch"
            )

    assert response.read() == b"after\n"
    assert exc_info.value.code == 404


def test_enforcement_blocks_unrecorded_git_subprocess_url(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/repo.git"

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(BenchmarkBoundaryViolation) as exc_info:
            subprocess.run(
                ["git", "clone", url],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    assert str(exc_info.value) == f"external subprocess URL blocked: {url}"


def test_enforcement_replays_recorded_git_subprocess_failure(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/repo.git"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["git_failures"] = {
        url: {
            "returncode": 128,
            "stdout": "",
            "stderr": "fatal: unable to access repository\n",
        }
    }
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        completed = subprocess.run(
            ["git", "ls-remote", "https://example.invalid/repo"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    assert completed.returncode == 128
    assert completed.stdout == ""
    assert completed.stderr == "fatal: unable to access repository\n"


def test_enforcement_replays_recorded_subprocess_command(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    command = "GIT_TERMINAL_PROMPT=0 git ls-remote https://example.invalid/repo 2>&1 | head -5"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["subprocess_replays"] = {
        command: {
            "returncode": 0,
            "stdout": "abc123\tHEAD\n",
            "stderr": "",
        }
    }
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    assert completed.returncode == 0
    assert completed.stdout == "abc123\tHEAD\n"
    assert completed.stderr == ""


def test_enforcement_does_not_replay_subprocess_command_in_network_denied(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    command = "git ls-remote https://example.invalid/repo"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["subprocess_replays"] = {
        command: {
            "returncode": 0,
            "stdout": "abc123\tHEAD\n",
            "stderr": "",
        }
    }
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    environment = {**_environment(manifest_path), "YMIR_BENCHMARK_NETWORK_MODE": "network_denied"}

    with enforce_benchmark_boundaries(environment):
        with pytest.raises(BenchmarkBoundaryViolation) as exc_info:
            subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    assert str(exc_info.value) == "external subprocess URL blocked: https://example.invalid/repo"


def test_enforcement_blocks_unrecorded_git_popen_url(tmp_path: Path) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/repo.git"

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(BenchmarkBoundaryViolation) as exc_info:
            subprocess.Popen(
                ["git", "clone", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    assert str(exc_info.value) == f"external subprocess URL blocked: {url}"


def test_enforcement_blocks_unrecorded_async_git_subprocess_url(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/repo.git"

    async def run_process() -> None:
        with enforce_benchmark_boundaries(_environment(manifest_path)):
            await asyncio.create_subprocess_exec(
                "git",
                "clone",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

    with pytest.raises(BenchmarkBoundaryViolation) as exc_info:
        asyncio.run(run_process())

    assert str(exc_info.value) == f"external subprocess URL blocked: {url}"


def test_enforcement_returns_replay_miss_for_async_popen_pipe_read(
    tmp_path: Path,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    url = "https://example.invalid/missing.patch"

    async def run_process() -> tuple[int, bytes]:
        with enforce_benchmark_boundaries(_environment(manifest_path)):
            process = await asyncio.create_subprocess_exec(
                "curl",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert process.stdout is not None
            stdout = await process.stdout.read()
            return await process.wait(), stdout

    returncode, stdout = asyncio.run(run_process())

    assert returncode == 0
    assert stdout == f"replay miss: URL is not recorded in replay cache: {url}\n".encode()


def test_enforcement_allows_mock_rewritten_git_subprocess_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    repo_path = tmp_path / "repo.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(repo_path)], check=True)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{repo_path.resolve().as_uri()}"]',
                "\tinsteadOf = https://example.invalid/repo",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))

    environment = {
        **_environment(manifest_path),
        "MOCK_BLOCKED_URLS": "https://example.invalid/repo.git",
    }
    with enforce_benchmark_boundaries(environment):
        completed = subprocess.run(
            ["git", "ls-remote", "https://example.invalid/repo"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    assert completed.returncode == 0


def test_enforcement_allows_compound_mock_rewritten_git_subprocess_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = _write_replay_manifest(tmp_path, {})
    repo_path = tmp_path / "repo.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(repo_path)], check=True)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{repo_path.resolve().as_uri()}"]',
                "\tinsteadOf = https://example.invalid/repo.git",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))

    clone_path = tmp_path / "clone"
    environment = {
        **_environment(manifest_path),
        "MOCK_BLOCKED_URLS": "https://example.invalid/repo.git",
    }
    command = (
        f"rm -rf {shlex.quote(str(clone_path))} && "
        f"git clone https://example.invalid/repo.git {shlex.quote(str(clone_path))}"
    )
    with enforce_benchmark_boundaries(environment):
        completed = subprocess.run(
            command,
            check=False,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    assert completed.returncode == 0
    assert (clone_path / ".git").is_dir()


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


def _create_dated_git_repo(tmp_path: Path) -> tuple[Path, str, str, str]:
    repo_path = tmp_path / "dated-source-repo"
    repo_path.mkdir()
    subprocess.run(["git", "-C", str(repo_path), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo_path), "config", "user.email", "dev@example.com"], check=True
    )
    subprocess.run(["git", "-C", str(repo_path), "config", "user.name", "Dev"], check=True)
    branch = subprocess.check_output(
        ["git", "-C", str(repo_path), "symbolic-ref", "--short", "HEAD"],
        text=True,
    ).strip()
    _commit_with_date(repo_path, "before\n", "initial", "2025-09-01T00:00:00+0000")
    pre_fix_ref = subprocess.check_output(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    _commit_with_date(repo_path, "after\n", "future", "2025-09-20T00:00:00+0000")
    future_ref = subprocess.check_output(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    return repo_path, branch, pre_fix_ref, future_ref


def _commit_with_date(repo_path: Path, text: str, message: str, date: str) -> None:
    (repo_path / "source.c").write_text(text, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_path), "add", "source.c"], check=True)
    subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-q", "-m", message],
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": date,
        },
    )
