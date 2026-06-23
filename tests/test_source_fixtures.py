from __future__ import annotations

import base64
import subprocess
from pathlib import Path

import ymir_harness.source_fixtures as source_fixtures_module


def test_git_submodule_update_uses_gitlab_token_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    subprocess.run(["git", "init"], cwd=cases_dir, check=True, stdout=subprocess.DEVNULL)
    token_file = tmp_path / "gitlab-token"
    token_file.write_text("secret-token\n", encoding="utf-8")
    calls = []

    def fake_run_git(command, *, cwd: Path, env=None) -> None:
        calls.append((list(command), cwd, dict(env or {})))

    monkeypatch.setattr(source_fixtures_module, "_run_git", fake_run_git)

    source_fixtures_module._git_submodule_update(
        cases_dir,
        cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "private-repo",
        remote_url="https://gitlab.com/redhat/rhel/rpms/private-repo.git",
        git_env={"GITLAB_TOKEN_FILE": str(token_file)},
    )

    assert len(calls) == 1
    command, cwd, env = calls[0]
    expected_header = "Authorization: Basic " + base64.b64encode(b"oauth2:secret-token").decode(
        "ascii"
    )
    assert cwd == cases_dir
    assert "secret-token" not in " ".join(command)
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_KEY_0"] == "http.https://gitlab.com/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == expected_header


def test_git_submodule_update_disables_gitlab_prompt_without_token(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    subprocess.run(["git", "init"], cwd=cases_dir, check=True, stdout=subprocess.DEVNULL)
    calls = []

    def fake_run_git(command, *, cwd: Path, env=None) -> None:
        calls.append(dict(env or {}))

    monkeypatch.setattr(source_fixtures_module, "_run_git", fake_run_git)

    source_fixtures_module._git_submodule_update(
        cases_dir,
        cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "private-repo",
        remote_url="https://gitlab.com/redhat/rhel/rpms/private-repo.git",
        git_env={},
    )

    assert calls == [{"GIT_TERMINAL_PROMPT": "0"}]


def test_git_submodule_update_preserves_existing_git_config_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    subprocess.run(["git", "init"], cwd=cases_dir, check=True, stdout=subprocess.DEVNULL)
    calls = []

    def fake_run_git(command, *, cwd: Path, env=None) -> None:
        calls.append(dict(env or {}))

    monkeypatch.setattr(source_fixtures_module, "_run_git", fake_run_git)

    source_fixtures_module._git_submodule_update(
        cases_dir,
        cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "private-repo",
        remote_url="https://gitlab.com/redhat/rhel/rpms/private-repo.git",
        git_env={
            "GITLAB_TOKEN": "secret-token",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "url.file:///fixtures/.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://example.invalid/",
        },
    )

    env = calls[0]
    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_0"] == "url.file:///fixtures/.insteadOf"
    assert env["GIT_CONFIG_VALUE_0"] == "https://example.invalid/"
    assert env["GIT_CONFIG_KEY_1"] == "http.https://gitlab.com/.extraHeader"
    assert env["GIT_CONFIG_VALUE_1"].startswith("Authorization: Basic ")
