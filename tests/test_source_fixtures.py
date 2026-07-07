from __future__ import annotations

import base64
import os
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


def test_historical_source_fixture_materialization_prunes_future_objects(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch", "main"],
        cwd=cases_dir,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    source_repo = tmp_path / "source"
    old_commit, future_commit = _create_dated_source_repo(source_repo)
    remote_url = "https://gitlab.com/redhat/centos-stream/rpms/testpkg.git"

    source_fixtures_module.write_source_fixture_from_repository(
        cases_dir,
        "RHEL-12345",
        source_repo,
        remote_url=remote_url,
        as_of="2026-04-15T00:00:00Z",
        overwrite=True,
    )

    assert source_fixtures_module.source_cache_contains_object(
        cases_dir,
        "RHEL-12345",
        remote_url,
        old_commit,
    )
    assert not source_fixtures_module.source_cache_contains_object(
        cases_dir,
        "RHEL-12345",
        remote_url,
        future_commit,
    )
    assert source_fixtures_module.source_cache_repo_for_object(
        cases_dir,
        "RHEL-12345",
        remote_url,
        old_commit,
    )
    assert (
        source_fixtures_module.source_cache_repo_for_object(
            cases_dir,
            "RHEL-12345",
            remote_url,
            future_commit,
        )
        is None
    )

    source_cache_dir = source_fixtures_module.materialize_case_source_cache(
        cases_dir,
        "RHEL-12345",
        tmp_path / "materialized-source-cache",
    )
    repository = source_fixtures_module.find_source_cache_repository(source_cache_dir, remote_url)

    assert repository is not None
    assert source_fixtures_module.git_object_exists(repository, old_commit)
    assert not source_fixtures_module.git_object_exists(repository, future_commit)


def test_historical_source_fixture_materialization_batches_ref_fetches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = []

    def fake_run_git(command, *, cwd: Path, env=None) -> None:
        calls.append(list(command))

    monkeypatch.setattr(source_fixtures_module, "_run_git", fake_run_git)
    monkeypatch.setattr(source_fixtures_module, "git_object_exists", lambda _repo, _obj: True)

    refs = tuple(
        source_fixtures_module.SourceFixtureRef(
            name=f"refs/heads/branch-{index}",
            object=f"{index:040x}",
        )
        for index in range(513)
    )
    fixture = source_fixtures_module.SourceFixtureRepository(
        name="large-repo",
        remote_url="https://github.com/example/large-repo",
        manifest_path=tmp_path / "large-repo.json",
        path="source_cache/RHEL-12345/upstream/large-repo",
        refs=refs,
        head_object=refs[0].object,
        replay_as_of="2026-04-27T17:13:39Z",
    )

    source_fixtures_module._initialize_historical_source_fixture_repository(
        tmp_path / "large-repo",
        fixture,
        tmp_path / "materialized.git",
    )

    fetches = [command for command in calls if "fetch" in command]

    assert len(fetches) == 2
    assert len(fetches[0]) == 517
    assert len(fetches[1]) == 6
    assert all("ymir-harness-head" not in " ".join(fetch) for fetch in fetches)


def _create_dated_source_repo(repository: Path) -> tuple[str, str]:
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch", "main"],
        cwd=repository,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repository, check=True)

    old_commit = _commit_file(repository, "2026-04-01T00:00:00Z", "old\n", "old")
    future_commit = _commit_file(repository, "2026-05-01T00:00:00Z", "future\n", "future")
    return old_commit, future_commit


def _commit_file(repository: Path, commit_date: str, content: str, message: str) -> str:
    (repository / "package.spec").write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "package.spec"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repository,
        check=True,
        stdout=subprocess.DEVNULL,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": commit_date,
            "GIT_COMMITTER_DATE": commit_date,
        },
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
