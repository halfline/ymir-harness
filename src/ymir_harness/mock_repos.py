from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class MockRepoMaterializationError(RuntimeError):
    """Raised when benchmark mock repositories cannot be prepared."""


@dataclass(frozen=True)
class MaterializedRepo:
    package: str
    branch: str
    original_url: str
    local_path: Path
    pre_fix_ref: str

    def to_json(self) -> dict[str, str]:
        return {
            "package": self.package,
            "branch": self.branch,
            "original_url": self.original_url,
            "local_path": str(self.local_path),
            "pre_fix_ref": self.pre_fix_ref,
        }


@dataclass(frozen=True)
class MockRepoEnvironment:
    workdir: Path
    gitconfig_path: Path | None = None
    repos: tuple[MaterializedRepo, ...] = ()
    blocked_urls: tuple[str, ...] = ()
    zstream_override: Mapping[str, str] = field(default_factory=dict)

    def to_environment(self) -> dict[str, str]:
        env = {
            "YMIR_BENCHMARK_MOCK_REPOS_WORKDIR": str(self.workdir),
            "YMIR_BENCHMARK_MOCK_REPOS": json.dumps(
                [repo.to_json() for repo in self.repos],
                sort_keys=True,
            ),
        }
        if self.gitconfig_path is not None:
            env["GIT_CONFIG_GLOBAL"] = str(self.gitconfig_path)
            env["YMIR_BENCHMARK_GITCONFIG"] = str(self.gitconfig_path)
        if self.blocked_urls:
            env["MOCK_BLOCKED_URLS"] = "\n".join(self.blocked_urls)
        if self.zstream_override:
            env["YMIR_BENCHMARK_ZSTREAM_OVERRIDE"] = json.dumps(
                dict(self.zstream_override),
                sort_keys=True,
            )
        return env


def materialize_case_mock_repos(
    cases_dir: Path,
    results_dir: Path,
    case_id: str,
    *,
    repetition: int,
) -> MockRepoEnvironment | None:
    mock_paths = sorted((cases_dir / "mock_data").glob(f"*/{case_id}.json"))
    if not mock_paths:
        return None

    workdir = results_dir / f"repeat-{repetition}" / "mock-repos" / case_id
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    repos: list[MaterializedRepo] = []
    blocked_urls: list[str] = []
    zstream_override: dict[str, str] = {}
    git_rewrites: list[tuple[str, str]] = []

    for mock_path in mock_paths:
        config = _load_mock_config(mock_path)
        zstream_override.update(_string_mapping(config.get("zstream_override")))
        for index, repo_config in enumerate(_repo_configs(config, mock_path)):
            remote_url = repo_config.get("remote_url")
            if isinstance(remote_url, str) and remote_url:
                blocked_urls.extend(_remote_url_aliases(remote_url))
            materialized = _materialize_repo(repo_config, index, mock_path, workdir)
            if materialized is None:
                continue
            repos.append(materialized)
            git_rewrites.extend(
                (url, _git_url(materialized.local_path))
                for url in _remote_url_aliases(materialized.original_url)
            )

        for blocked_url in _string_list(config.get("blocked_original_urls")):
            blocked_urls.append(blocked_url)

    gitconfig_path = None
    if git_rewrites:
        gitconfig_path = workdir / "gitconfig"
        _write_gitconfig(gitconfig_path, git_rewrites)

    return MockRepoEnvironment(
        workdir=workdir,
        gitconfig_path=gitconfig_path,
        repos=tuple(repos),
        blocked_urls=tuple(dict.fromkeys(blocked_urls)),
        zstream_override=zstream_override,
    )


def _load_mock_config(path: Path) -> Mapping[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MockRepoMaterializationError(f"cannot read mock fixture {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise MockRepoMaterializationError(f"mock fixture must contain an object: {path}")
    return data


def _repo_configs(config: Mapping[str, Any], mock_path: Path) -> list[Mapping[str, Any]]:
    repos = config.get("repos")
    if not isinstance(repos, list):
        raise MockRepoMaterializationError(f"mock fixture repos must be a list: {mock_path}")
    output = []
    for index, repo in enumerate(repos):
        if not isinstance(repo, Mapping):
            raise MockRepoMaterializationError(
                f"mock fixture repos[{index}] must be an object: {mock_path}"
            )
        output.append(repo)
    return output


def _materialize_repo(
    repo_config: Mapping[str, Any],
    index: int,
    mock_path: Path,
    workdir: Path,
) -> MaterializedRepo | None:
    package = _required_string(repo_config, "package", mock_path, index)
    branch = _required_string(repo_config, "branch", mock_path, index)
    remote_url = _required_string(repo_config, "remote_url", mock_path, index)
    pre_fix_ref = _required_string(repo_config, "pre_fix_ref", mock_path, index)
    source_url = _optional_string(repo_config, "source_url", mock_path, index)

    source = _cloneable_source(source_url or remote_url)
    if source is None:
        return None

    destination = workdir / _repo_dir_name(package, index)
    _run_git(["clone", "--quiet", source, str(destination)], mock_path)
    _run_git(["-C", str(destination), "checkout", "--quiet", "--detach", pre_fix_ref], mock_path)

    return MaterializedRepo(
        package=package,
        branch=branch,
        original_url=remote_url,
        local_path=destination,
        pre_fix_ref=pre_fix_ref,
    )


def _required_string(
    repo_config: Mapping[str, Any],
    field: str,
    mock_path: Path,
    index: int,
) -> str:
    value = repo_config.get(field)
    if not isinstance(value, str) or not value:
        raise MockRepoMaterializationError(
            f"mock fixture repos[{index}].{field} must be a non-empty string: {mock_path}"
        )
    return value


def _optional_string(
    repo_config: Mapping[str, Any],
    field: str,
    mock_path: Path,
    index: int,
) -> str | None:
    value = repo_config.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise MockRepoMaterializationError(
            f"mock fixture repos[{index}].{field} must be a non-empty string: {mock_path}"
        )
    return value


def _cloneable_source(remote_url: str) -> str | None:
    parsed = urlparse(remote_url)
    if parsed.scheme == "file":
        return remote_url
    if parsed.scheme in {"http", "https", "ssh", "git"}:
        return None

    path = Path(remote_url)
    if path.is_absolute() or path.exists():
        return str(path)
    return None


def _repo_dir_name(package: str, index: int) -> str:
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in package)
    return f"{index:02d}-{safe or 'repo'}"


def _run_git(command: list[str], mock_path: Path) -> None:
    completed = subprocess.run(
        ["git", *command],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise MockRepoMaterializationError(
            f"git {' '.join(command)} failed for {mock_path}{detail}"
        )


def _git_url(path: Path) -> str:
    return path.resolve().as_uri()


def _write_gitconfig(path: Path, rewrites: list[tuple[str, str]]) -> None:
    lines = []
    for original_url, local_url in dict.fromkeys(rewrites):
        lines.extend(
            [
                f'[url "{local_url}"]',
                f"\tinsteadOf = {original_url}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def _remote_url_aliases(remote_url: str) -> tuple[str, ...]:
    parsed = urlparse(remote_url)
    if parsed.scheme not in {"http", "https", "ssh", "git"}:
        return (remote_url,)
    aliases = [remote_url]
    if remote_url.endswith(".git"):
        aliases.append(remote_url.removesuffix(".git"))
    else:
        aliases.append(f"{remote_url}.git")
    return tuple(dict.fromkeys(aliases))


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = value.strip()
        return [value] if value else []
    if not isinstance(value, list | tuple):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _string_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(item, str) and item}
