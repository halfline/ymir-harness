from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SOURCE_FIXTURE_SCHEMA_VERSION = 1
TRAILING_ESCAPED_URL_GARBAGE_RE = re.compile(r"(?:\\+[nrt]|\\+)+$", re.IGNORECASE)


class SourceFixtureError(RuntimeError):
    """Raised when a submodule-backed source fixture cannot be used."""


@dataclass(frozen=True)
class SourceFixtureRef:
    name: str
    object: str


@dataclass(frozen=True)
class SourceFixtureRepository:
    name: str
    remote_url: str
    manifest_path: Path
    path: str
    refs: tuple[SourceFixtureRef, ...]
    head: str | None = None
    head_object: str | None = None

    def ref_object(self, ref_name: str) -> str | None:
        return next((ref.object for ref in self.refs if ref.name == ref_name), None)

    def contains_object(self, obj: str) -> bool:
        return self.head_object == obj or any(ref.object == obj for ref in self.refs)


def source_fixture_name(remote_url: str) -> str:
    parsed = urlparse(remote_url)
    source = parsed.path.rstrip("/").rsplit("/", 1)[-1] if parsed.path else "repo"
    source = source.removesuffix(".git")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in source)
    digest = hashlib.sha256(remote_url.encode("utf-8")).hexdigest()[:12]
    return f"{safe or 'repo'}-{digest}"


def load_source_fixture_repositories(
    cases_dir: Path,
    case_id: str,
) -> tuple[SourceFixtureRepository, ...]:
    upstream_dir = cases_dir / "source_cache" / case_id / "upstream"
    if not upstream_dir.is_dir():
        return ()
    return tuple(
        _load_source_fixture_repository(path) for path in sorted(upstream_dir.glob("*.json"))
    )


def source_fixture_repositories_with_errors(
    cases_dir: Path,
    case_id: str,
) -> tuple[tuple[SourceFixtureRepository, ...], tuple[tuple[Path, str], ...]]:
    upstream_dir = cases_dir / "source_cache" / case_id / "upstream"
    if not upstream_dir.is_dir():
        return (), ()

    repositories = []
    errors = []
    for path in sorted(upstream_dir.glob("*.json")):
        try:
            repositories.append(_load_source_fixture_repository(path))
        except SourceFixtureError as exc:
            errors.append((path, str(exc)))
    return tuple(repositories), tuple(errors)


def source_fixture_path(
    cases_dir: Path,
    case_id: str,
    fixture: SourceFixtureRepository,
) -> Path:
    return cases_dir / "source_cache" / case_id / "upstream" / fixture.path


def source_fixture_gitlink_commit(
    cases_dir: Path,
    case_id: str,
    fixture: SourceFixtureRepository,
) -> str | None:
    path = source_fixture_path(cases_dir, case_id, fixture)
    root = git_worktree_root(cases_dir)
    if root is None:
        return None
    rel_path = _relative_to_root(path, root)
    staged = _git_output(["-C", str(root), "ls-files", "--stage", "--", rel_path])
    for line in staged.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "160000":
            return parts[1]

    committed = _git_output(["-C", str(root), "ls-tree", "HEAD", "--", rel_path])
    for line in committed.splitlines():
        metadata, _tab, _path = line.partition("\t")
        parts = metadata.split()
        if len(parts) >= 3 and parts[0] == "160000":
            return parts[2]
    if is_git_checkout(path):
        return git_rev_parse(path, "HEAD")
    return None


def source_fixture_submodule_url(
    cases_dir: Path,
    case_id: str,
    fixture: SourceFixtureRepository,
) -> str | None:
    path = source_fixture_path(cases_dir, case_id, fixture)
    root = git_worktree_root(cases_dir)
    if root is None:
        return None
    rel_path = _relative_to_root(path, root)
    gitmodules = root / ".gitmodules"
    if not gitmodules.is_file():
        return None
    value = _git_output(["config", "-f", str(gitmodules), "--get", f"submodule.{rel_path}.url"])
    return value.strip() or None


def source_cache_repositories(
    source_cache_dir: Path,
) -> tuple[Path, ...]:
    upstream_dir = source_cache_dir / "upstream"
    if not upstream_dir.is_dir():
        return ()
    return source_cache_git_repositories(upstream_dir)


def source_cache_git_repositories(upstream_dir: Path) -> tuple[Path, ...]:
    candidates = [upstream_dir, *sorted(upstream_dir.iterdir())]
    repositories = [
        candidate
        for candidate in candidates
        if candidate.is_dir() and (is_git_checkout(candidate) or is_bare_git_repository(candidate))
    ]
    return tuple(dict.fromkeys(repositories))


def find_source_cache_repository(
    source_cache_dir: Path,
    remote_url: str,
    *,
    obj: str | None = None,
) -> Path | None:
    repositories = source_cache_repositories(source_cache_dir)
    for exact in (True, False):
        expected_aliases = _source_cache_match_aliases(remote_url, exact=exact)
        for repository in repositories:
            cached_remote = git_remote_url(repository)
            if cached_remote is None:
                continue
            if expected_aliases & _source_cache_match_aliases(cached_remote, exact=exact):
                if obj is not None and not git_object_exists(repository, obj):
                    continue
                return repository
    return None


def find_source_fixture_repository(
    cases_dir: Path,
    case_id: str,
    remote_url: str,
    *,
    ref_name: str | None = None,
    obj: str | None = None,
) -> SourceFixtureRepository | None:
    repositories = load_source_fixture_repositories(cases_dir, case_id)
    for exact in (True, False):
        expected_aliases = _source_cache_match_aliases(remote_url, exact=exact)
        for repository in repositories:
            if expected_aliases & _source_cache_match_aliases(repository.remote_url, exact=exact):
                if ref_name is not None and repository.ref_object(ref_name) is None:
                    continue
                if obj is not None and not _source_fixture_has_object(
                    cases_dir,
                    case_id,
                    repository,
                    obj,
                ):
                    continue
                return repository
    return None


def _source_cache_match_aliases(remote_url: str, *, exact: bool) -> set[str]:
    aliases = remote_git_aliases(remote_url) if exact else source_cache_git_aliases(remote_url)
    return set(aliases)


def resolve_source_cache_ref(
    cases_dir: Path,
    case_id: str,
    remote_url: str,
    ref_name: str,
) -> str | None:
    fixture = find_source_fixture_repository(cases_dir, case_id, remote_url, ref_name=ref_name)
    return fixture.ref_object(ref_name) if fixture is not None else None


def source_cache_contains_object(cases_dir: Path, case_id: str, remote_url: str, obj: str) -> bool:
    fixture = find_source_fixture_repository(cases_dir, case_id, remote_url, obj=obj)
    if fixture is None:
        return False
    return _source_fixture_has_object(cases_dir, case_id, fixture, obj)


def source_cache_repo_for_object(
    cases_dir: Path,
    case_id: str,
    remote_url: str,
    obj: str | None = None,
) -> Path | None:
    fixture = find_source_fixture_repository(cases_dir, case_id, remote_url, obj=obj)
    if fixture is None:
        return None
    submodule = source_fixture_path(cases_dir, case_id, fixture)
    if not is_git_checkout(submodule):
        return None
    if obj is None or git_object_exists(submodule, obj):
        return submodule
    return None


def _source_fixture_has_object(
    cases_dir: Path,
    case_id: str,
    fixture: SourceFixtureRepository,
    obj: str,
) -> bool:
    if fixture.contains_object(obj):
        return True
    submodule = source_fixture_path(cases_dir, case_id, fixture)
    return submodule.exists() and is_git_checkout(submodule) and git_object_exists(submodule, obj)


def materialize_case_source_cache(
    cases_dir: Path,
    case_id: str,
    destination: Path,
) -> Path:
    source_cache_dir = cases_dir / "source_cache" / case_id
    fixtures = load_source_fixture_repositories(cases_dir, case_id)
    if not fixtures and not source_cache_dir.exists():
        return source_cache_dir

    if destination.exists():
        shutil.rmtree(destination)
    upstream_destination = destination / "upstream"

    for fixture in fixtures:
        upstream_destination.mkdir(parents=True, exist_ok=True)
        _ensure_source_fixture_submodule(cases_dir, case_id, fixture)
        materialize_source_fixture_repository(
            cases_dir,
            case_id,
            fixture,
            upstream_destination / f"{fixture.name}.git",
        )

    source_upstream = source_cache_dir / "upstream"
    if source_upstream.is_dir():
        upstream_destination.mkdir(parents=True, exist_ok=True)
        _link_non_manifest_sources(source_upstream, upstream_destination)

    lookaside = source_cache_dir / "lookaside"
    if lookaside.exists():
        _replace_link(destination / "lookaside", lookaside)

    return destination


def materialize_source_fixture_repository(
    cases_dir: Path,
    case_id: str,
    fixture: SourceFixtureRepository,
    destination: Path,
) -> Path:
    submodule = source_fixture_path(cases_dir, case_id, fixture)
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    _run_git(
        ["clone", "--bare", "--no-hardlinks", str(submodule), str(destination)],
        cwd=destination.parent,
    )
    _run_git(
        ["--git-dir", str(destination), "config", "remote.origin.url", fixture.remote_url],
        cwd=destination.parent,
    )
    _delete_git_refs(destination)

    for ref in fixture.refs:
        _run_git(
            ["--git-dir", str(destination), "update-ref", ref.name, ref.object],
            cwd=destination.parent,
        )

    if fixture.head and any(ref.name == fixture.head for ref in fixture.refs):
        _run_git(
            ["--git-dir", str(destination), "symbolic-ref", "HEAD", fixture.head],
            cwd=destination.parent,
        )
    elif fixture.head_object:
        _run_git(
            ["--git-dir", str(destination), "update-ref", "HEAD", fixture.head_object],
            cwd=destination.parent,
        )

    return destination


def _delete_git_refs(repository: Path) -> None:
    refs = _git_output(["--git-dir", str(repository), "for-each-ref", "--format=%(refname)"])
    for ref_name in refs.splitlines():
        if ref_name:
            _run_git(["--git-dir", str(repository), "update-ref", "-d", ref_name], cwd=repository)


def write_source_fixture_from_repository(
    cases_dir: Path,
    case_id: str,
    repository: Path,
    *,
    remote_url: str | None = None,
    name: str | None = None,
    as_of: str | None = None,
    overwrite: bool = False,
) -> Path:
    remote_url = remote_url or git_remote_url(repository)
    if not remote_url:
        raise SourceFixtureError(f"source repository has no remote.origin.url: {repository}")

    name = name or source_fixture_name(remote_url)
    manifest_path = cases_dir / "source_cache" / case_id / "upstream" / f"{name}.json"
    submodule_path = cases_dir / "source_cache" / case_id / "upstream" / name
    if manifest_path.exists() and not overwrite:
        return manifest_path

    if not is_git_worktree(cases_dir):
        raise SourceFixtureError(f"cases directory is not in a git worktree: {cases_dir}")

    refs = git_refs(repository, as_of=as_of)
    if not refs:
        raise SourceFixtureError(f"source repository has no heads or tags: {repository}")

    head_ref = git_symbolic_ref(repository, "HEAD")
    refs_by_name = dict(refs)
    head_object = (
        refs_by_name.get(head_ref)
        if head_ref is not None
        else _git_rev_list_before(repository, "HEAD", as_of)
    )
    if head_object is None:
        head_object = git_rev_parse(repository, "HEAD") if as_of is None else None
    _ensure_writable_submodule(
        cases_dir,
        submodule_path,
        repository,
        remote_url,
        head_ref=head_ref,
        head_object=head_object,
        overwrite=overwrite,
    )

    payload_refs = [
        {
            "name": ref_name,
            "object": object_name,
        }
        for ref_name, object_name in refs
    ]
    payload: dict[str, Any] = {
        "schema_version": SOURCE_FIXTURE_SCHEMA_VERSION,
        "name": name,
        "path": name,
        "remote_url": remote_url,
        "refs": payload_refs,
    }
    if as_of is not None:
        payload["replay_as_of"] = as_of
    if head_ref is not None and head_ref in refs_by_name:
        payload["head"] = head_ref
    if head_object is not None:
        payload["head_object"] = head_object

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def source_cache_git_rewrites(source_cache_dir: Path) -> tuple[tuple[str, str], ...]:
    repositories = source_cache_repositories(source_cache_dir)
    exact_rewrites: dict[str, str] = {}
    fallback_rewrites: dict[str, str] = {}

    for repository in repositories:
        remote_url = git_remote_url(repository)
        if remote_url is None:
            continue
        local_url = repository.resolve().as_uri()
        for alias in remote_git_aliases(remote_url):
            exact_rewrites.setdefault(alias, local_url)

    for repository in repositories:
        remote_url = git_remote_url(repository)
        if remote_url is None:
            continue
        local_url = repository.resolve().as_uri()
        for alias in source_cache_git_aliases(remote_url):
            if alias in exact_rewrites:
                continue
            fallback_rewrites.setdefault(alias, local_url)

    return tuple(exact_rewrites.items()) + tuple(fallback_rewrites.items())


def source_cache_git_aliases(remote_url: str) -> tuple[str, ...]:
    remote_url = _canonicalize_git_url(remote_url)
    aliases = [*remote_git_aliases(remote_url)]
    parsed = urlparse(remote_url)
    if parsed.scheme in {"http", "https"}:
        parts = [part for part in parsed.path.strip("/").removesuffix(".git").split("/") if part]
        if len(parts) >= 2 and parts[-2] == "rpms":
            package = parts[-1]
            fedora_url = f"https://src.fedoraproject.org/rpms/{parts[-1]}.git"
            aliases.extend(remote_git_aliases(fedora_url))
            if parsed.hostname == "gitlab.com" and len(parts) >= 4 and parts[0] == "redhat":
                for namespace in ("centos-stream", "rhel"):
                    gitlab_url = f"https://gitlab.com/redhat/{namespace}/rpms/{package}.git"
                    aliases.extend(remote_git_aliases(gitlab_url))
        if parsed.hostname in {"github.com", "code.qt.io"} and len(parts) >= 2 and parts[0] == "qt":
            qt_project = "/".join(parts)
            aliases.extend(remote_git_aliases(f"https://github.com/{qt_project}.git"))
            aliases.extend(remote_git_aliases(f"https://code.qt.io/{qt_project}.git"))
        if parsed.hostname == "gitlab.gnome.org" and len(parts) >= 2:
            github_url = f"https://github.com/{'/'.join(parts)}.git"
            aliases.extend(remote_git_aliases(github_url))
    return tuple(dict.fromkeys(aliases))


def remote_git_aliases(remote_url: str) -> tuple[str, ...]:
    remote_url = _canonicalize_git_url(remote_url)
    aliases = [remote_url]
    if remote_url.endswith(".git"):
        aliases.append(remote_url.removesuffix(".git"))
    else:
        aliases.append(f"{remote_url}.git")
    return tuple(dict.fromkeys(aliases))


def git_remote_url(repository: Path) -> str | None:
    completed = subprocess.run(
        git_command(repository, ["config", "--get", "remote.origin.url"]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def git_rev_parse(repository: Path, ref_name: str) -> str | None:
    completed = subprocess.run(
        git_command(repository, ["rev-parse", "--verify", ref_name]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def git_symbolic_ref(repository: Path, ref_name: str) -> str | None:
    completed = subprocess.run(
        git_command(repository, ["symbolic-ref", "-q", ref_name]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def git_object_exists(repository: Path, obj: str) -> bool:
    completed = subprocess.run(
        git_command(repository, ["cat-file", "-e", f"{obj}^{{object}}"]),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return completed.returncode == 0


def git_refs(repository: Path, *, as_of: str | None = None) -> tuple[tuple[str, str], ...]:
    completed = subprocess.run(
        git_command(
            repository,
            [
                "for-each-ref",
                "--format=%(refname)%09%(objectname)",
                "refs/heads",
                "refs/tags",
                "refs/remotes/origin",
            ],
        ),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise SourceFixtureError(f"cannot list source repository refs for {repository}{detail}")

    refs = {}
    for line in completed.stdout.splitlines():
        ref_name, object_name = line.split("\t", 1)
        ref_name = _source_fixture_ref_name(ref_name)
        if ref_name is None or ref_name in refs:
            continue
        if as_of is not None:
            object_name = _git_rev_list_before(repository, object_name, as_of) or ""
            if not object_name:
                continue
        refs[ref_name] = object_name
    return tuple(refs.items())


def _source_fixture_ref_name(ref_name: str) -> str | None:
    if ref_name == "refs/remotes/origin/HEAD":
        return None
    prefix = "refs/remotes/origin/"
    if ref_name.startswith(prefix):
        return f"refs/heads/{ref_name.removeprefix(prefix)}"
    return ref_name


def _git_rev_list_before(repository: Path, rev: str, as_of: str | None) -> str | None:
    if as_of is None:
        return git_rev_parse(repository, rev)
    completed = subprocess.run(
        git_command(repository, ["rev-list", "-n", "1", f"--before={as_of}", rev]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise SourceFixtureError(f"cannot resolve source repository ref {rev} as of {as_of}{detail}")
    return completed.stdout.strip() or None


def git_object_dir(repository: Path) -> Path:
    completed = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--git-path", "objects"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise SourceFixtureError(f"cannot resolve git object directory for {repository}{detail}")
    objects_dir = Path(completed.stdout.strip())
    if not objects_dir.is_absolute():
        objects_dir = repository / objects_dir
    return objects_dir


def git_command(repository: Path, args: Sequence[str]) -> list[str]:
    if is_bare_git_repository(repository):
        _ensure_bare_git_runtime_dirs(repository)
        return ["git", "--git-dir", str(repository), *args]
    return ["git", "-C", str(repository), *args]


def is_git_checkout(path: Path) -> bool:
    return (path / ".git").exists()


def is_bare_git_repository(path: Path) -> bool:
    return (path / "HEAD").is_file() and (path / "objects").is_dir()


def is_git_worktree(path: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def git_worktree_root(path: Path) -> Path | None:
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    output = completed.stdout.strip()
    return Path(output) if output else None


def _load_source_fixture_repository(path: Path) -> SourceFixtureRepository:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceFixtureError(f"cannot read source fixture manifest: {exc}") from exc
    if not isinstance(data, Mapping):
        raise SourceFixtureError("source fixture manifest must contain an object")

    schema_version = data.get("schema_version")
    if schema_version != SOURCE_FIXTURE_SCHEMA_VERSION:
        raise SourceFixtureError(
            f"source fixture manifest schema_version must be {SOURCE_FIXTURE_SCHEMA_VERSION}"
        )

    name = _required_string(data, "name")
    remote_url = _required_string(data, "remote_url")
    refs_value = data.get("refs")
    if not isinstance(refs_value, list) or not refs_value:
        raise SourceFixtureError("source fixture manifest refs must be a non-empty list")

    refs = []
    for index, value in enumerate(refs_value):
        if not isinstance(value, Mapping):
            raise SourceFixtureError(f"source fixture manifest refs[{index}] must be an object")
        refs.append(
            SourceFixtureRef(
                name=_required_string(value, "name"),
                object=_required_string(value, "object"),
            )
        )

    return SourceFixtureRepository(
        name=name,
        path=_required_string(data, "path"),
        remote_url=remote_url,
        manifest_path=path,
        refs=tuple(refs),
        head=_optional_string(data, "head"),
        head_object=_optional_string(data, "head_object"),
    )


def _ensure_source_fixture_submodule(
    cases_dir: Path,
    case_id: str,
    fixture: SourceFixtureRepository,
) -> None:
    path = source_fixture_path(cases_dir, case_id, fixture)
    if not is_git_checkout(path):
        _git_submodule_update(cases_dir, path)
    if not is_git_checkout(path):
        raise SourceFixtureError(f"source fixture submodule is not initialized: {path}")

    _run_git(["remote", "set-url", "origin", fixture.remote_url], cwd=path)
    missing_refspecs = [
        f"+{ref.name}:{ref.name}" for ref in fixture.refs if not git_object_exists(path, ref.object)
    ]
    if fixture.head_object and not git_object_exists(path, fixture.head_object):
        head_refspec = _head_refspec(fixture)
        if head_refspec is not None:
            missing_refspecs.append(head_refspec)
    if missing_refspecs:
        _run_git(
            ["fetch", "--no-tags", "origin", *tuple(dict.fromkeys(missing_refspecs))],
            cwd=path,
        )
    if fixture.head_object:
        _run_git(["checkout", "--quiet", "--detach", fixture.head_object], cwd=path)


def _ensure_writable_submodule(
    cases_dir: Path,
    path: Path,
    repository: Path,
    remote_url: str,
    *,
    head_ref: str | None,
    head_object: str | None,
    overwrite: bool,
) -> None:
    root = git_worktree_root(cases_dir)
    if root is None:
        raise SourceFixtureError(f"cases directory is not in a git worktree: {cases_dir}")
    rel_path = _relative_to_root(path, root)
    if path.exists() and not is_git_checkout(path):
        if not overwrite:
            raise SourceFixtureError(f"source fixture submodule path already exists: {path}")
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

    if not is_git_checkout(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        command = ["-c", "protocol.file.allow=always", "submodule", "add", "--force"]
        branch = _branch_name(head_ref)
        if branch is not None:
            command.extend(["-b", branch])
        command.extend([str(repository.resolve()), rel_path])
        _run_git(command, cwd=root)
        _run_git(["submodule", "absorbgitdirs", "--", rel_path], cwd=root)
        _unstage_submodule_add(root, rel_path)
    else:
        _run_git(["fetch", "--no-tags", str(repository.resolve())], cwd=path)

    _write_submodule_config(root, rel_path, remote_url, head_ref)
    _run_git(["remote", "set-url", "origin", remote_url], cwd=path)
    if head_object is not None:
        _run_git(["checkout", "--quiet", "--detach", head_object], cwd=path)


def _git_submodule_update(cases_dir: Path, path: Path) -> None:
    root = git_worktree_root(cases_dir)
    if root is None:
        raise SourceFixtureError(f"cases directory is not in a git worktree: {cases_dir}")
    rel_path = _relative_to_root(path, root)
    command = [
        "submodule",
        "update",
        "--init",
        "--recursive",
        "--depth",
        "1",
        "--filter=blob:none",
        "--",
        rel_path,
    ]
    try:
        _run_git(command, cwd=root)
    except SourceFixtureError:
        _run_git(["submodule", "update", "--init", "--recursive", "--", rel_path], cwd=root)


def _write_submodule_config(
    root: Path,
    rel_path: str,
    remote_url: str,
    head_ref: str | None,
) -> None:
    gitmodules = root / ".gitmodules"
    _run_git(["config", "-f", str(gitmodules), f"submodule.{rel_path}.path", rel_path], cwd=root)
    _run_git(["config", "-f", str(gitmodules), f"submodule.{rel_path}.url", remote_url], cwd=root)
    branch = _branch_name(head_ref)
    if branch is not None:
        _run_git(
            ["config", "-f", str(gitmodules), f"submodule.{rel_path}.branch", branch],
            cwd=root,
        )


def _unstage_submodule_add(root: Path, rel_path: str) -> None:
    _run_git(["reset", "-q", "--", ".gitmodules", rel_path], cwd=root)


def _head_refspec(fixture: SourceFixtureRepository) -> str | None:
    if fixture.head is not None:
        return f"+{fixture.head}:{fixture.head}"
    return None


def _branch_name(ref_name: str | None) -> str | None:
    if ref_name is None or not ref_name.startswith("refs/heads/"):
        return None
    return ref_name.removeprefix("refs/heads/")


def _link_non_manifest_sources(source: Path, destination: Path) -> None:
    for child in source.iterdir():
        if child.is_file() and child.suffix == ".json":
            continue
        if is_git_checkout(child) or is_bare_git_repository(child):
            continue
        if (destination / child.name).exists() or (destination / child.name).is_symlink():
            continue
        _replace_link(destination / child.name, child)


def _replace_link(link_path: Path, target: Path) -> None:
    if link_path.exists() or link_path.is_symlink():
        if link_path.is_dir() and not link_path.is_symlink():
            shutil.rmtree(link_path)
        else:
            link_path.unlink()
    link_path.parent.mkdir(parents=True, exist_ok=True)
    link_path.symlink_to(target.resolve(), target_is_directory=target.is_dir())


def _ensure_bare_git_runtime_dirs(repository: Path) -> None:
    (repository / "refs" / "heads").mkdir(parents=True, exist_ok=True)
    (repository / "refs" / "tags").mkdir(parents=True, exist_ok=True)


def _required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise SourceFixtureError(f"source fixture manifest {key} must be a non-empty string")
    return value


def _optional_string(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SourceFixtureError(f"source fixture manifest {key} must be a non-empty string")
    return value


def _relative_to_root(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError as exc:
        raise SourceFixtureError(f"source fixture path is outside git worktree: {path}") from exc


def _git_output(command: Sequence[str]) -> str:
    completed = subprocess.run(
        ["git", *command],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout


def _run_git(command: Sequence[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        ["git", *command],
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise SourceFixtureError(f"git command failed ({' '.join(command)}){detail}")


def _canonicalize_git_url(value: Any) -> str:
    url = value if isinstance(value, str) else str(value)
    url = url.strip()
    if not url:
        return url

    url = re.split(r"\\+[nrt]", url, maxsplit=1, flags=re.IGNORECASE)[0]
    split = re.split(r"[\s\"'<>]", url, maxsplit=1)
    url = split[0] if split else url
    previous = None
    while previous != url:
        previous = url
        url = url.rstrip(".,;:)]}\"'")
        url = TRAILING_ESCAPED_URL_GARBAGE_RE.sub("", url)
        url = url.strip()
    return url
