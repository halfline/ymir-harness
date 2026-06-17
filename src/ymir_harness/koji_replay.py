from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ymir_harness.replay import ReplayCacheError

BREWHUB_URL = "https://brewhub.engineering.redhat.com/brewhub"
KOJI_CANDIDATE_BUILDS_MANIFEST_KEY = "koji_candidate_builds"


def candidate_build_key(package: str, dist_git_branch: str) -> str:
    return f"{package}|{dist_git_branch}"


def candidate_build_branches(dist_git_branch: str) -> tuple[str, ...]:
    branches = [dist_git_branch]
    higher = higher_stream_branch(dist_git_branch)
    if higher is not None:
        branches.append(higher)
    return tuple(dict.fromkeys(branches))


def higher_stream_branch(dist_git_branch: str) -> str | None:
    match = re.match(
        r"^(?P<prefix>rhel-(?P<x>\d+)\.)(?P<y>\d+)(?P<suffix>\.\d+)?$",
        dist_git_branch,
    )
    if match is None:
        return None
    y = int(match.group("y"))
    suffix = match.group("suffix") or ""
    return match.group("prefix") + str(min(y + 1, 10)) + suffix


def fetch_candidate_build(package: str, dist_git_branch: str) -> dict[str, Any]:
    try:
        import koji  # type: ignore[import-not-found]
        from specfile.utils import EVR
    except ImportError as exc:
        raise RuntimeError(f"Koji candidate-build capture dependencies are missing: {exc}") from exc

    candidate_tags = [
        f"{dist_git_branch}-candidate",
        f"{dist_git_branch}-z-candidate",
    ]
    session = koji.ClientSession(BREWHUB_URL)
    ssl_verify = True
    latest: tuple[Any, Mapping[str, Any], str] | None = None
    for tag in candidate_tags:
        try:
            builds = _list_tagged(session, package=package, tag=tag)
        except Exception as exc:
            if not _is_ssl_verification_error(exc):
                raise
            session = koji.ClientSession(BREWHUB_URL, opts={"no_ssl_verify": True})
            ssl_verify = False
            builds = _list_tagged(session, package=package, tag=tag)
        if not builds:
            continue
        build = builds[0]
        evr = _evr_from_build(EVR, build)
        if latest is None or _candidate_build_is_newer(evr, build, latest):
            latest = (evr, build, tag)

    if latest is None:
        joined = " or ".join(candidate_tags)
        raise RuntimeError(f"There are no builds of {package} in {joined}")

    evr, build, tag = latest
    metadata = session.getBuild(build["build_id"], strict=True)
    source = str(metadata.get("source") or "")
    source_ref = source.split("#")[-1] if "#" in source else source
    return {
        "package": package,
        "dist_git_branch": dist_git_branch,
        "koji_url": BREWHUB_URL,
        "ssl_verify": ssl_verify,
        "candidate_tags": candidate_tags,
        "selected_tag": tag,
        "build": dict(build),
        "metadata": dict(metadata),
        "evr": _evr_to_json(evr),
        "source_ref": source_ref,
    }


def _list_tagged(session: Any, *, package: str, tag: str) -> list[Mapping[str, Any]]:
    return session.listTagged(
        package=package,
        tag=tag,
        latest=True,
        inherit=True,
        strict=False,
    )


def _is_ssl_verification_error(exc: BaseException) -> bool:
    text = str(exc)
    return "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text


def _candidate_build_is_newer(
    evr: Any,
    build: Mapping[str, Any],
    latest: tuple[Any, Mapping[str, Any], str],
) -> bool:
    latest_evr, latest_build, _latest_tag = latest
    try:
        return latest_evr < evr
    except NotImplementedError:
        return _candidate_sort_key(build) > _candidate_sort_key(latest_build)


def _candidate_sort_key(build: Mapping[str, Any]) -> tuple[str, str, int]:
    return (
        str(build.get("completion_time") or build.get("creation_time") or ""),
        str(build.get("nvr") or ""),
        int(build.get("build_id") or build.get("id") or 0),
    )


def recorded_candidate_build_from_environment(
    package: str,
    dist_git_branch: str,
) -> tuple[Any, str]:
    manifest = os.environ.get("YMIR_BENCHMARK_REPLAY_MANIFEST")
    if not manifest:
        raise ReplayCacheError(
            "Koji candidate build replay miss: "
            f"package={package} dist_git_branch={dist_git_branch} manifest is not set"
        )
    return recorded_candidate_build(Path(manifest), package, dist_git_branch)


def recorded_candidate_build(
    manifest_path: Path,
    package: str,
    dist_git_branch: str,
) -> tuple[Any, str]:
    try:
        from specfile.utils import EVR
    except ImportError as exc:
        raise ReplayCacheError(f"specfile EVR dependency is missing: {exc}") from exc

    records = _load_candidate_build_records(manifest_path)
    key = candidate_build_key(package, dist_git_branch)
    record = records.get(key)
    if not isinstance(record, Mapping):
        raise ReplayCacheError(
            f"Koji candidate build replay miss: package={package} dist_git_branch={dist_git_branch}"
        )

    evr_payload = record.get("evr")
    source_ref = record.get("source_ref")
    if not isinstance(evr_payload, Mapping) or not isinstance(source_ref, str):
        raise ReplayCacheError(
            "Koji candidate build replay record is invalid: "
            f"package={package} dist_git_branch={dist_git_branch}"
        )
    return _evr_from_payload(EVR, evr_payload), source_ref


def _load_candidate_build_records(manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayCacheError(f"cannot read replay manifest: {manifest_path}") from exc
    if not isinstance(manifest, Mapping):
        raise ReplayCacheError(f"replay manifest must contain an object: {manifest_path}")
    records = manifest.get(KOJI_CANDIDATE_BUILDS_MANIFEST_KEY)
    if not isinstance(records, Mapping):
        return {}
    return {key: value for key, value in records.items() if isinstance(key, str)}


def _evr_from_build(evr_type: Any, build: Mapping[str, Any]) -> Any:
    return evr_type(
        epoch=build.get("epoch") or 0,
        version=str(build["version"]),
        release=str(build["release"]),
    )


def _evr_to_json(evr: Any) -> dict[str, Any]:
    return {
        "epoch": evr.epoch,
        "version": evr.version,
        "release": evr.release,
    }


def _evr_from_payload(evr_type: Any, payload: Mapping[str, Any]) -> Any:
    return evr_type(
        epoch=payload.get("epoch") or 0,
        version=str(payload["version"]),
        release=str(payload["release"]),
    )
