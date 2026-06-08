from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any


def artifact_environment(actual_path: Path) -> dict[str, str]:
    artifact_dir = (
        actual_path.parent.parent / "artifacts" / actual_path.stem.removesuffix(".actual")
    )
    return {"YMIR_BENCHMARK_ARTIFACT_DIR": str(artifact_dir)}


def merge_artifact_fields(
    actual: dict[str, Any],
    *,
    request_artifact_dir: Path | None,
    state: Any,
    payload: Mapping[str, Any],
) -> None:
    artifacts = _unique_strings(
        [
            *_artifact_values(actual.get("generated_artifacts")),
            *_artifact_values(payload),
            *_artifact_values(_field_value(state, "artifacts")),
            *_artifact_values(_field_value(state, "generated_artifacts")),
            *_artifact_dir_files(request_artifact_dir),
        ]
    )
    if artifacts:
        actual["generated_artifacts"] = artifacts

    touched_files = _unique_strings(
        [
            *_string_list(actual.get("touched_files")),
            *_string_list(payload.get("files_to_git_add")),
            *_string_list(payload.get("touched_files")),
            *_string_list(payload.get("changed_files")),
            *_string_list(_field_value(state, "touched_files")),
            *_string_list(_field_value(state, "changed_files")),
        ]
    )
    if touched_files:
        actual["touched_files"] = touched_files

    for name in ("spec_patches", "changelog_entries", "unrelated_source_changes"):
        values = _unique_strings(
            [
                *_string_list(actual.get(name)),
                *_string_list(payload.get(name)),
                *_string_list(_field_value(state, name)),
            ]
        )
        if values:
            actual[name] = values


def _artifact_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        values = []
        for key in (
            "path",
            "file",
            "filename",
            "srpm_path",
            "patch_path",
            "diff_path",
            "spec_path",
        ):
            values.extend(_string_list(value.get(key)))
        for key in ("artifacts", "generated_artifacts", "files"):
            values.extend(_artifact_values(value.get(key)))
        return values
    if isinstance(value, list | tuple | set):
        values = []
        for item in value:
            values.extend(_artifact_values(item))
        return values
    return _string_list(value)


def _artifact_dir_files(artifact_dir: Path | None) -> list[str]:
    if artifact_dir is None or not artifact_dir.is_dir():
        return []
    return [str(path) for path in sorted(artifact_dir.rglob("*")) if path.is_file()]


def _field_value(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = value.strip()
        return [value] if value else []
    if isinstance(value, Path):
        return [str(value)]
    if isinstance(value, list | tuple | set):
        values = []
        for item in value:
            values.extend(_string_list(item))
        return values
    return []


def _unique_strings(values: list[str]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
