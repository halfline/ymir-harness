from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BackportArtifactCapture:
    generated_artifacts: list[str] = field(default_factory=list)
    touched_files: list[str] = field(default_factory=list)
    spec_patches: list[str] = field(default_factory=list)
    unrelated_source_changes: list[str] = field(default_factory=list)
    manifest_path: Path | None = None
    warnings: list[str] = field(default_factory=list)


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


def capture_backport_artifacts(
    *,
    case_id: str,
    package: str,
    state: Any,
    payload: Mapping[str, Any],
    request_artifact_dir: Path | None,
) -> BackportArtifactCapture:
    capture = BackportArtifactCapture()
    if request_artifact_dir is None:
        return capture

    artifact_dir = request_artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "case_id": case_id,
        "workflow": "ymir-backport",
        "captured_files": {},
        "source_paths": {},
        "touched_files": [],
        "spec_patches": [],
        "unrelated_source_changes": [],
        "warnings": [],
    }

    srpm_path = _path_or_none(payload.get("srpm_path"))
    if srpm_path is not None:
        manifest["source_paths"]["srpm_path"] = str(srpm_path)
        copied_srpm = _copy_existing_file(
            srpm_path,
            artifact_dir / "srpms" / srpm_path.name,
            capture.warnings,
        )
        if copied_srpm is not None:
            capture.generated_artifacts.append(str(copied_srpm))
            manifest["captured_files"]["srpm"] = str(copied_srpm)

    result_path = artifact_dir / "backport_result.json"
    result_path.write_text(_json_dumps(dict(payload)), encoding="utf-8")
    capture.generated_artifacts.append(str(result_path))
    manifest["captured_files"]["backport_result"] = str(result_path)

    log_result = _model_payload(_field_value(state, "log_result"))
    if log_result:
        log_path = artifact_dir / "log_result.json"
        log_path.write_text(_json_dumps(log_result), encoding="utf-8")
        capture.generated_artifacts.append(str(log_path))
        manifest["captured_files"]["log_result"] = str(log_path)

    local_clone = _path_or_none(_field_value(state, "local_clone"))
    if local_clone is not None:
        manifest["source_paths"]["local_clone"] = str(local_clone)
        if local_clone.is_dir():
            _capture_git_backport_files(
                local_clone=local_clone,
                package=package,
                artifact_dir=artifact_dir,
                capture=capture,
                manifest=manifest,
            )
        else:
            capture.warnings.append(f"local_clone is not a directory: {local_clone}")

    manifest["touched_files"] = capture.touched_files
    manifest["spec_patches"] = capture.spec_patches
    manifest["unrelated_source_changes"] = capture.unrelated_source_changes
    manifest["warnings"] = capture.warnings
    manifest_path = artifact_dir / "manifest.json"
    manifest_path.write_text(_json_dumps(manifest), encoding="utf-8")
    capture.generated_artifacts.append(str(manifest_path))
    capture.manifest_path = manifest_path
    return capture


def _capture_git_backport_files(
    *,
    local_clone: Path,
    package: str,
    artifact_dir: Path,
    capture: BackportArtifactCapture,
    manifest: dict[str, Any],
) -> None:
    diff = _git_output(local_clone, "diff", "HEAD~1", "HEAD")
    if diff is not None and diff.strip():
        diff_path = artifact_dir / "commit.diff"
        diff_path.write_text(diff, encoding="utf-8")
        capture.generated_artifacts.append(str(diff_path))
        manifest["captured_files"]["commit_diff"] = str(diff_path)

    touched_files = _git_name_output(local_clone, "diff", "HEAD~1", "HEAD", "--name-only")
    capture.touched_files.extend(touched_files)

    spec_path = local_clone / f"{package}.spec"
    spec_text = None
    if spec_path.is_file():
        spec_capture_path = artifact_dir / "spec_file.spec"
        spec_text = spec_path.read_text(encoding="utf-8", errors="replace")
        spec_capture_path.write_text(spec_text, encoding="utf-8")
        capture.generated_artifacts.append(str(spec_capture_path))
        manifest["captured_files"]["spec_file"] = str(spec_capture_path)
    else:
        capture.warnings.append(f"spec file not found: {spec_path}")

    patch_files = _changed_patch_files(local_clone, touched_files)
    if patch_files:
        patches_dir = artifact_dir / "patches"
        patches_dir.mkdir(parents=True, exist_ok=True)
        copied_patch_paths = []
        for patch_path in patch_files:
            copied_patch = _copy_existing_file(
                patch_path,
                patches_dir / patch_path.name,
                capture.warnings,
            )
            if copied_patch is None:
                continue
            capture.generated_artifacts.append(str(copied_patch))
            copied_patch_paths.append(str(copied_patch))
        if copied_patch_paths:
            manifest["captured_files"]["patch_files"] = copied_patch_paths

    if spec_text is not None:
        patch_names = {path.name for path in patch_files}
        capture.spec_patches.extend(_spec_patch_lines(spec_text, patch_names))

    capture.unrelated_source_changes.extend(
        _unrelated_changed_files(touched_files, package=package)
    )


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


def _path_or_none(value: Any) -> Path | None:
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value.strip():
        return Path(value)
    return None


def _model_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        return {}
    return payload if isinstance(payload, dict) else {}


def _json_dumps(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _copy_existing_file(source: Path, destination: Path, warnings: list[str]) -> Path | None:
    if not source.is_file():
        warnings.append(f"artifact file not found: {source}")
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve(strict=False) == destination.resolve(strict=False):
        return destination
    try:
        shutil.copy2(source, destination)
    except OSError as exc:
        warnings.append(f"could not copy artifact {source}: {exc}")
        return None
    return destination


def _git_output(repo_path: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout


def _git_name_output(repo_path: Path, *args: str) -> list[str]:
    output = _git_output(repo_path, *args)
    if output is None:
        return []
    return [line for line in output.splitlines() if line.strip()]


def _changed_patch_files(repo_path: Path, changed_files: list[str]) -> list[Path]:
    patch_suffixes = (".patch", ".diff")
    return [
        repo_path / path
        for path in changed_files
        if path.endswith(patch_suffixes) and (repo_path / path).is_file()
    ]


def _spec_patch_lines(spec_text: str, patch_names: set[str]) -> list[str]:
    patch_lines = []
    for line in spec_text.splitlines():
        patch_line = _patch_tag_line(line)
        if patch_line is not None:
            patch_lines.append(patch_line)
    if not patch_names:
        return patch_lines
    return [
        line
        for line in patch_lines
        if any(patch_name in line for patch_name in sorted(patch_names))
    ]


def _patch_tag_line(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    head = stripped.split(":", 1)[0]
    if not head.lower().startswith("patch"):
        return None
    return stripped if ":" in stripped else None


def _unrelated_changed_files(changed_files: list[str], *, package: str) -> list[str]:
    allowed_names = {f"{package}.spec", "sources"}
    unrelated = []
    for path in changed_files:
        name = Path(path).name
        if name in allowed_names or name.endswith((".patch", ".diff")):
            continue
        unrelated.append(path)
    return unrelated


def _unique_strings(values: list[str]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
