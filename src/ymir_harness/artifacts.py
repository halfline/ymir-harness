from __future__ import annotations

from pathlib import Path


def artifact_environment(actual_path: Path) -> dict[str, str]:
    artifact_dir = (
        actual_path.parent.parent / "artifacts" / actual_path.stem.removesuffix(".actual")
    )
    return {"YMIR_BENCHMARK_ARTIFACT_DIR": str(artifact_dir)}
