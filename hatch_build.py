from __future__ import annotations

import subprocess
from pathlib import Path

from hatchling.metadata.plugin.interface import MetadataHookInterface


class YmirHarnessMetadataHook(MetadataHookInterface):
    def update(self, metadata: dict) -> None:
        root = Path(self.root)
        _ensure_ui_workflows_submodule(root)
        metadata["dependencies"] = [
            "PyYAML>=6.0",
            "ymir-common",
            "ymir-tools",
            "litellm!=1.82.7,!=1.82.8",
            "arize-phoenix-otel>=0.13.0",
            "beautifulsoup4>=4.13.4",
            "beeai-framework[duckduckgo,mcp]==0.1.80",
            "fastmcp>=2.11.3",
            "google-cloud-aiplatform>=1.38",
            "openinference-instrumentation-beeai>=0.1.8",
            "typer>=0.16.0",
            "backoff>=2.2.1",
            "tomli-w>=1.2.0",
            "sentry-sdk>=2.13.0",
        ]


def _ensure_ui_workflows_submodule(root: Path) -> None:
    checkout = root / "ai-workflows"
    if _looks_like_ymir_checkout(checkout):
        return

    if not (root / ".git").exists():
        message = (
            "ai-workflows is not initialized; run "
            "`git submodule update --init ai-workflows` before syncing"
        )
        raise RuntimeError(message)

    completed = subprocess.run(
        ["git", "-C", str(root), "submodule", "update", "--init", "ai-workflows"],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        message = "failed to initialize ai-workflows submodule"
        if details:
            message = f"{message}: {details}"
        raise RuntimeError(message)

    if not _looks_like_ymir_checkout(checkout):
        raise RuntimeError("ai-workflows submodule did not provide the ymir package")


def _looks_like_ymir_checkout(path: Path) -> bool:
    return (path / "ymir" / "agents").is_dir()
