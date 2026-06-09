from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

YMIR_WORKFLOWS_SUBMODULE = "ui-workflows"


def harness_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_ymir_source_path() -> Path:
    return harness_root() / YMIR_WORKFLOWS_SUBMODULE


def ensure_ymir_source_path(source_path: Path | None = None) -> Path | None:
    checkout = (source_path or default_ymir_source_path()).resolve()
    if _looks_like_ymir_checkout(checkout):
        _prepend_sys_path(checkout)
        return checkout

    if _ymir_module_loaded() or importlib.util.find_spec("ymir") is not None:
        return None

    raise ImportError(
        f"Ymir source checkout is not available at {checkout}. "
        f"Run `git submodule update --init {YMIR_WORKFLOWS_SUBMODULE}` from "
        "the ymir-harness checkout, or install ymir into the active environment."
    )


def _looks_like_ymir_checkout(path: Path) -> bool:
    return (path / "ymir").is_dir() and (path / "ymir" / "agents").is_dir()


def _prepend_sys_path(path: Path) -> None:
    for existing in sys.path:
        try:
            if Path(existing or ".").resolve() == path:
                return
        except OSError:
            continue
    sys.path.insert(0, str(path))


def _ymir_module_loaded() -> bool:
    return any(name == "ymir" or name.startswith("ymir.") for name in sys.modules)
