"""Ymir benchmark harness utilities."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _read_source_tree_version() -> str:
    return (
        (Path(__file__).resolve().parents[2] / "VERSION")
        .read_text(
            encoding="utf-8",
        )
        .strip()
    )


try:
    __version__ = version("ymir-harness")
except PackageNotFoundError:
    __version__ = _read_source_tree_version()
