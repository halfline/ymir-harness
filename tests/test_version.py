from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

from ymir_harness import __version__


def test_version_comes_from_version_file() -> None:
    expected = (
        (Path(__file__).resolve().parents[1] / "VERSION")
        .read_text(
            encoding="utf-8",
        )
        .strip()
    )

    assert __version__ == expected
    assert version("ymir-harness") == expected
