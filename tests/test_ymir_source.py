from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from ymir_harness.ymir_source import ensure_ymir_source_path


def test_ensure_ymir_source_path_prepends_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "ai-workflows"
    (checkout / "ymir" / "agents").mkdir(parents=True)
    monkeypatch.setattr(sys, "path", [str(tmp_path / "other")])

    resolved = ensure_ymir_source_path(checkout)

    assert resolved == checkout.resolve()
    assert sys.path[0] == str(checkout.resolve())


def test_ensure_ymir_source_path_does_not_duplicate_existing_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "ai-workflows"
    (checkout / "ymir" / "agents").mkdir(parents=True)
    monkeypatch.setattr(sys, "path", [str(checkout.resolve())])

    ensure_ymir_source_path(checkout)

    assert sys.path == [str(checkout.resolve())]


def test_ensure_ymir_source_path_accepts_loaded_test_modules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "path", [])
    monkeypatch.setitem(sys.modules, "ymir", types.ModuleType("ymir"))

    assert ensure_ymir_source_path(tmp_path / "missing") is None


def test_ensure_ymir_source_path_reports_missing_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "path", [])
    for name in list(sys.modules):
        if name == "ymir" or name.startswith("ymir."):
            monkeypatch.delitem(sys.modules, name, raising=False)

    with pytest.raises(ImportError, match="git submodule update --init ai-workflows"):
        ensure_ymir_source_path(tmp_path / "missing")
