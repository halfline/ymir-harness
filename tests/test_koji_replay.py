from __future__ import annotations

import json
import sys
import types
from pathlib import Path

from ymir_harness.koji_replay import (
    candidate_build_branches,
    candidate_build_key,
    fetch_candidate_build,
    higher_stream_branch,
    recorded_candidate_build,
    _candidate_build_is_newer,
)


def test_candidate_build_key_includes_package_and_branch() -> None:
    assert candidate_build_key("redis", "rhel-9.6.0") == "redis|rhel-9.6.0"


def test_candidate_build_branches_includes_higher_zstream() -> None:
    assert candidate_build_branches("rhel-9.6.0") == ("rhel-9.6.0", "rhel-9.7.0")
    assert candidate_build_branches("c9s") == ("c9s",)


def test_higher_stream_branch_preserves_suffix() -> None:
    assert higher_stream_branch("rhel-9.6.0") == "rhel-9.7.0"
    assert higher_stream_branch("rhel-10.10") == "rhel-10.10"
    assert higher_stream_branch("c9s") is None


def test_recorded_candidate_build_reads_manifest_evr(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "recorded_files": {},
                "koji_candidate_builds": {
                    "redis|rhel-9.6.0": {
                        "evr": {
                            "epoch": 0,
                            "version": "6.2.20",
                            "release": "3.el9",
                        },
                        "source_ref": "source-ref",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    evr, source_ref = recorded_candidate_build(manifest, "redis", "rhel-9.6.0")

    assert evr.epoch == 0
    assert evr.version == "6.2.20"
    assert evr.release == "3.el9"
    assert source_ref == "source-ref"


def test_candidate_build_fallback_orders_by_time_and_build_id() -> None:
    class BrokenEvr:
        def __lt__(self, _other):
            raise NotImplementedError

    older = {
        "completion_time": "2025-01-01 00:00:00",
        "nvr": "redis-6.2.20-1.el9",
        "build_id": 10,
    }
    newer = {
        "completion_time": "2025-01-01 00:00:00",
        "nvr": "redis-6.2.20-2.el9",
        "build_id": 11,
    }

    assert _candidate_build_is_newer(BrokenEvr(), newer, (BrokenEvr(), older, "tag"))


def test_fetch_candidate_build_uses_koji_event_for_as_of(monkeypatch) -> None:
    calls = []

    class EVR:
        def __init__(self, *, epoch, version, release):
            self.epoch = epoch
            self.version = version
            self.release = release

        def __lt__(self, other):
            return (self.epoch, self.version, self.release) < (
                other.epoch,
                other.version,
                other.release,
            )

    class ClientSession:
        def __init__(self, url, opts=None):
            self.url = url
            self.opts = opts

        def getLastEvent(self, *, before, strict):
            calls.append(("getLastEvent", before, strict))
            return {"id": 9876, "ts": before - 1}

        def listTagged(self, **kwargs):
            calls.append(("listTagged", kwargs))
            if kwargs["tag"].endswith("-z-candidate"):
                return []
            return [
                {
                    "build_id": 42,
                    "epoch": 0,
                    "version": "6.2.20",
                    "release": "3.el9",
                    "completion_time": "2025-09-12 09:00:00",
                    "nvr": "redis-6.2.20-3.el9",
                }
            ]

        def getBuild(self, build_id, *, strict):
            calls.append(("getBuild", build_id, strict))
            return {"source": "git://example.invalid/redis#abc123"}

    koji_module = types.ModuleType("koji")
    koji_module.ClientSession = ClientSession
    specfile_module = types.ModuleType("specfile")
    specfile_utils_module = types.ModuleType("specfile.utils")
    specfile_utils_module.EVR = EVR
    monkeypatch.setitem(sys.modules, "koji", koji_module)
    monkeypatch.setitem(sys.modules, "specfile", specfile_module)
    monkeypatch.setitem(sys.modules, "specfile.utils", specfile_utils_module)

    record = fetch_candidate_build(
        "redis",
        "rhel-9.6.0",
        as_of="2025-09-12T09:46:42Z",
    )

    assert record["source_ref"] == "abc123"
    assert record["replay_as_of"] == "2025-09-12T09:46:42Z"
    assert record["koji_event"]["id"] == 9876
    list_tagged_calls = [call for call in calls if call[0] == "listTagged"]
    assert [call[1]["event"] for call in list_tagged_calls] == [9876, 9876]
