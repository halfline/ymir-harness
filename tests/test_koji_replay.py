from __future__ import annotations

import json
from pathlib import Path

from ymir_harness.koji_replay import (
    candidate_build_branches,
    candidate_build_key,
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
