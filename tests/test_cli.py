from __future__ import annotations

import json
from pathlib import Path

import pytest

from ymir_harness import __version__
from ymir_harness.cli import main


def test_cli_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"ymir-harness {__version__}\n"


def test_cli_scores_result_to_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    expected_path = tmp_path / "expected.json"
    actual_path = tmp_path / "actual.json"
    expected_path.write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            }
        ),
        encoding="utf-8",
    )
    actual_path.write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "dnsmasq",
            }
        ),
        encoding="utf-8",
    )

    assert main(["score-result", str(expected_path), str(actual_path)]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["passed"] is True


def test_cli_scores_result_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    output_path = tmp_path / "reports" / "results.json"
    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "dnsmasq",
            "expected_basis": "historical_jira_state",
            "ground_truth_confidence": "high",
            "answer_leakage": "none",
            "case_status": "active",
            "network_mode": "replay_only",
            "requires_source_cache": False,
        },
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )

    assert (
        main(
            [
                "score-results",
                str(cases_dir),
                str(actual_dir),
                "--output",
                str(output_path),
                "--run-id",
                "baseline-1",
                "--ymir-sha",
                "6e22912f83d57ddae1031e6207d4716171a99be0",
                "--variant",
                "baseline",
            ]
        )
        == 0
    )

    assert "1 headline passed" in capsys.readouterr().out
    output = json.loads(output_path.read_text(encoding="utf-8"))
    assert output["summary"]["headline_passed"] == 1
    assert output["run_id"] == "baseline-1"
    assert output["ymir_sha"] == "6e22912f83d57ddae1031e6207d4716171a99be0"
    assert output["variant"] == "baseline"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")