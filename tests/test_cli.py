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
