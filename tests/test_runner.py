from __future__ import annotations

from pathlib import Path

from ymir_harness.models import CaseValidationResult, ValidationReport
from ymir_harness.runner import build_run_report


def test_build_run_report_assigns_actual_paths(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_expected(cases_dir, "RHEL-12345")
    _write_expected(cases_dir, "RHEL-23456")
    validation_report = ValidationReport(
        cases_dir=cases_dir,
        phase=1,
        cases=[
            CaseValidationResult(
                case_id="RHEL-12345",
                case_type="not_affected",
                status="valid",
            ),
            CaseValidationResult(
                case_id="RHEL-23456",
                case_type="not_affected",
                status="skipped",
            ),
        ],
    )

    report = build_run_report(
        cases_dir,
        results_dir,
        validation_report=validation_report,
        run_id="baseline-1",
        variant="baseline",
        repeat=2,
    )

    entries = {(entry.case_id, entry.repetition): entry for entry in report.entries}
    assert entries["RHEL-12345", 1].actual_path == (
        results_dir.resolve() / "repeat-1" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert entries["RHEL-12345", 2].actual_path == (
        results_dir.resolve() / "repeat-2" / "actual-results" / "RHEL-12345.actual.json"
    )
    assert entries["RHEL-23456", 1].actual_path is None
    assert entries["RHEL-23456", 2].actual_path is None


def _write_expected(cases_dir: Path, case_id: str) -> None:
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected_path.parent.mkdir(parents=True, exist_ok=True)
    expected_path.write_text("{}\n", encoding="utf-8")
