from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.models import RunCaseResult, RunReport, ValidationReport
from ymir_harness.scoring import _fixture_checksum

RUNNER_NOT_WIRED_REASON = "workflow adapters are not wired yet"


def default_results_dir(cases_dir: Path, run_id: str) -> Path:
    return cases_dir / "reports" / "runs" / run_id


def build_run_report(
    cases_dir: Path,
    results_dir: Path,
    *,
    validation_report: ValidationReport,
    run_id: str,
    variant: str,
    ymir_sha: str | None = None,
    features: Sequence[str] = (),
) -> RunReport:
    cases_dir = cases_dir.resolve()
    results_dir = results_dir.resolve()
    return RunReport(
        cases_dir=cases_dir,
        results_dir=results_dir,
        entries=[
            _run_case_result(cases_dir, case.case_id, case.case_type, case.status)
            for case in validation_report.cases
        ],
        run_id=run_id,
        variant=variant,
        ymir_sha=ymir_sha,
        harness_version=__version__,
        fixture_checksum=_fixture_checksum(cases_dir),
        features=list(features),
    )


def _run_case_result(
    cases_dir: Path,
    case_id: str,
    case_type: str | None,
    validation_status: str,
) -> RunCaseResult:
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    if validation_status == "skipped":
        return RunCaseResult(
            case_id=case_id,
            case_type=case_type,
            status="skipped",
            expected_path=expected_path if expected_path.is_file() else None,
            reason="case is excluded by fixture metadata",
        )

    return RunCaseResult(
        case_id=case_id,
        case_type=case_type,
        status="not_run",
        expected_path=expected_path if expected_path.is_file() else None,
        reason=RUNNER_NOT_WIRED_REASON,
    )
