from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.reports import write_validation_reports
from ymir_harness.scoring import load_json_file, score_case, score_result_directory
from ymir_harness.validation import validate_case_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ymir-harness",
        description="Validate and score replayed Ymir benchmark cases.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate-cases",
        help="validate a benchmark_cases directory before running agents",
    )
    validate.add_argument("cases_dir", type=Path)
    validate.add_argument("--phase", type=int, choices=(1, 2), default=1)
    validate.add_argument(
        "--reports-dir",
        type=Path,
        help="directory for fixture-validation reports; defaults to CASES_DIR/reports",
    )
    validate.add_argument(
        "--json",
        action="store_true",
        help="print the validation report JSON to stdout",
    )
    validate.set_defaults(func=_cmd_validate_cases)

    score = subparsers.add_parser(
        "score-result",
        help="compare one expected JSON file with one actual result JSON file",
    )
    score.add_argument("expected_json", type=Path)
    score.add_argument("actual_json", type=Path)
    score.add_argument(
        "--output",
        type=Path,
        help="write the score report JSON to this path instead of stdout",
    )
    score.set_defaults(func=_cmd_score_result)

    score_many = subparsers.add_parser(
        "score-results",
        help="score every expected case with actual result files from a directory",
    )
    score_many.add_argument("cases_dir", type=Path)
    score_many.add_argument("actual_results_dir", type=Path)
    score_many.add_argument(
        "--output",
        type=Path,
        help="write aggregate score JSON to this path; defaults to CASES_DIR/reports/results.json",
    )
    score_many.add_argument(
        "--json",
        action="store_true",
        help="print the aggregate score report JSON to stdout",
    )
    score_many.set_defaults(func=_cmd_score_results)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_validate_cases(args: argparse.Namespace) -> int:
    report = validate_case_directory(args.cases_dir, phase=args.phase)
    reports_dir = args.reports_dir or args.cases_dir / "reports"
    write_validation_reports(report, reports_dir)

    if args.json:
        json.dump(report.to_json(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        summary = report.summary()
        sys.stdout.write(
            "fixture validation: "
            f"{summary['valid']} valid, "
            f"{summary['warning-only']} warning-only, "
            f"{summary['invalid']} invalid, "
            f"{summary['skipped']} skipped\n"
        )
        sys.stdout.write(f"reports written to {reports_dir}\n")

    return 1 if report.has_blocking_errors else 0


def _cmd_score_result(args: argparse.Namespace) -> int:
    expected = load_json_file(args.expected_json)
    actual = load_json_file(args.actual_json)
    report = score_case(expected, actual)
    payload = json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    return 0 if report.passed else 1


def _cmd_score_results(args: argparse.Namespace) -> int:
    report = score_result_directory(args.cases_dir, args.actual_results_dir)
    output_path = args.output or args.cases_dir / "reports" / "results.json"
    payload = json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload, encoding="utf-8")

    if args.json:
        sys.stdout.write(payload)
    else:
        summary = report.summary()
        sys.stdout.write(
            "score results: "
            f"{summary['headline_passed']} headline passed, "
            f"{summary['headline_failed']} headline failed, "
            f"{summary['headline_missing']} headline missing, "
            f"{summary['non_headline']} non-headline\n"
        )
        sys.stdout.write(f"report written to {output_path}\n")

    return 1 if report.has_headline_failures else 0
