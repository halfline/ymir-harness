from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.comparison import compare_result_reports, render_comparison_markdown
from ymir_harness.models import (
    ALLOWED_ANSWER_LEAKAGE,
    ALLOWED_BACKPORT_SOURCES,
    ALLOWED_CASE_STATUSES,
    ALLOWED_CASE_TYPES,
    ALLOWED_EXPECTED_BASES,
    ALLOWED_GROUND_TRUTH_CONFIDENCE,
    ALLOWED_NETWORK_MODES,
    ALLOWED_REFERENCE_PATCH_MODES,
    ALLOWED_RESOLUTIONS,
)
from ymir_harness.reports import write_validation_reports
from ymir_harness.provenance import parse_provenance_items
from ymir_harness.scoring import load_json_file, score_case, score_result_directory
from ymir_harness.validation import validate_case_directory

WORKFLOW_CHOICES = ("none", "ymir-triage", "ymir-backport", "ymir-rebase", "ymir-rebuild")


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
    validate.add_argument(
        "--workflow",
        choices=WORKFLOW_CHOICES,
        default="none",
        help="validate requirements for a selected workflow; defaults to full case validation",
    )
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
    score_many.add_argument(
        "--run-id",
        help="record the benchmark run identifier in the aggregate score report",
    )
    score_many.add_argument(
        "--ymir-sha",
        help="record the benchmarked Ymir git SHA in the aggregate score report",
    )
    score_many.add_argument(
        "--variant",
        help="record the benchmark variant name in the aggregate score report",
    )
    score_many.add_argument(
        "--provenance",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="record additional run provenance; may be provided more than once",
    )
    score_many.set_defaults(func=_cmd_score_results)

    for compare_name in ("compare-results", "compare"):
        compare = subparsers.add_parser(
            compare_name,
            help="compare two aggregate score-results JSON reports",
        )
        compare.add_argument("baseline_json", type=Path)
        compare.add_argument("candidate_json", type=Path)
        compare.add_argument(
            "--output",
            type=Path,
            help="write comparison JSON to this path instead of stdout",
        )
        compare.add_argument(
            "--markdown-output",
            type=Path,
            help="write a Markdown comparison report to this path",
        )
        compare.set_defaults(func=_cmd_compare_results)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_validate_cases(args: argparse.Namespace) -> int:
    report = validate_case_directory(
        args.cases_dir,
        workflow=_validation_workflow(args.workflow),
    )
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
    cases_dir = (
        args.expected_json.parent.parent if args.expected_json.parent.name == "expected" else None
    )
    report = score_case(expected, actual, cases_dir=cases_dir)
    payload = json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    return 0 if report.passed else 1


def _cmd_score_results(args: argparse.Namespace) -> int:
    report = score_result_directory(
        args.cases_dir,
        args.actual_results_dir,
        run_id=args.run_id,
        ymir_sha=args.ymir_sha,
        variant=args.variant,
        provenance=_parse_provenance_or_exit(args.provenance),
    )
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
def _validation_workflow(workflow: str) -> str | None:
    if workflow == "none":
        return None
    return workflow


def _parse_provenance_or_exit(items: Sequence[str]) -> dict[str, str]:
    try:
        return parse_provenance_items(items)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def _cmd_compare_results(args: argparse.Namespace) -> int:
    report = compare_result_reports(args.baseline_json, args.candidate_json)
    payload = json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(render_comparison_markdown(report), encoding="utf-8")

    return 1 if report.has_headline_regressions else 0
