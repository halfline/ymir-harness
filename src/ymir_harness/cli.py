from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.comparison import compare_result_reports, render_comparison_markdown
from ymir_harness.reports import write_validation_reports
from ymir_harness.runner import build_run_report, default_results_dir
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
    score_many.set_defaults(func=_cmd_score_results)

    run = subparsers.add_parser(
        "run",
        help="validate benchmark cases and write a placeholder run report",
    )
    run.add_argument("--cases", type=Path, required=True, help="benchmark_cases directory")
    run.add_argument("--variant", required=True, help="benchmark variant name")
    run.add_argument("--run-id", help="benchmark run identifier; defaults to VARIANT")
    run.add_argument("--ymir-sha", help="record the benchmarked Ymir git SHA")
    run.add_argument(
        "--repeat",
        type=_positive_int,
        default=1,
        help="number of repetitions to record for each runnable case",
    )
    run.add_argument(
        "--feature",
        dest="features",
        action="append",
        default=[],
        help="record an enabled feature flag; may be provided more than once",
    )
    run.add_argument("--phase", type=int, choices=(1, 2), default=1)
    run.add_argument("--results-dir", type=Path, help="directory for run artifacts")
    run.add_argument("--output", type=Path, help="write run report JSON to this path")
    run.add_argument("--json", action="store_true", help="print the run report JSON to stdout")
    run.set_defaults(func=_cmd_run)

    compare = subparsers.add_parser(
        "compare-results",
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
    report = score_result_directory(
        args.cases_dir,
        args.actual_results_dir,
        run_id=args.run_id,
        ymir_sha=args.ymir_sha,
        variant=args.variant,
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


def _cmd_run(args: argparse.Namespace) -> int:
    run_id = args.run_id or args.variant
    results_dir = args.results_dir or default_results_dir(args.cases, run_id)
    validation_report = validate_case_directory(args.cases, phase=args.phase)
    validation_reports_dir = args.cases / "reports"
    write_validation_reports(validation_report, validation_reports_dir)

    if validation_report.has_blocking_errors:
        summary = validation_report.summary()
        sys.stdout.write(
            "benchmark run blocked: "
            f"{summary['invalid']} invalid, "
            f"{summary['global_errors']} global errors\n"
        )
        sys.stdout.write(f"validation reports written to {validation_reports_dir}\n")
        return 1

    report = build_run_report(
        args.cases,
        results_dir,
        validation_report=validation_report,
        run_id=run_id,
        variant=args.variant,
        ymir_sha=args.ymir_sha,
        features=args.features,
        repeat=args.repeat,
    )
    output_path = args.output or results_dir / "run.json"
    payload = json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload, encoding="utf-8")

    if args.json:
        sys.stdout.write(payload)
    else:
        summary = report.summary()
        sys.stdout.write(
            "benchmark run: "
            f"{summary['not_run']} not run, "
            f"{summary['skipped']} skipped, "
            f"{summary['unsupported']} unsupported\n"
        )
        sys.stdout.write(f"run report written to {output_path}\n")

    return 1 if report.has_failures else 0


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        msg = f"invalid positive integer: {value}"
        raise argparse.ArgumentTypeError(msg) from exc
    if parsed < 1:
        msg = f"invalid positive integer: {value}"
        raise argparse.ArgumentTypeError(msg)
    return parsed


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
