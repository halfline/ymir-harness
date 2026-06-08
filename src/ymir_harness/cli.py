from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.collect_case import (
    CollectCaseError,
    CollectCaseRequest,
    MockRepoInput,
    collect_case,
    load_alternate_outcomes,
    parse_key_value_items,
    parse_web_record_items,
)
from ymir_harness.comparison import compare_result_reports, render_comparison_markdown
from ymir_harness.models import (
    ALLOWED_ANSWER_LEAKAGE,
    ALLOWED_CASE_STATUSES,
    ALLOWED_CASE_TYPES,
    ALLOWED_EXPECTED_BASES,
    ALLOWED_GROUND_TRUTH_CONFIDENCE,
    ALLOWED_NETWORK_MODES,
    ALLOWED_REFERENCE_PATCH_MODES,
    ALLOWED_RESOLUTIONS,
)
from ymir_harness.reports import write_validation_reports
from ymir_harness.runner import (
    append_global_issues,
    build_run_report,
    default_results_dir,
    load_case_manifest,
    select_validation_cases,
)
from ymir_harness.provenance import parse_provenance_items
from ymir_harness.scoring import load_json_file, score_case, score_result_directory
from ymir_harness.validation import validate_case_directory
from ymir_harness.ymir_workflows import (
    make_ymir_backport_executor,
    make_ymir_rebuild_executor,
    make_ymir_rebase_executor,
    make_ymir_triage_executor,
)


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

    collect = subparsers.add_parser(
        "collect-case",
        help="scaffold one benchmark case from local files or Jira fetches",
    )
    collect.add_argument("--cases", type=Path, required=True, help="benchmark_cases directory")
    collect.add_argument("--case-id", required=True, help="Jira issue key / benchmark case id")
    collect.add_argument("--case-type", choices=sorted(ALLOWED_CASE_TYPES), required=True)
    collect.add_argument("--resolution", choices=sorted(ALLOWED_RESOLUTIONS), required=True)
    collect.add_argument("--package", required=True, help="source package name")
    collect.add_argument("--target-branch", help="expected target dist-git branch")
    collect.add_argument("--fix-version", help="expected fix version when branch is not enough")
    collect.add_argument(
        "--expected-basis",
        choices=sorted(ALLOWED_EXPECTED_BASES),
        default="manual_review",
    )
    collect.add_argument(
        "--ground-truth-confidence",
        choices=sorted(ALLOWED_GROUND_TRUTH_CONFIDENCE),
        default="medium",
    )
    collect.add_argument(
        "--answer-leakage",
        choices=sorted(ALLOWED_ANSWER_LEAKAGE),
        default="none",
    )
    collect.add_argument(
        "--case-status",
        choices=sorted(ALLOWED_CASE_STATUSES),
        default="quarantined",
    )
    collect.add_argument(
        "--case-status-reason",
        default="fixture scaffold requires ground-truth review",
    )
    collect.add_argument(
        "--network-mode",
        choices=sorted(ALLOWED_NETWORK_MODES),
        default="network_denied",
    )
    collect.add_argument("--cve-id", dest="cve_ids", action="append", default=[])
    collect.add_argument("--patch-url", dest="patch_urls", action="append", default=[])
    collect.add_argument("--fix-source", dest="fix_sources", action="append", default=[])
    collect.add_argument("--notes")
    collect.add_argument(
        "--alternate-outcome",
        dest="alternate_outcomes",
        action="append",
        type=Path,
        default=[],
        help="JSON object with expected-result overrides for an acceptable alternate",
    )
    collect.add_argument("--mock-agent", default="triage")
    collect.add_argument("--remote-url", help="mock repo original remote URL or local path")
    collect.add_argument("--pre-fix-ref", help="commit/ref before the historical fix")
    collect.add_argument("--branch", help="mock repo source branch")
    collect.add_argument(
        "--zstream-override",
        action="append",
        default=[],
        metavar="MAJOR=BRANCH",
    )
    collect.add_argument(
        "--blocked-original-url",
        action="append",
        default=[],
        help="extra original URL prefix to block during replay",
    )
    collect.add_argument(
        "--reference-patch",
        type=Path,
        help="local patch file to copy into mock_data/*/reference_patches",
    )
    collect.add_argument(
        "--reference-patch-mode",
        choices=sorted(ALLOWED_REFERENCE_PATCH_MODES),
    )
    collect.add_argument("--jira-issue-json", type=Path)
    collect.add_argument("--jira-comments-json", type=Path)
    collect.add_argument("--jira-links-json", type=Path)
    collect.add_argument(
        "--jira-url",
        help="Jira issue browse or REST API URL to fetch into jiras/CASE_ID",
    )
    collect.add_argument(
        "--jira-base-url",
        help="Jira instance base URL used to fetch CASE_ID into jiras/CASE_ID",
    )
    collect.add_argument(
        "--jira-token-env",
        default="JIRA_TOKEN",
        help="environment variable containing a Jira token",
    )
    collect.add_argument(
        "--jira-token-file",
        type=Path,
        help="file containing a Jira token",
    )
    collect.add_argument(
        "--jira-email",
        help="Atlassian account email for Jira Basic auth",
    )
    collect.add_argument(
        "--http-timeout",
        type=float,
        default=30.0,
        help="timeout in seconds for Jira fetches",
    )
    collect.add_argument("--attachment", dest="attachments", action="append", type=Path, default=[])
    collect.add_argument(
        "--web-record",
        dest="web_records",
        action="append",
        default=[],
        metavar="URL=PATH",
        help="copy a recorded response file and map it to URL in web_cache manifest",
    )
    collect.add_argument(
        "--source-upstream",
        action="append",
        type=Path,
        default=[],
        help="copy upstream source archive or clone into source_cache/CASE/upstream",
    )
    collect.add_argument(
        "--source-lookaside",
        action="append",
        type=Path,
        default=[],
        help="copy lookaside artifact into source_cache/CASE/lookaside",
    )
    collect.add_argument("--overwrite", action="store_true")
    collect.add_argument("--json", action="store_true", help="print collection result JSON")
    collect.set_defaults(func=_cmd_collect_case)

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
        "--case",
        dest="case_ids",
        action="append",
        default=[],
        help="run only the named case id; may be provided more than once",
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
    run.add_argument(
        "--workflow",
        choices=("none", "ymir-triage", "ymir-backport", "ymir-rebase", "ymir-rebuild"),
        default="none",
        help="workflow executor to invoke; defaults to placeholder run entries",
    )
    run.add_argument(
        "--provenance",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="record additional run provenance; may be provided more than once",
    )
    run.set_defaults(func=_cmd_run)

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


def _cmd_collect_case(args: argparse.Namespace) -> int:
    try:
        request = _collect_case_request(args)
        result = collect_case(request)
    except (CollectCaseError, ValueError) as exc:
        sys.stderr.write(f"collect-case failed: {exc}\n")
        return 1

    if args.json:
        json.dump(result.to_json(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            f"collected {result.case_id}: {len(result.written_paths)} files written\n"
        )
        if result.warnings:
            for warning in result.warnings:
                sys.stdout.write(f"warning: {warning}\n")
    return 0


def _collect_case_request(args: argparse.Namespace) -> CollectCaseRequest:
    mock_repo = _collect_mock_repo(args)
    return CollectCaseRequest(
        cases_dir=args.cases,
        case_id=args.case_id,
        case_type=args.case_type,
        resolution=args.resolution,
        package=args.package,
        expected_basis=args.expected_basis,
        ground_truth_confidence=args.ground_truth_confidence,
        answer_leakage=args.answer_leakage,
        case_status=args.case_status,
        case_status_reason=args.case_status_reason,
        network_mode=args.network_mode,
        target_branch=args.target_branch,
        fix_version=args.fix_version,
        cve_ids=tuple(args.cve_ids),
        patch_urls=tuple(args.patch_urls),
        fix_sources=tuple(args.fix_sources),
        notes=args.notes,
        alternate_acceptable_outcomes=load_alternate_outcomes(args.alternate_outcomes),
        reference_patch_mode=args.reference_patch_mode,
        mock_repo=mock_repo,
        jira_url=args.jira_url,
        jira_base_url=args.jira_base_url,
        jira_token_env=args.jira_token_env,
        jira_token_file=args.jira_token_file,
        jira_email=args.jira_email,
        http_timeout=args.http_timeout,
        jira_issue_json=args.jira_issue_json,
        jira_comments_json=args.jira_comments_json,
        jira_links_json=args.jira_links_json,
        attachments=tuple(args.attachments),
        reference_patch=args.reference_patch,
        web_records=parse_web_record_items(args.web_records),
        source_upstream=tuple(args.source_upstream),
        source_lookaside=tuple(args.source_lookaside),
        overwrite=args.overwrite,
    )



def _collect_mock_repo(args: argparse.Namespace) -> MockRepoInput | None:
    values = {
        "remote_url": args.remote_url,
        "pre_fix_ref": args.pre_fix_ref,
        "branch": args.branch,
    }
    if not any(values.values()):
        if args.reference_patch is not None:
            msg = "--reference-patch requires --remote-url, --pre-fix-ref, and --branch"
            raise ValueError(msg)
        return None
    missing = [name for name, value in values.items() if not value]
    if missing:
        missing_options = ", ".join(f"--{name.replace('_', '-')}" for name in missing)
        msg = f"mock repo metadata is incomplete; missing {missing_options}"
        raise ValueError(msg)
    return MockRepoInput(
        remote_url=args.remote_url,
        pre_fix_ref=args.pre_fix_ref,
        branch=args.branch,
        agent=args.mock_agent,
        zstream_override=parse_key_value_items(
            args.zstream_override,
            option_name="--zstream-override",
        ),
        blocked_original_urls=tuple(args.blocked_original_url),
    )


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


def _cmd_run(args: argparse.Namespace) -> int:
    run_id = args.run_id or args.variant
    results_dir = args.results_dir or default_results_dir(args.cases, run_id)
    validation_report = validate_case_directory(args.cases, phase=args.phase)
    manifest_case_ids, manifest_issues = load_case_manifest(args.cases)
    validation_report = append_global_issues(validation_report, manifest_issues)
    validation_report = select_validation_cases(
        validation_report,
        args.case_ids or manifest_case_ids,
    )
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
        executor=_run_executor(args.workflow),
        provenance=_parse_provenance_or_exit(args.provenance),
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


def _run_executor(workflow: str):
    if workflow == "ymir-triage":
        return make_ymir_triage_executor()
    if workflow == "ymir-backport":
        return make_ymir_backport_executor()
    if workflow == "ymir-rebase":
        return make_ymir_rebase_executor()
    if workflow == "ymir-rebuild":
        return make_ymir_rebuild_executor()
    return None


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
