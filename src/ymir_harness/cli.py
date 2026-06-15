from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlparse

from ymir_harness import __version__
from ymir_harness.collect_case import (
    CollectCaseError,
    CollectCaseRequest,
    collect_case,
)
from ymir_harness.capture_missing import (
    CaptureMissingResult,
    blocked_urls_from_run_path,
    capture_missing,
    jira_requests_from_run_path,
)
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

WORKFLOW_CHOICES = ("none", "ymir-triage", "ymir-backport", "ymir-rebase", "ymir-rebuild")
MAX_PREPARE_AUTO_ALLOWED_HOSTS = 16


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

    prepare = subparsers.add_parser(
        "prepare-case",
        help="collect and iteratively capture replay evidence for one case",
    )
    prepare.add_argument("--cases", type=Path, required=True, help="benchmark_cases directory")
    prepare.add_argument(
        "--case",
        "--case-id",
        dest="case_id",
        required=True,
        help="case id to prepare",
    )
    prepare.add_argument(
        "--workflow",
        choices=tuple(choice for choice in WORKFLOW_CHOICES if choice != "none"),
        default="ymir-triage",
        help="workflow executor to run while preparing the case",
    )
    prepare.add_argument("--variant", default="prepare", help="benchmark variant name")
    prepare.add_argument("--run-id", help="base benchmark run identifier")
    prepare.add_argument("--ymir-sha", help="record the benchmarked Ymir git SHA")
    prepare.add_argument(
        "--repeat",
        type=_positive_int,
        default=1,
        help="number of repetitions to record for each iteration",
    )
    prepare.add_argument(
        "--max-iterations",
        type=_positive_int,
        default=3,
        help="maximum run/capture iterations before stopping",
    )
    prepare.add_argument(
        "--feature",
        dest="features",
        action="append",
        default=[],
        help="record an enabled feature flag; may be provided more than once",
    )
    prepare.add_argument(
        "--results-dir",
        type=Path,
        help="base directory for iteration run artifacts",
    )
    prepare.add_argument(
        "--jira-url",
        help="Jira issue browse or REST API URL to import before the first run",
    )
    prepare.add_argument(
        "--jira-base-url",
        help="Jira instance base URL used to import CASE before the first run",
    )
    prepare.add_argument(
        "--gitlab-mr",
        dest="gitlab_mr_url",
        help="GitLab merge request URL to import before the first run",
    )
    prepare.add_argument(
        "--mock-repo-cache",
        type=Path,
        help="clone or refresh mock repos into this local cache during collection",
    )
    prepare.add_argument(
        "--allow-host",
        dest="allowed_hosts",
        action="append",
        default=[],
        help=(
            "extra host allowed for read-only capture; defaults include "
            f"{', '.join(DEFAULT_ALLOWED_HOSTS)}"
        ),
    )
    prepare.add_argument(
        "--jira-token-env",
        default="JIRA_TOKEN",
        help="environment variable containing a Jira token",
    )
    prepare.add_argument("--jira-token-file", type=Path, help="file containing a Jira token")
    prepare.add_argument("--jira-email", help="Atlassian account email for Jira Basic auth")
    prepare.add_argument(
        "--gitlab-token-env",
        default="GITLAB_TOKEN",
        help="environment variable containing a GitLab private token",
    )
    prepare.add_argument(
        "--as-of",
        help=(
            "historical Jira timestamp to reconstruct search results against; "
            "defaults to the first existing Ymir/Jotnar result comment when available"
        ),
    )
    prepare.add_argument(
        "--http-timeout",
        type=float,
        default=30.0,
        help="timeout in seconds for read-only collection and capture",
    )
    prepare.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing collected or captured fixture files",
    )
    prepare.add_argument("--json", action="store_true", help="print preparation result JSON")
    prepare.add_argument(
        "--provenance",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="record additional run provenance; may be provided more than once",
    )
    prepare.set_defaults(func=_cmd_prepare_case)

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
    run.add_argument("--results-dir", type=Path, help="directory for run artifacts")
    run.add_argument("--output", type=Path, help="write run report JSON to this path")
    run.add_argument("--json", action="store_true", help="print the run report JSON to stdout")
    run.add_argument(
        "--workflow",
        choices=WORKFLOW_CHOICES,
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

def _cmd_prepare_case(args: argparse.Namespace) -> int:
    provenance = _parse_provenance_or_exit(args.provenance)
    try:
        payload, exit_code = _prepare_case(args, provenance)
    except (CaptureMissingError, CollectCaseError, ValueError) as exc:
        sys.stderr.write(f"prepare-case failed: {exc}\n")
        return 2

    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json:
        sys.stdout.write(encoded)
    else:
        sys.stdout.write(
            f"prepare case: {payload['status']}, {len(payload['iterations'])} iteration(s)\n"
        )
        if payload.get("collected"):
            sys.stdout.write(
                f"collected {payload['case_id']}: "
                f"{len(payload['collected'].get('written_paths', []))} files written\n"
            )
        for iteration in payload["iterations"]:
            run = iteration["run"]
            sys.stdout.write(
                f"iteration {iteration['iteration']}: run {run['run_id']} -> {run['summary']}\n"
            )
            capture = iteration.get("capture")
            if capture:
                sys.stdout.write(
                    "  capture: "
                    f"{len(capture['captured'])} URL(s), "
                    f"{len(capture['captured_jira'])} Jira request(s), "
                    f"{len(capture['captured_git_failures'])} git failure(s), "
                    f"{len(capture['failed'])} failure(s)\n"
                )
            if auto_allowed_hosts := iteration.get("auto_allowed_hosts"):
                sys.stdout.write(
                    f"  auto-allowed hosts: {', '.join(str(host) for host in auto_allowed_hosts)}\n"
                )
    return exit_code


def _prepare_case(
    args: argparse.Namespace,
    provenance: dict[str, str],
) -> tuple[dict[str, object], int]:
    collected = None
    if _prepare_should_collect(args):
        collected = collect_case(_prepare_collect_request(args)).to_json()

    auto_allowed_hosts: list[str] = []
    payload: dict[str, object] = {
        "case_id": args.case_id,
        "cases_dir": str(args.cases),
        "workflow": args.workflow,
        "variant": args.variant,
        "status": "max_iterations",
        "collected": collected,
        "auto_allowed_hosts": auto_allowed_hosts,
        "iterations": [],
    }
    iterations: list[dict[str, object]] = []
    payload["iterations"] = iterations
    exit_code = 1

    for iteration in range(1, args.max_iterations + 1):
        run_id = _prepare_iteration_run_id(args, iteration)
        results_dir = _prepare_iteration_results_dir(args, run_id, iteration)
        run_payload, report, run_exit_code = _prepare_run_iteration(
            args,
            run_id=run_id,
            results_dir=results_dir,
            provenance=provenance,
        )
        iteration_payload: dict[str, object] = {
            "iteration": iteration,
            "run": run_payload,
        }
        iterations.append(iteration_payload)

        if report is None:
            payload["status"] = "validation_blocked"
            exit_code = run_exit_code
            break

        if not report.has_failures and not _prepare_has_replay_candidates(results_dir):
            payload["status"] = "succeeded"
            exit_code = 0
            break

        capture_result, iteration_auto_allowed_hosts = _prepare_capture_missing(
            args,
            results_dir,
            auto_allowed_hosts,
        )
        if iteration_auto_allowed_hosts:
            iteration_payload["auto_allowed_hosts"] = iteration_auto_allowed_hosts
        capture_payload = capture_result.to_json()
        iteration_payload["capture"] = capture_payload
        if capture_result.failed:
            payload["status"] = "capture_failed"
            exit_code = 2
            break

        captured_count = (
            len(capture_result.captured)
            + len(capture_result.captured_jira)
            + len(capture_result.captured_source)
            + len(capture_result.captured_git_failures)
        )
        if captured_count == 0:
            payload["status"] = "blocked"
            exit_code = run_exit_code or 1
            break
    else:
        payload["status"] = "max_iterations"
        exit_code = 1

    return payload, exit_code


def _prepare_has_replay_candidates(results_dir: Path) -> bool:
    try:
        return bool(
            blocked_urls_from_run_path(results_dir) or jira_requests_from_run_path(results_dir)
        )
    except CaptureMissingError:
        return False


def _prepare_capture_missing(
    args: argparse.Namespace,
    results_dir: Path,
    auto_allowed_hosts: list[str],
) -> tuple[CaptureMissingResult, list[str]]:
    aggregate_result: CaptureMissingResult | None = None
    iteration_auto_allowed_hosts: list[str] = []

    while True:
        capture_result = capture_missing(
            _prepare_capture_request(
                args,
                results_dir,
                auto_allowed_hosts=auto_allowed_hosts,
            )
        )
        aggregate_result = _merge_capture_results(aggregate_result, capture_result)
        if capture_result.failed:
            break

        added_hosts = _prepare_auto_allowed_hosts(
            capture_result,
            user_allowed_hosts=args.allowed_hosts,
            auto_allowed_hosts=auto_allowed_hosts,
        )
        if not added_hosts:
            break
        auto_allowed_hosts.extend(added_hosts)
        iteration_auto_allowed_hosts.extend(added_hosts)

    if aggregate_result is None:
        raise CaptureMissingError(f"capture did not run for {results_dir}")
    return aggregate_result, iteration_auto_allowed_hosts


def _merge_capture_results(
    base: CaptureMissingResult | None,
    update: CaptureMissingResult,
) -> CaptureMissingResult:
    if base is None:
        return update

    base.candidate_urls = _dedupe_sequence([*base.candidate_urls, *update.candidate_urls])
    base.candidate_jira_requests = _dedupe_json_objects(
        [*base.candidate_jira_requests, *update.candidate_jira_requests]
    )
    base.captured.extend(update.captured)
    base.captured_jira.extend(update.captured_jira)
    base.captured_source.extend(update.captured_source)
    base.captured_git_failures.extend(update.captured_git_failures)
    base.skipped.extend(update.skipped)
    base.failed.extend(update.failed)

    captured_urls = {capture.url for capture in base.captured}
    captured_urls.update(capture.url for capture in base.captured_jira)
    captured_urls.update(capture.url for capture in base.captured_source)
    captured_urls.update(capture.url for capture in base.captured_git_failures)
    base.skipped = [skip for skip in base.skipped if skip.url not in captured_urls]
    return base


def _prepare_auto_allowed_hosts(
    capture_result: CaptureMissingResult,
    *,
    user_allowed_hosts: Sequence[str],
    auto_allowed_hosts: Sequence[str],
) -> list[str]:
    known_hosts = {host.lower() for host in (*DEFAULT_ALLOWED_HOSTS, *user_allowed_hosts)}
    known_hosts.update(host.lower() for host in auto_allowed_hosts)
    remaining_slots = MAX_PREPARE_AUTO_ALLOWED_HOSTS - len(auto_allowed_hosts)
    if remaining_slots <= 0:
        return []

    added_hosts: list[str] = []
    for skipped in capture_result.skipped:
        if skipped.reason != "host is not allowed":
            continue
        host = _prepare_safe_auto_allowed_host(skipped.url)
        if host is None or host in known_hosts:
            continue
        known_hosts.add(host)
        added_hosts.append(host)
        if len(added_hosts) >= remaining_slots:
            break
    return added_hosts


def _prepare_safe_auto_allowed_host(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None

    host = parsed.hostname.rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        return None

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host

    if not address.is_global:
        return None
    return host


def _dedupe_sequence(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _dedupe_json_objects(values):
    return list({json.dumps(value, sort_keys=True): value for value in values}.values())


def _prepare_should_collect(args: argparse.Namespace) -> bool:
    return any((args.jira_url, args.jira_base_url, args.gitlab_mr_url))


def _prepare_collect_request(args: argparse.Namespace) -> CollectCaseRequest:
    return CollectCaseRequest(
        cases_dir=args.cases,
        case_id=args.case_id,
        case_status_reason="fixture scaffold prepared for replay experiments",
        mock_agent=_workflow_mock_agent(args.workflow),
        mock_repo_cache=args.mock_repo_cache,
        jira_url=args.jira_url,
        jira_base_url=args.jira_base_url,
        jira_token_env=args.jira_token_env,
        jira_token_file=args.jira_token_file,
        jira_email=args.jira_email,
        gitlab_mr_url=args.gitlab_mr_url,
        gitlab_token_env=args.gitlab_token_env,
        http_timeout=args.http_timeout,
        overwrite=args.overwrite,
    )


def _prepare_capture_request(
    args: argparse.Namespace,
    results_dir: Path,
    *,
    auto_allowed_hosts: Sequence[str] = (),
) -> CaptureMissingRequest:
    allowed_hosts = tuple(
        dict.fromkeys((*DEFAULT_ALLOWED_HOSTS, *args.allowed_hosts, *auto_allowed_hosts))
    )
    return CaptureMissingRequest(
        cases_dir=args.cases,
        run_path=results_dir,
        case_id=args.case_id,
        allowed_hosts=allowed_hosts,
        gitlab_token_env=args.gitlab_token_env,
        jira_token_env=args.jira_token_env,
        jira_token_file=args.jira_token_file,
        jira_email=args.jira_email,
        as_of=args.as_of,
        http_timeout=args.http_timeout,
        overwrite=args.overwrite,
    )


def _prepare_run_iteration(
    args: argparse.Namespace,
    *,
    run_id: str,
    results_dir: Path,
    provenance: dict[str, str],
):
    validation_report = validate_case_directory(
        args.cases,
        workflow=_validation_workflow(args.workflow),
    )
    manifest_case_ids, manifest_issues = load_case_manifest(args.cases)
    validation_report = append_global_issues(validation_report, manifest_issues)
    validation_report = select_validation_cases(
        validation_report,
        [args.case_id] or manifest_case_ids,
    )
    validation_reports_dir = args.cases / "reports"
    write_validation_reports(validation_report, validation_reports_dir)

    output_path = results_dir / "run.json"
    if validation_report.has_blocking_errors:
        summary = validation_report.summary()
        return (
            {
                "run_id": run_id,
                "results_dir": str(results_dir),
                "run_json": None,
                "summary": summary,
                "blocked": True,
            },
            None,
            1,
        )

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
        provenance=provenance,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return (
        {
            "run_id": run_id,
            "results_dir": str(results_dir),
            "run_json": str(output_path),
            "summary": report.summary(),
            "blocked": False,
        },
        report,
        1 if report.has_failures else 0,
    )


def _prepare_iteration_run_id(args: argparse.Namespace, iteration: int) -> str:
    base_run_id = args.run_id or f"{args.variant}-{args.case_id}"
    return f"{base_run_id}-iter-{iteration}"


def _prepare_iteration_results_dir(
    args: argparse.Namespace,
    run_id: str,
    iteration: int,
) -> Path:
    if args.results_dir is not None:
        return args.results_dir / f"iteration-{iteration}"
    return default_results_dir(args.cases, run_id)


def _workflow_mock_agent(workflow: str) -> str:
    if workflow.startswith("ymir-"):
        return workflow.removeprefix("ymir-")
    return "triage"

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


def _cmd_run(args: argparse.Namespace) -> int:
    run_id = args.run_id or args.variant
    results_dir = args.results_dir or default_results_dir(args.cases, run_id)
    validation_report = validate_case_directory(
        args.cases,
        workflow=_validation_workflow(args.workflow),
    )
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


def _validation_workflow(workflow: str) -> str | None:
    if workflow == "none":
        return None
    return workflow


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
