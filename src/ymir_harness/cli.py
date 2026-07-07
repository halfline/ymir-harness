from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

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
from ymir_harness.capture_missing import (
    DEFAULT_ALLOWED_HOSTS,
    CaptureMissingError,
    CaptureMissingRequest,
    CaptureMissingResult,
    blocked_urls_from_run_path,
    capture_missing,
    jira_requests_from_run_path,
    lookaside_source_requests_from_run_path,
)
from ymir_harness.comparison import compare_result_reports, render_comparison_markdown
from ymir_harness.jira_replay import derive_as_of
from ymir_harness.koji_replay import (
    KOJI_CANDIDATE_BUILDS_MANIFEST_KEY,
    candidate_build_branches,
    candidate_build_key,
    fetch_candidate_build,
)
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
    SCHEMA_VERSION,
)
from ymir_harness.replay import canonicalize_replay_url
from ymir_harness.reports import write_validation_reports
from ymir_harness.runner import (
    STOP_ON_REPLAY_MISS_ENV,
    append_global_issues,
    build_run_report,
    default_results_dir,
    load_case_manifest,
    select_validation_cases,
)
from ymir_harness.provenance import parse_provenance_items
from ymir_harness.scoring import load_json_file, score_case, score_result_directory
from ymir_harness.source_fixtures import (
    SourceFixtureError,
    resolve_source_cache_ref,
    source_cache_contains_object,
    source_cache_repo_for_object,
)
from ymir_harness.validation import validate_case_directory
from ymir_harness.ymir_workflows import (
    make_ymir_backport_executor,
    make_ymir_rebuild_executor,
    make_ymir_rebase_executor,
    make_ymir_triage_executor,
)


WORKFLOW_CHOICES = ("none", "ymir-triage", "ymir-backport", "ymir-rebase", "ymir-rebuild")
MAX_PREPARE_AUTO_ALLOWED_HOSTS = 16
DEFAULT_PREPARE_WORKFLOW_PROGRESS_INTERVAL_SECONDS = "2"


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

    activate = subparsers.add_parser(
        "activate-case",
        help="promote a quarantined case to active after a passing replay run",
    )
    activate.add_argument("--cases", type=Path, required=True, help="benchmark_cases directory")
    activate.add_argument(
        "--case",
        "--case-id",
        dest="case_id",
        required=True,
        help="case id to activate",
    )
    activate.add_argument(
        "--workflow",
        choices=WORKFLOW_CHOICES,
        default="none",
        help="validate requirements for a selected workflow before activation",
    )
    activate.add_argument(
        "--run-report",
        type=Path,
        help=(
            "passing run.json to use as activation evidence; defaults to the newest "
            "run report under CASES/reports/runs containing CASE"
        ),
    )
    activate.add_argument("--json", action="store_true", help="print activation JSON")
    activate.set_defaults(func=_cmd_activate_case)

    collect = subparsers.add_parser(
        "collect-case",
        help="scaffold one benchmark case from local files or read-only evidence fetches",
    )
    collect.add_argument("--cases", type=Path, required=True, help="benchmark_cases directory")
    collect.add_argument("--case-id", required=True, help="Jira issue key / benchmark case id")
    collect.add_argument(
        "--case-type",
        choices=sorted(ALLOWED_CASE_TYPES),
        help="benchmark case type; derived from Jira when omitted",
    )
    collect.add_argument(
        "--resolution",
        choices=sorted(ALLOWED_RESOLUTIONS),
        help="expected resolution; derived from completed Jira when omitted",
    )
    collect.add_argument("--package", help="source package name; derived from Jira when omitted")
    collect.add_argument("--target-branch", help="expected target dist-git branch")
    collect.add_argument("--fix-version", help="expected fix version when branch is not enough")
    collect.add_argument(
        "--expected-basis",
        choices=sorted(ALLOWED_EXPECTED_BASES),
        help="ground-truth basis; defaults to historical_jira_state for Jira imports",
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
        help=(
            "expected replay network policy; defaults to replay_only when "
            "patch/web/GitLab MR evidence is provided, otherwise network_denied"
        ),
    )
    collect.add_argument("--cve-id", dest="cve_ids", action="append", default=[])
    collect.add_argument("--patch-url", dest="patch_urls", action="append", default=[])
    collect.add_argument("--fix-source", dest="fix_sources", action="append", default=[])
    collect.add_argument(
        "--backport-source",
        choices=sorted(ALLOWED_BACKPORT_SOURCES),
        help="backport patch source bucket; inferred from patch URLs when omitted",
    )
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
        "--mock-repo-cache",
        type=Path,
        help="clone/fetch mock repos into this local cache for fixture generation",
    )
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
        "--gitlab-mr",
        dest="gitlab_mr_url",
        help="GitLab merge request URL to fetch into web_cache and mock_data",
    )
    collect.add_argument(
        "--gitlab-token-env",
        default="GITLAB_TOKEN",
        help="environment variable containing a GitLab private token",
    )
    collect.add_argument(
        "--http-timeout",
        type=float,
        default=30.0,
        help="timeout in seconds for Jira/GitLab fetches",
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

    capture = subparsers.add_parser(
        "capture-missing",
        help="capture allowed missing replay URLs from a prior run into web_cache",
    )
    capture.add_argument("--cases", type=Path, required=True, help="benchmark_cases directory")
    capture.add_argument(
        "--from-run",
        dest="run_path",
        type=Path,
        required=True,
        help="run directory or run artifact to scan for blocked replay URLs",
    )
    capture.add_argument("--case", dest="case_id", required=True, help="case id to update")
    capture.add_argument(
        "--allow-host",
        dest="allowed_hosts",
        action="append",
        default=[],
        help=(
            "extra host allowed for read-only capture; defaults include "
            f"{', '.join(DEFAULT_ALLOWED_HOSTS)}"
        ),
    )
    capture.add_argument(
        "--gitlab-token-env",
        default="GITLAB_TOKEN",
        help="environment variable containing a GitLab private token",
    )
    capture.add_argument(
        "--jira-token-env",
        default="JIRA_TOKEN",
        help="environment variable containing a Jira token",
    )
    capture.add_argument("--jira-token-file", type=Path, help="file containing a Jira token")
    capture.add_argument("--jira-email", help="Atlassian account email for Jira Basic auth")
    capture.add_argument(
        "--as-of",
        help=(
            "historical Jira timestamp to reconstruct search results against; "
            "defaults to the first existing Ymir/Jotnar result comment when available"
        ),
    )
    capture.add_argument(
        "--http-timeout",
        type=float,
        default=30.0,
        help="timeout in seconds for read-only captures",
    )
    capture.add_argument(
        "--dry-run",
        action="store_true",
        help="list candidate URLs without fetching or writing web_cache",
    )
    capture.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing recorded files for captured URLs",
    )
    capture.add_argument("--json", action="store_true", help="print capture result JSON")
    capture.set_defaults(func=_cmd_capture_missing)

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
    prepare.add_argument(
        "--activate-on-pass",
        action="store_true",
        help="promote the case to active after prepare-case finishes with a passing replay",
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


def _cmd_activate_case(args: argparse.Namespace) -> int:
    try:
        payload = _activate_case(
            args.cases,
            args.case_id,
            workflow=_validation_workflow(args.workflow),
            run_report_path=args.run_report,
        )
    except ValueError as exc:
        sys.stderr.write(f"activate-case failed: {exc}\n")
        return 1

    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(f"activated {payload['case_id']} using {payload['run_report']}\n")
        sys.stdout.write(f"validation reports written to {payload['validation_reports_dir']}\n")
    return 0


def _activate_case(
    cases_dir: Path,
    case_id: str,
    *,
    workflow: str | None,
    run_report_path: Path | None = None,
) -> dict[str, object]:
    cases_dir = cases_dir.resolve()
    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    if not expected_path.is_file():
        raise ValueError(f"expected fixture is missing: {expected_path}")

    expected_text = expected_path.read_text(encoding="utf-8")
    expected = load_json_file(expected_path)
    _activate_validate_expected_policy(expected, expected_path)

    validation_reports_dir = cases_dir / "reports"
    pre_report = _activate_validate_selected_case(cases_dir, case_id, workflow)
    write_validation_reports(pre_report, validation_reports_dir)
    if pre_report.has_blocking_errors:
        raise ValueError(
            "fixture validation failed before activation; "
            f"reports written to {validation_reports_dir}"
        )

    evidence_path = _activate_run_report_path(cases_dir, case_id, run_report_path)
    entry_count = _activate_require_passing_run_report(evidence_path, case_id)

    updated = dict(expected)
    updated["case_status"] = "active"
    updated.pop("case_status_reason", None)
    expected_path.write_text(
        json.dumps(updated, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    post_report = _activate_validate_selected_case(cases_dir, case_id, workflow)
    write_validation_reports(post_report, validation_reports_dir)
    if post_report.has_blocking_errors:
        expected_path.write_text(expected_text, encoding="utf-8")
        raise ValueError(
            "activated fixture failed validation and was restored; "
            f"reports written to {validation_reports_dir}"
        )

    return {
        "case_id": case_id,
        "cases_dir": str(cases_dir),
        "expected_path": str(expected_path),
        "run_report": str(evidence_path),
        "run_report_entries": entry_count,
        "status": "activated",
        "validation_reports_dir": str(validation_reports_dir),
    }


def _activate_validate_expected_policy(expected: Mapping[str, Any], expected_path: Path) -> None:
    case_status = expected.get("case_status")
    if case_status != "quarantined":
        raise ValueError(
            f"case_status must be 'quarantined' before activation: "
            f"{expected_path} has {case_status!r}"
        )
    network_mode = expected.get("network_mode")
    if network_mode != "replay_only":
        raise ValueError(
            f"network_mode must be 'replay_only' before activation: "
            f"{expected_path} has {network_mode!r}"
        )
    if expected.get("answer_leakage") == "explicit":
        raise ValueError(f"explicit answer leakage cases cannot be activated: {expected_path}")


def _activate_validate_selected_case(
    cases_dir: Path,
    case_id: str,
    workflow: str | None,
) -> Any:
    report = validate_case_directory(cases_dir, workflow=workflow)
    _, manifest_issues = load_case_manifest(cases_dir)
    report = append_global_issues(report, manifest_issues)
    return select_validation_cases(report, [case_id])


def _activate_run_report_path(
    cases_dir: Path,
    case_id: str,
    run_report_path: Path | None,
) -> Path:
    if run_report_path is not None:
        return run_report_path

    runs_dir = cases_dir / "reports" / "runs"
    candidates = sorted(
        runs_dir.glob("*/run.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        try:
            if _activate_run_report_entries(candidate, case_id):
                return candidate
        except ValueError:
            continue

    raise ValueError(
        f"no run report containing {case_id} was found under {runs_dir}; pass --run-report"
    )


def _activate_require_passing_run_report(run_report_path: Path, case_id: str) -> int:
    entries = _activate_run_report_entries(run_report_path, case_id)
    if not entries:
        raise ValueError(f"run report does not contain {case_id}: {run_report_path}")

    non_passing = [
        str(entry.get("status"))
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("status") != "passed"
    ]
    if non_passing:
        statuses = ", ".join(non_passing)
        raise ValueError(
            f"run report has non-passing entries for {case_id}: {statuses} ({run_report_path})"
        )
    return len(entries)


def _activate_run_report_entries(run_report_path: Path, case_id: str) -> list[Mapping[str, Any]]:
    try:
        report = load_json_file(run_report_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"cannot read run report {run_report_path}: {exc}") from exc

    entries = report.get("cases")
    if not isinstance(entries, list):
        raise ValueError(f"run report must include a cases list: {run_report_path}")
    return [
        entry for entry in entries if isinstance(entry, Mapping) and entry.get("case_id") == case_id
    ]


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
        sys.stdout.write(f"collected {result.case_id}: {len(result.written_paths)} files written\n")
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
        backport_source=args.backport_source,
        notes=args.notes,
        alternate_acceptable_outcomes=load_alternate_outcomes(args.alternate_outcomes),
        reference_patch_mode=args.reference_patch_mode,
        mock_repo=mock_repo,
        mock_agent=args.mock_agent,
        mock_repo_cache=args.mock_repo_cache,
        jira_url=args.jira_url,
        jira_base_url=args.jira_base_url,
        jira_token_env=args.jira_token_env,
        jira_token_file=args.jira_token_file,
        jira_email=args.jira_email,
        gitlab_mr_url=args.gitlab_mr_url,
        gitlab_token_env=args.gitlab_token_env,
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


def _cmd_capture_missing(args: argparse.Namespace) -> int:
    allowed_hosts = tuple(dict.fromkeys((*DEFAULT_ALLOWED_HOSTS, *args.allowed_hosts)))
    request = CaptureMissingRequest(
        cases_dir=args.cases,
        run_path=args.run_path,
        case_id=args.case_id,
        allowed_hosts=allowed_hosts,
        gitlab_token_env=args.gitlab_token_env,
        jira_token_env=args.jira_token_env,
        jira_token_file=args.jira_token_file,
        jira_email=args.jira_email,
        as_of=args.as_of,
        http_timeout=args.http_timeout,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
    )
    try:
        result = capture_missing(request)
    except CaptureMissingError as exc:
        sys.stderr.write(f"capture-missing failed: {exc}\n")
        return 2

    payload = json.dumps(result.to_json(), indent=2, sort_keys=True) + "\n"
    if args.json:
        sys.stdout.write(payload)
    else:
        sys.stdout.write(
            f"captured {len(result.captured)} missing URL(s), "
            f"{len(result.captured_source)} source fixture(s), "
            f"{len(result.captured_git_failures)} git failure(s), "
            f"{len(result.captured_subprocesses)} subprocess replay(s), "
            f"{len(result.captured_koji_candidate_builds)} Koji candidate build(s); "
            f"skipped {len(result.skipped)}; failed {len(result.failed)}\n"
        )
    return 1 if result.failed else 0


def _cmd_prepare_case(args: argparse.Namespace) -> int:
    provenance = _parse_provenance_or_exit(args.provenance)
    try:
        payload, exit_code = _prepare_case(args, provenance)
    except (CaptureMissingError, CollectCaseError, ValueError) as exc:
        sys.stderr.write(f"prepare-case failed: {exc}\n")
        return 2

    if exit_code == 0 and args.activate_on_pass:
        try:
            activation = _prepare_activate_on_pass(args, payload)
        except ValueError as exc:
            sys.stderr.write(f"prepare-case activation failed: {exc}\n")
            return 2
        payload["activation"] = activation

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
                    f"{len(capture.get('captured_source', []))} source fixture(s), "
                    f"{len(capture['captured_git_failures'])} git failure(s), "
                    f"{len(capture.get('captured_subprocesses', []))} subprocess replay(s), "
                    f"{len(capture.get('captured_koji_candidate_builds', []))} "
                    "Koji candidate build(s), "
                    f"{len(capture['failed'])} failure(s)\n"
                )
            if auto_allowed_hosts := iteration.get("auto_allowed_hosts"):
                sys.stdout.write(
                    f"  auto-allowed hosts: {', '.join(str(host) for host in auto_allowed_hosts)}\n"
                )
        if activation := payload.get("activation"):
            triage_result = payload.get("triage_result")
            if isinstance(triage_result, Mapping):
                triage_activation = triage_result.get("activation")
                if isinstance(triage_activation, Mapping):
                    if triage_activation.get("status") == "activated":
                        sys.stdout.write(
                            "activated sibling triage "
                            f"{triage_activation['case_id']} using "
                            f"{triage_activation['run_report']}\n"
                        )
                    elif triage_activation.get("status") == "already_active":
                        sys.stdout.write(
                            f"sibling triage {triage_activation['case_id']} is already active\n"
                        )
            sys.stdout.write(
                f"activated {activation['case_id']} using {activation['run_report']}\n"
            )
    return exit_code


def _prepare_activate_on_pass(
    args: argparse.Namespace,
    payload: dict[str, object],
) -> dict[str, object]:
    triage_activation = _prepare_activate_sibling_triage(args, payload)
    if triage_activation is not None:
        triage_result = payload.get("triage_result")
        if isinstance(triage_result, dict):
            triage_result["activation"] = triage_activation

    return _activate_case(
        args.cases,
        args.case_id,
        workflow=_validation_workflow(args.workflow),
        run_report_path=_prepare_success_run_report(payload),
    )


def _prepare_activate_sibling_triage(
    args: argparse.Namespace,
    payload: Mapping[str, object],
) -> dict[str, object] | None:
    if args.workflow != "ymir-backport":
        return None

    triage_result = payload.get("triage_result")
    if not isinstance(triage_result, Mapping) or triage_result.get("status") not in {
        "cached",
        "generated",
    }:
        return None

    triage_cases_dir = _prepare_sibling_triage_cases_dir(args.cases)
    if triage_cases_dir is None:
        return None

    expected = _prepare_load_expected(triage_cases_dir, args.case_id)
    if expected is None:
        return None
    if expected.get("case_status") == "active":
        return {
            "case_id": args.case_id,
            "cases_dir": str(triage_cases_dir.resolve()),
            "expected_path": str(
                (triage_cases_dir / "expected" / f"{args.case_id}.expected.json").resolve()
            ),
            "status": "already_active",
        }

    run_report = _string_or_none(triage_result.get("run_report"))

    return _activate_case(
        triage_cases_dir,
        args.case_id,
        workflow=_validation_workflow("ymir-triage"),
        run_report_path=Path(run_report) if run_report is not None else None,
    )


def _prepare_case(
    args: argparse.Namespace,
    provenance: dict[str, str],
) -> tuple[dict[str, object], int]:
    triage_result = _prepare_backport_triage_result(args, provenance)
    if triage_result is not None and triage_result.get("status") not in {
        "cached",
        "generated",
    }:
        payload: dict[str, object] = {
            "case_id": args.case_id,
            "cases_dir": str(args.cases),
            "workflow": args.workflow,
            "variant": args.variant,
            "status": "triage_failed",
            "collected": None,
            "auto_allowed_hosts": [],
            "triage_result": triage_result,
            "iterations": [],
        }
        return payload, 1

    collected = None
    if _prepare_should_collect(args):
        collected = collect_case(_prepare_collect_request(args)).to_json()
    else:
        collected = _prepare_complete_existing_case(args)

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
    if triage_result is not None:
        payload["triage_result"] = triage_result
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

        if not report.has_failures and not _prepare_has_replay_candidates(
            results_dir,
            args.cases,
            args.case_id,
        ):
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
            + len(capture_result.captured_subprocesses)
            + len(capture_result.captured_koji_candidate_builds)
        )
        if captured_count == 0:
            if _prepare_has_only_recorded_replay_candidates(capture_result):
                if not report.has_failures:
                    payload["status"] = "succeeded"
                    exit_code = 0
                    break
                payload["status"] = "blocked"
                exit_code = run_exit_code or 1
                break
            payload["status"] = "blocked"
            exit_code = run_exit_code or 1
            break
        completion = _prepare_complete_existing_case(args)
        if completion is not None:
            iteration_payload["collected"] = completion
            if collected is None:
                collected = completion
    else:
        payload["status"] = "max_iterations"
        exit_code = 1

    payload["collected"] = collected
    return payload, exit_code


def _prepare_backport_triage_result(
    args: argparse.Namespace,
    provenance: dict[str, str],
) -> dict[str, object] | None:
    if args.workflow != "ymir-backport":
        return None

    destination = args.cases / "triage_results" / f"{args.case_id}.actual.json"
    if destination.is_file():
        return {
            "case_id": args.case_id,
            "path": str(destination),
            "status": "cached",
        }

    triage_cases_dir = _prepare_sibling_triage_cases_dir(args.cases)
    if triage_cases_dir is None:
        return {
            "case_id": args.case_id,
            "status": "missing_triage_cases",
            "message": "sibling ymir-triage cases directory was not found",
        }

    triage_args = _prepare_backport_triage_args(args, triage_cases_dir)
    triage_payload, triage_exit_code = _prepare_case(triage_args, provenance)
    if triage_exit_code != 0 or triage_payload.get("status") != "succeeded":
        return {
            "case_id": args.case_id,
            "exit_code": triage_exit_code,
            "status": "triage_prepare_failed",
            "prepare": triage_payload,
        }

    run_report_path = _prepare_success_run_report(triage_payload)
    source = _prepare_passing_triage_actual_path(run_report_path, args.case_id)
    if source is None:
        return {
            "case_id": args.case_id,
            "run_report": str(run_report_path),
            "status": "missing_triage_actual",
        }

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return {
        "case_id": args.case_id,
        "run_report": str(run_report_path),
        "source_path": str(source),
        "status": "generated",
        "written_path": str(destination),
    }


def _prepare_backport_triage_args(
    args: argparse.Namespace,
    triage_cases_dir: Path,
) -> argparse.Namespace:
    triage_args = argparse.Namespace(**vars(args))
    triage_args.cases = triage_cases_dir
    triage_args.workflow = "ymir-triage"
    if not args.overwrite and _prepare_load_expected(triage_cases_dir, args.case_id) is not None:
        triage_args.jira_url = None
        triage_args.jira_base_url = None
        triage_args.gitlab_mr_url = None
    if args.run_id:
        triage_args.run_id = f"{args.run_id}-triage"
    return triage_args


def _prepare_sibling_triage_cases_dir(cases_dir: Path) -> Path | None:
    if cases_dir.name != "ymir-backport":
        return None
    triage_cases_dir = cases_dir.parent / "ymir-triage"
    return triage_cases_dir if triage_cases_dir.is_dir() else None


def _prepare_passing_triage_actual_path(run_report_path: Path, case_id: str) -> Path | None:
    try:
        run_report = load_json_file(run_report_path)
    except (OSError, json.JSONDecodeError, ValueError):
        return None

    entries = run_report.get("cases")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("case_id") != case_id or entry.get("status") != "passed":
            continue
        actual_path = _string_or_none(entry.get("actual_path"))
        if actual_path is None:
            continue
        path = Path(actual_path)
        if not path.is_absolute():
            path = run_report_path.parent / path
        if path.is_file():
            return path
    return None


def _prepare_success_run_report(payload: Mapping[str, object]) -> Path:
    iterations = payload.get("iterations")
    if not isinstance(iterations, list):
        raise ValueError("prepare-case payload does not include iterations")
    for iteration in reversed(iterations):
        if not isinstance(iteration, Mapping):
            continue
        run = iteration.get("run")
        if not isinstance(run, Mapping):
            continue
        run_json = run.get("run_json")
        if isinstance(run_json, str) and run_json:
            return Path(run_json)
    raise ValueError("prepare-case did not produce a run report for activation")


def _prepare_has_only_recorded_replay_candidates(capture_result: CaptureMissingResult) -> bool:
    if not capture_result.skipped:
        return False
    recorded_reasons = {
        "source repo is already recorded",
        "subprocess command is already recorded",
        "subprocess command is recorded",
        "URL is already recorded",
        "URL is already recorded with successful content",
    }
    recorded_urls = {skip.url for skip in capture_result.skipped if skip.reason in recorded_reasons}
    unresolved_skips = [
        skip
        for skip in capture_result.skipped
        if skip.reason not in recorded_reasons and skip.url not in recorded_urls
    ]
    return not unresolved_skips


def _prepare_complete_existing_case(args: argparse.Namespace) -> dict[str, object] | None:
    expected = _prepare_load_expected(args.cases, args.case_id)
    if expected is None:
        return None

    written_paths: list[Path] = []
    warnings: list[str] = []
    expected = _prepare_write_inferred_expected_data(args, expected, written_paths, warnings)
    _prepare_write_inferred_mock_data(args, expected, written_paths, warnings)
    _prepare_write_inferred_koji_candidate_builds(args, expected, written_paths, warnings)
    if not written_paths and not warnings:
        return None
    return {
        "case_id": args.case_id,
        "cases_dir": str(args.cases.resolve()),
        "written_paths": [str(path) for path in written_paths],
        "warnings": warnings,
        "fetched_urls": [],
    }


def _prepare_load_expected(cases_dir: Path, case_id: str) -> Mapping[str, Any] | None:
    path = cases_dir / "expected" / f"{case_id}.expected.json"
    if not path.is_file():
        return None
    loaded = load_json_file(path)
    return loaded if isinstance(loaded, Mapping) else None


def _prepare_write_inferred_expected_data(
    args: argparse.Namespace,
    expected: Mapping[str, Any],
    written_paths: list[Path],
    warnings: list[str],
) -> Mapping[str, Any]:
    requested_branch = _prepare_mock_requested_branch(args, expected)
    current_branch = _string_or_none(expected.get("target_branch"))
    if (
        args.workflow != "ymir-backport"
        or requested_branch is None
        or requested_branch == current_branch
    ):
        return expected
    if not args.overwrite:
        warnings.append(
            "expected fixture target_branch differs from generated triage result "
            f"({current_branch!r} != {requested_branch!r}); rerun with --overwrite to update it"
        )
        return expected

    updated = dict(expected)
    updated["target_branch"] = requested_branch
    expected_path = args.cases / "expected" / f"{args.case_id}.expected.json"
    expected_path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written_paths.append(expected_path)
    return updated


def _prepare_write_inferred_mock_data(
    args: argparse.Namespace,
    expected: Mapping[str, Any],
    written_paths: list[Path],
    warnings: list[str],
) -> None:
    agent = _workflow_mock_agent(args.workflow)
    if agent is None:
        return

    mock_path = args.cases / "mock_data" / agent / f"{args.case_id}.json"
    if mock_path.exists() and not args.overwrite:
        return

    package = _prepare_mock_package(args, expected)
    requested_branch = _prepare_mock_requested_branch(args, expected)
    if package is None or requested_branch is None:
        return

    source_branch = _prepare_centos_stream_branch(requested_branch)
    if source_branch is None:
        warnings.append(
            "mock_data fixture was not written; cannot infer CentOS Stream branch "
            f"from {requested_branch!r}"
        )
        return

    remote_url = _prepare_mock_distgit_url(args, package, requested_branch)
    pre_fix_ref = _prepare_mock_pre_fix_ref(
        args,
        expected=expected,
        package=package,
        requested_branch=requested_branch,
        source_branch=source_branch,
        remote_url=remote_url,
    )
    if pre_fix_ref is None:
        warnings.append(
            "mock_data fixture was not written; source_cache does not "
            f"contain branch {source_branch!r} for {package}"
        )
        return

    payload: dict[str, Any] = {
        "case_id": args.case_id,
        "case_type": expected.get("case_type"),
        "repos": [
            {
                "branch": _prepare_mock_materialized_branch(args, source_branch, requested_branch),
                "package": package,
                "pre_fix_ref": pre_fix_ref,
                "remote_url": remote_url,
            }
        ],
        "schema_version": 1,
    }
    zstream_override = _prepare_zstream_override(source_branch, requested_branch)
    if zstream_override:
        payload["zstream_override"] = zstream_override

    mock_path.parent.mkdir(parents=True, exist_ok=True)
    mock_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written_paths.append(mock_path)


def _prepare_write_inferred_koji_candidate_builds(
    args: argparse.Namespace,
    expected: Mapping[str, Any],
    written_paths: list[Path],
    warnings: list[str],
) -> None:
    if args.workflow != "ymir-backport" or expected.get("network_mode") == "network_denied":
        return

    package = _prepare_mock_package(args, expected)
    requested_branch = _prepare_mock_requested_branch(args, expected)
    if package is None or requested_branch is None:
        return

    manifest_path = args.cases / "web_cache" / args.case_id / "manifest.json"
    manifest = _prepare_load_web_manifest(manifest_path, expected)
    records = manifest.setdefault(KOJI_CANDIDATE_BUILDS_MANIFEST_KEY, {})
    if not isinstance(records, dict):
        warnings.append(
            "Koji candidate build fixtures were not written; "
            f"{KOJI_CANDIDATE_BUILDS_MANIFEST_KEY} is not an object"
        )
        return

    as_of = args.as_of or derive_as_of(args.cases, args.case_id)
    wrote = False
    for branch in candidate_build_branches(requested_branch):
        key = candidate_build_key(package, branch)
        if key in records and not args.overwrite:
            continue
        try:
            records[key] = fetch_candidate_build(
                package,
                branch,
                as_of=as_of,
                timeout=getattr(args, "http_timeout", None),
            )
        except Exception as exc:
            warnings.append(f"skipped Koji candidate build for {package} {branch}: {exc}")
            continue
        wrote = True

    if not wrote:
        return
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written_paths.append(manifest_path)


def _prepare_load_web_manifest(
    manifest_path: Path,
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    if manifest_path.is_file():
        loaded = load_json_file(manifest_path)
        if isinstance(loaded, Mapping):
            return dict(loaded)
    return {
        "case_id": expected.get("case_id"),
        "case_type": expected.get("case_type"),
        KOJI_CANDIDATE_BUILDS_MANIFEST_KEY: {},
        "recorded_files": {},
        "required_urls": [],
        "schema_version": SCHEMA_VERSION,
    }


def _prepare_mock_package(args: argparse.Namespace, expected: Mapping[str, Any]) -> str | None:
    triage_result = _prepare_load_backport_triage_result(args)
    triage_data = _mapping_or_empty(triage_result.get("data")) if triage_result else {}
    return _string_or_none(
        triage_data.get("package")
        or (triage_result or {}).get("package")
        or expected.get("package")
    )


def _prepare_mock_requested_branch(
    args: argparse.Namespace,
    expected: Mapping[str, Any],
) -> str | None:
    triage_result = _prepare_load_backport_triage_result(args)
    triage_data = _mapping_or_empty(triage_result.get("data")) if triage_result else {}
    return _string_or_none(
        triage_data.get("target_branch")
        or (triage_result or {}).get("target_branch")
        or triage_data.get("fix_version")
        or (triage_result or {}).get("fix_version")
        or expected.get("target_branch")
        or expected.get("fix_version")
    )


def _prepare_mock_materialized_branch(
    args: argparse.Namespace,
    source_branch: str,
    requested_branch: str,
) -> str:
    if args.workflow == "ymir-backport" and _prepare_load_backport_triage_result(args) is not None:
        return requested_branch
    return source_branch


def _prepare_load_backport_triage_result(args: argparse.Namespace) -> Mapping[str, Any] | None:
    if args.workflow != "ymir-backport":
        return None
    path = args.cases / "triage_results" / f"{args.case_id}.actual.json"
    if not path.is_file():
        return None
    loaded = load_json_file(path)
    return loaded if isinstance(loaded, Mapping) else None


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _prepare_centos_stream_branch(expected_branch: str) -> str | None:
    if re.fullmatch(r"c\d+s", expected_branch):
        return expected_branch
    match = re.match(r"rhel-(\d+)(?:\.|$)", expected_branch)
    if match is None:
        return None
    return f"c{match.group(1)}s"


def _prepare_centos_stream_distgit_url(package: str) -> str:
    return f"https://gitlab.com/redhat/centos-stream/rpms/{quote(package, safe='._+-')}.git"


def _prepare_rhel_distgit_url(package: str) -> str:
    return f"https://gitlab.com/redhat/rhel/rpms/{quote(package, safe='._+-')}.git"


def _prepare_mock_distgit_url(
    args: argparse.Namespace,
    package: str,
    requested_branch: str,
) -> str:
    if args.workflow == "ymir-backport" and not re.fullmatch(r"c\d+s", requested_branch):
        return _prepare_rhel_distgit_url(package)
    return _prepare_centos_stream_distgit_url(package)


def _prepare_mock_pre_fix_ref(
    args: argparse.Namespace,
    *,
    expected: Mapping[str, Any],
    package: str,
    requested_branch: str,
    source_branch: str,
    remote_url: str,
) -> str | None:
    return (
        _prepare_internal_rhel_branch_parent_ref(
            args,
            package=package,
            requested_branch=requested_branch,
            remote_url=remote_url,
        )
        or _prepare_patch_parent_ref(args, expected=expected, remote_url=remote_url)
        or _prepare_merge_request_parent_ref(args, remote_url=remote_url)
        or resolve_source_cache_ref(
            args.cases,
            args.case_id,
            remote_url,
            f"refs/heads/{source_branch}",
        )
    )


def _prepare_internal_rhel_branch_parent_ref(
    args: argparse.Namespace,
    *,
    package: str,
    requested_branch: str,
    remote_url: str,
) -> str | None:
    if args.workflow != "ymir-backport" or re.fullmatch(r"c\d+s", requested_branch):
        return None
    branches_path = (
        args.cases
        / "web_cache"
        / args.case_id
        / "gitlab"
        / "internal_rhel"
        / package
        / "branches.json"
    )
    try:
        branches = json.loads(branches_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(branches, list):
        return None
    for branch in branches:
        if not isinstance(branch, Mapping) or branch.get("name") != requested_branch:
            continue
        commit = branch.get("commit")
        if not isinstance(commit, Mapping):
            continue
        parent_ids = commit.get("parent_ids")
        if not isinstance(parent_ids, list):
            continue
        for parent_id in parent_ids:
            if not isinstance(parent_id, str) or not parent_id:
                continue
            if source_cache_contains_object(args.cases, args.case_id, remote_url, parent_id):
                return parent_id
    return None


def _prepare_patch_parent_ref(
    args: argparse.Namespace,
    *,
    expected: Mapping[str, Any],
    remote_url: str,
) -> str | None:
    for url in (
        *_string_list(expected.get("patch_urls")),
        *_string_list(expected.get("fix_sources")),
    ):
        commit = _prepare_commit_sha_from_url(url)
        if commit is None:
            continue
        parent = _prepare_source_cache_parent(args, remote_url=remote_url, commit=commit)
        if parent is not None:
            return parent
    return None


def _prepare_merge_request_parent_ref(
    args: argparse.Namespace,
    *,
    remote_url: str,
) -> str | None:
    commits_path = args.cases / "web_cache" / args.case_id / "gitlab" / "commits.json"
    try:
        commits = json.loads(commits_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(commits, list):
        return None

    commit_ids = {
        commit.get("id")
        for commit in commits
        if isinstance(commit, Mapping) and isinstance(commit.get("id"), str)
    }
    for commit in commits:
        if not isinstance(commit, Mapping):
            continue
        parent_ids = commit.get("parent_ids")
        if not isinstance(parent_ids, list):
            continue
        for parent_id in parent_ids:
            if (
                isinstance(parent_id, str)
                and parent_id
                and parent_id not in commit_ids
                and source_cache_contains_object(args.cases, args.case_id, remote_url, parent_id)
            ):
                return parent_id
    return None


def _prepare_commit_sha_from_url(url: str) -> str | None:
    match = re.search(r"/-/commit/([0-9a-f]{40})(?:[./?#]|$)", url, re.IGNORECASE)
    if match is not None:
        return match.group(1)
    match = re.search(r"/commit/([0-9a-f]{40})(?:[./?#]|$)", url, re.IGNORECASE)
    return match.group(1) if match is not None else None


def _prepare_source_cache_parent(
    args: argparse.Namespace,
    *,
    remote_url: str,
    commit: str,
) -> str | None:
    repository = source_cache_repo_for_object(args.cases, args.case_id, remote_url, commit)
    if repository is None:
        return None
    completed = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", f"{commit}^"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    parent = completed.stdout.strip()
    if not parent or not source_cache_contains_object(args.cases, args.case_id, remote_url, parent):
        return None
    return parent


def _prepare_zstream_override(branch: str, expected_branch: str) -> dict[str, str]:
    if expected_branch == branch:
        return {}
    match = re.search(r"\brhel-(\d+)", expected_branch)
    if match is None:
        return {}
    return {match.group(1): expected_branch}


def _string_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = value.strip()
        return [value] if value else []
    if not isinstance(value, list | tuple):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _prepare_has_replay_candidates(
    results_dir: Path,
    cases_dir: Path | None = None,
    case_id: str | None = None,
) -> bool:
    try:
        blocked_urls = blocked_urls_from_run_path(results_dir)
        recorded_urls = _prepare_recorded_replay_urls(cases_dir, case_id)
        blocked_urls = [
            blocked
            for blocked in blocked_urls
            if not _prepare_blocked_url_is_recorded(
                blocked.url,
                recorded_urls,
                cases_dir,
                case_id,
            )
        ]
        lookaside_sources = _prepare_unrecorded_lookaside_sources(
            results_dir,
            cases_dir,
            case_id,
        )
        return bool(blocked_urls or jira_requests_from_run_path(results_dir) or lookaside_sources)
    except CaptureMissingError:
        return False


def _prepare_unrecorded_lookaside_sources(
    results_dir: Path,
    cases_dir: Path | None,
    case_id: str | None,
) -> list[tuple[str, str]]:
    if case_id is None:
        return []
    requests = lookaside_source_requests_from_run_path(results_dir, case_id)
    if cases_dir is None:
        return [(request.filename, request.url) for request in requests]
    return [
        (request.filename, request.url)
        for request in requests
        if not (cases_dir / "source_cache" / case_id / "lookaside" / request.filename).is_file()
    ]


def _prepare_blocked_url_is_recorded(
    url: str,
    recorded_urls: set[str],
    cases_dir: Path | None,
    case_id: str | None,
) -> bool:
    canonical_url = canonicalize_replay_url(url)
    if canonical_url in recorded_urls:
        return True
    if cases_dir is None or case_id is None:
        return False
    try:
        return source_cache_repo_for_object(cases_dir, case_id, canonical_url) is not None
    except SourceFixtureError:
        return False


def _prepare_recorded_replay_urls(cases_dir: Path | None, case_id: str | None) -> set[str]:
    if cases_dir is None or case_id is None:
        return set()
    manifest_path = cases_dir / "web_cache" / case_id / "manifest.json"
    try:
        manifest = load_json_file(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return set()

    recorded: set[str] = set()
    required_urls = manifest.get("required_urls")
    if isinstance(required_urls, list):
        recorded.update(
            canonicalize_replay_url(url)
            for url in required_urls
            if isinstance(url, str) and canonicalize_replay_url(url)
        )

    recorded_files = manifest.get("recorded_files")
    if isinstance(recorded_files, Mapping):
        recorded.update(
            canonicalize_replay_url(url)
            for url in recorded_files
            if isinstance(url, str) and canonicalize_replay_url(url)
        )
    return recorded


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
    base.captured_subprocesses.extend(update.captured_subprocesses)
    base.captured_koji_candidate_builds.extend(update.captured_koji_candidate_builds)
    base.skipped.extend(update.skipped)
    base.failed.extend(update.failed)

    captured_urls = {capture.url for capture in base.captured}
    captured_urls.update(capture.url for capture in base.captured_jira)
    captured_urls.update(capture.url for capture in base.captured_source)
    captured_urls.update(capture.url for capture in base.captured_git_failures)
    captured_urls.update(
        f"koji-candidate-build:{capture.key}" for capture in base.captured_koji_candidate_builds
    )
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
        base_env=_prepare_run_environment(),
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


def _prepare_run_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.setdefault(
        "YMIR_HARNESS_WORKFLOW_PROGRESS_INTERVAL",
        DEFAULT_PREPARE_WORKFLOW_PROGRESS_INTERVAL_SECONDS,
    )
    environment.setdefault(STOP_ON_REPLAY_MISS_ENV, "1")
    return environment


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
        _write_run_summary(report)
        sys.stdout.write(f"run report written to {output_path}\n")

    return 1 if report.has_failures else 0


def _write_run_summary(report: Any) -> None:
    summary = report.summary()
    sys.stdout.write(
        "benchmark run: "
        f"{summary['passed']} passed, "
        f"{summary['failed']} failed, "
        f"{int(summary.get('timeout', 0))} timeout, "
        f"{summary['not_run']} not run, "
        f"{summary['skipped']} skipped, "
        f"{summary['unsupported']} unsupported\n"
    )
    metrics = _run_metric_summary(report)
    if metrics:
        sys.stdout.write(f"metrics: {metrics}\n")


def _run_metric_summary(report: Any) -> str | None:
    entries = list(getattr(report, "entries", []))
    parts = []

    runtimes = [
        value
        for value in (_number_or_none(getattr(entry, "runtime_seconds", None)) for entry in entries)
        if value is not None
    ]
    if runtimes:
        parts.append(
            f"runtime {_format_seconds(sum(runtimes))} total / "
            f"{_format_seconds(sum(runtimes) / len(runtimes))} avg"
        )

    token_counts = [
        value for value in (_entry_token_count(entry) for entry in entries) if value is not None
    ]
    if token_counts:
        parts.append(f"tokens {_format_number(sum(token_counts) / len(token_counts))} avg")

    tool_calls = [
        value
        for value in (_entry_metric_number(entry, "tool_call_count") for entry in entries)
        if value is not None
    ]
    if tool_calls:
        parts.append(f"tool calls {_format_number(sum(tool_calls) / len(tool_calls))} avg")

    costs = [
        value
        for value in (_entry_metric_number(entry, "total_cost_usd") for entry in entries)
        if value is not None
    ]
    if costs:
        parts.append(
            f"cost ${_format_number(sum(costs))} total / "
            f"${_format_number(sum(costs) / len(costs))} avg"
        )

    return "; ".join(parts) if parts else None


def _entry_token_count(entry: Any) -> float | None:
    direct = _entry_metric_number(entry, "token_count")
    if direct is not None:
        return direct

    usage = _entry_advisory_metric(entry, "token_usage")
    if isinstance(usage, Mapping):
        token_values = [
            _number_or_none(value) for key, value in usage.items() if "token" in str(key).lower()
        ]
        numbers = [value for value in token_values if value is not None]
        if numbers:
            return sum(numbers)
        all_values = [_number_or_none(value) for value in usage.values()]
        all_numbers = [value for value in all_values if value is not None]
        if all_numbers:
            return sum(all_numbers)
    return _number_or_none(usage)


def _entry_metric_number(entry: Any, name: str) -> float | None:
    return _number_or_none(_entry_advisory_metric(entry, name))


def _entry_advisory_metric(entry: Any, name: str) -> Any:
    score = getattr(entry, "score", None)
    if score is None:
        return None
    for metric in getattr(score, "advisory_metrics", []):
        if getattr(metric, "name", None) == name:
            return getattr(metric, "value", None)
    return None


def _number_or_none(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _format_seconds(value: float) -> str:
    return f"{_format_number(value)}s"


def _format_number(value: float) -> str:
    text = f"{value:.4f}" if abs(value) < 1 else f"{value:.2f}"
    return text.rstrip("0").rstrip(".")


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
