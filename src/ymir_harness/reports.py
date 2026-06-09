from __future__ import annotations

import json
from pathlib import Path

from ymir_harness.models import ValidationIssue, ValidationReport


def write_validation_reports(report: ValidationReport, reports_dir: Path) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)

    json_path = reports_dir / "fixture-validation.json"
    md_path = reports_dir / "fixture-validation.md"
    errors_path = reports_dir / "fixture-validation-errors.md"

    json_path.write_text(
        json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_validation_markdown(report), encoding="utf-8")
    errors_path.write_text(render_validation_errors_markdown(report), encoding="utf-8")

    return [json_path, md_path, errors_path]


def render_validation_markdown(report: ValidationReport) -> str:
    summary = report.summary()
    lines = [
        "# Fixture Validation",
        "",
        f"- Cases directory: `{report.cases_dir}`",
        f"- Valid: `{summary['valid']}`",
        f"- Warning-only: `{summary['warning-only']}`",
        f"- Invalid: `{summary['invalid']}`",
        f"- Skipped: `{summary['skipped']}`",
        "",
        "| Case | Type | Case Status | Validation | Errors | Warnings |",
        "| --- | --- | --- | --- | ---: | ---: |",
    ]
    for case in report.cases:
        lines.append(
            "| "
            f"{case.case_id} | "
            f"{case.case_type or ''} | "
            f"{case.case_status or ''} | "
            f"{case.status} | "
            f"{case.error_count} | "
            f"{case.warning_count} |"
        )

    all_issues = [*report.global_issues]
    for case in report.cases:
        all_issues.extend(case.issues)

    if all_issues:
        lines.extend(["", "## Issues", ""])
        lines.extend(_render_issue_lines(all_issues))

    return "\n".join(lines).rstrip() + "\n"


def render_validation_errors_markdown(report: ValidationReport) -> str:
    errors = [issue for issue in report.global_issues if issue.severity == "error"]
    for case in report.cases:
        errors.extend(issue for issue in case.issues if issue.severity == "error")

    lines = ["# Fixture Validation Errors", ""]
    if not errors:
        lines.append("No validation errors.")
    else:
        lines.extend(_render_issue_lines(errors))
    return "\n".join(lines).rstrip() + "\n"


def _render_issue_lines(issues: list[ValidationIssue]) -> list[str]:
    lines = []
    for issue in issues:
        location = issue.case_id or "global"
        if issue.path:
            location = f"{location} `{issue.path}`"
        lines.append(f"- `{issue.severity}` `{issue.category}` {location}: {issue.message}")
    return lines
