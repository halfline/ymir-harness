from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = {SCHEMA_VERSION}

ALLOWED_CASE_TYPES = {
    "cve_backport",
    "rebase",
    "not_affected",
    "postponed",
    "clarification_needed",
    "rebuild",
    "dependency_rebuild",
    "messy_triage",
}

ALLOWED_RESOLUTIONS = {
    "backport",
    "rebase",
    "rebuild",
    "not_affected",
    "postponed",
    "clarification_needed",
}

ALLOWED_EXPECTED_BASES = {
    "merged_mr",
    "maintainer_decision",
    "build_result",
    "manual_review",
    "historical_jira_state",
}

ALLOWED_GROUND_TRUTH_CONFIDENCE = {"high", "medium", "low"}
ALLOWED_ANSWER_LEAKAGE = {"none", "partial", "explicit"}
ALLOWED_CASE_STATUSES = {"active", "quarantined", "excluded"}
ALLOWED_NETWORK_MODES = {"replay_only", "network_denied", "live_non_reproducible"}
ALLOWED_REFERENCE_PATCH_MODES = {"applies", "scope_only", "semantic_reference"}
ALLOWED_BACKPORT_SOURCES = {"upstream", "distgit", "mixed"}

FAILURE_CATEGORIES = {
    "missing_metadata",
    "schema_mismatch",
    "mock_repo_mismatch",
    "invalid_pre_fix_ref",
    "fix_already_present",
    "reference_patch_invalid",
    "web_cache_incomplete",
    "source_cache_incomplete",
    "ground_truth_ambiguous",
    "network_policy_invalid",
    "jira_mock_invalid",
}

IssueSeverity = Literal["error", "warning"]
CaseValidationStatus = Literal["valid", "invalid", "warning-only", "skipped"]


@dataclass(frozen=True)
class ValidationIssue:
    severity: IssueSeverity
    category: str
    message: str
    case_id: str | None = None
    path: str | None = None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
        }
        if self.case_id is not None:
            payload["case_id"] = self.case_id
        if self.path is not None:
            payload["path"] = self.path
        return payload


@dataclass
class CaseValidationResult:
    case_id: str
    case_type: str | None = None
    case_status: str | None = None
    status: CaseValidationStatus = "valid"
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "warning")

    def finalize(self) -> None:
        if self.case_status == "excluded":
            self.status = "skipped"
        elif self.error_count:
            self.status = "invalid"
        elif self.warning_count:
            self.status = "warning-only"
        else:
            self.status = "valid"

    def to_json(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "case_status": self.case_status,
            "status": self.status,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [issue.to_json() for issue in self.issues],
        }


@dataclass
class ValidationReport:
    cases_dir: Path
    cases: list[CaseValidationResult] = field(default_factory=list)
    global_issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def has_blocking_errors(self) -> bool:
        if any(issue.severity == "error" for issue in self.global_issues):
            return True
        return any(case.status == "invalid" for case in self.cases)

    def summary(self) -> dict[str, int]:
        counts = {
            "valid": 0,
            "invalid": 0,
            "warning-only": 0,
            "skipped": 0,
            "global_errors": sum(1 for issue in self.global_issues if issue.severity == "error"),
            "global_warnings": sum(
                1 for issue in self.global_issues if issue.severity == "warning"
            ),
        }
        for case in self.cases:
            counts[case.status] += 1
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "cases_dir": str(self.cases_dir),
            "summary": self.summary(),
            "global_issues": [issue.to_json() for issue in self.global_issues],
            "cases": [case.to_json() for case in self.cases],
        }
