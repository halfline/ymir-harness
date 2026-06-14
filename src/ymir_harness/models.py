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
ScoreMetricStatus = Literal["pass", "fail", "skipped"]
RunCaseStatus = Literal["not_run", "passed", "failed", "timeout", "skipped", "unsupported"]


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


@dataclass(frozen=True)
class ScoreMetric:
    name: str
    status: ScoreMetricStatus
    expected: Any = None
    actual: Any = None
    notes: str | None = None

    def to_json(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "status": self.status,
            "expected": self.expected,
            "actual": self.actual,
        }
        if self.notes:
            payload["notes"] = self.notes
        return payload


@dataclass(frozen=True)
class AdvisoryMetric:
    name: str
    value: Any

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
        }


@dataclass
class ScoreReport:
    case_id: str
    case_type: str | None
    metrics: list[ScoreMetric]
    advisory_metrics: list[AdvisoryMetric] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(metric.status != "fail" for metric in self.metrics)

    def summary(self) -> dict[str, int | bool]:
        return {
            "passed": self.passed,
            "pass": sum(1 for metric in self.metrics if metric.status == "pass"),
            "fail": sum(1 for metric in self.metrics if metric.status == "fail"),
            "skipped": sum(1 for metric in self.metrics if metric.status == "skipped"),
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": self.case_id,
            "case_type": self.case_type,
            "summary": self.summary(),
            "metrics": [metric.to_json() for metric in self.metrics],
            "advisory_metrics": [metric.to_json() for metric in self.advisory_metrics],
        }


@dataclass
class RunCaseResult:
    case_id: str
    case_type: str | None
    status: RunCaseStatus
    repetition: int = 1
    expected_path: Path | None = None
    actual_path: Path | None = None
    score: ScoreReport | None = None
    runtime_seconds: float | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "status": self.status,
            "repetition": self.repetition,
            "expected_path": str(self.expected_path) if self.expected_path else None,
            "actual_path": str(self.actual_path) if self.actual_path else None,
        }
        if self.score is not None:
            payload["score"] = self.score.to_json()
        if self.runtime_seconds is not None:
            payload["runtime_seconds"] = self.runtime_seconds
        if self.reason:
            payload["reason"] = self.reason
        if self.warnings:
            payload["warnings"] = self.warnings
        return payload


@dataclass
class RunReport:
    cases_dir: Path
    results_dir: Path
    entries: list[RunCaseResult]
    run_id: str
    variant: str
    ymir_sha: str | None = None
    harness_version: str | None = None
    fixture_checksum: str | None = None
    features: list[str] = field(default_factory=list)
    repeat: int = 1
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def has_failures(self) -> bool:
        return any(entry.status in {"failed", "timeout"} for entry in self.entries)

    def summary(self) -> dict[str, int | bool]:
        counts: dict[str, int | bool] = {
            "total": len(self.entries),
            "not_run": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "unsupported": 0,
            "has_failures": self.has_failures,
        }
        for entry in self.entries:
            if entry.status == "timeout":
                counts["timeout"] = int(counts.get("timeout", 0)) + 1
            else:
                counts[entry.status] = int(counts[entry.status]) + 1
            if entry.warnings:
                counts["warnings"] = int(counts.get("warnings", 0)) + len(entry.warnings)
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "variant": self.variant,
            "ymir_sha": self.ymir_sha,
            "harness_version": self.harness_version,
            "fixture_checksum": self.fixture_checksum,
            "features": self.features,
            "repeat": self.repeat,
            "provenance": self.provenance,
            "cases_dir": str(self.cases_dir),
            "results_dir": str(self.results_dir),
            "summary": self.summary(),
            "cases": [entry.to_json() for entry in self.entries],
        }
