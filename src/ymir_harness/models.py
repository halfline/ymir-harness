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
ScoreCollectionStatus = Literal["passed", "failed", "missing", "skipped"]
ComparisonDelta = Literal[
    "win",
    "regression",
    "unchanged_pass",
    "unchanged_fail",
    "missing_in_baseline",
    "missing_in_candidate",
    "non_headline",
]


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
    phase: int
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
            "phase": self.phase,
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


@dataclass
class ScoreReport:
    case_id: str
    case_type: str | None
    metrics: list[ScoreMetric]

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
        }


@dataclass
class ScoreCollectionEntry:
    case_id: str
    case_type: str | None
    case_status: str | None
    expected_path: Path
    actual_path: Path | None
    status: ScoreCollectionStatus
    headline: bool
    headline_reason: str | None = None
    score: ScoreReport | None = None
    reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "case_status": self.case_status,
            "expected_path": str(self.expected_path),
            "actual_path": str(self.actual_path) if self.actual_path else None,
            "status": self.status,
            "headline": self.headline,
        }
        if self.headline_reason:
            payload["headline_reason"] = self.headline_reason
        if self.reason:
            payload["reason"] = self.reason
        if self.score is not None:
            payload["score"] = self.score.to_json()
        return payload


@dataclass
class ScoreCollectionReport:
    cases_dir: Path
    actual_results_dir: Path
    entries: list[ScoreCollectionEntry]
    run_id: str | None = None
    ymir_sha: str | None = None
    variant: str | None = None
    harness_version: str | None = None
    fixture_checksum: str | None = None

    @property
    def has_headline_failures(self) -> bool:
        return any(
            entry.headline and entry.status in {"failed", "missing"} for entry in self.entries
        )

    def summary(self) -> dict[str, int | bool]:
        counts: dict[str, int | bool] = {
            "total": len(self.entries),
            "passed": 0,
            "failed": 0,
            "missing": 0,
            "skipped": 0,
            "headline_passed": 0,
            "headline_failed": 0,
            "headline_missing": 0,
            "non_headline": 0,
            "has_headline_failures": self.has_headline_failures,
        }
        for entry in self.entries:
            counts[entry.status] = int(counts[entry.status]) + 1
            if entry.headline:
                if entry.status in {"passed", "failed", "missing"}:
                    key = f"headline_{entry.status}"
                    counts[key] = int(counts[key]) + 1
            else:
                counts["non_headline"] = int(counts["non_headline"]) + 1
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "ymir_sha": self.ymir_sha,
            "variant": self.variant,
            "harness_version": self.harness_version,
            "fixture_checksum": self.fixture_checksum,
            "cases_dir": str(self.cases_dir),
            "actual_results_dir": str(self.actual_results_dir),
            "summary": self.summary(),
            "cases": [entry.to_json() for entry in self.entries],
        }


@dataclass(frozen=True)
class ComparisonEntry:
    case_id: str
    case_type: str | None
    headline: bool
    baseline_status: str | None
    candidate_status: str | None
    delta: ComparisonDelta
    headline_reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        payload = {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "headline": self.headline,
            "baseline_status": self.baseline_status,
            "candidate_status": self.candidate_status,
            "delta": self.delta,
        }
        if self.headline_reason:
            payload["headline_reason"] = self.headline_reason
        return payload


@dataclass
class ComparisonReport:
    baseline_path: Path
    candidate_path: Path
    entries: list[ComparisonEntry]

    @property
    def has_headline_regressions(self) -> bool:
        return any(
            entry.headline and entry.delta in {"regression", "missing_in_candidate"}
            for entry in self.entries
        )

    def summary(self) -> dict[str, int | bool]:
        counts: dict[str, int | bool] = {
            "total": len(self.entries),
            "headline_total": 0,
            "wins": 0,
            "regressions": 0,
            "unchanged_pass": 0,
            "unchanged_fail": 0,
            "missing_in_baseline": 0,
            "missing_in_candidate": 0,
            "non_headline": 0,
            "has_headline_regressions": self.has_headline_regressions,
        }
        for entry in self.entries:
            if entry.delta == "win":
                counts["wins"] = int(counts["wins"]) + 1
            elif entry.delta == "regression":
                counts["regressions"] = int(counts["regressions"]) + 1
            else:
                counts[entry.delta] = int(counts[entry.delta]) + 1
            if entry.headline:
                counts["headline_total"] = int(counts["headline_total"]) + 1
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "baseline_path": str(self.baseline_path),
            "candidate_path": str(self.candidate_path),
            "summary": self.summary(),
            "cases": [entry.to_json() for entry in self.entries],
        }
