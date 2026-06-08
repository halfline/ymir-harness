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
RunCaseStatus = Literal["not_run", "passed", "failed", "timeout", "skipped", "unsupported"]
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
    provenance: dict[str, Any] = field(default_factory=dict)

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
            "provenance": self.provenance,
            "cases_dir": str(self.cases_dir),
            "actual_results_dir": str(self.actual_results_dir),
            "summary": self.summary(),
            "cases": [entry.to_json() for entry in self.entries],
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


@dataclass(frozen=True)
class ComparisonEntry:
    case_id: str
    case_type: str | None
    headline: bool
    baseline_status: str | None
    candidate_status: str | None
    delta: ComparisonDelta
    headline_reason: str | None = None
    baseline_repetitions: int | None = None
    candidate_repetitions: int | None = None
    baseline_stability: str | None = None
    candidate_stability: str | None = None
    baseline_runtime_seconds: float | None = None
    candidate_runtime_seconds: float | None = None
    runtime_delta_seconds: float | None = None
    baseline_token_count: float | None = None
    candidate_token_count: float | None = None
    token_delta: float | None = None
    baseline_tool_call_count: float | None = None
    candidate_tool_call_count: float | None = None
    tool_call_delta: float | None = None
    baseline_total_cost_usd: float | None = None
    candidate_total_cost_usd: float | None = None
    cost_delta_usd: float | None = None

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
        if self.baseline_repetitions is not None:
            payload["baseline_repetitions"] = self.baseline_repetitions
        if self.candidate_repetitions is not None:
            payload["candidate_repetitions"] = self.candidate_repetitions
        if self.baseline_stability is not None:
            payload["baseline_stability"] = self.baseline_stability
        if self.candidate_stability is not None:
            payload["candidate_stability"] = self.candidate_stability
        if self.baseline_runtime_seconds is not None:
            payload["baseline_runtime_seconds"] = self.baseline_runtime_seconds
        if self.candidate_runtime_seconds is not None:
            payload["candidate_runtime_seconds"] = self.candidate_runtime_seconds
        if self.runtime_delta_seconds is not None:
            payload["runtime_delta_seconds"] = self.runtime_delta_seconds
        if self.baseline_token_count is not None:
            payload["baseline_token_count"] = self.baseline_token_count
        if self.candidate_token_count is not None:
            payload["candidate_token_count"] = self.candidate_token_count
        if self.token_delta is not None:
            payload["token_delta"] = self.token_delta
        if self.baseline_tool_call_count is not None:
            payload["baseline_tool_call_count"] = self.baseline_tool_call_count
        if self.candidate_tool_call_count is not None:
            payload["candidate_tool_call_count"] = self.candidate_tool_call_count
        if self.tool_call_delta is not None:
            payload["tool_call_delta"] = self.tool_call_delta
        if self.baseline_total_cost_usd is not None:
            payload["baseline_total_cost_usd"] = self.baseline_total_cost_usd
        if self.candidate_total_cost_usd is not None:
            payload["candidate_total_cost_usd"] = self.candidate_total_cost_usd
        if self.cost_delta_usd is not None:
            payload["cost_delta_usd"] = self.cost_delta_usd
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

    def summary(self) -> dict[str, int | bool | float]:
        counts: dict[str, int | bool | float] = {
            "total": len(self.entries),
            "headline_total": 0,
            "wins": 0,
            "regressions": 0,
            "unchanged_pass": 0,
            "unchanged_fail": 0,
            "missing_in_baseline": 0,
            "missing_in_candidate": 0,
            "non_headline": 0,
            "stable_wins": 0,
            "stable_regressions": 0,
            "flaky_cases": 0,
            "has_headline_regressions": self.has_headline_regressions,
        }
        cost_delta = 0.0
        runtime_delta = 0.0
        token_delta = 0.0
        tool_call_delta = 0.0
        has_cost_delta = False
        has_runtime_delta = False
        has_token_delta = False
        has_tool_call_delta = False
        for entry in self.entries:
            if entry.delta == "win":
                counts["wins"] = int(counts["wins"]) + 1
            elif entry.delta == "regression":
                counts["regressions"] = int(counts["regressions"]) + 1
            else:
                counts[entry.delta] = int(counts[entry.delta]) + 1
            if entry.headline:
                counts["headline_total"] = int(counts["headline_total"]) + 1
            stable = entry.baseline_stability == "stable" and entry.candidate_stability == "stable"
            if stable and entry.delta == "win":
                counts["stable_wins"] = int(counts["stable_wins"]) + 1
            if stable and entry.delta == "regression":
                counts["stable_regressions"] = int(counts["stable_regressions"]) + 1
            if entry.baseline_stability == "flaky" or entry.candidate_stability == "flaky":
                counts["flaky_cases"] = int(counts["flaky_cases"]) + 1
            if entry.cost_delta_usd is not None:
                cost_delta += entry.cost_delta_usd
                has_cost_delta = True
            if entry.runtime_delta_seconds is not None:
                runtime_delta += entry.runtime_delta_seconds
                has_runtime_delta = True
            if entry.token_delta is not None:
                token_delta += entry.token_delta
                has_token_delta = True
            if entry.tool_call_delta is not None:
                tool_call_delta += entry.tool_call_delta
                has_tool_call_delta = True
        if has_cost_delta:
            counts["cost_delta_usd"] = cost_delta
        if has_runtime_delta:
            counts["runtime_delta_seconds"] = runtime_delta
        if has_token_delta:
            counts["token_delta"] = token_delta
        if has_tool_call_delta:
            counts["tool_call_delta"] = tool_call_delta
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "baseline_path": str(self.baseline_path),
            "candidate_path": str(self.candidate_path),
            "summary": self.summary(),
            "cases": [entry.to_json() for entry in self.entries],
        }
