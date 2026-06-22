from __future__ import annotations

import json
from pathlib import Path

from ymir_harness import __version__
from ymir_harness.scoring import score_case, score_result_directory


def test_score_case_accepts_nested_triage_result() -> None:
    expected = {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "cve_ids": ["CVE-2026-0001"],
        "patch_urls": ["https://example.invalid/fix.patch"],
    }
    actual = {
        "resolution": "Resolution.BACKPORT",
        "data": {
            "package": "dnsmasq",
            "fix_version": "rhel-8.10.z",
            "cve_id": "CVE-2026-0001",
            "patch_urls": ["https://example.invalid/fix.patch"],
        },
    }

    report = score_case(expected, actual)

    assert report.passed
    assert report.summary()["fail"] == 0


def test_score_case_reports_jira_issue_mismatches() -> None:
    expected = {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"jira_issue": "RHEL-99999"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["jira_issue"].expected == "RHEL-12345"
    assert failed["jira_issue"].actual == "RHEL-99999"


def test_score_case_uses_explicit_expected_jira_issue() -> None:
    expected = {
        "schema_version": 1,
        "case_id": "fixture-001",
        "jira_issue": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "fixture-001",
        "jira_issue": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["jira_issue"].expected == "RHEL-12345"
    assert metrics["jira_issue"].actual == "RHEL-12345"


def test_score_case_infers_distgit_backport_source_from_patch_urls() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "redis",
        "target_branch": "rhel-9.6.z",
        "patch_urls": [
            "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/"
            "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1.patch"
        ],
        "backport_source": "distgit",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "redis",
        "target_branch": "rhel-9.6.z",
        "patch_urls": [
            "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/"
            "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1.patch"
        ],
    }

    report = score_case(expected, actual)

    assert report.passed
    assert {metric.name: metric for metric in report.metrics}["backport_source"].actual == "distgit"


def test_score_case_infers_distgit_backport_source_from_pkgs_devel_cgit_patch() -> None:
    patch_url = (
        "https://pkgs.devel.redhat.com/cgit/rpms/redis/patch/"
        "?h=rhel-9.8.0&id=0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1"
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "redis",
        "target_branch": "rhel-9.2.0",
        "patch_urls": [patch_url],
        "backport_source": "distgit",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "redis",
        "target_branch": "rhel-9.2.0",
        "patch_urls": [patch_url],
    }

    report = score_case(expected, actual)

    assert report.passed
    assert {metric.name: metric for metric in report.metrics}["backport_source"].actual == "distgit"


def test_score_case_reports_backport_source_mismatch() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "kea",
        "target_branch": "rhel-10.0.z",
        "patch_urls": [
            "https://gitlab.com/redhat/centos-stream/rpms/kea/-/commit/"
            "2222222222222222222222222222222222222222.patch"
        ],
        "backport_source": "distgit",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "kea",
        "target_branch": "rhel-10.0.z",
        "patch_urls": [
            "https://github.com/isc-projects/kea/commit/"
            "1111111111111111111111111111111111111111.patch"
        ],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["backport_source"].expected == "distgit"
    assert failed["backport_source"].actual == "upstream"


def test_score_case_extracts_cve_ids_from_modern_triage_text() -> None:
    expected = {
        "schema_version": 1,
        "case_id": "RHEL-12345",
        "case_type": "not_affected",
        "resolution": "not_affected",
        "package": "rpm-ostree",
        "cve_ids": ["CVE-2026-28390"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "not_affected",
        "resolution": "not-affected",
        "package": "rpm-ostree",
        "data": {
            "findings": "CVE-2026-28390 is not in the package execute path.",
        },
    }

    report = score_case(expected, actual)

    assert report.passed


def test_score_case_reports_field_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "libtiff",
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name for metric in report.metrics if metric.status == "fail"}
    assert failed == {"package"}


def test_score_case_does_not_treat_fix_version_as_target_branch() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "fix_version": "rhel-8.10.z",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "c8s",
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["target_branch"].status == "skipped"


def test_score_case_accepts_alternate_acceptable_outcome() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "target_branch": "rhel-8.10.z",
        "alternate_acceptable_outcomes": [
            {
                "resolution": "rebase",
                "target_branch": "rhel-9.0.z",
            }
        ],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "rebase",
        "package": "dnsmasq",
        "target_branch": "rhel-9.0.z",
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["alternate_acceptable_outcome"].status == "pass"
    assert metrics["resolution"].expected == "rebase"


def test_score_case_reports_affectedness_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "not_affected",
        "affectedness": "not affected",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "not_affected",
        "package": "dnsmasq",
        "data": {"affectedness": True},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["affectedness"].expected == "not_affected"
    assert failed["affectedness"].actual == "affected"


def test_score_case_fails_unsafe_operation_attempts() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "unsafe_operations": ["git push origin HEAD"],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["unsafe_operations"].actual == ["git push origin HEAD"]


def test_score_case_fails_replay_violations() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"replay_violations": ["unrecorded URL: https://example.invalid/advisory"]},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["replay_violations"].actual == [
        "unrecorded URL: https://example.invalid/advisory"
    ]


def test_score_case_fails_missing_required_artifacts() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "required_artifacts": ["fix.patch", "dnsmasq.spec"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "generated_artifacts": ["fix.patch"],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["required_artifacts"].actual == ["fix.patch"]
    assert failed["required_artifacts"].notes == "missing required artifacts: dnsmasq.spec"


def test_score_case_accepts_required_artifact_kinds_from_manifest(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "artifacts"
    manifest_path = artifact_dir / "manifest.json"
    _write_json(
        manifest_path,
        {
            "captured_files": {
                "commit_diff": str(artifact_dir / "commit.diff"),
                "spec_file": str(artifact_dir / "spec_file.spec"),
                "patch_files": [str(artifact_dir / "patches" / "fix-cve.patch")],
                "srpm": str(artifact_dir / "srpms" / "dnsmasq.src.rpm"),
            }
        },
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "required_artifact_kinds": ["commit_diff", "spec_file", "patch_files", "srpm"],
        "patch_file_patterns": ["fix-cve"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "artifact_manifest": str(manifest_path),
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["required_artifact_kinds"].actual == [
        "commit_diff",
        "patch_files",
        "spec_file",
        "srpm",
    ]
    assert metrics["patch_file_patterns"].actual == ["fix-cve.patch"]


def test_score_case_reports_required_artifact_kind_and_patch_pattern_failures(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifacts"
    manifest_path = artifact_dir / "manifest.json"
    _write_json(
        manifest_path,
        {
            "captured_files": {
                "spec_file": str(artifact_dir / "spec_file.spec"),
                "patch_files": [str(artifact_dir / "patches" / "wrong.patch")],
            }
        },
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "required_artifact_kinds": ["commit_diff", "spec_file", "srpm"],
        "patch_file_pattern": "fix-cve",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "artifact_manifest": str(manifest_path),
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["required_artifact_kinds"].expected == [
        "commit_diff",
        "spec_file",
        "srpm",
    ]
    assert failed["required_artifact_kinds"].actual == ["patch_files", "spec_file"]
    assert failed["required_artifact_kinds"].notes == (
        "missing required artifact kinds: commit_diff, srpm"
    )
    assert failed["patch_file_patterns"].actual == ["wrong.patch"]
    assert failed["patch_file_patterns"].notes == "missing patch file patterns: fix-cve"


def test_score_case_fails_unrelated_source_changes() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"unrelated_source_changes": ["README.md"]},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["unrelated_source_changes"].expected == []
    assert failed["unrelated_source_changes"].actual == ["README.md"]


def test_score_case_reports_touched_file_scope_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "touched_files": ["SPECS/dnsmasq.spec", "SOURCES/fix.patch"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "changed_files": ["SOURCES/fix.patch", "SPECS/dnsmasq.spec", "README.md"],
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["touched_files"].actual == [
        "README.md",
        "SOURCES/fix.patch",
        "SPECS/dnsmasq.spec",
    ]
    assert failed["touched_files"].notes == "unexpected touched files: README.md"


def test_score_case_derives_patch_scope_from_reference_patch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_text(
        cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch",
        _source_patch_text("source.c"),
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "patch_touched_files": ["source.c"],
    }

    report = score_case(expected, actual, cases_dir=cases_dir)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["patch_touched_files"].status == "pass"
    assert metrics["patch_touched_files"].expected == ["source.c"]


def test_score_case_skips_reference_patch_scope_for_triage_without_patch_scope(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_text(
        cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch",
        _source_patch_text("source.c"),
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "workflow": "ymir-triage",
    }

    report = score_case(expected, actual, cases_dir=cases_dir)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["patch_touched_files"].status == "skipped"


def test_score_case_derives_patch_scope_from_reference_patch_added_patch_file(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    nested_patch = _source_patch_text("src/option.c")
    outer_patch = (
        "diff --git a/fix.patch b/fix.patch\n"
        "new file mode 100644\n"
        "index 0000000..1111111\n"
        "--- /dev/null\n"
        "+++ b/fix.patch\n"
        f"@@ -0,0 +1,{len(nested_patch.splitlines())} @@\n"
        + "".join(f"+{line}\n" for line in nested_patch.splitlines())
    )
    _write_text(
        cases_dir / "mock_data" / "backport" / "reference_patches" / "RHEL-12345.patch",
        outer_patch,
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "patch_touched_files": ["src/option.c"],
    }

    report = score_case(expected, actual, cases_dir=cases_dir)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["patch_touched_files"].expected == ["src/option.c"]


def test_score_case_reports_patch_scope_failures_from_reference_patch(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_text(
        cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch",
        _source_patch_text("source.c"),
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "patch_touched_files": ["README.md", "source.c"],
    }

    report = score_case(expected, actual, cases_dir=cases_dir)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["patch_touched_files"].expected == ["source.c"]
    assert failed["patch_touched_files"].actual == ["README.md", "source.c"]
    assert failed["patch_touched_files"].notes == "unexpected touched files: README.md"


def test_score_case_parses_generated_patch_scope(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    generated_patch = tmp_path / "agent.patch"
    _write_text(
        cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch",
        _source_patch_text("source.c"),
    )
    _write_text(generated_patch, _source_patch_text("source.c"))
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "generated_artifacts": [str(generated_patch)],
    }

    report = score_case(expected, actual, cases_dir=cases_dir)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["patch_touched_files"].status == "pass"
    assert metrics["patch_touched_files"].actual == ["source.c"]


def test_score_case_uses_manifest_patch_files_before_commit_diff(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    artifact_dir = tmp_path / "artifacts"
    generated_patch = artifact_dir / "patches" / "fix.patch"
    commit_diff = artifact_dir / "commit.diff"
    manifest_path = artifact_dir / "manifest.json"
    _write_text(
        cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch",
        _source_patch_text("source.c"),
    )
    _write_text(generated_patch, _source_patch_text("source.c"))
    _write_text(commit_diff, _source_patch_text("dnsmasq.spec"))
    _write_json(
        manifest_path,
        {
            "captured_files": {
                "commit_diff": str(commit_diff),
                "patch_files": [str(generated_patch)],
            }
        },
    )
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "artifact_manifest": str(manifest_path),
        "generated_artifacts": [str(commit_diff), str(generated_patch)],
    }

    report = score_case(expected, actual, cases_dir=cases_dir)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["patch_touched_files"].actual == ["source.c"]


def test_score_case_reports_spec_patch_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "spec_patches": ["Patch0001: fix-cve.patch"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"spec_patches": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["spec_patches"].expected == ["Patch0001: fix-cve.patch"]
    assert failed["spec_patches"].actual == []


def test_score_case_reports_changelog_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "changelog_entries": ["- Resolves: RHEL-12345 CVE-2026-0001"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"changelog_entries": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["changelog_entries"].expected == ["- Resolves: RHEL-12345 CVE-2026-0001"]
    assert failed["changelog_entries"].actual == []


def test_score_case_reports_build_result_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "build_result": "passed",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"build_result": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["build_result"].expected == "passed"
    assert failed["build_result"].actual == "failed"


def test_score_case_reports_prep_result_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "prep_result": "passed",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"prep_result": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["prep_result"].expected == "passed"
    assert failed["prep_result"].actual == "failed"


def test_score_case_reports_reference_patch_parse_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "reference_patch_parse_status": "parsed",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"reference_patch_parse_status": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["reference_patch_parse_status"].expected == "parsed"
    assert failed["reference_patch_parse_status"].actual == "failed"


def test_score_case_reports_reference_patch_apply_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "reference_patch_apply_status": "applied",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"reference_patch_apply_status": "failed"},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["reference_patch_apply_status"].expected == "applied"
    assert failed["reference_patch_apply_status"].actual == "failed"


def test_score_case_reports_fix_source_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "fix_sources": ["upstream commit abc123"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "data": {"fix_sources": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["fix_sources"].expected == ["upstream commit abc123"]
    assert failed["fix_sources"].actual == []


def test_score_case_skips_fix_sources_missing_from_actual() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "fix_sources": ["upstream commit abc123"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }

    report = score_case(expected, actual)

    assert report.passed
    metrics = {metric.name: metric for metric in report.metrics}
    assert metrics["fix_sources"].status == "skipped"


def test_score_case_reports_dependency_issue_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "dependency_issues": ["RHEL-23456"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "data": {"dependency_issues": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["dependency_issues"].expected == ["RHEL-23456"]
    assert failed["dependency_issues"].actual == []


def test_score_case_reports_sibling_issue_failures() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "sibling_issues": ["RHEL-34567"],
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "dependency_rebuild",
        "resolution": "rebuild",
        "package": "dnsmasq",
        "data": {"sibling_issues": []},
    }

    report = score_case(expected, actual)

    assert not report.passed
    failed = {metric.name: metric for metric in report.metrics if metric.status == "fail"}
    assert failed["sibling_issues"].expected == ["RHEL-34567"]
    assert failed["sibling_issues"].actual == []


def test_score_case_records_advisory_metrics_without_failing() -> None:
    expected = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
    }
    actual = {
        "case_id": "RHEL-12345",
        "case_type": "cve_backport",
        "resolution": "backport",
        "package": "dnsmasq",
        "runtime_seconds": 42.5,
        "data": {
            "token_usage": {"input": 1200, "output": 300},
            "iteration_count": 12,
            "tool_call_count": 7,
            "retry_count": 1,
            "total_cost_usd": 4.25,
            "llm_judge_notes": "consistent with reference result",
        },
    }

    report = score_case(expected, actual)

    assert report.passed
    assert report.summary()["fail"] == 0
    advisory = {metric["name"]: metric["value"] for metric in report.to_json()["advisory_metrics"]}
    assert advisory == {
        "llm_judge_notes": "consistent with reference result",
        "runtime_seconds": 42.5,
        "token_usage": {"input": 1200, "output": 300},
        "iteration_count": 12,
        "tool_call_count": 7,
        "retry_count": 1,
        "total_cost_usd": 4.25,
    }


def test_score_result_directory_accepts_recorded_patch_commit_coverage(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    commit_sha = "b94b44407a088e6e8278d9db8b59fb377e84bda4"
    extra_sha = "8297bbc00c14c5db3ad3d1570dd74f137aec2f7d"
    commit_url = f"https://gitlab.example/group/pkg/-/commit/{commit_sha}.patch"
    mr_url = "https://gitlab.example/group/pkg/-/merge_requests/7.patch"

    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "glib2",
            "case_status": "active",
            "patch_urls": [commit_url],
        },
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "glib2",
            "patch_urls": [mr_url],
        },
    )
    _write_json(
        cases_dir / "web_cache" / "RHEL-12345" / "manifest.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "required_urls": [commit_url, mr_url],
            "recorded_files": {
                commit_url: "patches/commit.patch",
                mr_url: "patches/mr.patch",
            },
        },
    )
    _write_text(
        cases_dir / "web_cache" / "RHEL-12345" / "patches" / "commit.patch",
        "diff --git a/redis.spec b/redis.spec\n",
    )
    _write_text(
        cases_dir / "web_cache" / "RHEL-12345" / "patches" / "mr.patch",
        (
            f"From {commit_sha} Mon Sep 17 00:00:00 2001\n"
            f"From {extra_sha} Mon Sep 17 00:00:00 2001\n"
        ),
    )

    report = score_result_directory(cases_dir, actual_dir)

    assert report.entries[0].status == "passed"
    metrics = {metric.name: metric for metric in report.entries[0].score.metrics}
    assert metrics["patch_urls"].status == "pass"
    assert metrics["patch_urls"].notes == (
        "actual patch URLs include the expected patch commit IDs"
    )


def test_score_result_directory_accepts_equivalent_pkgs_devel_patch_url(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    commit_sha = "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1"
    expected_url = f"https://gitlab.com/redhat/rhel/rpms/redis/-/commit/{commit_sha}.patch"
    actual_url = (
        "https://pkgs.devel.redhat.com/cgit/rpms/redis/patch/"
        f"?h=rhel-9.8.0&id={commit_sha}"
    )

    _write_json(
        cases_dir / "expected" / "RHEL-12345.expected.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "redis",
            "case_status": "active",
            "patch_urls": [expected_url],
        },
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": "redis",
            "patch_urls": [actual_url],
        },
    )
    _write_json(
        cases_dir / "web_cache" / "RHEL-12345" / "manifest.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "required_urls": [expected_url],
            "recorded_files": {
                expected_url: "patches/commit.patch",
            },
        },
    )
    _write_text(
        cases_dir / "web_cache" / "RHEL-12345" / "patches" / "commit.patch",
        f"From {commit_sha} Mon Sep 17 00:00:00 2001\n",
    )

    report = score_result_directory(cases_dir, actual_dir)

    assert report.entries[0].status == "passed"
    metrics = {metric.name: metric for metric in report.entries[0].score.metrics}
    assert metrics["patch_urls"].status == "pass"
    assert metrics["patch_urls"].notes == (
        "actual patch URLs include the expected patch commit IDs"
    )


def test_score_result_directory_collects_headline_results(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        package="dnsmasq",
        case_status="active",
    )
    _write_expected(
        cases_dir,
        "RHEL-23456",
        package="libtiff",
        case_status="excluded",
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )

    report = score_result_directory(cases_dir, actual_dir)

    assert not report.has_headline_failures
    assert report.summary()["headline_passed"] == 1
    assert report.summary()["skipped"] == 1
    assert [entry.status for entry in report.entries] == ["passed", "skipped"]


def test_score_result_directory_records_run_metadata(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        package="dnsmasq",
        case_status="active",
    )
    _write_json(
        actual_dir / "RHEL-12345.actual.json",
        {
            "case_id": "RHEL-12345",
            "resolution": "backport",
            "package": "dnsmasq",
        },
    )

    report = score_result_directory(
        cases_dir,
        actual_dir,
        run_id="baseline-2026-06-04T120000Z",
        ymir_sha="6e22912f83d57ddae1031e6207d4716171a99be0",
        variant="baseline",
    )

    payload = report.to_json()
    assert payload["run_id"] == "baseline-2026-06-04T120000Z"
    assert payload["ymir_sha"] == "6e22912f83d57ddae1031e6207d4716171a99be0"
    assert payload["variant"] == "baseline"
    assert payload["harness_version"] == __version__
    fixture_checksum = payload["fixture_checksum"]
    assert isinstance(fixture_checksum, str)
    assert fixture_checksum.startswith("sha256:")
    assert len(fixture_checksum) == len("sha256:") + 64

    _write_json(cases_dir / "reports" / "results.json", {"generated": True})
    repeated_payload = score_result_directory(cases_dir, actual_dir).to_json()
    assert repeated_payload["fixture_checksum"] == fixture_checksum


def test_score_result_directory_records_headline_reasons(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    actual_dir = tmp_path / "actual-results"
    _write_expected(
        cases_dir,
        "RHEL-12345",
        package="dnsmasq",
        case_status="quarantined",
        case_status_reason="requires human judgment",
    )
    _write_expected(
        cases_dir,
        "RHEL-23456",
        package="libtiff",
        case_status="active",
        ground_truth_confidence="low",
    )
    _write_expected(
        cases_dir,
        "RHEL-34567",
        package="openssl",
        case_status="active",
        answer_leakage="explicit",
    )
    _write_expected(
        cases_dir,
        "RHEL-45678",
        package="kernel",
        case_status="active",
        network_mode="live_non_reproducible",
    )
    _write_expected(
        cases_dir,
        "RHEL-56789",
        package="zlib",
        case_status="excluded",
        case_status_reason="fixture cannot be replayed",
    )
    _write_expected(
        cases_dir,
        "RHEL-67890",
        package="butane",
        case_status="active",
        answer_leakage="production_signal",
    )
    for case_id, package in (
        ("RHEL-12345", "dnsmasq"),
        ("RHEL-23456", "libtiff"),
        ("RHEL-34567", "openssl"),
        ("RHEL-45678", "kernel"),
        ("RHEL-67890", "butane"),
    ):
        _write_json(
            actual_dir / f"{case_id}.actual.json",
            {
                "case_id": case_id,
                "resolution": "backport",
                "package": package,
            },
        )

    report = score_result_directory(cases_dir, actual_dir)

    entries = {entry.case_id: entry for entry in report.entries}
    assert entries["RHEL-12345"].headline_reason == "case_status is quarantined"
    assert entries["RHEL-23456"].headline_reason == "ground_truth_confidence is low"
    assert entries["RHEL-34567"].headline_reason == "answer_leakage is explicit"
    assert entries["RHEL-45678"].headline_reason == "network_mode is live_non_reproducible"
    assert entries["RHEL-56789"].headline_reason == "case_status is excluded"
    assert entries["RHEL-67890"].headline_reason is None
    assert entries["RHEL-56789"].reason == "fixture cannot be replayed"
    payload_cases = {case["case_id"]: case for case in report.to_json()["cases"]}
    assert payload_cases["RHEL-12345"]["headline_reason"] == "case_status is quarantined"


def _write_expected(
    cases_dir: Path,
    case_id: str,
    *,
    package: str,
    case_status: str,
    ground_truth_confidence: str = "high",
    answer_leakage: str = "none",
    network_mode: str = "replay_only",
    case_status_reason: str | None = None,
) -> None:
    _write_json(
        cases_dir / "expected" / f"{case_id}.expected.json",
        {
            "schema_version": 1,
            "case_id": case_id,
            "case_type": "cve_backport",
            "resolution": "backport",
            "package": package,
            "expected_basis": "merged_mr",
            "ground_truth_confidence": ground_truth_confidence,
            "answer_leakage": answer_leakage,
            "case_status": case_status,
            "case_status_reason": case_status_reason,
            "network_mode": network_mode,
        },
    )


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _source_patch_text(path: str) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        "index 5d308e1..85c3040 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
