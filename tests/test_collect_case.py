from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

from ymir_harness.collect_case import (
    CollectCaseError,
    CollectCaseRequest,
    MockRepoInput,
    WebRecord,
    collect_case,
)
import ymir_harness.collect_case as collect_case_module
from ymir_harness.validation import validate_case_directory


def test_collect_case_writes_fixture_scaffold(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    issue_json = _write_json(
        tmp_path / "inputs" / "issue.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "key": "RHEL-12345",
            "fields": {"summary": "Backport CVE fix"},
        },
    )
    patch_path = _write_text(
        tmp_path / "inputs" / "fix.patch",
        "diff --git a/source.c b/source.c\n",
    )
    web_record = _write_text(tmp_path / "inputs" / "fix.response", "cached patch\n")
    source_archive = _write_text(tmp_path / "inputs" / "source.tar.gz", "source\n")

    result = collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            cve_ids=("CVE-2026-0001",),
            patch_urls=("https://example.invalid/fix.patch",),
            reference_patch_mode="scope_only",
            mock_repo=MockRepoInput(
                remote_url="https://example.invalid/dnsmasq.git",
                pre_fix_ref="abc123",
                branch="c9s",
                agent="backport",
                zstream_override={"8": "rhel-8.10.z"},
            ),
            jira_issue_json=issue_json,
            reference_patch=patch_path,
            web_records=(
                WebRecord(
                    url="https://example.invalid/fix.patch",
                    source_path=web_record,
                ),
            ),
            source_upstream=(source_archive,),
            source_lookaside=(source_archive,),
            notes="Historical merged MR establishes the expected result.",
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["case_status"] == "quarantined"
    assert expected["case_status_reason"] == "fixture scaffold requires ground-truth review"
    assert expected["resolution"] == "backport"
    assert expected["cve_ids"] == ["CVE-2026-0001"]
    assert expected["patch_urls"] == ["https://example.invalid/fix.patch"]
    assert expected["reference_patch_mode"] == "scope_only"
    assert (cases_dir / "cases.yaml").read_text(encoding="utf-8") == "cases:\n  - RHEL-12345\n"

    mock = json.loads(
        (cases_dir / "mock_data" / "backport" / "RHEL-12345.json").read_text(encoding="utf-8")
    )
    assert mock["repos"][0]["remote_url"] == "https://example.invalid/dnsmasq.git"
    assert mock["zstream_override"] == {"8": "rhel-8.10.z"}
    assert (
        cases_dir / "mock_data" / "backport" / "reference_patches" / "RHEL-12345.patch"
    ).is_file()

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["required_urls"] == ["https://example.invalid/fix.patch"]
    recorded_path = (
        cases_dir
        / "web_cache"
        / "RHEL-12345"
        / manifest["recorded_files"]["https://example.invalid/fix.patch"]
    )
    assert recorded_path.read_text(encoding="utf-8") == "cached patch\n"
    assert (cases_dir / "source_cache" / "RHEL-12345" / "upstream" / "source.tar.gz").is_file()
    assert (cases_dir / "source_cache" / "RHEL-12345" / "lookaside" / "source.tar.gz").is_file()
    assert result.warnings == []

    report = validate_case_directory(cases_dir)
    assert not report.has_blocking_errors


def test_collect_case_refuses_to_overwrite_existing_files(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    request = CollectCaseRequest(
        cases_dir=cases_dir,
        case_id="RHEL-12345",
        case_type="not_affected",
        resolution="not_affected",
        package="dnsmasq",
    )

    collect_case(request)

    with pytest.raises(CollectCaseError, match="refusing to overwrite"):
        collect_case(request)


def test_collect_case_rejects_network_denied_external_records(tmp_path: Path) -> None:
    with pytest.raises(CollectCaseError, match="network_denied cases must not declare"):
        collect_case(
            CollectCaseRequest(
                cases_dir=tmp_path / "benchmark_cases",
                case_id="RHEL-12345",
                case_type="not_affected",
                resolution="not_affected",
                package="dnsmasq",
                network_mode="network_denied",
                patch_urls=("https://example.invalid/fix.patch",),
            )
        )


def test_collect_case_fetches_jira_issue_comments_and_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {
                "summary": "Backport CVE fix",
                "issuelinks": [
                    {
                        "outwardIssue": {
                            "key": "RHEL-23456",
                            "fields": {"summary": "Original issue"},
                        }
                    }
                ],
            },
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {
            "comments": [{"body": "Please backport this fix."}],
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [
            {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
        ],
        "https://issues.example.invalid/rest/api/2/issue/RHEL-23456": {
            "key": "RHEL-23456",
            "fields": {"summary": "Original issue"},
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-23456/comment": {"comments": []},
        "https://issues.example.invalid/rest/api/2/issue/RHEL-23456/remotelink": [],
    }
    seen_urls: list[str] = []
    monkeypatch.setattr(
        collect_case_module,
        "urlopen",
        _fake_urlopen(responses, seen_urls),
    )

    result = collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            network_mode="network_denied",
            jira_url="https://issues.example.invalid/browse/RHEL-12345",
        )
    )

    jira_dir = tmp_path / "benchmark_cases" / "jiras" / "RHEL-12345"
    issue = json.loads((jira_dir / "issue.json").read_text(encoding="utf-8"))
    comments = json.loads((jira_dir / "comments.json").read_text(encoding="utf-8"))
    links = json.loads((jira_dir / "links.json").read_text(encoding="utf-8"))
    starting = json.loads((jira_dir / "starting-issue.json").read_text(encoding="utf-8"))
    linked = json.loads(
        (jira_dir / "linked" / "RHEL-23456" / "starting-issue.json").read_text(encoding="utf-8")
    )
    assert issue["key"] == "RHEL-12345"
    assert comments["comments"][0]["body"] == "Please backport this fix."
    assert links["links"][0]["object"]["url"] == (
        "https://gitlab.example/group/pkg/-/merge_requests/7"
    )
    assert starting["fields"]["comment"]["comments"] == [{"body": "Please backport this fix."}]
    assert starting["remote_links"] == []
    assert linked["key"] == "RHEL-23456"
    assert linked["fields"]["summary"] == "Original issue"
    assert result.fetched_urls == seen_urls == list(responses)


def test_collect_case_fetches_jira_with_basic_auth_token_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {"summary": "Backport CVE fix"},
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {"comments": []},
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [],
    }
    token_file = _write_text(tmp_path / "jira-token", "secret-token\n")
    authorizations: list[str | None] = []

    def fake_urlopen(request, timeout: float):
        authorizations.append(request.get_header("Authorization"))
        return _fake_urlopen(responses, [])(request, timeout)

    monkeypatch.setattr(collect_case_module, "urlopen", fake_urlopen)

    collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            network_mode="network_denied",
            jira_url="https://issues.example.invalid/browse/RHEL-12345",
            jira_token_file=token_file,
            jira_email="maintainer@example.invalid",
        )
    )

    expected = "Basic " + base64.b64encode(b"maintainer@example.invalid:secret-token").decode(
        "ascii"
    )
    assert authorizations == [expected, expected, expected]


def test_collect_case_wraps_local_jira_link_arrays(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    issue_json = _write_json(
        tmp_path / "inputs" / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {"summary": "Not affected", "components": [{"name": "dnsmasq"}]},
        },
    )
    comments_json = _write_json(tmp_path / "inputs" / "comments.json", {"comments": []})
    links_json = _write_json(
        tmp_path / "inputs" / "links.json",
        [{"object": {"url": "https://example.invalid/reference"}}],
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="not_affected",
            resolution="not_affected",
            package="dnsmasq",
            jira_issue_json=issue_json,
            jira_comments_json=comments_json,
            jira_links_json=links_json,
        )
    )

    links = json.loads(
        (cases_dir / "jiras" / "RHEL-12345" / "links.json").read_text(encoding="utf-8")
    )
    assert links["case_id"] == "RHEL-12345"
    assert links["links"] == [{"object": {"url": "https://example.invalid/reference"}}]

    report = validate_case_directory(cases_dir)
    assert not report.has_blocking_errors


def test_collect_case_normalizes_gitlab_links_as_patch_urls() -> None:
    issue = {
        "fields": {
            "description": (
                "Review https://gitlab.example/group/pkg/-/merge_requests/7 and "
                "https://gitlab.example/group/pkg/-/commit/abc123."
            ),
        },
    }

    assert collect_case_module._patch_urls_from_jira_evidence(issue) == [
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch",
        "https://gitlab.example/group/pkg/-/commit/abc123.patch",
    ]

def test_collect_case_imports_completed_jira_without_repeated_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fdnsmasq"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    internal_project_url = "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fdnsmasq"
    internal_branches_url = "https://gitlab.com/api/v4/projects/42/repository/branches"
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {
                "summary": "CVE-2026-0001 in dnsmasq",
                "description": "Reporter supplied reproducer.",
                "customfield_10669": "dnsmasq",
                "components": [{"name": "dnsmasq"}],
                "fixVersions": [{"name": "rhel-8.10.z"}],
                "labels": ["security", "ymir_triaged_backport"],
                "status": {"name": "Closed"},
            },
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {
            "comments": [
                {
                    "body": "The reproducer fails before the upstream fix.",
                    "author": {"displayName": "Reporter"},
                },
                {
                    "body": "*Resolution*: backport\n*Package*: dnsmasq",
                    "author": {"displayName": "Jotnar Project"},
                },
            ],
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [
            {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
        ],
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7": {
            "iid": 7,
            "target_branch": "c8s",
            "web_url": "https://gitlab.example/group/pkg/-/merge_requests/7",
            "diff_refs": {
                "base_sha": "base123",
                "head_sha": "head123",
                "start_sha": "start123",
            },
        },
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/commits": [
            {"id": "abc123", "title": "Fix CVE"}
        ],
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/changes": {
            "changes": [{"old_path": "source.c", "new_path": "source.c"}]
        },
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch": (
            "diff --git a/source.c b/source.c\n"
        ),
        rules_url: "Follow dnsmasq maintainer rules.\n",
        internal_project_url: {"id": 42, "path_with_namespace": "redhat/rhel/rpms/dnsmasq"},
        internal_branches_url: [{"name": "rhel-8.10.z"}],
    }
    seen_urls: list[str] = []
    monkeypatch.setattr(
        collect_case_module,
        "urlopen",
        _fake_urlopen(responses, seen_urls),
    )

    result = collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            jira_url="https://issues.example.invalid/browse/RHEL-12345",
        )
    )

    cases_dir = tmp_path / "benchmark_cases"
    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["case_type"] == "cve_backport"
    assert expected["resolution"] == "backport"
    assert expected["package"] == "dnsmasq"
    assert expected["fix_version"] == "rhel-8.10.z"
    assert expected["cve_ids"] == ["CVE-2026-0001"]
    assert expected["expected_basis"] == "historical_jira_state"
    assert expected["network_mode"] == "replay_only"
    assert expected["patch_urls"] == ["https://gitlab.example/group/pkg/-/merge_requests/7.patch"]
    assert expected["fix_sources"] == ["https://gitlab.example/group/pkg/-/merge_requests/7"]
    assert result.warnings == []

    mock = json.loads(
        (cases_dir / "mock_data" / "triage" / "RHEL-12345.json").read_text(encoding="utf-8")
    )
    assert mock["repos"] == [
        {
            "branch": "c8s",
            "package": "dnsmasq",
            "pre_fix_ref": "base123",
            "remote_url": "https://gitlab.example/group/pkg.git",
        }
    ]
    assert mock["zstream_override"] == {"8": "rhel-8.10.z"}
    reference_patch = cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch"
    assert reference_patch.read_text(encoding="utf-8") == "diff --git a/source.c b/source.c\n"

    assert (
        cases_dir
        / "web_cache"
        / "RHEL-12345"
        / "gitlab"
        / "internal_rhel"
        / "dnsmasq"
        / "branches.json"
    ).is_file()

    jira_dir = cases_dir / "jiras" / "RHEL-12345"
    full_issue = json.loads((jira_dir / "issue.json").read_text(encoding="utf-8"))
    starting = json.loads((jira_dir / "starting-issue.json").read_text(encoding="utf-8"))
    assert full_issue["fields"]["status"]["name"] == "Closed"
    assert full_issue["fields"]["labels"] == ["security", "ymir_triaged_backport"]
    assert starting["fields"]["status"] == {"name": "New"}
    assert starting["fields"]["labels"] == ["security"]
    assert starting["fields"]["comment"]["comments"] == [
        {
            "body": "The reproducer fails before the upstream fix.",
            "author": {"displayName": "Reporter"},
        }
    ]
    assert starting["remote_links"] == []

    report = validate_case_directory(cases_dir)
    assert not report.has_blocking_errors
    assert result.fetched_urls == seen_urls == list(responses)


def test_collect_case_extracts_jotnar_outputs_without_starting_leakage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_patch_url = "https://gitlab.gnome.example/GNOME/glib/-/commit/abc123.patch"
    bad_patch_url = "https://gitlab.gnome.example/GNOME/glib/-/commit/not-a-patch.patch"
    mr_url = "https://gitlab.example/redhat/rpms/glib2/-/merge_requests/64"
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fglib2"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    internal_project_url = "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fglib2"
    internal_branches_url = "https://gitlab.com/api/v4/projects/43/repository/branches"
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {
                "summary": "CVE-2026-0001 in glib2",
                "components": [{"name": "glib2"}],
                "fixVersions": [{"name": "rhel-9.7.z"}],
                "labels": [
                    "security",
                    "jotnar_backported",
                    "jotnar_merged",
                    "rhel-jotnar-pilot",
                ],
                "status": {"name": "Closed"},
            },
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {
            "comments": [
                {
                    "body": "Reporter supplied reproducer.",
                    "author": {"displayName": "Reporter"},
                },
                {
                    "body": (
                        "Output from Triage Agent:\n\n"
                        f"*Resolution*: backport\n*Patch URL*: {upstream_patch_url}\n"
                        f"*Patch URL*: {bad_patch_url}\n"
                    ),
                    "author": {"displayName": "J\u00f6tnar Project"},
                },
                {
                    "body": f"Output from Backport Agent:\n\n{mr_url}\n",
                    "author": {"displayName": "J\u00f6tnar Project"},
                },
                {
                    "body": "This ticket moved to Integration/Release Pending.",
                    "author": {"displayName": "RHEL Jira bot"},
                },
                {
                    "body": "Advisory RHBA-2025:12345 released on 2025-11-11.",
                    "author": {"displayName": "e-tool"},
                },
            ],
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [],
        "https://gitlab.example/api/v4/projects/redhat%2Frpms%2Fglib2/merge_requests/64": {
            "iid": 64,
            "web_url": mr_url,
        },
        "https://gitlab.example/api/v4/projects/redhat%2Frpms%2Fglib2/merge_requests/64/commits": [
            {"id": "abc123", "title": "Fix CVE"}
        ],
        "https://gitlab.example/api/v4/projects/redhat%2Frpms%2Fglib2/merge_requests/64/changes": {
            "changes": [{"old_path": "source.c", "new_path": "source.c"}]
        },
        f"{mr_url}.patch": "diff --git a/source.c b/source.c\n",
        upstream_patch_url: "diff --git a/upstream.c b/upstream.c\n",
        bad_patch_url: "<!DOCTYPE html><html><body>not a patch</body></html>",
        rules_url: "Follow glib2 maintainer rules.\n",
        internal_project_url: {"id": 43, "path_with_namespace": "redhat/rhel/rpms/glib2"},
        internal_branches_url: [{"name": "rhel-9.7.z"}],
    }
    seen_urls: list[str] = []
    monkeypatch.setattr(
        collect_case_module,
        "urlopen",
        _fake_urlopen(responses, seen_urls),
    )

    result = collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            jira_url="https://issues.example.invalid/browse/RHEL-12345",
        )
    )

    cases_dir = tmp_path / "benchmark_cases"
    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["case_type"] == "cve_backport"
    assert expected["resolution"] == "backport"
    assert expected["package"] == "glib2"
    assert expected["fix_version"] == "rhel-9.7.z"
    assert expected["network_mode"] == "replay_only"
    assert expected["patch_urls"] == [upstream_patch_url, f"{mr_url}.patch"]
    assert expected["fix_sources"] == [mr_url]
    assert any("fetched content is not a patch" in warning for warning in result.warnings)

    starting = json.loads(
        (cases_dir / "jiras" / "RHEL-12345" / "starting-issue.json").read_text(encoding="utf-8")
    )
    assert starting["fields"]["status"] == {"name": "New"}
    assert starting["fields"]["labels"] == ["security"]
    assert starting["fields"]["comment"]["comments"] == [
        {
            "body": "Reporter supplied reproducer.",
            "author": {"displayName": "Reporter"},
        }
    ]
    assert starting["remote_links"] == []

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["recorded_files"][upstream_patch_url] == "jira/patches/001.patch"
    assert bad_patch_url not in manifest["recorded_files"]
    assert manifest["recorded_files"][f"{mr_url}.patch"] == "gitlab/merge_request.patch"

    assert (
        manifest["recorded_files"][internal_project_url]
        == "gitlab/internal_rhel/glib2/project.json"
    )
    assert (
        manifest["recorded_files"][internal_branches_url]
        == "gitlab/internal_rhel/glib2/branches.json"
    )

    report = validate_case_directory(cases_dir)
    assert not report.has_blocking_errors
    assert seen_urls == list(responses)


def test_collect_case_fetches_gitlab_mr_into_replay_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fdnsmasq"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    responses = {
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7": {
            "iid": 7,
            "target_branch": "c9s",
            "web_url": "https://gitlab.example/group/pkg/-/merge_requests/7",
            "diff_refs": {
                "base_sha": "inferred-base",
                "head_sha": "head123",
                "start_sha": "start123",
            },
        },
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/commits": [
            {"id": "abc123", "title": "Fix CVE"}
        ],
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/changes": {
            "changes": [{"old_path": "source.c", "new_path": "source.c"}]
        },
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch": (
            "diff --git a/source.c b/source.c\n"
        ),
        rules_url: "Follow dnsmasq maintainer rules.\n",
    }
    seen_urls: list[str] = []
    monkeypatch.setattr(
        collect_case_module,
        "urlopen",
        _fake_urlopen(responses, seen_urls),
    )

    result = collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            reference_patch_mode="scope_only",
            gitlab_mr_url="https://gitlab.example/group/pkg/-/merge_requests/7",
            mock_repo=MockRepoInput(
                remote_url="https://gitlab.example/group/pkg.git",
                pre_fix_ref="abc123",
                branch="c9s",
            ),
        )
    )

    cases_dir = tmp_path / "benchmark_cases"
    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["patch_urls"] == ["https://gitlab.example/group/pkg/-/merge_requests/7.patch"]
    assert expected["fix_sources"] == ["https://gitlab.example/group/pkg/-/merge_requests/7"]
    mock = json.loads(
        (cases_dir / "mock_data" / "triage" / "RHEL-12345.json").read_text(encoding="utf-8")
    )
    assert mock["repos"][0] == {
        "branch": "c9s",
        "package": "dnsmasq",
        "pre_fix_ref": "abc123",
        "remote_url": "https://gitlab.example/group/pkg.git",
    }
    reference_patch = cases_dir / "mock_data" / "triage" / "reference_patches" / "RHEL-12345.patch"
    assert reference_patch.read_text(encoding="utf-8") == ("diff --git a/source.c b/source.c\n")

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["required_urls"] == [
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch",
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7",
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/commits",
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/changes",
        rules_url,
    ]
    assert manifest["recorded_files"] == {
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7": (
            "gitlab/merge_request.json"
        ),
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/commits": (
            "gitlab/commits.json"
        ),
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/changes": (
            "gitlab/changes.json"
        ),
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch": ("gitlab/merge_request.patch"),
        rules_url: "gitlab/maintainer_rules/dnsmasq/AGENTS.md",
    }
    assert result.fetched_urls == seen_urls == list(responses)


def test_collect_case_caches_mock_repo_source(tmp_path: Path) -> None:
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    cases_dir = tmp_path / "benchmark_cases"
    cache_dir = tmp_path / "repo-cache"

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            mock_repo=MockRepoInput(
                remote_url="https://gitlab.example/group/pkg.git",
                source_url=str(source_repo),
                pre_fix_ref=pre_fix_ref,
                branch="c9s",
            ),
            mock_repo_cache=cache_dir,
        )
    )

    mock = json.loads(
        (cases_dir / "mock_data" / "triage" / "RHEL-12345.json").read_text(encoding="utf-8")
    )
    repo = mock["repos"][0]
    cached_repo = Path(repo["source_url"])
    assert repo["remote_url"] == "https://gitlab.example/group/pkg.git"
    assert cached_repo.is_dir()
    assert cached_repo.parent == cache_dir.resolve()
    subprocess.run(
        ["git", "-C", str(cached_repo), "cat-file", "-e", f"{pre_fix_ref}^{{commit}}"],
        check=True,
    )

    report = validate_case_directory(cases_dir)
    assert not report.has_blocking_errors


def test_collect_case_overwrite_replaces_existing_files(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    request = CollectCaseRequest(
        cases_dir=cases_dir,
        case_id="RHEL-12345",
        case_type="not_affected",
        resolution="not_affected",
        package="dnsmasq",
    )
    collect_case(request)

    updated = CollectCaseRequest(
        cases_dir=cases_dir,
        case_id="RHEL-12345",
        case_type="not_affected",
        resolution="not_affected",
        package="libtiff",
        overwrite=True,
    )
    collect_case(updated)

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["package"] == "libtiff"


def _fake_urlopen(
    responses: dict[str, object],
    seen_urls: list[str],
):
    def fake_urlopen(request, timeout: float):
        del timeout
        url = request.full_url
        seen_urls.append(url)
        if url not in responses:
            raise OSError(f"unexpected URL: {url}")
        body = responses[url]
        if not isinstance(body, str):
            body = json.dumps(body)
        return _FakeHttpResponse(body.encode("utf-8"))

    return fake_urlopen


class _FakeHttpResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _create_git_repo(tmp_path: Path) -> tuple[Path, str]:
    repo_path = tmp_path / "source-repo"
    repo_path.mkdir()
    subprocess.run(["git", "-C", str(repo_path), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo_path), "config", "user.email", "dev@example.com"], check=True
    )
    subprocess.run(["git", "-C", str(repo_path), "config", "user.name", "Dev"], check=True)
    (repo_path / "source.c").write_text("pre-fix\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_path), "add", "source.c"], check=True)
    subprocess.run(["git", "-C", str(repo_path), "commit", "-q", "-m", "initial"], check=True)
    pre_fix_ref = subprocess.check_output(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    (repo_path / "source.c").write_text("fixed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_path), "commit", "-am", "fix", "-q"], check=True)
    return repo_path, pre_fix_ref


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
