import base64
import hashlib
import os
from urllib.error import HTTPError

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


@pytest.fixture(autouse=True)
def _stub_koji_candidate_builds(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_fetch_candidate_build(package: str, branch: str):
        return {
            "package": package,
            "dist_git_branch": branch,
            "evr": {
                "epoch": 0,
                "version": "1.0",
                "release": "1.el9",
            },
            "source_ref": f"{package}-{branch}-ref",
        }

    monkeypatch.setattr(collect_case_module, "fetch_candidate_build", fake_fetch_candidate_build)
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
            "fields": {
                "summary": "Original issue",
                "issuelinks": [
                    {
                        "outwardIssue": {
                            "key": "RHEL-34567",
                            "fields": {"summary": "Ancestor issue"},
                        }
                    }
                ],
            },
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
    assert not (jira_dir / "linked" / "RHEL-34567").exists()
    assert result.fetched_urls == seen_urls == list(responses)


def test_collect_case_writes_embedded_linked_jira_for_local_issue_json(
    tmp_path: Path,
) -> None:
    issue_path = tmp_path / "issue.json"
    issue_path.write_text(
        json.dumps(
            {
                "key": "RHEL-12345",
                "fields": {
                    "summary": "Clone issue",
                    "issuelinks": [
                        {
                            "outwardIssue": {
                                "key": "RHEL-23456",
                                "fields": {"summary": "Original issue"},
                            }
                        }
                    ],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            network_mode="network_denied",
            jira_issue_json=issue_path,
        )
    )

    linked = json.loads(
        (
            tmp_path
            / "benchmark_cases"
            / "jiras"
            / "RHEL-12345"
            / "linked"
            / "RHEL-23456"
            / "starting-issue.json"
        ).read_text(encoding="utf-8")
    )
    assert linked["key"] == "RHEL-23456"
    assert linked["fields"]["summary"] == "Original issue"


def test_collect_case_uses_embedded_linked_jira_when_fetch_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {
                "summary": "Clone issue",
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
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {"comments": []},
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [],
        "https://issues.example.invalid/rest/api/2/issue/RHEL-23456": HTTPError(
            "https://issues.example.invalid/rest/api/2/issue/RHEL-23456",
            403,
            "Forbidden",
            None,
            None,
        ),
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

    linked = json.loads(
        (
            tmp_path
            / "benchmark_cases"
            / "jiras"
            / "RHEL-12345"
            / "linked"
            / "RHEL-23456"
            / "starting-issue.json"
        ).read_text(encoding="utf-8")
    )
    assert linked["key"] == "RHEL-23456"
    assert linked["fields"]["summary"] == "Original issue"
    assert any(
        warning.startswith(
            "used embedded linked Jira RHEL-23456: failed to fetch "
            "https://issues.example.invalid/rest/api/2/issue/RHEL-23456"
        )
        and "HTTP Error 403" in warning
        for warning in result.warnings
    )


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
    assert expected["target_branch"] == "c8s"
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
        / "maintainer_rules"
        / "dnsmasq"
        / "AGENTS.md"
    ).read_text(encoding="utf-8") == "Follow dnsmasq maintainer rules.\n"
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

    report = validate_case_directory(cases_dir, workflow="ymir-triage")
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
            "target_branch": "rhel-9.7.0",
            "web_url": mr_url,
            "diff_refs": {
                "base_sha": "base123",
                "head_sha": "head123",
                "start_sha": "start123",
            },
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
    assert expected["target_branch"] == "rhel-9.7.0"
    assert expected["fix_version"] == "rhel-9.7.z"
    assert expected["network_mode"] == "replay_only"
    assert expected["patch_urls"] == [upstream_patch_url]
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
    assert manifest["recorded_files"][rules_url] == "gitlab/maintainer_rules/glib2/AGENTS.md"
    assert (
        manifest["recorded_files"][internal_project_url]
        == "gitlab/internal_rhel/glib2/project.json"
    )
    assert (
        manifest["recorded_files"][internal_branches_url]
        == "gitlab/internal_rhel/glib2/branches.json"
    )

    report = validate_case_directory(cases_dir, workflow="ymir-triage")
    assert not report.has_blocking_errors
    assert seen_urls == list(responses)


def test_collect_case_scrubs_comments_after_historical_as_of(tmp_path: Path) -> None:
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "summary": "Backport CVE fix",
                "components": [{"name": "dnsmasq"}],
                "fixVersions": [{"name": "rhel-8.10.z"}],
            },
        },
    )
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "body": "Reporter supplied reproducer.",
                    "created": "2025-09-10T00:00:00.000+0000",
                },
                {
                    "body": "*Resolution*: backport",
                    "created": "2025-09-12T09:46:43.672+0000",
                },
                {
                    "body": "A later human comment that did not exist during triage.",
                    "created": "2025-09-13T00:00:00.000+0000",
                },
            ]
        },
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            network_mode="network_denied",
            jira_issue_json=issue_json,
            jira_comments_json=comments_json,
        )
    )

    jira_dir = tmp_path / "benchmark_cases" / "jiras" / "RHEL-12345"
    reconstruction = json.loads((jira_dir / "reconstruction.json").read_text(encoding="utf-8"))
    starting = json.loads((jira_dir / "starting-issue.json").read_text(encoding="utf-8"))
    assert reconstruction["as_of"] == "2025-09-12T09:46:43.671999Z"
    assert starting["fields"]["comment"]["comments"] == [
        {
            "body": "Reporter supplied reproducer.",
            "created": "2025-09-10T00:00:00.000+0000",
        }
    ]

def test_collect_case_records_commit_patches_from_jira_merge_request_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = "glib2"
    downstream_mr_url = "https://gitlab.example/redhat/rpms/glib2/-/merge_requests/7"
    mr_patch_url = "https://gitlab.gnome.example/GNOME/glib/-/merge_requests/4470.patch"
    commit_one = "c" * 40
    commit_two = "d" * 40
    commit_one_patch_url = f"https://gitlab.gnome.example/GNOME/glib/-/commit/{commit_one}.patch"
    commit_one_format_url = (
        f"https://gitlab.gnome.example/GNOME/glib/-/commit/{commit_one}?format=.patch"
    )
    commit_two_patch_url = f"https://gitlab.gnome.example/GNOME/glib/-/commit/{commit_two}.patch"
    commit_two_format_url = (
        f"https://gitlab.gnome.example/GNOME/glib/-/commit/{commit_two}?format=.patch"
    )
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fglib2"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    internal_project_url = "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fglib2"
    project_id = 501034256
    internal_branches_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/branches"
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {
                "summary": "GDBusConnection serial overflow",
                "components": [{"name": package}],
                "fixVersions": [{"name": "rhel-9.7.z"}],
                "labels": ["ymir_triaged_backport"],
            },
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {
            "comments": [
                {
                    "body": f"*Resolution*: backport\n*Patch URL*: {mr_patch_url}\n",
                    "author": {"displayName": "Jotnar Project"},
                }
            ],
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [
            {"object": {"url": downstream_mr_url}}
        ],
        "https://gitlab.example/api/v4/projects/redhat%2Frpms%2Fglib2/merge_requests/7": {
            "iid": 7,
            "target_branch": "c9s",
            "web_url": downstream_mr_url,
            "diff_refs": {
                "base_sha": "base123",
                "head_sha": "head123",
                "start_sha": "start123",
            },
        },
        "https://gitlab.example/api/v4/projects/redhat%2Frpms%2Fglib2/merge_requests/7/commits": [
            {"id": "abc123", "title": "Fix overflow"}
        ],
        "https://gitlab.example/api/v4/projects/redhat%2Frpms%2Fglib2/merge_requests/7/changes": {
            "changes": [{"old_path": "source.c", "new_path": "source.c"}]
        },
        f"{downstream_mr_url}.patch": "diff --git a/downstream.c b/downstream.c\n",
        mr_patch_url: (
            f"From {commit_one} Mon Sep 17 00:00:00 2001\n"
            "Subject: [PATCH 1/2] Fix overflow\n"
            "\n"
            "diff --git a/source.c b/source.c\n"
            f"From {commit_two} Mon Sep 17 00:00:00 2001\n"
            "Subject: [PATCH 2/2] Validate serial\n"
            "\n"
            "diff --git a/test.c b/test.c\n"
        ),
        commit_one_patch_url: "diff --git a/source.c b/source.c\n",
        commit_two_patch_url: "diff --git a/test.c b/test.c\n",
        rules_url: "Follow glib2 maintainer rules.\n",
        internal_project_url: HTTPError(internal_project_url, 404, "Not Found", None, None),
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
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )

    assert result.warnings == []
    assert expected["patch_urls"] == [mr_patch_url]
    assert manifest["recorded_files"][mr_patch_url] == "jira/patches/001.patch"
    assert manifest["recorded_files"][commit_one_patch_url] == (
        f"gitlab/commit_patches/{commit_one}.patch"
    )
    assert manifest["recorded_files"][commit_one_format_url] == (
        f"gitlab/commit_patches/{commit_one}-format.patch"
    )
    assert manifest["recorded_files"][commit_two_patch_url] == (
        f"gitlab/commit_patches/{commit_two}.patch"
    )
    assert manifest["recorded_files"][commit_two_format_url] == (
        f"gitlab/commit_patches/{commit_two}-format.patch"
    )
    assert (
        manifest["recorded_files"][internal_branches_url]
        == "gitlab/internal_rhel/glib2/branches.json"
    )
    assert result.fetched_urls == seen_urls == list(responses)


def test_collect_case_synthesizes_hidden_internal_branch_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fglib2"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    internal_project_url = "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fglib2"
    project_id = 501034256
    internal_branches_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/branches"
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345": {
            "key": "RHEL-12345",
            "fields": {
                "summary": "CVE-2026-0001 in glib2",
                "components": [{"name": "glib2"}],
                "fixVersions": [{"name": "rhel-9.7.z"}],
                "labels": ["ymir_triaged_backport"],
            },
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {"comments": []},
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [],
        rules_url: "Follow glib2 maintainer rules.\n",
        internal_project_url: HTTPError(internal_project_url, 404, "Not Found", None, None),
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
            mock_repo=MockRepoInput(
                remote_url="https://gitlab.example/glib2.git",
                pre_fix_ref="abc123",
                branch="c9s",
            ),
        )
    )

    cases_dir = tmp_path / "benchmark_cases"
    branches = json.loads(
        (
            cases_dir
            / "web_cache"
            / "RHEL-12345"
            / "gitlab"
            / "internal_rhel"
            / "glib2"
            / "branches.json"
        ).read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )

    assert result.warnings == []
    assert branches[0]["name"] == "rhel-9.7.z"
    assert (
        manifest["recorded_files"][internal_project_url]
        == "gitlab/internal_rhel/glib2/project.json"
    )
    assert (
        manifest["recorded_files"][internal_branches_url]
        == "gitlab/internal_rhel/glib2/branches.json"
    )


def test_collect_case_fetches_internal_branch_records_from_local_jira(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "summary": "Backport CVE fix",
                "components": [{"name": "glib2"}],
                "fixVersions": [{"name": "rhel-9.7.z"}],
                "labels": ["ymir_triaged_backport"],
            },
        },
    )
    comments_json = _write_json(tmp_path / "comments.json", {"comments": []})
    links_json = _write_json(tmp_path / "links.json", [])
    internal_project_url = "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fglib2"
    project_id = 501034256
    internal_branches_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/branches"
    responses = {
        internal_project_url: HTTPError(internal_project_url, 404, "Not Found", None, None),
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
            jira_issue_json=issue_json,
            jira_comments_json=comments_json,
            jira_links_json=links_json,
        )
    )

    cases_dir = tmp_path / "benchmark_cases"
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    branches = json.loads(
        (
            cases_dir
            / "web_cache"
            / "RHEL-12345"
            / "gitlab"
            / "internal_rhel"
            / "glib2"
            / "branches.json"
        ).read_text(encoding="utf-8")
    )

    assert branches[0]["name"] == "rhel-9.7.z"
    assert (
        manifest["recorded_files"][internal_project_url]
        == "gitlab/internal_rhel/glib2/project.json"
    )
    assert (
        manifest["recorded_files"][internal_branches_url]
        == "gitlab/internal_rhel/glib2/branches.json"
    )
    assert seen_urls == result.fetched_urls == [internal_project_url]


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
        if isinstance(body, BaseException):
            raise body
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
