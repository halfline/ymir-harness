from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
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
    def fake_fetch_candidate_build(
        package: str,
        branch: str,
        *,
        as_of: str | None = None,
        timeout: float | None = None,
    ):
        return {
            "package": package,
            "dist_git_branch": branch,
            "replay_as_of": as_of,
            "evr": {
                "epoch": 0,
                "version": "1.0",
                "release": "1.el9",
            },
            "source_ref": f"{package}-{branch}-ref",
        }

    monkeypatch.setattr(collect_case_module, "fetch_candidate_build", fake_fetch_candidate_build)


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
        "\n".join(
            [
                "diff --git a/source.c b/source.c",
                "index e69de29..2c43c3c 100644",
                "--- a/source.c",
                "+++ b/source.c",
                "@@ -0,0 +1 @@",
                "+fixed",
                "",
            ]
        ),
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
    assert expected["backport_source"] == "upstream"
    assert expected["reference_patch_mode"] == "scope_only"
    assert expected["required_artifact_kinds"] == [
        "commit_diff",
        "spec_file",
        "patch_files",
        "srpm",
    ]
    assert expected["patch_file_patterns"] == ["RHEL-12345"]
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


def test_collect_case_infers_distgit_backport_source(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            patch_urls=(
                "https://gitlab.com/redhat/rhel/rpms/redis/-/commit/"
                "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1.patch",
            ),
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["backport_source"] == "distgit"


def test_collect_case_infers_pkgs_devel_backport_source_and_semantic_reference(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    patch_url = (
        "https://pkgs.devel.redhat.com/cgit/rpms/redis/patch/"
        "?h=rhel-9.8.0&id=0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1"
    )
    patch_path = _write_text(
        tmp_path / "inputs" / "fix.patch",
        "diff --git a/redis.spec b/redis.spec\n",
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.2.0",
            expected_basis="historical_jira_state",
            network_mode="replay_only",
            patch_urls=(patch_url,),
            reference_patch=patch_path,
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["backport_source"] == "distgit"
    assert expected["reference_patch_mode"] == "semantic_reference"


def test_collect_case_infers_mixed_backport_source(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="kea",
            target_branch="rhel-10.0.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            patch_urls=(
                "https://github.com/isc-projects/kea/commit/"
                "1111111111111111111111111111111111111111.patch",
                "https://gitlab.com/redhat/centos-stream/rpms/kea/-/commit/"
                "2222222222222222222222222222222222222222.patch",
            ),
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["backport_source"] == "mixed"


def test_collect_case_uses_jira_issue_patch_file_pattern(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            patch_urls=(
                "https://gitlab.example/group/pkg/-/merge_requests/7.patch",
                "https://gitlab.example/group/pkg/-/commit/" + ("a" * 40) + ".patch",
            ),
            mock_repo=MockRepoInput(
                remote_url="https://gitlab.example/group/pkg.git",
                pre_fix_ref="abc123",
                branch="c9s",
                agent="backport",
            ),
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["required_artifact_kinds"] == [
        "commit_diff",
        "spec_file",
        "patch_files",
        "srpm",
    ]
    assert expected["patch_file_patterns"] == ["RHEL-12345"]


def test_collect_case_warns_when_auto_discovered_gitlab_mr_is_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    mr_url = "https://gitlab.com/redhat/rhel/rpms/redis/-/merge_requests/6"
    patch_url = f"{mr_url}.patch"
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {"summary": "Backport CVE fix"},
        },
    )
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "body": (
                        "Output from Ymir Backport Agent\n"
                        f"*Resolution*: backport\n*Patch URL*: {patch_url}\n"
                    )
                }
            ]
        },
    )
    responses: dict[str, object] = {}
    seen_urls: list[str] = []
    monkeypatch.setattr(collect_case_module, "_gitlab_token", lambda token_env: None)
    monkeypatch.setattr(collect_case_module, "urlopen", _fake_urlopen(responses, seen_urls))

    result = collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            jira_issue_json=issue_json,
            jira_comments_json=comments_json,
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["patch_urls"] == [patch_url]
    assert expected["backport_source"] == "distgit"
    assert any("skipped auto-discovered GitLab MR" in warning for warning in result.warnings)
    assert any("skipped Jira patch URL" in warning for warning in result.warnings)
    assert seen_urls == []


def test_collect_case_fails_when_explicit_gitlab_mr_is_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mr_url = "https://gitlab.com/redhat/rhel/rpms/redis/-/merge_requests/6"
    api_url = "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fredis/merge_requests/6"
    responses = {api_url: HTTPError(api_url, 404, "Not Found", None, None)}
    seen_urls: list[str] = []
    monkeypatch.setattr(collect_case_module, "_gitlab_token", lambda token_env: None)
    monkeypatch.setattr(collect_case_module, "urlopen", _fake_urlopen(responses, seen_urls))

    with pytest.raises(CollectCaseError, match="failed to fetch"):
        collect_case(
            CollectCaseRequest(
                cases_dir=tmp_path / "benchmark_cases",
                case_id="RHEL-12345",
                case_type="cve_backport",
                resolution="backport",
                package="redis",
                target_branch="rhel-9.6.z",
                expected_basis="merged_mr",
                network_mode="replay_only",
                gitlab_mr_url=mr_url,
            )
        )

    assert seen_urls == [api_url]


def test_collect_case_uses_gitlab_api_diff_when_mr_patch_is_forbidden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    mr_url = "https://gitlab.com/redhat/rhel/rpms/redis/-/merge_requests/6"
    commit_sha = "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1"
    diff_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fredis"
        f"/repository/commits/{commit_sha}/diff"
    )
    responses = {
        "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fredis/merge_requests/6": {
            "iid": 6,
            "target_branch": "rhel-9.6.0",
            "web_url": mr_url,
            "diff_refs": {
                "base_sha": "4549b5e1d58b86ef6c81f4089684034c1d3b302d",
                "head_sha": commit_sha,
                "start_sha": "4549b5e1d58b86ef6c81f4089684034c1d3b302d",
            },
        },
        "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fredis/merge_requests/6/commits": [
            {"id": commit_sha, "title": "rebase to 6.2.22"}
        ],
        "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fredis/merge_requests/6/changes": {
            "changes": [{"old_path": "redis.spec", "new_path": "redis.spec"}]
        },
        f"{mr_url}.patch": HTTPError(f"{mr_url}.patch", 403, "Forbidden", None, None),
        diff_url: [
            {
                "old_path": "redis.spec",
                "new_path": "redis.spec",
                "diff": "@@ -1 +1 @@\n-Version: 6.2.20\n+Version: 6.2.22\n",
                "new_file": False,
                "deleted_file": False,
            }
        ],
    }
    seen_urls: list[str] = []
    monkeypatch.setattr(collect_case_module, "_gitlab_token", lambda token_env: "token")
    monkeypatch.setattr(collect_case_module, "urlopen", _fake_urlopen(responses, seen_urls))

    result = collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            gitlab_mr_url=mr_url,
        )
    )

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    recorded = (
        cases_dir / "web_cache" / "RHEL-12345" / manifest["recorded_files"][f"{mr_url}.patch"]
    )
    assert recorded.read_text(encoding="utf-8").startswith("diff --git a/redis.spec")
    assert any("used GitLab API diff" in warning for warning in result.warnings)
    assert diff_url in seen_urls


def test_collect_case_uses_gitlab_api_diff_for_jira_commit_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    commit_sha = "0bfb2e457d6fc7c8c1b88e6d00930e321ec47ee1"
    patch_url = f"https://gitlab.com/redhat/rhel/rpms/redis/-/commit/{commit_sha}.patch"
    diff_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Frhel%2Frpms%2Fredis"
        f"/repository/commits/{commit_sha}/diff"
    )
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "body": (
                        "Output from Ymir Backport Agent\n"
                        f"*Resolution*: backport\n*Patch URL*: {patch_url}\n"
                    )
                }
            ]
        },
    )
    responses = {
        patch_url: HTTPError(patch_url, 403, "Forbidden", None, None),
        diff_url: [
            {
                "old_path": ".gitignore",
                "new_path": ".gitignore",
                "diff": "@@ -1 +1,2 @@\n old\n+new\n",
                "new_file": False,
                "deleted_file": False,
            }
        ],
    }
    seen_urls: list[str] = []
    monkeypatch.setattr(collect_case_module, "_gitlab_token", lambda token_env: "token")
    monkeypatch.setattr(collect_case_module, "urlopen", _fake_urlopen(responses, seen_urls))

    result = collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            jira_comments_json=comments_json,
        )
    )

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    recorded = cases_dir / "web_cache" / "RHEL-12345" / manifest["recorded_files"][patch_url]
    assert recorded.read_text(encoding="utf-8").startswith("diff --git a/.gitignore")
    assert any("used GitLab API diff" in warning for warning in result.warnings)
    assert diff_url in seen_urls


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


def test_collect_case_records_koji_candidate_builds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    mr_url = "https://gitlab.com/redhat/rhel/rpms/redis/-/merge_requests/1"
    patch_url = f"{mr_url}.patch"
    as_of = "2026-01-02T03:04:04.999999Z"
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "created": "2026-01-02T03:04:05Z",
                    "body": "Output from triage agent",
                }
            ]
        },
    )
    calls: list[tuple[str, str, str | None]] = []

    def fake_fetch_gitlab_mr_evidence(_gitlab_mr_url, _request, _result):
        return (
            {"target_branch": "rhel-9.6.0", "source_branch": "fix"},
            [],
            patch_url,
            b"diff --git a/source.c b/source.c\n",
            [
                collect_case_module.FetchedRecord(
                    url=patch_url,
                    relative_path="gitlab/merge_request.patch",
                    body=b"diff --git a/source.c b/source.c\n",
                )
            ],
        )

    def fake_maintainer_rules(package, _request, _result):
        return collect_case_module.FetchedRecord(
            url=f"https://rules.example/{package}/AGENTS.md",
            relative_path=f"gitlab/maintainer_rules/{package}/AGENTS.md",
            body=b"",
        )

    def fake_fetch_candidate_build(
        package: str,
        branch: str,
        *,
        as_of: str | None = None,
        timeout: float | None = None,
    ):
        calls.append((package, branch, as_of, timeout))
        return {
            "package": package,
            "dist_git_branch": branch,
            "replay_as_of": as_of,
            "evr": {
                "epoch": 0,
                "version": "6.2.20",
                "release": "3.el9" if branch == "rhel-9.6.0" else "2.el9",
            },
            "source_ref": f"{package}-{branch}-ref",
        }

    monkeypatch.setattr(
        collect_case_module,
        "_fetch_gitlab_mr_evidence",
        fake_fetch_gitlab_mr_evidence,
    )
    monkeypatch.setattr(
        collect_case_module,
        "_fetch_maintainer_rules_record",
        fake_maintainer_rules,
    )
    monkeypatch.setattr(collect_case_module, "fetch_candidate_build", fake_fetch_candidate_build)

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.0",
            expected_basis="merged_mr",
            network_mode="replay_only",
            cve_ids=("CVE-2026-0001",),
            gitlab_mr_url=mr_url,
            jira_comments_json=comments_json,
            overwrite=True,
        )
    )

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )

    assert calls == [
        ("redis", "rhel-9.6.0", as_of, 30.0),
        ("redis", "rhel-9.7.0", as_of, 30.0),
    ]
    assert manifest["koji_candidate_builds"]["redis|rhel-9.6.0"]["evr"] == {
        "epoch": 0,
        "version": "6.2.20",
        "release": "3.el9",
    }
    assert (
        manifest["koji_candidate_builds"]["redis|rhel-9.7.0"]["source_ref"]
        == "redis-rhel-9.7.0-ref"
    )


def test_collect_case_auto_caches_package_distgit_when_cache_is_requested(
    tmp_path: Path,
) -> None:
    request = CollectCaseRequest(
        cases_dir=tmp_path / "benchmark_cases",
        case_id="RHEL-12345",
        package="rpm-ostree",
        network_mode="replay_only",
        mock_repo_cache=tmp_path / "mock-repos",
    )

    assert collect_case_module._auto_source_project_urls(  # noqa: SLF001
        request,
        collect_case_module.FetchedEvidence(),
    ) == ("https://gitlab.com/redhat/centos-stream/rpms/rpm-ostree",)


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
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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
        "https://issues.example.invalid/rest/api/2/issue/RHEL-23456?expand=changelog": {
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


def test_collect_case_overwrite_clears_stale_jira_replay_state(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    jira_dir = cases_dir / "jiras" / "RHEL-12345"
    _write_json(jira_dir / "api" / "search" / "stale.json", {"response": {"issues": []}})
    _write_json(jira_dir / "linked" / "RHEL-OLD" / "issue.json", {"key": "RHEL-OLD"})
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {"summary": "Backport CVE fix"},
        },
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            network_mode="network_denied",
            jira_issue_json=issue_json,
            overwrite=True,
        )
    )

    assert not (jira_dir / "api").exists()
    assert not (jira_dir / "linked").exists()
    assert (jira_dir / "issue.json").is_file()


def test_collect_case_uses_embedded_linked_jira_when_fetch_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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
        "https://issues.example.invalid/rest/api/2/issue/RHEL-23456?expand=changelog": HTTPError(
            "https://issues.example.invalid/rest/api/2/issue/RHEL-23456?expand=changelog",
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
            "https://issues.example.invalid/rest/api/2/issue/RHEL-23456?expand=changelog"
        )
        and "HTTP Error 403" in warning
        for warning in result.warnings
    )


def test_collect_case_fetches_jira_with_basic_auth_token_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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


def test_collect_case_infers_backport_from_human_assessment_comment(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "summary": "CVE-2026-0001 qt6-qtdeclarative issue [rhel-10.2.z]",
                "customfield_10669": "qt6",
                "components": [{"name": "qt6-qtdeclarative"}],
                "fixVersions": [{"name": "rhel-10.2.z"}],
                "labels": ["Security"],
            },
        },
    )
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "body": (
                        "Fix Assessment: CLEAN BACKPORT - small upstream change.\n"
                        "Recommended Action: Backport the fix into qt6-qtdeclarative"
                    )
                }
            ]
        },
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            jira_issue_json=issue_json,
            jira_comments_json=comments_json,
            network_mode="network_denied",
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["resolution"] == "backport"
    assert expected["case_type"] == "cve_backport"
    assert expected["package"] == "qt6-qtdeclarative"
    assert expected["fix_version"] == "rhel-10.2.z"


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
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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


def test_triage_expected_patch_urls_ignore_backport_only_result_comment(
    tmp_path: Path,
) -> None:
    upstream_patch_url = "https://github.example/upstream/pkg/commit/abc123.patch"
    mr_url = "https://gitlab.example/redhat/rpms/pkg/-/merge_requests/64"
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "body": f"Output from Backport Agent:\n\n{mr_url}\n",
                    "author": {"displayName": "Jotnar Project"},
                }
            ]
        },
    )
    fetched = collect_case_module.FetchedEvidence(
        jira_patch_urls=(upstream_patch_url,),
        gitlab_mr_url=mr_url,
        gitlab_patch_url=f"{mr_url}.patch",
    )

    triage_request = CollectCaseRequest(
        cases_dir=tmp_path / "benchmark_cases",
        case_id="RHEL-12345",
        expected_basis="historical_jira_state",
        mock_agent="triage",
        jira_comments_json=comments_json,
    )
    backport_request = CollectCaseRequest(
        cases_dir=tmp_path / "benchmark_cases",
        case_id="RHEL-12345",
        expected_basis="historical_jira_state",
        mock_agent="backport",
        jira_comments_json=comments_json,
    )

    assert collect_case_module._expected_patch_urls(triage_request, fetched) == (
        upstream_patch_url,
    )
    assert collect_case_module._expected_patch_urls(backport_request, fetched) == (
        f"{mr_url}.patch",
    )


def test_historical_expected_patch_urls_use_first_completed_agent_result(
    tmp_path: Path,
) -> None:
    first_patch_url = "https://github.example/upstream/pkg/commit/first.patch"
    later_patch_url = "https://github.example/upstream/pkg/commit/later.patch"
    comments_json = _write_json(
        tmp_path / "comments.json",
        {
            "comments": [
                {
                    "body": (
                        "Output from Ymir Triage Agent:\n\n"
                        "Ymir picked up your request and started processing."
                    ),
                    "author": {"displayName": "Red Hat Comaintainer Ymir Agent"},
                },
                {
                    "body": (
                        "Output from Ymir Triage Agent:\n\n"
                        "*Resolution*: backport\n"
                        f"*Patch URL 1*: {first_patch_url}\n"
                    ),
                    "author": {"displayName": "Red Hat Comaintainer Ymir Agent"},
                },
                {
                    "body": (
                        "Output from Ymir Triage Agent:\n\n"
                        "*Resolution*: backport\n"
                        f"*Patch URL 1*: {first_patch_url}\n"
                        f"*Patch URL 2*: {later_patch_url}\n"
                    ),
                    "author": {"displayName": "Red Hat Comaintainer Ymir Agent"},
                },
            ]
        },
    )
    request = CollectCaseRequest(
        cases_dir=tmp_path / "benchmark_cases",
        case_id="RHEL-12345",
        expected_basis="historical_jira_state",
        mock_agent="triage",
        jira_comments_json=comments_json,
    )

    assert collect_case_module._expected_patch_urls(
        request,
        collect_case_module.FetchedEvidence(),
    ) == (first_patch_url,)


def test_backport_expected_patch_urls_prefer_triage_result(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    triage_patch_url = "https://gitlab.example/redhat/rpms/pkg/-/commit/abc123.patch"
    jira_patch_url = "https://gitlab.example/redhat/rpms/pkg/-/merge_requests/64.patch"
    triage_result_path = cases_dir / "triage_results" / "RHEL-12345.actual.json"
    triage_result_path.parent.mkdir(parents=True)
    triage_result_path.write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "resolution": "backport",
                "patch_urls": [triage_patch_url],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    request = CollectCaseRequest(
        cases_dir=cases_dir,
        case_id="RHEL-12345",
        expected_basis="historical_jira_state",
        mock_agent="backport",
    )
    fetched = collect_case_module.FetchedEvidence(
        jira_patch_urls=(jira_patch_url,),
    )

    assert collect_case_module._expected_patch_urls(request, fetched) == (triage_patch_url,)


def test_backport_patch_fetch_candidates_include_triage_result(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    request_patch_url = "https://example.invalid/request.patch"
    jira_patch_url = "https://gitlab.example/redhat/rpms/pkg/-/merge_requests/64.patch"
    triage_patch_url = "https://pkgs.example/rpms/pkg/patch/?h=rhel-9.8&id=abc123"
    triage_result_path = cases_dir / "triage_results" / "RHEL-12345.actual.json"
    triage_result_path.parent.mkdir(parents=True)
    triage_result_path.write_text(
        json.dumps({"data": {"patch_urls": [triage_patch_url]}}) + "\n",
        encoding="utf-8",
    )
    request = CollectCaseRequest(
        cases_dir=cases_dir,
        case_id="RHEL-12345",
        mock_agent="backport",
        patch_urls=(request_patch_url,),
    )

    assert collect_case_module._candidate_patch_urls_to_fetch(
        request,
        (jira_patch_url,),
    ) == (request_patch_url, jira_patch_url, triage_patch_url)


def test_backport_reference_patch_prefers_triage_result_patch_body(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    triage_patch_url = "https://github.example/upstream/pkg/commit/first.patch"
    later_patch_url = "https://github.example/upstream/pkg/commit/later.patch"
    mr_patch_url = "https://gitlab.example/redhat/rpms/pkg/-/merge_requests/64.patch"
    triage_result_path = cases_dir / "triage_results" / "RHEL-12345.actual.json"
    triage_result_path.parent.mkdir(parents=True)
    triage_result_path.write_text(
        json.dumps({"data": {"patch_urls": [triage_patch_url]}}) + "\n",
        encoding="utf-8",
    )
    request = CollectCaseRequest(
        cases_dir=cases_dir,
        case_id="RHEL-12345",
        mock_agent="backport",
        mock_repo=MockRepoInput(
            remote_url="https://gitlab.example/redhat/rpms/pkg.git",
            pre_fix_ref="abc123",
            branch="rhel-9.6.0",
            agent="backport",
        ),
    )
    fetched = collect_case_module.FetchedEvidence(
        jira_patch_urls=(triage_patch_url, later_patch_url),
        gitlab_patch_url=mr_patch_url,
        gitlab_patch_body=(b"diff --git a/source.c b/source.c\ndiff --git a/test.c b/test.c\n"),
        web_records=(
            collect_case_module.FetchedRecord(
                url=triage_patch_url,
                relative_path="jira/patches/001.patch",
                body=b"diff --git a/source.c b/source.c\n",
            ),
            collect_case_module.FetchedRecord(
                url=later_patch_url,
                relative_path="jira/patches/002.patch",
                body=b"diff --git a/test.c b/test.c\n",
            ),
        ),
    )

    collect_case_module._write_mock_data(
        cases_dir,
        request,
        fetched,
        collect_case_module.CollectCaseResult(case_id="RHEL-12345", cases_dir=cases_dir),
    )

    reference_patch = (
        cases_dir / "mock_data" / "backport" / "reference_patches" / "RHEL-12345.patch"
    )
    assert reference_patch.read_bytes() == b"diff --git a/source.c b/source.c\n"


def test_collect_case_scrubs_comments_after_historical_as_of(tmp_path: Path) -> None:
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "summary": "Backport CVE fix",
                "components": [{"name": "dnsmasq"}],
                "fixVersions": [{"name": "rhel-8.10.z"}],
                "status": {"name": "Integration"},
                "labels": ["Security", "ymir_backported"],
                "customfield_10578": "dnsmasq-2.90-1.el8_10.4",
                "updated": "2025-09-13T00:00:00.000+0000",
            },
            "changelog": {
                "histories": [
                    {
                        "created": "2025-09-12T10:00:00.000+0000",
                        "items": [
                            {
                                "field": "status",
                                "fieldId": "status",
                                "fromString": "Planning",
                                "toString": "Integration",
                            },
                            {
                                "field": "labels",
                                "fieldId": "labels",
                                "fromString": "Security ymir_triage_in_progress",
                                "toString": "Security ymir_backported",
                            },
                            {
                                "field": "Fixed in Build",
                                "fieldId": "customfield_10578",
                                "fromString": None,
                                "toString": "dnsmasq-2.90-1.el8_10.4",
                            },
                        ],
                    }
                ]
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
    assert "changelog" not in starting
    assert starting["fields"]["status"] == {"name": "Planning"}
    assert starting["fields"]["labels"] == ["Security"]
    assert starting["fields"]["customfield_10578"] is None
    assert starting["fields"]["updated"] == "2025-09-12T09:46:43.671999Z"
    assert starting["fields"]["comment"]["comments"] == [
        {
            "body": "Reporter supplied reproducer.",
            "created": "2025-09-10T00:00:00.000+0000",
        }
    ]


def test_collect_case_fetches_gitlab_mr_into_replay_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fdnsmasq"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    commit_one = "a" * 40
    commit_two = "b" * 40
    mr_patch_body = (
        f"From {commit_one} Mon Sep 17 00:00:00 2001\n"
        "Subject: [PATCH 1/2] Fix CVE\n"
        "\n"
        "diff --git a/source.c b/source.c\n"
        f"From {commit_two} Mon Sep 17 00:00:00 2001\n"
        "Subject: [PATCH 2/2] Add regression test\n"
        "\n"
        "diff --git a/test.c b/test.c\n"
    )
    commit_one_patch_url = f"https://gitlab.example/group/pkg/-/commit/{commit_one}.patch"
    commit_one_format_url = f"https://gitlab.example/group/pkg/-/commit/{commit_one}?format=.patch"
    commit_two_patch_url = f"https://gitlab.example/group/pkg/-/commit/{commit_two}.patch"
    commit_two_format_url = f"https://gitlab.example/group/pkg/-/commit/{commit_two}?format=.patch"
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
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch": mr_patch_body,
        commit_one_patch_url: "diff --git a/source.c b/source.c\n",
        commit_two_patch_url: "diff --git a/test.c b/test.c\n",
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
    assert "required_artifact_kinds" not in expected
    assert "patch_file_patterns" not in expected
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
    assert reference_patch.read_text(encoding="utf-8") == mr_patch_body

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["required_urls"] == [
        "https://gitlab.example/group/pkg/-/merge_requests/7.patch",
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7",
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/commits",
        "https://gitlab.example/api/v4/projects/group%2Fpkg/merge_requests/7/changes",
        commit_one_patch_url,
        commit_one_format_url,
        commit_two_patch_url,
        commit_two_format_url,
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
        commit_one_patch_url: f"gitlab/commit_patches/{commit_one}.patch",
        commit_one_format_url: f"gitlab/commit_patches/{commit_one}-format.patch",
        commit_two_patch_url: f"gitlab/commit_patches/{commit_two}.patch",
        commit_two_format_url: f"gitlab/commit_patches/{commit_two}-format.patch",
        rules_url: "gitlab/maintainer_rules/dnsmasq/AGENTS.md",
    }
    assert result.fetched_urls == seen_urls == list(responses)


def test_collect_case_infers_backport_from_auto_discovered_gitlab_mr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    mr_url = "https://gitlab.example/group/pkg/-/merge_requests/7"
    patch_url = f"{mr_url}.patch"
    issue_json = _write_json(
        tmp_path / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "summary": "Closed historical bug",
                "status": {"name": "Closed"},
                "resolution": {"name": "Done-Errata"},
                "components": [{"name": "dnsmasq"}],
                "fixVersions": [{"name": "rhel-8.10"}],
                "labels": [],
            },
        },
    )
    comments_json = _write_json(
        tmp_path / "comments.json",
        {"comments": [{"body": "Human discussion without structured resolution."}]},
    )
    links_json = _write_json(
        tmp_path / "links.json",
        [{"object": {"url": mr_url}}],
    )

    def fake_fetch_gitlab_mr_evidence(_gitlab_mr_url, _request, _result):
        return (
            {
                "target_branch": "c8s",
                "web_url": mr_url,
                "diff_refs": {"base_sha": "prefix"},
            },
            [{"id": "fix123"}],
            patch_url,
            b"diff --git a/source.c b/source.c\n",
            [
                collect_case_module.FetchedRecord(
                    url=patch_url,
                    relative_path="gitlab/merge_request.patch",
                    body=b"diff --git a/source.c b/source.c\n",
                )
            ],
        )

    def fake_maintainer_rules(package, _request, _result):
        return collect_case_module.FetchedRecord(
            url=f"https://rules.example/{package}/AGENTS.md",
            relative_path=f"gitlab/maintainer_rules/{package}/AGENTS.md",
            body=b"",
        )

    def fake_internal_branches(package, fix_version, _request, _result):
        return (
            collect_case_module.FetchedRecord(
                url=f"https://gitlab.example/internal/{package}",
                relative_path=f"gitlab/internal_rhel/{package}/project.json",
                body=b"{}",
            ),
            collect_case_module.FetchedRecord(
                url=f"https://gitlab.example/internal/{package}/branches",
                relative_path=f"gitlab/internal_rhel/{package}/branches.json",
                body=json.dumps([{"name": fix_version}]).encode("utf-8"),
            ),
        )

    monkeypatch.setattr(
        collect_case_module,
        "_fetch_gitlab_mr_evidence",
        fake_fetch_gitlab_mr_evidence,
    )
    monkeypatch.setattr(
        collect_case_module,
        "_fetch_maintainer_rules_record",
        fake_maintainer_rules,
    )
    monkeypatch.setattr(
        collect_case_module,
        "_fetch_internal_rhel_branch_records",
        fake_internal_branches,
    )

    collect_case(
        CollectCaseRequest(
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            network_mode="replay_only",
            mock_agent="backport",
            jira_issue_json=issue_json,
            jira_comments_json=comments_json,
            jira_links_json=links_json,
        )
    )

    expected = json.loads(
        (cases_dir / "expected" / "RHEL-12345.expected.json").read_text(encoding="utf-8")
    )
    assert expected["resolution"] == "backport"
    assert expected["case_type"] == "cve_backport"
    assert expected["package"] == "dnsmasq"
    assert expected["target_branch"] == "c8s"
    assert expected["fix_version"] == "rhel-8.10"
    assert expected["patch_urls"] == [patch_url]
    assert expected["required_artifact_kinds"] == [
        "commit_diff",
        "spec_file",
        "patch_files",
        "srpm",
    ]
    assert expected["patch_file_patterns"] == ["RHEL-12345"]

    mock = json.loads(
        (cases_dir / "mock_data" / "backport" / "RHEL-12345.json").read_text(encoding="utf-8")
    )
    assert mock["repos"][0] == {
        "branch": "c8s",
        "package": "dnsmasq",
        "pre_fix_ref": "prefix",
        "remote_url": "https://gitlab.example/group/pkg.git",
    }


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
    project_id = collect_case_module._synthetic_internal_rhel_project_id(package)
    internal_branches_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/branches"
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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
    project_id = collect_case_module._synthetic_internal_rhel_project_id("glib2")
    internal_branches_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/branches"
    responses = {
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345?expand=changelog": {
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
    project_id = collect_case_module._synthetic_internal_rhel_project_id("glib2")
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
                zstream_override={"8": "rhel-8.10.z"},
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

    report = validate_case_directory(cases_dir, workflow="ymir-triage")
    assert not report.has_blocking_errors


def test_localize_mock_repo_cache_authenticates_existing_gitlab_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_dir = tmp_path / "repo-cache"
    destination = cache_dir / collect_case_module._mock_repo_cache_name(  # noqa: SLF001
        "https://gitlab.com/redhat/rhel/rpms/redis.git"
    )
    destination.mkdir(parents=True)
    commands: list[list[str]] = []

    monkeypatch.setattr(collect_case_module, "_gitlab_token", lambda token_env: "token")

    def fake_run_git(command, cwd):
        commands.append(list(command))

    monkeypatch.setattr(collect_case_module, "_run_git", fake_run_git)

    request = CollectCaseRequest(
        cases_dir=tmp_path / "benchmark_cases",
        case_id="RHEL-178383",
        mock_repo=MockRepoInput(
            remote_url="https://gitlab.com/redhat/rhel/rpms/redis.git",
            pre_fix_ref="abc123",
            branch="rhel-9.4.0",
        ),
        mock_repo_cache=cache_dir,
    )

    localized = collect_case_module._localize_mock_repo_cache(request)  # noqa: SLF001

    authorization = base64.b64encode(b"oauth2:token").decode("ascii")
    assert commands[0] == [
        "-c",
        f"http.https://gitlab.com/.extraHeader=Authorization: Basic {authorization}",
        "-C",
        str(destination),
        "remote",
        "update",
        "--prune",
    ]
    assert commands[1] == [
        "-C",
        str(destination),
        "cat-file",
        "-e",
        "abc123^{commit}",
    ]
    assert localized.mock_repo is not None
    assert localized.mock_repo.source_url == str(destination)


def test_collect_case_caches_lookaside_sources_from_prefixed_mock_repo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_body = b"source archive\n"
    archive_hash = hashlib.sha512(archive_body).hexdigest()
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    (source_repo / "redis.spec").write_text(
        "Name: redis\nVersion: 6.2.20\nSource0: redis-6.2.20.tar.gz\n",
        encoding="utf-8",
    )
    (source_repo / "sources").write_text(
        f"SHA512 (redis-6.2.20.tar.gz) = {archive_hash}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "redis.spec", "sources"], check=True)
    subprocess.run(["git", "-C", str(source_repo), "commit", "-q", "-m", "add sources"], check=True)
    pre_fix_ref = subprocess.check_output(
        ["git", "-C", str(source_repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    rhpkg = bin_dir / "rhpkg"
    rhpkg.write_text(
        "#!/bin/sh\nprintf 'source archive\\n' > redis-6.2.20.tar.gz\n",
        encoding="utf-8",
    )
    rhpkg.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")

    result = collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.0",
            mock_repo=MockRepoInput(
                remote_url="https://gitlab.example/group/redis.git",
                source_url=str(source_repo),
                pre_fix_ref=pre_fix_ref,
                branch="rhel-9.6.0",
            ),
        )
    )

    cached_archive = (
        tmp_path
        / "benchmark_cases"
        / "source_cache"
        / "RHEL-12345"
        / "lookaside"
        / "redis-6.2.20.tar.gz"
    )
    assert cached_archive.read_bytes() == archive_body
    assert result.warnings == []


def test_collect_case_caches_lookaside_sources_from_spec_source_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_body = b"source archive\n"
    archive_hash = hashlib.sha512(archive_body).hexdigest()
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    (source_repo / "redis.spec").write_text(
        "\n".join(
            [
                "Name: redis",
                "Version: 6.2.20",
                "Source0: https://downloads.example.invalid/%{name}-%{version}.tar.gz",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (source_repo / "sources").write_text(
        f"SHA512 (redis-6.2.20.tar.gz) = {archive_hash}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(source_repo), "add", "redis.spec", "sources"], check=True)
    subprocess.run(["git", "-C", str(source_repo), "commit", "-q", "-m", "add sources"], check=True)
    pre_fix_ref = subprocess.check_output(
        ["git", "-C", str(source_repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    monkeypatch.setattr(
        collect_case_module,
        "_run_package_sources_command",
        lambda *args, **kwargs: "rhpkg is not installed",
    )
    seen_urls: list[str] = []
    source_url = "https://downloads.example.invalid/redis-6.2.20.tar.gz"
    monkeypatch.setattr(
        collect_case_module,
        "urlopen",
        _fake_urlopen({source_url: archive_body}, seen_urls),
    )

    result = collect_case(
        CollectCaseRequest(
            cases_dir=tmp_path / "benchmark_cases",
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="redis",
            target_branch="rhel-9.6.0",
            mock_repo=MockRepoInput(
                remote_url="https://gitlab.example/group/redis.git",
                source_url=str(source_repo),
                pre_fix_ref=pre_fix_ref,
                branch="rhel-9.6.0",
            ),
        )
    )

    cached_archive = (
        tmp_path
        / "benchmark_cases"
        / "source_cache"
        / "RHEL-12345"
        / "lookaside"
        / "redis-6.2.20.tar.gz"
    )
    assert cached_archive.read_bytes() == archive_body
    assert source_url in seen_urls
    assert result.warnings == []


def test_collect_case_caches_gitlab_project_source_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_root = tmp_path / "benchmark_cases"
    cases_dir = cases_root / "ymir-triage"
    cases_dir.mkdir(parents=True)
    subprocess.run(["git", "init", str(cases_root)], check=True, stdout=subprocess.DEVNULL)
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{source_repo.resolve().as_uri()}"]',
                "\tinsteadOf = https://gitlab.com/group/pkg.git",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))

    mr_url = "https://gitlab.com/group/pkg/-/merge_requests/7"
    rules_url = (
        "https://gitlab.com/api/v4/projects/redhat%2Fcentos-stream%2Frules%2Fdnsmasq"
        "/repository/files/AGENTS.md/raw?ref=main"
    )
    responses = {
        "https://gitlab.com/api/v4/projects/group%2Fpkg/merge_requests/7": {
            "iid": 7,
            "target_branch": "c9s",
            "web_url": mr_url,
            "diff_refs": {
                "base_sha": pre_fix_ref,
                "head_sha": "head123",
                "start_sha": pre_fix_ref,
            },
        },
        "https://gitlab.com/api/v4/projects/group%2Fpkg/merge_requests/7/commits": [
            {"id": "abc123", "title": "Fix CVE"}
        ],
        "https://gitlab.com/api/v4/projects/group%2Fpkg/merge_requests/7/changes": {
            "changes": [{"old_path": "source.c", "new_path": "source.c"}]
        },
        f"{mr_url}.patch": "diff --git a/source.c b/source.c\n",
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
            cases_dir=cases_dir,
            case_id="RHEL-12345",
            case_type="cve_backport",
            resolution="backport",
            package="dnsmasq",
            target_branch="rhel-8.10.z",
            expected_basis="merged_mr",
            network_mode="replay_only",
            gitlab_mr_url=mr_url,
        )
    )

    upstream_dir = cases_dir / "source_cache" / "RHEL-12345" / "upstream"
    manifests = list(upstream_dir.glob("*.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    checkout = upstream_dir / manifest["path"]
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "cat-file",
            "-e",
            f"{pre_fix_ref}^{{commit}}",
        ],
        check=True,
    )
    assert manifest["remote_url"] == "https://gitlab.com/group/pkg.git"
    assert (cases_root / ".gitmodules").is_file()
    assert result.warnings == []
    assert seen_urls == list(responses)


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
        if isinstance(body, BaseException):
            raise body
        if isinstance(body, bytes):
            return _FakeHttpResponse(body)
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
