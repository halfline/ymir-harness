from __future__ import annotations

import json
from pathlib import Path

import pytest

from ymir_harness.jira_mock import (
    JiraMockMaterializationError,
    build_ymir_jira_mock_issue,
    materialize_ymir_jira_mock,
)


def test_build_ymir_jira_mock_issue_combines_structured_evidence(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "key": "RHEL-12345",
            "fields": {
                "summary": "Backport CVE fix",
                "comment": {"comments": [{"body": "stale embedded comment"}]},
            },
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "comments.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "comments": [{"body": "fresh fetched comment"}],
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "links.json",
        {
            "schema_version": 1,
            "case_id": "RHEL-12345",
            "case_type": "cve_backport",
            "links": [{"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}],
        },
    )

    payload = build_ymir_jira_mock_issue(cases_dir, "RHEL-12345")

    assert payload["key"] == "RHEL-12345"
    assert payload["fields"]["summary"] == "Backport CVE fix"
    assert payload["fields"]["comment"] == {
        "comments": [{"body": "fresh fetched comment"}],
        "maxResults": 1,
        "startAt": 0,
        "total": 1,
    }
    assert payload["remote_links"] == [
        {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
    ]


def test_build_ymir_jira_mock_issue_defaults_missing_optional_evidence(
    tmp_path: Path,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "fields": {"summary": "Backport CVE fix"},
        },
    )

    payload = build_ymir_jira_mock_issue(cases_dir, "RHEL-12345")

    assert payload["key"] == "RHEL-12345"
    assert payload["fields"]["comment"] == {
        "comments": [],
        "maxResults": 0,
        "startAt": 0,
        "total": 0,
    }
    assert payload["remote_links"] == []


def test_build_ymir_jira_mock_issue_prefers_starting_issue(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "labels": ["ymir_triaged_backport"],
                "comment": {"comments": [{"body": "*Resolution*: backport"}]},
            },
            "remote_links": [
                {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
            ],
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "comments.json",
        {
            "comments": [{"body": "*Resolution*: backport"}],
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "links.json",
        {
            "links": [{"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}],
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "starting-issue.json",
        {
            "key": "RHEL-12345",
            "fields": {
                "labels": [],
                "comment": {"comments": [{"body": "Reporter supplied reproducer."}]},
            },
            "remote_links": [],
        },
    )

    payload = build_ymir_jira_mock_issue(cases_dir, "RHEL-12345")

    assert payload["fields"]["labels"] == []
    assert payload["fields"]["comment"]["comments"] == [{"body": "Reporter supplied reproducer."}]
    assert payload["remote_links"] == []


def test_build_ymir_jira_mock_issue_rejects_invalid_fields(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": [],
        },
    )

    with pytest.raises(JiraMockMaterializationError, match="fields must be an object"):
        build_ymir_jira_mock_issue(cases_dir, "RHEL-12345")


def test_materialize_ymir_jira_mock_writes_flat_issue_file(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "key": "RHEL-12345",
            "fields": {"summary": "Backport CVE fix"},
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "linked" / "RHEL-23456" / "issue.json",
        {
            "key": "RHEL-23456",
            "fields": {"summary": "Linked original issue"},
        },
    )

    target_dir = materialize_ymir_jira_mock(
        cases_dir,
        results_dir,
        "RHEL-12345",
        repetition=2,
    )

    assert target_dir == results_dir / "repeat-2" / "jira-mock"
    payload = json.loads((target_dir / "RHEL-12345").read_text(encoding="utf-8"))
    assert payload["fields"]["comment"]["comments"] == []
    assert payload["remote_links"] == []
    linked_payload = json.loads((target_dir / "RHEL-23456").read_text(encoding="utf-8"))
    assert linked_payload["fields"]["summary"] == "Linked original issue"


def test_materialize_ymir_jira_mock_embeds_dev_status(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    results_dir = tmp_path / "results"
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "issue.json",
        {
            "id": "10001",
            "key": "RHEL-12345",
            "fields": {"summary": "Backport CVE fix"},
        },
    )
    _write_json(
        cases_dir / "jiras" / "RHEL-12345" / "dev-status.json",
        {
            "summary": {"repository": {"byInstanceType": {"GitLab": {"count": 1}}}},
            "details": {
                "GitLab:repository": [
                    {
                        "repositories": [
                            {
                                "url": "https://gitlab.example/group/pkg",
                                "commits": [{"url": "https://gitlab.example/group/pkg/-/commit/1"}],
                            }
                        ]
                    }
                ]
            },
        },
    )

    target_dir = materialize_ymir_jira_mock(
        cases_dir,
        results_dir,
        "RHEL-12345",
        repetition=1,
    )

    payload = json.loads((target_dir / "RHEL-12345").read_text(encoding="utf-8"))
    assert payload["dev_status"]["summary"]["repository"]["byInstanceType"]["GitLab"] == {
        "count": 1
    }
    assert payload["dev_status"]["details"]["GitLab:repository"][0]["repositories"][0][
        "commits"
    ] == [{"url": "https://gitlab.example/group/pkg/-/commit/1"}]


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
