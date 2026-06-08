from __future__ import annotations

import json
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
        (cases_dir / "mock_data" / "backport" / "RHEL-12345.json").read_text(
            encoding="utf-8"
        )
    )
    assert mock["repos"][0]["remote_url"] == "https://example.invalid/dnsmasq.git"
    assert mock["zstream_override"] == {"8": "rhel-8.10.z"}
    assert (
        cases_dir / "mock_data" / "backport" / "reference_patches" / "RHEL-12345.patch"
    ).is_file()

    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["required_urls"] == ["https://example.invalid/fix.patch"]
    recorded_path = cases_dir / "web_cache" / "RHEL-12345" / manifest["recorded_files"][
        "https://example.invalid/fix.patch"
    ]
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
            "fields": {"summary": "Backport CVE fix"},
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/comment": {
            "comments": [{"body": "Please backport this fix."}],
        },
        "https://issues.example.invalid/rest/api/2/issue/RHEL-12345/remotelink": [
            {"object": {"url": "https://gitlab.example/group/pkg/-/merge_requests/7"}}
        ],
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
            jira_url="https://issues.example.invalid/browse/RHEL-12345",
        )
    )

    jira_dir = tmp_path / "benchmark_cases" / "jiras" / "RHEL-12345"
    issue = json.loads((jira_dir / "issue.json").read_text(encoding="utf-8"))
    comments = json.loads((jira_dir / "comments.json").read_text(encoding="utf-8"))
    links = json.loads((jira_dir / "links.json").read_text(encoding="utf-8"))
    assert issue["key"] == "RHEL-12345"
    assert comments["comments"][0]["body"] == "Please backport this fix."
    assert links["links"][0]["object"]["url"] == (
        "https://gitlab.example/group/pkg/-/merge_requests/7"
    )
    assert result.fetched_urls == seen_urls == list(responses)



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


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
