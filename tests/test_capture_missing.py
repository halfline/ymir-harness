from __future__ import annotations

import io
import json
import urllib.request
from pathlib import Path
from urllib.error import HTTPError

import pytest

import ymir_harness.capture_missing as capture_missing_module
from ymir_harness.capture_missing import CaptureMissingRequest, capture_missing
from ymir_harness.enforcement import enforce_benchmark_boundaries
from ymir_harness.jira_replay import (
    jira_issue_replay_miss,
    jira_search_fixture_path,
    jira_search_replay_miss,
)


def test_capture_missing_records_allowed_blocked_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_dir = tmp_path / "run"
    url = "https://gitlab.example/group/pkg/-/commit/abc123.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_dir / "repeat-1" / "mcp-gateway" / "RHEL-12345.stderr.log",
        f"BenchmarkBoundaryViolation: unrecorded replay URL blocked: {url}\n",
    )

    def fake_urlopen(request, timeout: float):
        assert request.full_url == url
        assert timeout == 30.0
        return _Response(b"diff --git a/source.c b/source.c\n", "text/x-patch")

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_dir,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
        )
    )

    assert result.candidate_urls == [url]
    assert [capture.url for capture in result.captured] == [url]
    assert result.skipped == []
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    recorded_path = cases_dir / "web_cache" / "RHEL-12345" / manifest["recorded_files"][url]
    assert manifest["required_urls"] == [url]
    assert manifest["response_metadata"][url]["status"] == 200
    assert recorded_path.read_bytes() == b"diff --git a/source.c b/source.c\n"


def test_capture_missing_records_replay_miss_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.json"
    url = "https://gitlab.example/group/pkg/-/commit/abc123.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        f'{{"reason": "replay miss: URL is not recorded in replay cache: {url}"}}\n',
    )

    def fake_urlopen(request, timeout: float):
        assert request.full_url == url
        assert timeout == 30.0
        return _Response(b"diff --git a/source.c b/source.c\n", "text/x-patch")

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
        )
    )

    assert result.candidate_urls == [url]
    assert [capture.url for capture in result.captured] == [url]


def test_capture_missing_canonicalizes_escaped_newline_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.json"
    clean_url = "https://gitlab.example/group/pkg"
    escaped_url = clean_url + r"\\n\\"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(run_file, f'{{"reason": "replay miss: {escaped_url}"}}\n')

    def fake_urlopen(request, timeout: float):
        assert request.full_url == clean_url
        assert timeout == 30.0
        return _Response(b"ok\n", "text/plain")

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
        )
    )

    assert result.candidate_urls == [clean_url]
    assert [capture.url for capture in result.captured] == [clean_url]


def test_capture_missing_skips_disallowed_hosts(tmp_path: Path) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.json"
    url = "https://untrusted.example/fix.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(run_file, f'{{"reason": "unrecorded replay URL blocked: {url}"}}\n')

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
        )
    )

    assert result.candidate_urls == [url]
    assert result.captured == []
    assert result.skipped[0].reason == "host is not allowed"
    assert not (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").exists()


def test_capture_missing_preserves_http_error_status_for_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.json"
    url = "https://gitlab.example/group/pkg/-/commit/missing.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(run_file, f'{{"reason": "unrecorded replay URL blocked: {url}"}}\n')

    def fake_urlopen(_request, timeout: float):
        assert timeout == 30.0
        raise HTTPError(
            url,
            404,
            "Not Found",
            {"Content-Type": "text/html"},
            io.BytesIO(b"missing patch\n"),
        )

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
        )
    )

    manifest_path = cases_dir / "web_cache" / "RHEL-12345" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert result.captured[0].status == 404
    assert manifest["response_metadata"][url]["status"] == 404

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(HTTPError) as exc_info:
            urllib.request.urlopen(url)

    assert exc_info.value.code == 404
    assert exc_info.value.read() == b"missing patch\n"


def test_capture_missing_records_jira_search_with_as_of_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    search_url = "https://redhat.atlassian.net/rest/api/3/search/jql"
    payload = {
        "jql": 'component = "glib2"',
        "fields": ["fixVersions", "created"],
        "maxResults": 50,
    }
    _write_expected(cases_dir, "RHEL-114059")
    _write_text(run_file, jira_search_replay_miss(search_url, payload) + "\n")

    def fake_urlopen(request, timeout: float):
        assert timeout == 30.0
        if request.full_url == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-4139":
            assert request.get_method() == "GET"
            return _Response(
                json.dumps(
                    {
                        "id": "10001",
                        "key": "RHEL-4139",
                        "fields": {
                            "created": "2025-09-01T00:00:00.000+0000",
                            "summary": "Fixed glib issue",
                            "status": {"name": "Closed"},
                        },
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if request.full_url == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-4139/comment":
            return _Response(
                json.dumps(
                    {
                        "comments": [
                            {
                                "body": "Contemporary linked issue comment.",
                                "created": "2025-09-02T00:00:00.000+0000",
                            },
                            {
                                "body": "Future linked issue comment.",
                                "created": "2025-10-02T00:00:00.000+0000",
                            },
                        ]
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if request.full_url == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-4139/remotelink":
            return _Response(b"[]", "application/json")
        if request.full_url == (
            "https://redhat.atlassian.net/rest/dev-status/1.0/issue/summary?issueId=10001"
        ):
            return _Response(
                json.dumps(
                    {
                        "summary": {
                            "repository": {
                                "byInstanceType": {"GitLab": {"count": 1, "name": "GitLab"}}
                            }
                        }
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if request.full_url == (
            "https://redhat.atlassian.net/rest/dev-status/1.0/issue/detail"
            "?issueId=10001&applicationType=GitLab&dataType=repository"
        ):
            return _Response(
                json.dumps(
                    {
                        "detail": [
                            {
                                "repositories": [
                                    {
                                        "url": "https://gitlab.example/group/glib",
                                        "commits": [
                                            {
                                                "url": (
                                                    "https://gitlab.example/group/glib"
                                                    "/-/commit/abc123"
                                                )
                                            }
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if request.full_url == (
            "https://redhat.atlassian.net/rest/api/3/issue/RHEL-999999?fields=created,updated"
        ):
            assert request.get_method() == "GET"
            return _Response(
                json.dumps(
                    {
                        "key": "RHEL-999999",
                        "fields": {"created": "2025-10-01T00:00:00.000+0000"},
                    }
                ).encode("utf-8"),
                "application/json",
            )
        assert request.full_url == search_url
        assert request.get_method() == "POST"
        assert json.loads(request.data.decode("utf-8")) == payload
        return _Response(
            json.dumps(
                {
                    "issues": [
                        {
                            "key": "RHEL-4139",
                            "id": "10001",
                            "fields": {
                                "created": "2025-09-01T00:00:00.000+0000",
                                "fixVersions": [{"name": "rhel-9.8"}],
                            },
                        },
                        {
                            "key": "RHEL-999999",
                            "id": "10002",
                            "fields": {
                                "fixVersions": [{"name": "rhel-9.9"}],
                            },
                        },
                    ]
                }
            ).encode("utf-8"),
            "application/json",
        )

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-114059",
            as_of="2025-09-12T09:46:42Z",
        )
    )

    assert result.candidate_urls == []
    assert [capture.kind for capture in result.captured_jira] == ["jira_search"]
    fixture = json.loads(
        jira_search_fixture_path(cases_dir, "RHEL-114059", payload).read_text(encoding="utf-8")
    )
    assert fixture["reconstruction"]["as_of"] == "2025-09-12T09:46:42Z"
    assert [issue["key"] for issue in fixture["response"]["issues"]] == ["RHEL-4139"]
    linked_dir = cases_dir / "jiras" / "RHEL-114059" / "linked" / "RHEL-4139"
    linked_comments = json.loads((linked_dir / "comments.json").read_text(encoding="utf-8"))
    linked_starting = json.loads((linked_dir / "starting-issue.json").read_text(encoding="utf-8"))
    dev_status = json.loads((linked_dir / "dev-status.json").read_text(encoding="utf-8"))
    assert linked_comments["comments"] == [
        {
            "body": "Contemporary linked issue comment.",
            "created": "2025-09-02T00:00:00.000+0000",
        }
    ]
    assert linked_starting["fields"]["status"] == {"name": "New"}
    assert dev_status["summary"]["repository"]["byInstanceType"]["GitLab"]["count"] == 1
    assert dev_status["details"]["GitLab:repository"][0]["repositories"][0]["commits"] == [
        {"url": "https://gitlab.example/group/glib/-/commit/abc123"}
    ]


def test_capture_missing_records_jira_issue_miss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    issue_url = "https://redhat.atlassian.net/rest/api/3/issue/RHEL-23456"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(run_file, jira_issue_replay_miss(issue_url, "RHEL-23456") + "\n")

    def fake_urlopen(request, timeout: float):
        assert timeout == 30.0
        if request.full_url == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-23456":
            return _Response(
                json.dumps(
                    {
                        "key": "RHEL-23456",
                        "fields": {
                            "summary": "Linked issue",
                            "status": {"name": "Closed"},
                        },
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if request.full_url == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-23456/comment":
            return _Response(
                json.dumps(
                    {
                        "comments": [
                            {
                                "body": "Contemporary linked issue comment.",
                                "created": "2025-09-02T00:00:00.000+0000",
                            },
                            {
                                "body": "Future linked issue comment.",
                                "created": "2025-10-02T00:00:00.000+0000",
                            },
                        ]
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if (
            request.full_url
            == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-23456/remotelink"
        ):
            return _Response(b"[]", "application/json")
        raise AssertionError(request.full_url)

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            as_of="2025-09-12T09:46:42Z",
        )
    )

    assert [capture.kind for capture in result.captured_jira] == ["jira_issue"]
    assert result.captured_jira[0].relative_path == "linked/RHEL-23456/issue.json"
    linked_dir = cases_dir / "jiras" / "RHEL-12345" / "linked" / "RHEL-23456"
    linked_comments = json.loads((linked_dir / "comments.json").read_text(encoding="utf-8"))
    linked_starting = json.loads((linked_dir / "starting-issue.json").read_text(encoding="utf-8"))
    assert linked_comments["comments"] == [
        {
            "body": "Contemporary linked issue comment.",
            "created": "2025-09-02T00:00:00.000+0000",
        }
    ]
    assert linked_starting["fields"]["status"] == {"name": "New"}

class _Response:
    def __init__(self, body: bytes, content_type: str):
        self.status = 200
        self.headers = {"Content-Type": content_type}
        self._body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _write_expected(cases_dir: Path, case_id: str) -> None:
    _write_text(
        cases_dir / "expected" / f"{case_id}.expected.json",
        json.dumps(
            {
                "schema_version": 1,
                "case_id": case_id,
                "case_type": "cve_backport",
                "resolution": "backport",
                "package": "glib2",
            }
        )
        + "\n",
    )


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _environment(manifest_path: Path) -> dict[str, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {
        "YMIR_BENCHMARK_NETWORK_MODE": "replay_only",
        "YMIR_BENCHMARK_REPLAY_MANIFEST": str(manifest_path),
        "YMIR_BENCHMARK_RECORDED_URLS": json.dumps(list(manifest["recorded_files"])),
    }
