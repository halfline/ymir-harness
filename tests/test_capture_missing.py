from __future__ import annotations

import io
import json
import os
import subprocess
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


def test_default_allowed_hosts_include_metacpan_subdomains() -> None:
    assert capture_missing_module._allowed_url(
        "https://fastapi.metacpan.org/v1/release/HTTP-Daemon",
        capture_missing_module.DEFAULT_ALLOWED_HOSTS,
    )
    assert capture_missing_module._allowed_url(
        "https://cpan.metacpan.org/authors/id/O/OA/OALDERS/HTTP-Daemon-6.12.tar.gz",
        capture_missing_module.DEFAULT_ALLOWED_HOSTS,
    )
    assert capture_missing_module._allowed_url(
        "https://pkgs.devel.redhat.com/repo/rpms/redis/archive.tar.gz",
        capture_missing_module.DEFAULT_ALLOWED_HOSTS,
    )
    assert capture_missing_module._allowed_url(
        "https://sources.stream.centos.org/sources/rpms/redis/archive.tar.gz",
        capture_missing_module.DEFAULT_ALLOWED_HOSTS,
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


def test_capture_missing_records_missing_lookaside_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_dir = tmp_path / "run"
    archive_body = b"source archive\n"
    archive_hash = capture_missing_module.hashlib.sha512(archive_body).hexdigest()
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_dir / "repeat-1" / "actual-results" / "RHEL-12345.actual.json",
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "package": "redis",
                "target_branch": "rhel-9.6.0",
                "backport_error": (
                    "rpmbuild -bp failed: redis-6.2.22.tar.gz not found in lookaside cache"
                ),
            }
        ),
    )
    _write_text(
        run_dir / "RHEL-12345" / "redis" / "sources",
        f"SHA512 (redis-6.2.22.tar.gz) = {archive_hash}\n",
    )
    expected_url = (
        "https://lookaside.example/sources/rpms/redis/redis-6.2.22.tar.gz/"
        f"sha512/{archive_hash}/redis-6.2.22.tar.gz"
    )
    seen_urls: list[str] = []

    def fake_urlopen(request, timeout: float):
        assert request.full_url == expected_url
        assert timeout == 30.0
        seen_urls.append(request.full_url)
        return _Response(archive_body, "application/gzip")

    monkeypatch.setattr(
        capture_missing_module,
        "_lookaside_base_url",
        lambda _branch: "https://lookaside.example/sources",
    )
    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_dir,
            case_id="RHEL-12345",
            allowed_hosts=("lookaside.example",),
        )
    )

    cached_archive = cases_dir / "source_cache" / "RHEL-12345" / "lookaside" / "redis-6.2.22.tar.gz"
    assert cached_archive.read_bytes() == archive_body
    assert seen_urls == [expected_url]
    assert [(capture.kind, capture.url) for capture in result.captured_source] == [
        ("lookaside", expected_url)
    ]


def test_capture_missing_mirrors_replay_miss_project_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, pre_fix_ref = _create_git_repo(tmp_path)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{source_repo.resolve().as_uri()}"]',
                "\tinsteadOf = https://github.com/opencontainers/runc.git",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))
    run_file = tmp_path / "run.json"
    url = "https://github.com/opencontainers/runc"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        f'{{"reason": "external subprocess URL blocked: {url}"}}\n',
    )

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            overwrite=True,
        )
    )

    assert [capture.kind for capture in result.captured_source] == ["source_fixture"]
    manifest_path = cases_dir / result.captured_source[0].relative_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checkout = manifest_path.with_suffix("")
    subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e", f"{pre_fix_ref}^{{commit}}"],
        check=True,
    )
    assert manifest["remote_url"] == f"{url}.git"


def test_capture_missing_mirrors_source_refs_as_of(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, branch, pre_fix_ref, future_ref = _create_dated_git_repo(tmp_path)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{source_repo.resolve().as_uri()}"]',
                "\tinsteadOf = https://github.com/opencontainers/runc.git",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))
    run_file = tmp_path / "run.json"
    url = "https://github.com/opencontainers/runc"
    as_of = "2025-09-12T09:46:42Z"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(run_file, f'{{"reason": "external subprocess URL blocked: {url}"}}\n')

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            as_of=as_of,
            overwrite=True,
        )
    )

    assert result.failed == []
    manifest_path = cases_dir / result.captured_source[0].relative_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["replay_as_of"] == as_of
    assert manifest["head_object"] == pre_fix_ref
    assert {ref["name"]: ref["object"] for ref in manifest["refs"]} == {
        f"refs/heads/{branch}": pre_fix_ref
    }
    checkout = manifest_path.with_suffix("")
    subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e", f"{future_ref}^{{commit}}"],
        check=True,
    )


def test_capture_missing_mirrors_source_from_suite_worktree_path(
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
                "\tinsteadOf = https://github.com/go-delve/delve.git",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))
    run_file = tmp_path / "run.json"
    url = "https://github.com/go-delve/delve.git"
    _write_expected(cases_dir, "RHEL-12345")
    web_manifest = cases_dir / "web_cache" / "RHEL-12345" / "manifest.json"
    _write_text(
        web_manifest,
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "case_type": "not_affected",
                "git_failures": {
                    "https://github.com/go-delve/delve": {
                        "returncode": 128,
                        "stderr": "old failure\n",
                        "stdout": "",
                    },
                    "https://github.com/go-delve/delve.git": {
                        "returncode": 128,
                        "stderr": "old failure\n",
                        "stdout": "",
                    },
                },
                "recorded_files": {},
                "required_urls": [],
                "schema_version": 1,
            }
        ),
    )
    _write_text(run_file, f'{{"reason": "external subprocess URL blocked: {url}"}}\n')

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            overwrite=True,
        )
    )

    assert result.captured_git_failures == []
    assert [capture.url for capture in result.captured_source] == [
        "https://github.com/go-delve/delve"
    ]
    manifest_path = cases_dir / result.captured_source[0].relative_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checkout = manifest_path.with_suffix("")
    subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e", f"{pre_fix_ref}^{{commit}}"],
        check=True,
    )
    assert manifest["remote_url"] == url
    assert (cases_root / ".gitmodules").is_file()
    updated_web_manifest = json.loads(web_manifest.read_text(encoding="utf-8"))
    assert "git_failures" not in updated_web_manifest


def test_capture_missing_records_tool_http_404_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    url = "https://github.com/example/project/commit/fix.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        f"ToolError('Failed to fetch patch from {url}: HTTP 404')\n",
    )

    def fake_urlopen(_request, timeout: float):
        assert timeout == 30.0
        raise HTTPError(
            url,
            404,
            "Not Found",
            {"Content-Type": "text/plain"},
            io.BytesIO(b"not found\n"),
        )

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
        )
    )

    assert result.candidate_urls == [url]
    assert result.captured[0].status == 404
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["response_metadata"][url]["status"] == 404


def test_capture_missing_records_tool_replay_miss_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    url = "https://github.com/example/project/commit/fix.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        f"ToolError('Failed to fetch patch from {url}: URL is not recorded in replay cache')\n",
    )

    def fake_urlopen(_request, timeout: float):
        assert timeout == 30.0
        return _Response(b"diff --git a/source.c b/source.c\n", "text/x-patch")

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
        )
    )

    assert result.candidate_urls == [url]
    assert result.captured[0].url == url


def test_capture_missing_keeps_existing_recording_on_http_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    url = "https://gitlab.example/group/pkg/-/commit/abc123.patch"
    web_cache = cases_dir / "web_cache" / "RHEL-12345"
    patch_path = web_cache / "jira" / "patches" / "001.patch"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        f"ToolError('Failed to fetch patch from {url}: HTTP 404')\n",
    )
    patch_path.parent.mkdir(parents=True)
    patch_path.write_text("diff --git a/source.c b/source.c\n", encoding="utf-8")
    (web_cache / "manifest.json").write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "required_urls": [url],
                "recorded_files": {url: "jira/patches/001.patch"},
                "response_metadata": {url: {"status": 200}},
            }
        ),
        encoding="utf-8",
    )

    def fake_urlopen(_request, timeout: float):
        assert timeout == 30.0
        raise HTTPError(
            url,
            403,
            "Forbidden",
            {"Content-Type": "text/html"},
            io.BytesIO(b"<html>forbidden</html>\n"),
        )

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
            overwrite=True,
        )
    )

    manifest = json.loads((web_cache / "manifest.json").read_text(encoding="utf-8"))
    assert result.captured == []
    assert result.skipped[0].reason == "URL is already recorded with successful content"
    assert manifest["recorded_files"][url] == "jira/patches/001.patch"
    assert patch_path.read_text(encoding="utf-8") == "diff --git a/source.c b/source.c\n"


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


def test_capture_missing_canonicalizes_escaped_newline_context_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    source_repo, _pre_fix_ref = _create_git_repo(tmp_path)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{source_repo.resolve().as_uri()}"]',
                "\tinsteadOf = https://github.com/redis/redis.git",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))
    run_file = tmp_path / "run.json"
    clean_url = "https://github.com/redis/redis.git"
    escaped_url = clean_url + r"\\nContext"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(run_file, f'{{"reason": "external subprocess URL blocked: {escaped_url}"}}\n')

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
        )
    )

    assert result.candidate_urls == [clean_url]
    assert [capture.url for capture in result.captured_source] == ["https://github.com/redis/redis"]
    manifest_path = cases_dir / result.captured_source[0].relative_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["remote_url"] == clean_url
    assert result.captured_git_failures == []


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


def test_capture_missing_records_transport_error_for_replay(
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
        raise OSError("Remote end closed connection without response")

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
    assert result.failed == []
    assert result.captured[0].status == 599
    assert manifest["response_metadata"][url]["status"] == 599
    assert (
        manifest["response_metadata"][url]["capture_error"]
        == "OSError: Remote end closed connection without response"
    )

    with enforce_benchmark_boundaries(_environment(manifest_path)):
        with pytest.raises(HTTPError) as exc_info:
            urllib.request.urlopen(url)

    assert exc_info.value.code == 599
    assert b"Remote end closed connection" in exc_info.value.read()


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
        if (
            request.full_url
            == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-4139?expand=changelog"
        ):
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
                                                "authorTimestamp": "2025-09-02T00:00:00.000+0000",
                                                "url": (
                                                    "https://gitlab.example/group/glib"
                                                    "/-/commit/abc123"
                                                ),
                                            },
                                            {
                                                "authorTimestamp": "2025-10-02T00:00:00.000+0000",
                                                "url": (
                                                    "https://gitlab.example/group/glib"
                                                    "/-/commit/future"
                                                ),
                                            },
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
        {
            "authorTimestamp": "2025-09-02T00:00:00.000+0000",
            "url": "https://gitlab.example/group/glib/-/commit/abc123",
        }
    ]


def test_capture_missing_filters_jira_search_empty_predicates_as_of(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    search_url = "https://redhat.atlassian.net/rest/api/3/search/jql"
    payload = {
        "jql": 'component = "redis" AND "Fixed in Build" is not EMPTY',
        "fields": ["fixVersions"],
        "maxResults": 50,
    }
    _write_expected(cases_dir, "RHEL-178383")
    _write_text(run_file, jira_search_replay_miss(search_url, payload) + "\n")

    def fake_urlopen(request, timeout: float):
        assert timeout == 30.0
        if request.full_url == (
            "https://redhat.atlassian.net/rest/api/2/issue/RHEL-178386?expand=changelog"
        ):
            return _Response(
                json.dumps(
                    {
                        "id": "10001",
                        "key": "RHEL-178386",
                        "fields": {
                            "created": "2026-05-21T13:48:33.995+0000",
                            "customfield_10578": "redis-6.2.7-1.el9_6.4",
                            "status": {"name": "Integration"},
                        },
                        "changelog": {
                            "histories": [
                                {
                                    "created": "2026-06-18T15:31:36.246+0000",
                                    "items": [
                                        {
                                            "field": "Fixed in Build",
                                            "fieldId": "customfield_10578",
                                            "fromString": None,
                                            "toString": "redis-6.2.7-1.el9_6.4",
                                        }
                                    ],
                                }
                            ]
                        },
                    }
                ).encode("utf-8"),
                "application/json",
            )
        if request.full_url == search_url:
            assert request.get_method() == "POST"
            assert json.loads(request.data.decode("utf-8")) == payload
            return _Response(
                json.dumps(
                    {
                        "issues": [
                            {
                                "key": "RHEL-178386",
                                "id": "10001",
                                "fields": {"fixVersions": [{"name": "rhel-9.6.z"}]},
                            }
                        ]
                    }
                ).encode("utf-8"),
                "application/json",
            )
        raise AssertionError(request.full_url)

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-178383",
            as_of="2026-05-31T07:18:08.888999Z",
        )
    )

    assert result.failed == []
    assert [capture.kind for capture in result.captured_jira] == ["jira_search"]
    fixture = json.loads(
        jira_search_fixture_path(cases_dir, "RHEL-178383", payload).read_text(encoding="utf-8")
    )
    assert fixture["response"]["issues"] == []
    assert not (cases_dir / "jiras" / "RHEL-178383" / "linked" / "RHEL-178386").exists()


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
        if (
            request.full_url
            == "https://redhat.atlassian.net/rest/api/2/issue/RHEL-23456?expand=changelog"
        ):
            return _Response(
                json.dumps(
                    {
                        "key": "RHEL-23456",
                        "changelog": {
                            "histories": [
                                {
                                    "created": "2025-09-20T00:00:00.000+0000",
                                    "items": [
                                        {
                                            "field": "status",
                                            "fromString": "New",
                                            "toString": "Closed",
                                        }
                                    ],
                                }
                            ]
                        },
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


def test_capture_missing_records_git_source_failure_for_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    run_file = tmp_path / "run.log"
    url = "https://gitlab.example/group/project.git"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        f"BenchmarkBoundaryViolation: external subprocess URL blocked: {url}\n",
    )

    def fake_run(command, check, stdout, stderr, text, cwd=None):
        if command[:4] == ["git", "-C", str(cases_dir), "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, stdout="true\n", stderr="")
        assert command[:4] == ["git", "clone", "--mirror", "--quiet"]
        assert command[4] == url
        assert cwd == Path(command[5]).parent
        assert check is False
        assert stdout == subprocess.PIPE
        assert stderr == subprocess.PIPE
        assert text is True
        return subprocess.CompletedProcess(
            command,
            128,
            stdout="",
            stderr="fatal: unable to access repository\n",
        )

    monkeypatch.setattr(capture_missing_module.subprocess, "run", fake_run)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("gitlab.example",),
        )
    )

    assert result.failed == []
    assert [capture.url for capture in result.captured_git_failures] == [url]
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    failure = manifest["git_failures"][url]
    assert failure["returncode"] == 128
    assert "fatal: unable to access repository" in failure["stderr"]
    assert "https://gitlab.example/group/project" in manifest["git_failures"]


def test_capture_missing_records_git_ls_remote_subprocess_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    url = "https://github.com/group/project"
    command = f"GIT_TERMINAL_PROMPT=0 git ls-remote {url} 2>&1 | head -5"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        "\n".join(
            [
                json.dumps({"input": {"command": command}}),
                f"BenchmarkBoundaryViolation: external subprocess URL blocked: {url}",
                "",
            ]
        ),
    )

    def fake_run(command_args, **kwargs):
        assert command_args == ["git", "ls-remote", url]
        assert kwargs["check"] is False
        assert kwargs["stdout"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.PIPE
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 30.0
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        return subprocess.CompletedProcess(
            command_args,
            0,
            stdout="abc123\tHEAD\nbranch\trefs/heads/main\n",
            stderr="",
        )

    monkeypatch.setattr(capture_missing_module.subprocess, "run", fake_run)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("github.com",),
        )
    )

    assert result.failed == []
    assert [capture.command for capture in result.captured_subprocesses] == [command]
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    replay = manifest["subprocess_replays"][command]
    assert replay == {
        "returncode": 0,
        "stderr": "",
        "stdout": "abc123\tHEAD\nbranch\trefs/heads/main\n",
    }
    assert "git_failures" not in manifest
    assert not (cases_dir / "source_cache" / "RHEL-12345").exists()


def test_capture_missing_records_git_ls_remote_subprocess_replay_as_of(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    source_repo, branch, pre_fix_ref, _future_ref = _create_dated_git_repo(tmp_path)
    gitconfig_path = tmp_path / "gitconfig"
    gitconfig_path.write_text(
        "\n".join(
            [
                f'[url "{source_repo.resolve().as_uri()}"]',
                "\tinsteadOf = https://github.com/group/project",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig_path))
    run_file = tmp_path / "run.log"
    url = "https://github.com/group/project"
    command = f"GIT_TERMINAL_PROMPT=0 git ls-remote {url} 2>&1 | head -5"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        "\n".join(
            [
                json.dumps({"input": {"command": command}}),
                f"BenchmarkBoundaryViolation: external subprocess URL blocked: {url}",
                "",
            ]
        ),
    )

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("github.com",),
            as_of="2025-09-12T09:46:42Z",
        )
    )

    assert result.failed == []
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["subprocess_replays"][command] == {
        "returncode": 0,
        "stderr": "",
        "stdout": f"{pre_fix_ref}\tHEAD\n{pre_fix_ref}\trefs/heads/{branch}\n",
    }
    assert not (cases_dir / "source_cache" / "RHEL-12345").exists()


def test_capture_missing_records_git_failure_when_clone_follows_ls_remote(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    subprocess.run(["git", "init", str(cases_dir)], check=True, stdout=subprocess.DEVNULL)
    run_file = tmp_path / "run.log"
    url = "https://github.com/group/project"
    ls_remote = f"git ls-remote {url} 2>&1 | head -5"
    clone = f"git clone --no-local {url} /tmp/project 2>&1 | tail -5"
    _write_expected(cases_dir, "RHEL-12345")
    _write_text(
        run_file,
        "\n".join(
            [
                json.dumps({"input": {"command": ls_remote}}),
                json.dumps({"input": {"command": clone}}),
                f"BenchmarkBoundaryViolation: external subprocess URL blocked: {url}",
                "",
            ]
        ),
    )

    def fake_run(command_args, **kwargs):
        if command_args[:4] == ["git", "-C", str(cases_dir), "rev-parse"]:
            return subprocess.CompletedProcess(command_args, 0, stdout="true\n", stderr="")
        if command_args == ["git", "ls-remote", url]:
            return subprocess.CompletedProcess(
                command_args,
                128,
                stdout="",
                stderr="remote: Repository not found.\n",
            )
        assert command_args[:4] == ["git", "clone", "--mirror", "--quiet"]
        assert command_args[4] == f"{url}.git"
        return subprocess.CompletedProcess(
            command_args,
            128,
            stdout="",
            stderr="fatal: repository not found\n",
        )

    monkeypatch.setattr(capture_missing_module.subprocess, "run", fake_run)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
            allowed_hosts=("github.com",),
        )
    )

    assert result.failed == []
    assert [capture.command for capture in result.captured_subprocesses] == [ls_remote]
    assert [capture.url for capture in result.captured_git_failures] == [url]
    manifest = json.loads(
        (cases_dir / "web_cache" / "RHEL-12345" / "manifest.json").read_text(encoding="utf-8")
    )
    assert ls_remote in manifest["subprocess_replays"]
    assert url in manifest["git_failures"]
    assert f"{url}.git" in manifest["git_failures"]


def test_capture_missing_preserves_existing_subprocess_replay_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases_dir = tmp_path / "benchmark_cases"
    run_file = tmp_path / "run.log"
    command = "GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/group/project 2>&1 | head -5"
    url = "https://github.com/example/project/commit/fix.patch"
    _write_expected(cases_dir, "RHEL-12345")
    web_cache = cases_dir / "web_cache" / "RHEL-12345"
    web_cache.mkdir(parents=True)
    (web_cache / "manifest.json").write_text(
        json.dumps(
            {
                "case_id": "RHEL-12345",
                "required_urls": [],
                "recorded_files": {},
                "subprocess_replays": {
                    command: {
                        "returncode": 0,
                        "stdout": "abc123\tHEAD\n",
                        "stderr": "",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    _write_text(
        run_file,
        f"ToolError('Failed to fetch patch from {url}: URL is not recorded in replay cache')\n",
    )

    def fake_urlopen(_request, timeout: float):
        assert timeout == 30.0
        return _Response(b"diff --git a/source.c b/source.c\n", "text/x-patch")

    monkeypatch.setattr(capture_missing_module, "urlopen", fake_urlopen)

    result = capture_missing(
        CaptureMissingRequest(
            cases_dir=cases_dir,
            run_path=run_file,
            case_id="RHEL-12345",
        )
    )

    assert result.failed == []
    manifest = json.loads((web_cache / "manifest.json").read_text(encoding="utf-8"))
    assert list(manifest["subprocess_replays"]) == [command]


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
    return repo_path, pre_fix_ref


def _create_dated_git_repo(tmp_path: Path) -> tuple[Path, str, str, str]:
    repo_path = tmp_path / "dated-source-repo"
    repo_path.mkdir()
    subprocess.run(["git", "-C", str(repo_path), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo_path), "config", "user.email", "dev@example.com"], check=True
    )
    subprocess.run(["git", "-C", str(repo_path), "config", "user.name", "Dev"], check=True)
    branch = subprocess.check_output(
        ["git", "-C", str(repo_path), "symbolic-ref", "--short", "HEAD"],
        text=True,
    ).strip()
    _commit_with_date(repo_path, "pre-fix\n", "initial", "2025-09-01T00:00:00+0000")
    pre_fix_ref = subprocess.check_output(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    _commit_with_date(repo_path, "future\n", "future", "2025-09-20T00:00:00+0000")
    future_ref = subprocess.check_output(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    return repo_path, branch, pre_fix_ref, future_ref


def _commit_with_date(repo_path: Path, text: str, message: str, date: str) -> None:
    (repo_path / "source.c").write_text(text, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_path), "add", "source.c"], check=True)
    subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-q", "-m", message],
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": date,
        },
    )


def _environment(manifest_path: Path) -> dict[str, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {
        "YMIR_BENCHMARK_NETWORK_MODE": "replay_only",
        "YMIR_BENCHMARK_REPLAY_MANIFEST": str(manifest_path),
        "YMIR_BENCHMARK_RECORDED_URLS": json.dumps(list(manifest["recorded_files"])),
    }
