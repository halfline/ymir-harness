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
