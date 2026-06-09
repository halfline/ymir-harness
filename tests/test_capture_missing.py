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
