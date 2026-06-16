from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from ymir_harness.jira_replay import (
    JiraReplayMiss,
    derive_as_of,
    filter_comments_as_of,
    parse_jira_replay_misses,
    write_jira_dev_status_fixture,
)
from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.replay import canonicalize_replay_url
from ymir_harness.scoring import load_json_file


DEFAULT_ALLOWED_HOSTS = (
    "gitlab.com",
    "gitlab.gnome.org",
    "github.com",
    "issues.redhat.com",
    "redhat.atlassian.net",
    "src.fedoraproject.org",
)
MISSING_URL_PATTERNS = (
    (
        "replay miss",
        re.compile(
            r"replay miss:\s*"
            r"(?:URL is not (?:recorded|available) in replay cache:\s*)?"
            r"(https?://[^\s\"'<>]+)"
        ),
    ),
    (
        "unrecorded replay URL blocked",
        re.compile(r"unrecorded replay URL blocked:\s*(https?://[^\s\"'<>]+)"),
    ),
    (
        "external subprocess URL blocked",
        re.compile(r"external subprocess URL blocked:\s*(https?://[^\s\"'<>]+)"),
    ),
    (
        "external network access blocked",
        re.compile(r"external network access blocked:\s*(https?://[^\s\"'<>]+)"),
    ),
    (
        "tool HTTP 404",
        re.compile(r"Failed to fetch patch from\s+(https?://[^\s\"'<>]+):\s*HTTP 404"),
    ),
    ("unrecorded URL", re.compile(r"unrecorded URL:\s*(https?://[^\s\"'<>]+)")),
)
TEXT_SUFFIXES = {".json", ".log", ".md", ".out", ".txt"}


class CaptureMissingError(RuntimeError):
    """Raised when missing replay evidence cannot be captured."""


@dataclass(frozen=True)
class BlockedUrl:
    reason: str
    url: str

    def to_replay_violation(self) -> str:
        return f"{self.reason}: {self.url}"


@dataclass(frozen=True)
class CaptureMissingRequest:
    cases_dir: Path
    run_path: Path
    case_id: str
    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS
    gitlab_token_env: str = "GITLAB_TOKEN"
    jira_token_env: str = "JIRA_TOKEN"
    jira_token_file: Path | None = None
    jira_email: str | None = None
    as_of: str | None = None
    http_timeout: float = 30.0
    dry_run: bool = False
    overwrite: bool = False


@dataclass(frozen=True)
class CapturedResponse:
    url: str
    relative_path: str
    status: int

    def to_json(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "relative_path": self.relative_path,
            "status": self.status,
        }


@dataclass(frozen=True)
class CapturedJiraRequest:
    kind: str
    method: str
    url: str
    relative_path: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "method": self.method,
            "url": self.url,
            "relative_path": self.relative_path,
        }


@dataclass(frozen=True)
class CaptureFailure:
    url: str
    reason: str

    def to_json(self) -> dict[str, str]:
        return {"url": self.url, "reason": self.reason}


@dataclass
class CaptureMissingResult:
    case_id: str
    cases_dir: Path
    run_path: Path
    candidate_urls: list[str] = field(default_factory=list)
    candidate_jira_requests: list[dict[str, Any]] = field(default_factory=list)
    captured: list[CapturedResponse] = field(default_factory=list)
    captured_jira: list[CapturedJiraRequest] = field(default_factory=list)
    skipped: list[CaptureFailure] = field(default_factory=list)
    failed: list[CaptureFailure] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "cases_dir": str(self.cases_dir),
            "run_path": str(self.run_path),
            "candidate_urls": self.candidate_urls,
            "candidate_jira_requests": self.candidate_jira_requests,
            "captured": [capture.to_json() for capture in self.captured],
            "captured_jira": [capture.to_json() for capture in self.captured_jira],
            "skipped": [skip.to_json() for skip in self.skipped],
            "failed": [failure.to_json() for failure in self.failed],
        }


@dataclass(frozen=True)
class _FetchedResponse:
    body: bytes
    status: int
    headers: Mapping[str, str]
    capture_error: str | None = None


def capture_missing(request: CaptureMissingRequest) -> CaptureMissingResult:
    cases_dir = request.cases_dir.resolve()
    run_path = request.run_path.resolve()
    result = CaptureMissingResult(
        case_id=request.case_id,
        cases_dir=cases_dir,
        run_path=run_path,
    )
    blocked_urls = blocked_urls_from_run_path(run_path)
    urls = list(dict.fromkeys(blocked.url for blocked in blocked_urls))
    url_reasons = _blocked_url_reasons(blocked_urls)
    result.candidate_urls.extend(urls)
    jira_requests = _blocked_jira_requests_from_run_path(run_path)
    result.candidate_jira_requests.extend(miss.to_json() for miss in jira_requests)

    manifest_path = cases_dir / "web_cache" / request.case_id / "manifest.json"
    manifest = _load_or_create_manifest(cases_dir, request.case_id, manifest_path)
    required_urls = _manifest_list(manifest.get("required_urls"))
    recorded_files = _manifest_mapping(manifest.get("recorded_files"))
    response_metadata = _manifest_mapping(manifest.get("response_metadata"))

    for url in urls:
        if not _allowed_url(url, request.allowed_hosts):
            result.skipped.append(CaptureFailure(url=url, reason="host is not allowed"))
            continue
        if url in recorded_files and not request.overwrite:
            result.skipped.append(CaptureFailure(url=url, reason="URL is already recorded"))
            continue
        if request.dry_run:
            continue

        try:
            fetched = _fetch_url(url, request, record_errors=True)
        except OSError as exc:
            result.failed.append(CaptureFailure(url=url, reason=str(exc)))
            continue
        if url in recorded_files and fetched.status >= 400:
            result.skipped.append(
                CaptureFailure(url=url, reason="URL is already recorded with successful content")
            )
            continue

        relative_path = _relative_capture_path(url)
        destination = manifest_path.parent / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(fetched.body)

        recorded_files[url] = relative_path
        response_metadata[url] = _response_metadata(fetched)
        if url not in required_urls:
            required_urls.append(url)
        result.captured.append(
            CapturedResponse(url=url, relative_path=relative_path, status=fetched.status)
        )

    as_of = request.as_of or derive_as_of(cases_dir, request.case_id)
    for miss in jira_requests:
        if miss.kind == "jira_issue":
            if miss.method != "GET":
                result.skipped.append(
                    CaptureFailure(url=miss.url, reason=f"unsupported Jira method {miss.method}")
                )
                continue
            if not _allowed_url(miss.url, request.allowed_hosts):
                result.skipped.append(CaptureFailure(url=miss.url, reason="host is not allowed"))
                continue
            issue_key = _jira_issue_key_from_miss(miss)
            if issue_key is None:
                result.skipped.append(CaptureFailure(url=miss.url, reason="Jira issue key missing"))
                continue
            jira_dir = _jira_fixture_dir(cases_dir, request.case_id, issue_key)
            if (jira_dir / "issue.json").is_file() and not request.overwrite:
                result.skipped.append(
                    CaptureFailure(url=miss.url, reason="Jira issue is already recorded")
                )
                continue
            if request.dry_run:
                continue
            captured_dir = _capture_jira_issue_fixture(
                miss.url,
                issue_key,
                cases_dir,
                request.case_id,
                as_of,
                request,
                result,
            )
            if captured_dir is not None:
                result.captured_jira.append(
                    CapturedJiraRequest(
                        kind=miss.kind,
                        method=miss.method,
                        url=miss.url,
                        relative_path=str(
                            (captured_dir / "issue.json").relative_to(
                                cases_dir / "jiras" / request.case_id
                            )
                        ),
                    )
                )
            continue

        result.skipped.append(
            CaptureFailure(url=miss.url, reason=f"unsupported Jira miss {miss.kind}")
        )
        continue

    manifest_changed = bool(result.captured)
    if not request.dry_run and manifest_changed:
        manifest["required_urls"] = required_urls
        manifest["recorded_files"] = recorded_files
        manifest["response_metadata"] = response_metadata
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return result


def _blocked_urls_from_run_path(run_path: Path) -> list[str]:
    return list(dict.fromkeys(blocked.url for blocked in blocked_urls_from_run_path(run_path)))


def _blocked_url_reasons(blocked_urls: Sequence[BlockedUrl]) -> dict[str, tuple[str, ...]]:
    reasons: dict[str, list[str]] = {}
    for blocked in blocked_urls:
        reasons.setdefault(blocked.url, []).append(blocked.reason)
    return {url: tuple(dict.fromkeys(url_reasons)) for url, url_reasons in reasons.items()}


def _blocked_jira_requests_from_run_path(run_path: Path) -> list[JiraReplayMiss]:
    return list(
        {
            json.dumps(miss.to_json(), sort_keys=True): miss
            for miss in jira_requests_from_run_path(run_path)
        }.values()
    )


def jira_requests_from_run_path(run_path: Path) -> list[JiraReplayMiss]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(path for path in run_path.rglob("*") if _looks_like_text_artifact(path))
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    misses: list[JiraReplayMiss] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        misses.extend(parse_jira_replay_misses(text))
    return misses


def blocked_urls_from_run_path(run_path: Path) -> list[BlockedUrl]:
    if run_path.is_file():
        paths = [run_path]
    elif run_path.is_dir():
        paths = sorted(path for path in run_path.rglob("*") if _looks_like_text_artifact(path))
    else:
        raise CaptureMissingError(f"run path does not exist: {run_path}")

    blocked_urls: list[BlockedUrl] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for reason, pattern in MISSING_URL_PATTERNS:
            for match in pattern.finditer(text):
                url = _clean_url(match.group(1))
                if url:
                    blocked_urls.append(BlockedUrl(reason=reason, url=url))
    return list({blocked.to_replay_violation(): blocked for blocked in blocked_urls}.values())


def _looks_like_text_artifact(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in TEXT_SUFFIXES


def _clean_url(url: str) -> str:
    return canonicalize_replay_url(url)


def _load_or_create_manifest(
    cases_dir: Path,
    case_id: str,
    manifest_path: Path,
) -> dict[str, Any]:
    if manifest_path.is_file():
        return load_json_file(manifest_path)

    expected_path = cases_dir / "expected" / f"{case_id}.expected.json"
    expected = load_json_file(expected_path) if expected_path.is_file() else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "case_type": expected.get("case_type"),
        "required_urls": [],
        "recorded_files": {},
    }


def _manifest_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        canonical for item in value if isinstance(item, str) and (canonical := _clean_url(item))
    ]


def _manifest_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {
        canonical: item
        for key, item in value.items()
        if isinstance(key, str) and (canonical := _clean_url(key))
    }


def _allowed_url(url: str, allowed_hosts: Sequence[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return False
    hostname = parsed.hostname.lower()
    return any(
        hostname == allowed.lower() or hostname.endswith(f".{allowed.lower()}")
        for allowed in allowed_hosts
    )


def _fetch_url(
    url: str,
    request: CaptureMissingRequest,
    *,
    record_errors: bool = False,
) -> _FetchedResponse:
    http_request = Request(url, headers=_headers_for_url(url, request), method="GET")
    try:
        with urlopen(http_request, timeout=request.http_timeout) as response:
            body = response.read()
            status = getattr(response, "status", None) or getattr(response, "code", 200)
            headers = _selected_headers(dict(response.headers.items()))
    except HTTPError as exc:
        body = exc.read()
        status = exc.code
        headers = _selected_headers(dict(exc.headers.items()))
    except OSError as exc:
        if not record_errors:
            raise
        return _transport_error_response(url, exc)
    return _FetchedResponse(body=body, status=int(status), headers=headers)


def _transport_error_response(url: str, exc: OSError) -> _FetchedResponse:
    reason = f"{type(exc).__name__}: {exc}".rstrip(": ")
    body = (f"ymir-harness captured fetch error\nurl: {url}\nerror: {reason}\n").encode("utf-8")
    return _FetchedResponse(
        body=body,
        status=599,
        headers={"Content-Type": "text/plain"},
        capture_error=reason,
    )




def _json_object_from_body(body: bytes, url: str) -> dict[str, Any]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureMissingError(f"failed to decode JSON response from {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise CaptureMissingError(f"JSON response from {url} must be an object")
    return data






def _capture_jira_issue_fixture(
    source_url: str,
    issue_key: str,
    cases_dir: Path,
    case_id: str,
    as_of: str | None,
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
) -> Path | None:
    jira_dir = _jira_fixture_dir(cases_dir, case_id, issue_key)
    if (jira_dir / "issue.json").is_file() and not request.overwrite:
        return None

    issue_url = _jira_issue_url(source_url, issue_key)
    try:
        issue_payload = _json_object_from_body(_fetch_url(issue_url, request).body, issue_url)
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=issue_url, reason=str(exc)))
        return None

    comments_url = f"{issue_url}/comment"
    links_url = f"{issue_url}/remotelink"
    try:
        comments_payload = _json_object_from_body(
            _fetch_url(comments_url, request).body,
            comments_url,
        )
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=comments_url, reason=str(exc)))
        comments_payload = {"comments": []}
    try:
        links_payload = _json_value_from_body(_fetch_url(links_url, request).body, links_url)
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=links_url, reason=str(exc)))
        links_payload = []

    filtered_comments = filter_comments_as_of(comments_payload, as_of=as_of)
    _write_json(jira_dir / "issue.json", issue_payload, overwrite=request.overwrite)
    _write_json(jira_dir / "comments.json", filtered_comments, overwrite=request.overwrite)
    _write_json(
        jira_dir / "links.json",
        {"schema_version": SCHEMA_VERSION, "case_id": issue_key, "links": links_payload},
        overwrite=request.overwrite,
    )
    _write_linked_starting_issue(
        jira_dir,
        issue_key,
        issue_payload,
        filtered_comments,
        as_of,
        overwrite=request.overwrite,
    )
    _capture_dev_status(
        source_url,
        cases_dir,
        case_id,
        issue_key,
        issue_payload,
        as_of,
        request,
        result,
    )
    return jira_dir


def _jira_fixture_dir(cases_dir: Path, case_id: str, issue_key: str) -> Path:
    if issue_key == case_id:
        return cases_dir / "jiras" / case_id
    return cases_dir / "jiras" / case_id / "linked" / issue_key


def _jira_issue_key_from_miss(miss: JiraReplayMiss) -> str | None:
    issue_key = miss.payload.get("issue_key")
    if isinstance(issue_key, str) and issue_key:
        return issue_key
    match = re.search(r"/issue/([A-Z][A-Z0-9]+-\d+)(?:/|$)", miss.url)
    return match.group(1) if match else None


def _write_linked_starting_issue(
    jira_dir: Path,
    issue_key: str,
    issue_payload: Mapping[str, Any],
    comments_payload: Mapping[str, Any],
    as_of: str | None,
    *,
    overwrite: bool,
) -> None:
    from ymir_harness.collect_case import _build_starting_jira_issue

    starting = _build_starting_jira_issue(
        issue_payload,
        comments_payload,
        case_id=issue_key,
        case_type=None,
        as_of=as_of,
    )
    _write_json(jira_dir / "starting-issue.json", starting, overwrite=overwrite)
    if as_of is not None:
        _write_json(
            jira_dir / "reconstruction.json",
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": issue_key,
                "as_of": as_of,
                "method": "captured_from_search_result",
            },
            overwrite=overwrite,
        )


def _capture_dev_status(
    search_url: str,
    cases_dir: Path,
    case_id: str,
    issue_key: str,
    issue_payload: Mapping[str, Any],
    as_of: str | None,
    request: CaptureMissingRequest,
    result: CaptureMissingResult,
) -> None:
    issue_id = issue_payload.get("id")
    if not isinstance(issue_id, str) or not issue_id:
        return
    summary_url = _jira_dev_status_summary_url(search_url, issue_id)
    try:
        summary_payload = _json_object_from_body(_fetch_url(summary_url, request).body, summary_url)
    except (OSError, CaptureMissingError) as exc:
        result.failed.append(CaptureFailure(url=summary_url, reason=str(exc)))
        return

    summary = summary_payload.get("summary")
    if not isinstance(summary, Mapping):
        summary = {}
    details: dict[str, Any] = {}
    repository_summary = summary.get("repository")
    by_instance = (
        repository_summary.get("byInstanceType")
        if isinstance(repository_summary, Mapping)
        else None
    )
    if isinstance(by_instance, Mapping):
        for app_type in by_instance:
            if not isinstance(app_type, str) or not app_type:
                continue
            detail_url = _jira_dev_status_detail_url(
                search_url,
                issue_id,
                application_type=app_type,
                data_type="repository",
            )
            try:
                detail_payload = _json_object_from_body(
                    _fetch_url(detail_url, request).body, detail_url
                )
            except (OSError, CaptureMissingError) as exc:
                result.failed.append(CaptureFailure(url=detail_url, reason=str(exc)))
                continue
            detail = detail_payload.get("detail")
            if isinstance(detail, list):
                details[f"{app_type}:repository"] = detail

    write_jira_dev_status_fixture(
        cases_dir,
        case_id,
        issue_key,
        summary=summary,
        details=details,
        as_of=as_of,
        overwrite=request.overwrite,
    )




def _jira_issue_url(search_url: str, issue_key: str) -> str:
    parsed = urlparse(search_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return f"{origin}/rest/api/2/issue/{quote(issue_key)}"




def _jira_dev_status_summary_url(search_url: str, issue_id: str) -> str:
    parsed = urlparse(search_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return f"{origin}/rest/dev-status/1.0/issue/summary?issueId={quote(issue_id)}"


def _jira_dev_status_detail_url(
    search_url: str,
    issue_id: str,
    *,
    application_type: str,
    data_type: str,
) -> str:
    parsed = urlparse(search_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return (
        f"{origin}/rest/dev-status/1.0/issue/detail?issueId={quote(issue_id)}"
        f"&applicationType={quote(application_type)}&dataType={quote(data_type)}"
    )


def _json_value_from_body(body: bytes, url: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureMissingError(f"failed to decode JSON response from {url}: {exc}") from exc


def _write_json(path: Path, data: object, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _headers_for_url(url: str, request: CaptureMissingRequest) -> dict[str, str]:
    headers = {"Accept": "*/*"}
    hostname = (urlparse(url).hostname or "").lower()
    if "gitlab" in hostname:
        token = os.environ.get(request.gitlab_token_env)
        if token:
            headers["PRIVATE-TOKEN"] = token
    if "jira" in hostname or "atlassian" in hostname:
        token = _jira_token(request)
        if token:
            headers["Authorization"] = _jira_authorization(token, request.jira_email)
            headers["Accept"] = "application/json"
    return headers


def _jira_token(request: CaptureMissingRequest) -> str | None:
    if request.jira_token_file is not None:
        try:
            return request.jira_token_file.expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            return None
    token = os.environ.get(request.jira_token_env)
    return token.strip() if token else None


def _jira_authorization(token: str, email: str | None) -> str:
    lowered = token.lower()
    if lowered.startswith("bearer ") or lowered.startswith("basic "):
        return token
    basic_email = email or os.environ.get("JIRA_EMAIL") or os.environ.get("ATLASSIAN_EMAIL")
    if basic_email:
        raw = f"{basic_email}:{token}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")
    return f"Bearer {token}"


def _selected_headers(headers: Mapping[str, str]) -> dict[str, str]:
    output = {}
    for name, value in headers.items():
        if name.lower() == "content-type":
            output["Content-Type"] = value
    return output


def _response_metadata(fetched: _FetchedResponse) -> dict[str, Any]:
    metadata: dict[str, Any] = {"status": fetched.status}
    if fetched.headers:
        metadata["headers"] = dict(fetched.headers)
    if fetched.capture_error:
        metadata["capture_error"] = fetched.capture_error
    return metadata


def _relative_capture_path(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown-host"
    suffix = _path_suffix(parsed.path)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return f"captured/{host}/{digest}{suffix}"


def _path_suffix(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in {".diff", ".html", ".json", ".md", ".patch", ".txt"}:
        return suffix
    return ".bin"
