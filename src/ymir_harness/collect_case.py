from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

import yaml

from ymir_harness.models import (
    ALLOWED_ANSWER_LEAKAGE,
    ALLOWED_CASE_STATUSES,
    ALLOWED_CASE_TYPES,
    ALLOWED_EXPECTED_BASES,
    ALLOWED_GROUND_TRUTH_CONFIDENCE,
    ALLOWED_NETWORK_MODES,
    ALLOWED_REFERENCE_PATCH_MODES,
    ALLOWED_RESOLUTIONS,
    SCHEMA_VERSION,
)


YMIR_RESULT_LABELS = {
    "ymir_needs_attention",
    "ymir_triaged",
    "ymir_triage_in_progress",
    "ymir_triaged_backport",
    "ymir_triaged_rebase",
    "ymir_triaged_rebuild",
    "ymir_rebased",
    "ymir_backported",
    "ymir_rebuilt",
    "ymir_merged",
    "ymir_rebase_errored",
    "ymir_backport_errored",
    "ymir_rebuild_errored",
    "ymir_triage_errored",
    "ymir_rebase_failed",
    "ymir_backport_failed",
    "ymir_rebuild_failed",
    "ymir_triaged_postponed",
    "ymir_triaged_not_affected",
    "ymir_retry_needed",
}
RESOLUTION_LABELS = {
    "jotnar_backported": "backport",
    "jotnar_rebased": "rebase",
    "jotnar_rebuilt": "rebuild",
    "ymir_triaged_backport": "backport",
    "ymir_triaged_rebase": "rebase",
    "ymir_triaged_rebuild": "rebuild",
    "ymir_triaged_postponed": "postponed",
    "ymir_triaged_not_affected": "not_affected",
    "ymir_needs_attention": "clarification_needed",
}
COMMENT_RESOLUTION_MAP = {
    "backport": "backport",
    "rebase": "rebase",
    "rebuild": "rebuild",
    "postponed": "postponed",
    "not-affected": "not_affected",
    "not_affected": "not_affected",
    "clarification-needed": "clarification_needed",
    "clarification_needed": "clarification_needed",
}
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s<>\]\[\"']+")
RESULT_COMMENT_PATTERNS = (
    "*resolution*",
    "advisory ",
    "agent failed to perform",
    "ai-generated contribution",
    "errata",
    "integration/release pending",
    "output from backport agent",
    "output from rebuild agent",
    "output from rebase agent",
    "output from triage agent",
    "push_ready",
    "rel_prep",
    "released on",
    "resolved in a recent advisory",
    "ymir_triaged",
    "ymir_backported",
    "ymir_rebased",
    "ymir_rebuilt",
)
CLOSED_STATUS_NAMES = {"closed", "done", "resolved", "verified"}


class CollectCaseError(RuntimeError):
    """Raised when a fixture scaffold cannot be collected safely."""


@dataclass(frozen=True)
class WebRecord:
    url: str
    source_path: Path


@dataclass(frozen=True)
class MockRepoInput:
    remote_url: str
    pre_fix_ref: str
    branch: str
    agent: str = "triage"
    source_url: str | None = None
    zstream_override: Mapping[str, str] = field(default_factory=dict)
    blocked_original_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class FetchedRecord:
    url: str
    relative_path: str
    body: bytes


@dataclass(frozen=True)
class FetchedJiraIssue:
    key: str
    issue: Mapping[str, Any]
    comments: Mapping[str, Any]
    links: Any


@dataclass(frozen=True)
class FetchedEvidence:
    jira_issue: Mapping[str, Any] | None = None
    jira_comments: Mapping[str, Any] | None = None
    jira_links: Any = None
    linked_jira_issues: tuple[FetchedJiraIssue, ...] = ()
    jira_patch_urls: tuple[str, ...] = ()
    gitlab_mr: Mapping[str, Any] | None = None
    gitlab_commits: Any = None
    gitlab_mr_url: str | None = None
    gitlab_patch_url: str | None = None
    gitlab_patch_body: bytes | None = None
    web_records: tuple[FetchedRecord, ...] = ()


@dataclass(frozen=True)
class CollectCaseRequest:
    cases_dir: Path
    case_id: str
    case_type: str | None = None
    resolution: str | None = None
    package: str | None = None
    expected_basis: str | None = None
    ground_truth_confidence: str = "medium"
    answer_leakage: str = "none"
    case_status: str = "quarantined"
    case_status_reason: str | None = "fixture scaffold requires ground-truth review"
    network_mode: str | None = None
    target_branch: str | None = None
    fix_version: str | None = None
    cve_ids: tuple[str, ...] = ()
    patch_urls: tuple[str, ...] = ()
    fix_sources: tuple[str, ...] = ()
    notes: str | None = None
    alternate_acceptable_outcomes: tuple[Mapping[str, Any], ...] = ()
    reference_patch_mode: str | None = None
    mock_repo: MockRepoInput | None = None
    mock_agent: str = "triage"
    mock_repo_cache: Path | None = None
    jira_url: str | None = None
    jira_base_url: str | None = None
    jira_token_env: str = "JIRA_TOKEN"
    jira_token_file: Path | None = None
    jira_email: str | None = None
    gitlab_mr_url: str | None = None
    gitlab_token_env: str = "GITLAB_TOKEN"
    http_timeout: float = 30.0
    jira_issue_json: Path | None = None
    jira_comments_json: Path | None = None
    jira_links_json: Path | None = None
    attachments: tuple[Path, ...] = ()
    reference_patch: Path | None = None
    web_records: tuple[WebRecord, ...] = ()
    source_upstream: tuple[Path, ...] = ()
    source_lookaside: tuple[Path, ...] = ()
    overwrite: bool = False


@dataclass
class CollectCaseResult:
    case_id: str
    cases_dir: Path
    written_paths: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fetched_urls: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "cases_dir": str(self.cases_dir),
            "written_paths": [str(path) for path in self.written_paths],
            "warnings": self.warnings,
            "fetched_urls": self.fetched_urls,
        }


def collect_case(request: CollectCaseRequest) -> CollectCaseResult:
    _validate_request(request, require_metadata=False)
    cases_dir = request.cases_dir.resolve()
    result = CollectCaseResult(case_id=request.case_id, cases_dir=cases_dir)
    fetched = _fetch_evidence(request, result)
    request = _complete_request(request, fetched)
    request = _localize_mock_repo_cache(request)
    _validate_request(request, require_metadata=True)
    cases_dir.mkdir(parents=True, exist_ok=True)

    _write_cases_manifest(cases_dir / "cases.yaml", request.case_id, request.overwrite, result)
    _write_expected(cases_dir, request, fetched, result)
    _write_jira_fixtures(cases_dir, request, fetched, result)
    _write_mock_data(cases_dir, request, fetched, result)
    _write_web_cache(cases_dir, request, fetched, result)
    _write_source_cache(cases_dir, request, result)

    _append_completion_warnings(request, fetched, result)
    return result


def parse_key_value_items(items: Sequence[str], *, option_name: str) -> dict[str, str]:
    parsed = {}
    for item in items:
        key, separator, value = item.partition("=")
        if not separator or not key:
            msg = f"{option_name} entries must use KEY=VALUE: {item}"
            raise ValueError(msg)
        parsed[key] = value
    return parsed


def parse_web_record_items(items: Sequence[str]) -> tuple[WebRecord, ...]:
    records = []
    for item in items:
        url, separator, path = item.partition("=")
        if not separator or not url or not path:
            msg = f"--web-record entries must use URL=PATH: {item}"
            raise ValueError(msg)
        records.append(WebRecord(url=url, source_path=Path(path)))
    return tuple(records)


def load_alternate_outcomes(paths: Sequence[Path]) -> tuple[Mapping[str, Any], ...]:
    alternates = []
    for path in paths:
        data = _load_json(path)
        if not isinstance(data, Mapping):
            msg = f"alternate outcome must be a JSON object: {path}"
            raise CollectCaseError(msg)
        alternates.append(data)
    return tuple(alternates)


def _fetch_evidence(
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> FetchedEvidence:
    jira_issue = None
    jira_comments = None
    jira_links = None
    jira_patch_urls: tuple[str, ...] = ()
    gitlab_mr = None
    gitlab_commits = None
    gitlab_records: list[FetchedRecord] = []
    gitlab_patch_url = None
    gitlab_patch_body = None
    linked_jira_issues: list[FetchedJiraIssue] = []

    if request.jira_url or request.jira_base_url:
        jira_urls = _jira_urls(request, request.case_id)
        jira_headers = _jira_headers(
            request.jira_token_env,
            token_file=request.jira_token_file,
            email=request.jira_email,
        )
        jira_issue = _fetch_json(
            jira_urls["issue"], headers=jira_headers, request=request, result=result
        )
        jira_comments = _fetch_json(
            jira_urls["comments"],
            headers=jira_headers,
            request=request,
            result=result,
        )
        jira_links = _fetch_json_value(
            jira_urls["links"],
            headers=jira_headers,
            request=request,
            result=result,
        )
        for linked_key in _linked_jira_keys(jira_issue, request.case_id):
            linked_urls = _jira_urls(request, linked_key)
            try:
                linked_issue = _fetch_json(
                    linked_urls["issue"],
                    headers=jira_headers,
                    request=request,
                    result=result,
                )
                linked_comments = _fetch_json(
                    linked_urls["comments"],
                    headers=jira_headers,
                    request=request,
                    result=result,
                )
                linked_links = _fetch_json_value(
                    linked_urls["links"],
                    headers=jira_headers,
                    request=request,
                    result=result,
                )
            except CollectCaseError as exc:
                result.warnings.append(f"skipped linked Jira {linked_key}: {exc}")
                continue
            linked_jira_issues.append(
                FetchedJiraIssue(
                    key=linked_key,
                    issue=linked_issue,
                    comments=linked_comments,
                    links=linked_links,
                )
            )

    jira_issue_source = _jira_issue_source(request, jira_issue)
    jira_comments_source = _jira_comments_source(request, jira_comments)
    jira_links_source = _jira_links_source(request, jira_links)
    if request.network_mode != "network_denied":
        jira_patch_urls = tuple(
            _patch_urls_from_jira_evidence(
                jira_issue_source,
                jira_comments_source,
                *[
                    value
                    for linked in linked_jira_issues
                    for value in (linked.issue, linked.comments)
                ],
            )
        )

    gitlab_mr_url = request.gitlab_mr_url
    if gitlab_mr_url is None and request.network_mode != "network_denied":
        gitlab_mr_url = _gitlab_mr_url_from_jira_evidence(
            jira_links_source,
            jira_issue_source,
            jira_comments_source,
        )

    if gitlab_mr_url:
        gitlab_urls = _gitlab_mr_urls(gitlab_mr_url)
        gitlab_headers = _gitlab_headers(request.gitlab_token_env)
        for name in ("merge_request", "commits", "changes"):
            url = gitlab_urls[name]
            body = _fetch_bytes(url, headers=gitlab_headers, request=request, result=result)
            if name == "merge_request":
                gitlab_mr = _json_object_from_body(body, url)
            elif name == "commits":
                gitlab_commits = _json_value_from_body(body, url)
            gitlab_records.append(
                FetchedRecord(
                    url=url,
                    relative_path=f"gitlab/{name}.json",
                    body=body,
                )
            )

        gitlab_patch_url = gitlab_urls["patch"]
        gitlab_patch_body = _fetch_bytes(
            gitlab_patch_url,
            headers=gitlab_headers,
            request=request,
            result=result,
        )
        gitlab_records.append(
            FetchedRecord(
                url=gitlab_patch_url,
                relative_path="gitlab/merge_request.patch",
                body=gitlab_patch_body,
            )
        )

    recorded_patch_urls = {gitlab_patch_url} if gitlab_patch_url else set()
    valid_jira_patch_urls: list[str] = []
    for index, patch_url in enumerate(jira_patch_urls, start=1):
        if patch_url in recorded_patch_urls:
            continue
        try:
            patch_body = _fetch_bytes(
                patch_url,
                headers={"Accept": "*/*"},
                request=request,
                result=result,
            )
        except CollectCaseError as exc:
            result.warnings.append(f"skipped Jira patch URL {patch_url}: {exc}")
            continue
        if not _looks_like_patch(patch_body):
            result.warnings.append(
                f"skipped Jira patch URL {patch_url}: fetched content is not a patch"
            )
            continue
        valid_jira_patch_urls.append(patch_url)
        gitlab_records.append(
            FetchedRecord(
                url=patch_url,
                relative_path=(
                    f"jira/patches/{len(valid_jira_patch_urls):03d}{_patch_suffix(patch_url)}"
                ),
                body=patch_body,
            )
        )
    jira_patch_urls = tuple(valid_jira_patch_urls)

    package = request.package or _derive_package(jira_issue_source)
    if (
        package is not None
        and request.network_mode != "network_denied"
        and (request.jira_url or request.jira_base_url or gitlab_mr_url)
    ):
        try:
            gitlab_records.append(_fetch_maintainer_rules_record(package, request, result))
        except CollectCaseError as exc:
            result.warnings.append(f"skipped maintainer rules for {package}: {exc}")

    return FetchedEvidence(
        jira_issue=jira_issue,
        jira_comments=jira_comments,
        jira_links=jira_links,
        linked_jira_issues=tuple(linked_jira_issues),
        jira_patch_urls=jira_patch_urls,
        gitlab_mr=gitlab_mr,
        gitlab_commits=gitlab_commits,
        gitlab_mr_url=gitlab_mr_url,
        gitlab_patch_url=gitlab_patch_url,
        gitlab_patch_body=gitlab_patch_body,
        web_records=tuple(gitlab_records),
    )


def _jira_issue_source(
    request: CollectCaseRequest,
    jira_issue: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    if jira_issue is not None:
        return jira_issue
    if request.jira_issue_json is None:
        return None
    data = _load_json(request.jira_issue_json)
    return data if isinstance(data, Mapping) else None


def _jira_comments_source(request: CollectCaseRequest, jira_comments: Any) -> Any:
    if jira_comments is not None:
        return jira_comments
    if request.jira_comments_json is None:
        return None
    return _load_json(request.jira_comments_json)


def _jira_links_source(request: CollectCaseRequest, jira_links: Any) -> Any:
    if jira_links is not None:
        return jira_links
    if request.jira_links_json is None:
        return None
    return _links_value(_load_json(request.jira_links_json))


def _jira_urls(request: CollectCaseRequest, case_id: str) -> dict[str, str]:
    if request.jira_url and case_id == request.case_id:
        issue_url = _jira_issue_api_url(request.jira_url, case_id)
    elif request.jira_url:
        issue_url = _join_url(_origin(request.jira_url), f"/rest/api/2/issue/{case_id}")
    elif request.jira_base_url:
        issue_url = _join_url(
            request.jira_base_url,
            f"/rest/api/2/issue/{case_id}",
        )
    else:
        raise CollectCaseError("jira URL configuration is missing")

    issue_base = issue_url.split("?", 1)[0].rstrip("/")
    return {
        "issue": issue_url,
        "comments": f"{issue_base}/comment",
        "links": f"{issue_base}/remotelink",
    }


def _linked_jira_keys(
    issue: Mapping[str, Any] | None,
    case_id: str,
) -> list[str]:
    fields = _issue_fields(issue)
    if fields is None:
        return []
    values = fields.get("issuelinks")
    if not isinstance(values, list):
        return []

    keys: list[str] = []
    for link in values:
        if not isinstance(link, Mapping):
            continue
        for name in ("inwardIssue", "outwardIssue"):
            linked = link.get(name)
            if not isinstance(linked, Mapping):
                continue
            key = _nonempty_string(linked.get("key"))
            if key is not None and key != case_id:
                keys.append(key)
    return list(dict.fromkeys(keys))


def _jira_issue_api_url(url: str, case_id: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise CollectCaseError(f"Jira URL must be absolute: {url}")

    if "/rest/api/" in parsed.path and "/issue/" in parsed.path:
        return url
    if "/browse/" in parsed.path:
        return _join_url(_origin(url), f"/rest/api/2/issue/{case_id}")
    return _join_url(_origin(url), f"/rest/api/2/issue/{case_id}")


def _gitlab_mr_urls(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise CollectCaseError(f"GitLab MR URL must be absolute: {url}")

    marker = "/-/merge_requests/"
    if marker not in parsed.path:
        raise CollectCaseError(f"GitLab MR URL must contain {marker}: {url}")

    project_path, iid_part = parsed.path.strip("/").split(marker, 1)
    iid = iid_part.strip("/").split("/", 1)[0].removesuffix(".patch")
    if not iid:
        raise CollectCaseError(f"GitLab MR URL is missing merge request id: {url}")

    project = quote(unquote(project_path), safe="")
    api_base = f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{project}/merge_requests/{iid}"
    normalized_mr_url = f"{parsed.scheme}://{parsed.netloc}/{project_path}/-/merge_requests/{iid}"
    return {
        "merge_request": api_base,
        "commits": f"{api_base}/commits",
        "changes": f"{api_base}/changes",
        "patch": f"{normalized_mr_url}.patch",
    }


def _json_object_from_body(body: bytes, url: str) -> Mapping[str, Any]:
    data = _json_value_from_body(body, url)
    if not isinstance(data, Mapping):
        raise CollectCaseError(f"fetched URL returned non-object JSON: {url}")
    return data


def _json_value_from_body(body: bytes, url: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectCaseError(f"fetched URL did not return JSON: {url}") from exc


def _gitlab_mr_url_from_jira_evidence(*values: Any) -> str | None:
    for value in _string_values(values):
        for candidate in _urls_from_text(value):
            if "/-/merge_requests/" not in candidate:
                continue
            parsed = urlparse(candidate)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                return candidate.removesuffix(".patch")
    return None


def _patch_urls_from_jira_evidence(*values: Any) -> list[str]:
    urls: list[str] = []
    for text in _string_values(values):
        for url in _urls_from_text(text):
            if patch_url := _patch_url_candidate(url):
                urls.append(patch_url)
    return list(dict.fromkeys(urls))


def _urls_from_text(text: str) -> list[str]:
    return [match.group(0).rstrip(".,;:)]}\"'") for match in URL_PATTERN.finditer(text)]


def _is_patch_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".patch", ".diff"))


def _patch_url_candidate(url: str) -> str | None:
    if _is_patch_url(url):
        return url
    path = urlparse(url).path
    if "/-/merge_requests/" in path or "/-/commit/" in path:
        return url.rstrip("/") + ".patch"
    return None


def _patch_suffix(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".diff"):
        return ".diff"
    return ".patch"


def _looks_like_patch(body: bytes) -> bool:
    prefix = body[:4096].decode("utf-8", errors="ignore").lstrip()
    return (
        prefix.startswith("From ") or prefix.startswith("diff --git ") or "\ndiff --git " in prefix
    )


def _string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _string_values(item)
        return
    if isinstance(value, list | tuple):
        for item in value:
            yield from _string_values(item)


def _join_url(base_url: str, path: str) -> str:
    return _origin(base_url) + path


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise CollectCaseError(f"URL must be absolute: {url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _jira_headers(
    token_env: str,
    *,
    token_file: Path | None,
    email: str | None,
) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = _jira_token(token_env, token_file)
    if token:
        headers["Authorization"] = _jira_authorization(token, email)
    return headers


def _jira_token(token_env: str, token_file: Path | None) -> str | None:
    if token_file is not None:
        return token_file.read_text(encoding="utf-8").strip()
    token = os.environ.get(token_env)
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


def _gitlab_headers(token_env: str) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = os.environ.get(token_env)
    if token:
        headers["PRIVATE-TOKEN"] = token
    return headers


def _fetch_json(
    url: str,
    *,
    headers: Mapping[str, str],
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> Mapping[str, Any]:
    body = _fetch_bytes(url, headers=headers, request=request, result=result)
    return _json_object_from_body(body, url)


def _fetch_json_value(
    url: str,
    *,
    headers: Mapping[str, str],
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> Any:
    body = _fetch_bytes(url, headers=headers, request=request, result=result)
    return _json_value_from_body(body, url)


def _fetch_bytes(
    url: str,
    *,
    headers: Mapping[str, str],
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> bytes:
    http_request = Request(url, headers=dict(headers), method="GET")
    try:
        with urlopen(http_request, timeout=request.http_timeout) as response:
            body = response.read()
    except OSError as exc:
        raise CollectCaseError(f"failed to fetch {url}: {exc}") from exc
    result.fetched_urls.append(url)
    return body


def _fetch_maintainer_rules_record(
    package: str,
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> FetchedRecord:
    url = _maintainer_rules_url(package)
    http_request = Request(url, headers=_gitlab_headers(request.gitlab_token_env), method="GET")
    try:
        with urlopen(http_request, timeout=request.http_timeout) as response:
            body = response.read()
    except HTTPError as exc:
        result.fetched_urls.append(url)
        if exc.code != 404:
            raise CollectCaseError(f"failed to fetch {url}: HTTP {exc.code}") from exc
        body = (
            f"No maintainer rules found for package '{package}' "
            "(file 'AGENTS.md' not found in rules repository)."
        ).encode("utf-8")
    except OSError as exc:
        raise CollectCaseError(f"failed to fetch {url}: {exc}") from exc
    else:
        result.fetched_urls.append(url)

    return FetchedRecord(
        url=url,
        relative_path=f"gitlab/maintainer_rules/{package}/AGENTS.md",
        body=body,
    )


def _maintainer_rules_url(package: str) -> str:
    project = quote(f"redhat/centos-stream/rules/{package}", safe="")
    file_path = quote("AGENTS.md", safe="")
    return f"https://gitlab.com/api/v4/projects/{project}/repository/files/{file_path}/raw?ref=main"


def _complete_request(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
) -> CollectCaseRequest:
    issue = _evidence_issue(request, fetched)
    comments = _evidence_comments(request, fetched)
    resolution = request.resolution or _derive_resolution(issue, comments)
    package = request.package or _derive_package(issue)
    fix_version = request.fix_version or _derive_fix_version(issue)
    target_branch = request.target_branch
    mock_repo = request.mock_repo or _derive_mock_repo(
        request,
        fetched,
        target_branch=target_branch,
        fix_version=fix_version,
    )

    return replace(
        request,
        case_type=request.case_type or _derive_case_type(resolution),
        resolution=resolution,
        package=package,
        expected_basis=request.expected_basis
        or ("historical_jira_state" if issue is not None else "manual_review"),
        network_mode=request.network_mode or _derive_network_mode(request, fetched),
        fix_version=fix_version,
        cve_ids=request.cve_ids or tuple(_derive_cve_ids(issue, comments)),
        mock_repo=mock_repo,
    )


def _localize_mock_repo_cache(request: CollectCaseRequest) -> CollectCaseRequest:
    if request.mock_repo_cache is None or request.mock_repo is None:
        return request

    cache_dir = request.mock_repo_cache.expanduser().resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)

    mock_repo = request.mock_repo
    source = mock_repo.source_url or mock_repo.remote_url
    destination = cache_dir / _mock_repo_cache_name(mock_repo.remote_url)
    if destination.exists():
        _run_git(["-C", str(destination), "remote", "update", "--prune"], destination)
    else:
        _run_git(["clone", "--mirror", "--quiet", source, str(destination)], destination)

    _run_git(
        ["-C", str(destination), "cat-file", "-e", f"{mock_repo.pre_fix_ref}^{{commit}}"],
        destination,
    )
    return replace(request, mock_repo=replace(mock_repo, source_url=str(destination)))


def _mock_repo_cache_name(remote_url: str) -> str:
    parsed = urlparse(remote_url)
    source = parsed.path.rstrip("/").rsplit("/", 1)[-1] if parsed.path else "repo"
    source = source.removesuffix(".git")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in source)
    digest = hashlib.sha256(remote_url.encode("utf-8")).hexdigest()[:12]
    return f"{safe or 'repo'}-{digest}.git"


def _run_git(command: Sequence[str], cwd: Path) -> None:
    completed = subprocess.run(
        ["git", *command],
        cwd=cwd if cwd.is_dir() else None,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise CollectCaseError(f"git {' '.join(command)} failed{detail}")


def _evidence_issue(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
) -> Mapping[str, Any] | None:
    if fetched.jira_issue is not None:
        return fetched.jira_issue
    if request.jira_issue_json is None:
        return None
    data = _load_json(request.jira_issue_json)
    return data if isinstance(data, Mapping) else None


def _evidence_comments(request: CollectCaseRequest, fetched: FetchedEvidence) -> Any:
    if fetched.jira_comments is not None:
        return fetched.jira_comments
    if request.jira_comments_json is None:
        return None
    return _load_json(request.jira_comments_json)


def _derive_resolution(issue: Mapping[str, Any] | None, comments: Any) -> str | None:
    for label in _issue_labels(issue):
        resolution = RESOLUTION_LABELS.get(label)
        if resolution is not None:
            return resolution

    for body in _comment_bodies(comments):
        if resolution := _comment_resolution(body):
            return resolution
    return None


def _derive_case_type(resolution: str | None) -> str | None:
    if resolution is None:
        return None
    return {
        "backport": "cve_backport",
        "rebase": "rebase",
        "rebuild": "dependency_rebuild",
        "not_affected": "not_affected",
        "postponed": "postponed",
        "clarification_needed": "clarification_needed",
    }.get(resolution)


def _derive_package(issue: Mapping[str, Any] | None) -> str | None:
    fields = _issue_fields(issue)
    if fields is None:
        return None

    downstream = fields.get("customfield_10669") or fields.get("Downstream Component Name")
    if package := _component_name(downstream):
        return package

    components = fields.get("components")
    if isinstance(components, list):
        for component in components:
            if isinstance(component, Mapping):
                if package := _component_name(component.get("name")):
                    return package
            elif package := _component_name(component):
                return package
    return None


def _derive_fix_version(issue: Mapping[str, Any] | None) -> str | None:
    fields = _issue_fields(issue)
    if fields is None:
        return None

    fix_versions = fields.get("fixVersions")
    if not isinstance(fix_versions, list):
        return None
    for version in fix_versions:
        if isinstance(version, Mapping):
            name = version.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
        elif isinstance(version, str) and version.strip():
            return version.strip()
    return None


def _derive_cve_ids(issue: Mapping[str, Any] | None, comments: Any) -> list[str]:
    values: list[str] = []
    for text in [*_issue_text_values(issue), *_comment_bodies(comments)]:
        values.extend(match.group(0).upper() for match in CVE_PATTERN.finditer(text))
    return list(dict.fromkeys(values))


def _derive_network_mode(request: CollectCaseRequest, fetched: FetchedEvidence) -> str:
    if (
        request.gitlab_mr_url
        or fetched.gitlab_patch_url
        or fetched.jira_patch_urls
        or fetched.web_records
        or request.patch_urls
        or request.web_records
    ):
        return "replay_only"
    return "network_denied"


def _derive_mock_repo(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
    *,
    target_branch: str | None,
    fix_version: str | None,
) -> MockRepoInput | None:
    if fetched.gitlab_mr is None:
        return None

    mr_url = _nonempty_string(fetched.gitlab_mr.get("web_url")) or fetched.gitlab_mr_url
    remote_url = _gitlab_remote_url_from_mr_url(mr_url)
    pre_fix_ref = _gitlab_pre_fix_ref(fetched.gitlab_mr, fetched.gitlab_commits)
    branch = _nonempty_string(fetched.gitlab_mr.get("target_branch"))
    if remote_url is None or pre_fix_ref is None or branch is None:
        return None

    expected_branch = target_branch or fix_version
    return MockRepoInput(
        remote_url=remote_url,
        pre_fix_ref=pre_fix_ref,
        branch=branch,
        agent=request.mock_agent,
        zstream_override=_zstream_override(branch, expected_branch),
    )


def _gitlab_remote_url_from_mr_url(url: str | None) -> str | None:
    if url is None:
        return None
    parsed = urlparse(url)
    marker = "/-/merge_requests/"
    if not parsed.scheme or not parsed.netloc or marker not in parsed.path:
        return None
    project_path = parsed.path.split(marker, 1)[0].rstrip("/")
    if not project_path:
        return None
    suffix = "" if project_path.endswith(".git") else ".git"
    return f"{parsed.scheme}://{parsed.netloc}{project_path}{suffix}"


def _gitlab_pre_fix_ref(mr: Mapping[str, Any], commits: Any) -> str | None:
    diff_refs = mr.get("diff_refs")
    if isinstance(diff_refs, Mapping):
        for name in ("base_sha", "start_sha"):
            if value := _nonempty_string(diff_refs.get(name)):
                return value

    if isinstance(commits, list) and commits:
        first_commit = commits[0]
        if isinstance(first_commit, Mapping):
            parent_ids = first_commit.get("parent_ids")
            if isinstance(parent_ids, list) and parent_ids:
                return _nonempty_string(parent_ids[0])
    return None


def _zstream_override(branch: str, expected_branch: str | None) -> dict[str, str]:
    if expected_branch is None or expected_branch == branch:
        return {}
    match = re.search(r"\brhel-(\d+)", expected_branch)
    if match is None:
        return {}
    return {match.group(1): expected_branch}


def _nonempty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _issue_fields(issue: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if issue is None:
        return None
    fields = issue.get("fields")
    return fields if isinstance(fields, Mapping) else None


def _issue_labels(issue: Mapping[str, Any] | None) -> list[str]:
    fields = _issue_fields(issue)
    if fields is None:
        return []
    labels = fields.get("labels")
    if not isinstance(labels, list):
        return []
    return [label.strip() for label in labels if isinstance(label, str) and label.strip()]


def _issue_text_values(issue: Mapping[str, Any] | None) -> list[str]:
    fields = _issue_fields(issue)
    if fields is None:
        return []
    values = []
    for name in ("summary", "description"):
        value = fields.get(name)
        if isinstance(value, str):
            values.append(value)
    for label in _issue_labels(issue):
        values.append(label)
    return values


def _comment_bodies(comments: Any) -> list[str]:
    bodies = []
    for comment in _comment_values(comments):
        body = comment.get("body")
        if isinstance(body, str):
            bodies.append(body)
        elif body is not None:
            bodies.append(json.dumps(body, sort_keys=True))
    return bodies


def _comment_values(comments: Any) -> list[Mapping[str, Any]]:
    source = comments
    if isinstance(source, Mapping):
        source = source.get("comments", [])
    if not isinstance(source, list):
        return []
    return [comment for comment in source if isinstance(comment, Mapping)]


def _comment_resolution(body: str) -> str | None:
    match = re.search(r"\*?resolution\*?\s*[:=-]\s*([A-Za-z_-]+)", body, re.IGNORECASE)
    if match is None:
        return None
    token = match.group(1).lower().replace("_", "-")
    return COMMENT_RESOLUTION_MAP.get(token)


def _component_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    if "/" in value:
        value = value.rsplit("/", 1)[-1]
    return value.strip() or None


def _validate_request(request: CollectCaseRequest, *, require_metadata: bool) -> None:
    if require_metadata:
        missing = [
            option
            for option, value in (
                ("--case-type", request.case_type),
                ("--resolution", request.resolution),
                ("--package", request.package),
                ("--expected-basis", request.expected_basis),
                ("--network-mode", request.network_mode),
            )
            if not isinstance(value, str) or not value
        ]
        if missing:
            raise CollectCaseError(
                "could not derive required case metadata; provide " + ", ".join(missing)
            )

    if request.case_type is not None:
        _validate_allowed(request.case_type, ALLOWED_CASE_TYPES, "case_type")
    if request.resolution is not None:
        _validate_allowed(request.resolution, ALLOWED_RESOLUTIONS, "resolution")
    if request.expected_basis is not None:
        _validate_allowed(request.expected_basis, ALLOWED_EXPECTED_BASES, "expected_basis")
    _validate_allowed(
        request.ground_truth_confidence,
        ALLOWED_GROUND_TRUTH_CONFIDENCE,
        "ground_truth_confidence",
    )
    _validate_allowed(request.answer_leakage, ALLOWED_ANSWER_LEAKAGE, "answer_leakage")
    _validate_allowed(request.case_status, ALLOWED_CASE_STATUSES, "case_status")
    if request.network_mode is not None:
        _validate_allowed(request.network_mode, ALLOWED_NETWORK_MODES, "network_mode")
    if request.reference_patch_mode is not None:
        _validate_allowed(
            request.reference_patch_mode,
            ALLOWED_REFERENCE_PATCH_MODES,
            "reference_patch_mode",
        )
    if require_metadata and request.resolution in {"backport", "rebase", "rebuild"}:
        if request.target_branch is None and request.fix_version is None:
            msg = "implementation cases should include target_branch or fix_version"
            raise CollectCaseError(msg)
    if request.network_mode == "network_denied" and (
        request.patch_urls or request.web_records or request.gitlab_mr_url
    ):
        msg = (
            "network_denied cases must not declare patch URLs, web records, "
            "or GitLab MR URLs; use replay_only"
        )
        raise CollectCaseError(msg)
    for path in _input_paths(request):
        if not path.exists():
            raise CollectCaseError(f"input path does not exist: {path}")


def _validate_allowed(value: str, allowed: set[str], name: str) -> None:
    if value not in allowed:
        raise CollectCaseError(f"unsupported {name}: {value!r}")


def _input_paths(request: CollectCaseRequest) -> list[Path]:
    paths = [
        request.jira_issue_json,
        request.jira_comments_json,
        request.jira_links_json,
        request.jira_token_file,
        request.reference_patch,
        *request.attachments,
        *request.source_upstream,
        *request.source_lookaside,
        *[record.source_path for record in request.web_records],
    ]
    return [path for path in paths if path is not None]


def _write_cases_manifest(
    path: Path,
    case_id: str,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    if not path.exists():
        _write_text(path, f"cases:\n  - {case_id}\n", overwrite=overwrite, result=result)
        return

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = data.get("cases") if isinstance(data, Mapping) else data
    if not isinstance(entries, list):
        raise CollectCaseError(f"cases.yaml must contain a list: {path}")

    if case_id in {_manifest_case_id(entry) for entry in entries}:
        return

    entries.append(case_id)
    payload = {"cases": entries} if isinstance(data, Mapping) else entries
    _write_text(path, yaml.safe_dump(payload, sort_keys=False), overwrite=True, result=result)


def _manifest_case_id(entry: Any) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, Mapping):
        value = entry.get("case_id")
        return value if isinstance(value, str) else None
    return None


def _write_expected(
    cases_dir: Path,
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
    result: CollectCaseResult,
) -> None:
    expected: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "resolution": request.resolution,
        "package": request.package,
        "expected_basis": request.expected_basis,
        "ground_truth_confidence": request.ground_truth_confidence,
        "answer_leakage": request.answer_leakage,
        "case_status": request.case_status,
        "case_status_reason": request.case_status_reason,
        "network_mode": request.network_mode,
    }
    for name, value in (
        ("target_branch", request.target_branch),
        ("fix_version", request.fix_version),
        ("notes", request.notes),
        ("reference_patch_mode", request.reference_patch_mode),
    ):
        if value is not None:
            expected[name] = value
    for name, values in (
        ("cve_ids", request.cve_ids),
        ("patch_urls", _effective_patch_urls(request, fetched)),
        ("fix_sources", _effective_fix_sources(request, fetched)),
    ):
        if values:
            expected[name] = list(values)
    if request.alternate_acceptable_outcomes:
        expected["alternate_acceptable_outcomes"] = [
            dict(alternate) for alternate in request.alternate_acceptable_outcomes
        ]

    _write_json(
        cases_dir / "expected" / f"{request.case_id}.expected.json",
        expected,
        overwrite=request.overwrite,
        result=result,
    )


def _write_jira_fixtures(
    cases_dir: Path,
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
    result: CollectCaseResult,
) -> None:
    jira_dir = cases_dir / "jiras" / request.case_id
    issue_for_start: Mapping[str, Any] | None = None
    comments_for_start: Any = None
    if fetched.jira_issue is not None:
        issue_for_start = fetched.jira_issue
        _write_json(
            jira_dir / "issue.json",
            fetched.jira_issue,
            overwrite=request.overwrite,
            result=result,
        )
    elif request.jira_issue_json is not None:
        issue_data = _load_json(request.jira_issue_json)
        if isinstance(issue_data, Mapping):
            issue_for_start = issue_data
        _copy_file(
            request.jira_issue_json,
            jira_dir / "issue.json",
            overwrite=request.overwrite,
            result=result,
        )
    else:
        issue_for_start = {
            "schema_version": SCHEMA_VERSION,
            "case_id": request.case_id,
            "case_type": request.case_type,
            "key": request.case_id,
            "fields": {
                "summary": f"TODO: collect Jira summary for {request.case_id}",
                "components": [{"name": request.package}],
            },
        }
        _write_json(
            jira_dir / "issue.json",
            issue_for_start,
            overwrite=request.overwrite,
            result=result,
        )

    if fetched.jira_comments is not None:
        comments_for_start = fetched.jira_comments
        _write_json(
            jira_dir / "comments.json",
            fetched.jira_comments,
            overwrite=request.overwrite,
            result=result,
        )
    elif request.jira_comments_json is not None:
        comments_for_start = _load_json(request.jira_comments_json)
        _copy_file(
            request.jira_comments_json,
            jira_dir / "comments.json",
            overwrite=request.overwrite,
            result=result,
        )
    else:
        comments_for_start = {
            "schema_version": SCHEMA_VERSION,
            "case_id": request.case_id,
            "case_type": request.case_type,
            "comments": [],
        }
        _write_json(
            jira_dir / "comments.json",
            comments_for_start,
            overwrite=request.overwrite,
            result=result,
        )

    if fetched.jira_links is not None:
        _write_json(
            jira_dir / "links.json",
            _jira_links_fixture_payload(request, fetched.jira_links),
            overwrite=request.overwrite,
            result=result,
        )
    elif request.jira_links_json is not None:
        _write_json(
            jira_dir / "links.json",
            _jira_links_fixture_payload(request, _load_json(request.jira_links_json)),
            overwrite=request.overwrite,
            result=result,
        )
    else:
        _write_json(
            jira_dir / "links.json",
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": request.case_id,
                "case_type": request.case_type,
                "links": [],
            },
            overwrite=request.overwrite,
            result=result,
        )

    if issue_for_start is not None:
        _write_json(
            jira_dir / "starting-issue.json",
            _build_starting_jira_issue(
                issue_for_start,
                comments_for_start,
                case_id=request.case_id,
                case_type=request.case_type,
            ),
            overwrite=request.overwrite,
            result=result,
        )

    for linked in fetched.linked_jira_issues:
        _write_fetched_jira_fixture(
            jira_dir / "linked" / linked.key,
            linked.key,
            None,
            linked.issue,
            linked.comments,
            linked.links,
            overwrite=request.overwrite,
            result=result,
        )

    for attachment in request.attachments:
        _copy_into_dir(
            attachment,
            jira_dir / "attachments",
            overwrite=request.overwrite,
            result=result,
        )


def _write_fetched_jira_fixture(
    jira_dir: Path,
    case_id: str,
    case_type: str | None,
    issue: Mapping[str, Any],
    comments: Mapping[str, Any],
    links: Any,
    *,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    _write_json(
        jira_dir / "issue.json",
        issue,
        overwrite=overwrite,
        result=result,
    )
    _write_json(
        jira_dir / "comments.json",
        comments,
        overwrite=overwrite,
        result=result,
    )
    _write_json(
        jira_dir / "links.json",
        _jira_links_fixture_payload_for(case_id, case_type, links),
        overwrite=overwrite,
        result=result,
    )
    _write_json(
        jira_dir / "starting-issue.json",
        _build_starting_jira_issue(
            issue,
            comments,
            case_id=case_id,
            case_type=case_type,
        ),
        overwrite=overwrite,
        result=result,
    )


def _jira_links_fixture_payload(request: CollectCaseRequest, links: Any) -> dict[str, Any]:
    return _jira_links_fixture_payload_for(request.case_id, request.case_type, links)


def _jira_links_fixture_payload_for(
    case_id: str,
    case_type: str | None,
    links: Any,
) -> dict[str, Any]:
    if isinstance(links, Mapping):
        payload = copy.deepcopy(dict(links))
        link_values = _links_value(payload)
    elif isinstance(links, list):
        payload = {}
        link_values = copy.deepcopy(links)
    else:
        raise CollectCaseError("Jira links JSON must contain an object or list")

    if not isinstance(link_values, list):
        raise CollectCaseError("Jira links must be a list")

    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("case_id", case_id)
    if case_type is not None:
        payload.setdefault("case_type", case_type)
    payload["links"] = link_values
    return payload


def _links_value(links: Any) -> Any:
    if isinstance(links, Mapping):
        if "links" in links:
            return links["links"]
        if "remote_links" in links:
            return links["remote_links"]
        return []
    return links


def _build_starting_jira_issue(
    issue: Mapping[str, Any],
    comments: Any,
    *,
    case_id: str,
    case_type: str | None,
) -> dict[str, Any]:
    payload = copy.deepcopy(dict(issue))
    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("case_id", case_id)
    if case_type is not None:
        payload.setdefault("case_type", case_type)
    payload.setdefault("key", case_id)

    fields = payload.get("fields")
    if not isinstance(fields, Mapping):
        fields = {}
    else:
        fields = copy.deepcopy(dict(fields))
    payload["fields"] = fields

    fields.setdefault("summary", f"TODO: collect Jira summary for {case_id}")
    fields.setdefault("description", "")
    fields.setdefault("components", [])
    fields.setdefault("fixVersions", [])
    fields["labels"] = _starting_labels(fields.get("labels"))
    fields["status"] = _starting_status(fields.get("status"))
    fields["resolution"] = None
    fields["comment"] = _starting_comment_block(comments, fields.get("comment"))
    payload["remote_links"] = []
    return payload


def _starting_labels(labels: Any) -> list[str]:
    if not isinstance(labels, list):
        return []
    return [
        label
        for label in labels
        if isinstance(label, str)
        and label
        and label not in YMIR_RESULT_LABELS
        and not label.startswith("ymir_")
        and not label.startswith("jotnar_")
        and "jotnar" not in label
    ]


def _starting_status(status: Any) -> Any:
    if not isinstance(status, Mapping):
        return {"name": "New"}
    name = status.get("name")
    if isinstance(name, str) and name.lower() in CLOSED_STATUS_NAMES:
        return {"name": "New"}
    return copy.deepcopy(dict(status))


def _starting_comment_block(comments: Any, issue_comment: Any) -> dict[str, Any]:
    source = comments if comments is not None else issue_comment
    comment_values = [
        copy.deepcopy(dict(comment))
        for comment in _comment_values(source)
        if not _is_result_comment(comment)
    ]
    return {
        "comments": comment_values,
        "maxResults": len(comment_values),
        "startAt": 0,
        "total": len(comment_values),
    }


def _is_result_comment(comment: Mapping[str, Any]) -> bool:
    body = comment.get("body")
    body_text = body if isinstance(body, str) else json.dumps(body, sort_keys=True)
    lowered_body = _normalized_text(body_text)
    if any(pattern in lowered_body for pattern in RESULT_COMMENT_PATTERNS):
        return True

    author = comment.get("author")
    if isinstance(author, Mapping):
        author_text = _normalized_text(
            " ".join(
                value
                for value in (
                    author.get("name"),
                    author.get("key"),
                    author.get("displayName"),
                    author.get("emailAddress"),
                )
                if isinstance(value, str)
            )
        )
        if (
            "automation bot" in author_text
            or "e-tool" in author_text
            or "errata-tool" in author_text
            or "jotnar" in author_text
            or "ymir" in author_text
            or "rhel jira bot" in author_text
        ):
            return True
    return False


def _normalized_text(value: str) -> str:
    return unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii").lower()


def _write_mock_data(
    cases_dir: Path,
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
    result: CollectCaseResult,
) -> None:
    mock_repo = request.mock_repo
    if mock_repo is None:
        return

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": request.case_id,
        "case_type": request.case_type,
        "repos": [
            {
                "package": request.package,
                "remote_url": mock_repo.remote_url,
                "pre_fix_ref": mock_repo.pre_fix_ref,
                "branch": mock_repo.branch,
            }
        ],
    }
    if mock_repo.source_url is not None:
        payload["repos"][0]["source_url"] = mock_repo.source_url
    if mock_repo.zstream_override:
        payload["zstream_override"] = dict(mock_repo.zstream_override)
    if mock_repo.blocked_original_urls:
        payload["blocked_original_urls"] = list(mock_repo.blocked_original_urls)

    _write_json(
        cases_dir / "mock_data" / mock_repo.agent / f"{request.case_id}.json",
        payload,
        overwrite=request.overwrite,
        result=result,
    )
    if request.reference_patch is not None:
        _copy_file(
            request.reference_patch,
            cases_dir
            / "mock_data"
            / mock_repo.agent
            / "reference_patches"
            / f"{request.case_id}.patch",
            overwrite=request.overwrite,
            result=result,
        )
    elif fetched.gitlab_patch_body is not None:
        _write_bytes(
            cases_dir
            / "mock_data"
            / mock_repo.agent
            / "reference_patches"
            / f"{request.case_id}.patch",
            fetched.gitlab_patch_body,
            overwrite=request.overwrite,
            result=result,
        )


def _write_web_cache(
    cases_dir: Path,
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
    result: CollectCaseResult,
) -> None:
    if request.network_mode == "network_denied" and not request.web_records:
        return

    cache_dir = cases_dir / "web_cache" / request.case_id
    required_urls = list(
        dict.fromkeys(
            [
                *_effective_patch_urls(request, fetched),
                *[record.url for record in request.web_records],
                *[record.url for record in fetched.web_records],
            ]
        )
    )
    recorded_files = {}
    for index, record in enumerate(request.web_records, start=1):
        destination = cache_dir / "recorded" / f"{index:03d}-{record.source_path.name}"
        _copy_file(record.source_path, destination, overwrite=request.overwrite, result=result)
        recorded_files[record.url] = destination.relative_to(cache_dir).as_posix()

    for record in fetched.web_records:
        destination = cache_dir / record.relative_path
        _write_bytes(destination, record.body, overwrite=request.overwrite, result=result)
        recorded_files[record.url] = record.relative_path

    if required_urls or request.network_mode == "replay_only":
        _write_json(
            cache_dir / "manifest.json",
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": request.case_id,
                "case_type": request.case_type,
                "required_urls": required_urls,
                "recorded_files": recorded_files,
            },
            overwrite=request.overwrite,
            result=result,
        )


def _write_source_cache(
    cases_dir: Path,
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> None:
    for source in request.source_upstream:
        _copy_into_dir(
            source,
            cases_dir / "source_cache" / request.case_id / "upstream",
            overwrite=request.overwrite,
            result=result,
        )
    for source in request.source_lookaside:
        _copy_into_dir(
            source,
            cases_dir / "source_cache" / request.case_id / "lookaside",
            overwrite=request.overwrite,
            result=result,
        )


def _append_completion_warnings(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
    result: CollectCaseResult,
) -> None:
    if request.mock_repo is None:
        result.warnings.append("mock_data fixture was not written; provide mock repo metadata")
    if request.network_mode == "replay_only":
        recorded_urls = {
            *[record.url for record in request.web_records],
            *[record.url for record in fetched.web_records],
        }
        missing = [
            url for url in _effective_patch_urls(request, fetched) if url not in recorded_urls
        ]
        if missing:
            result.warnings.append(
                "web_cache manifest requires recorded files for: " + ", ".join(missing)
            )
    if request.case_status == "active":
        result.warnings.append("active scaffold should be reviewed before headline scoring")


def _effective_patch_urls(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
) -> tuple[str, ...]:
    urls = [*request.patch_urls]
    urls.extend(fetched.jira_patch_urls)
    if fetched.gitlab_patch_url:
        urls.append(fetched.gitlab_patch_url)
    return tuple(dict.fromkeys(urls))


def _effective_fix_sources(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
) -> tuple[str, ...]:
    sources = [*request.fix_sources]
    if fetched.gitlab_mr_url:
        sources.append(fetched.gitlab_mr_url)
    return tuple(dict.fromkeys(sources))


def _write_json(
    path: Path,
    data: Mapping[str, Any],
    *,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    _write_text(
        path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        overwrite=overwrite,
        result=result,
    )


def _write_text(
    path: Path,
    text: str,
    *,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    _check_write_path(path, overwrite)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _record_written(path, result)


def _write_bytes(
    path: Path,
    data: bytes,
    *,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    _check_write_path(path, overwrite)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _record_written(path, result)


def _copy_file(
    source: Path,
    destination: Path,
    *,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    if not source.is_file():
        raise CollectCaseError(f"input file is not a file: {source}")
    _check_write_path(destination, overwrite)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    _record_written(destination, result)


def _copy_into_dir(
    source: Path,
    destination_dir: Path,
    *,
    overwrite: bool,
    result: CollectCaseResult,
) -> None:
    destination = destination_dir / source.name
    if source.is_dir():
        if destination.exists():
            if not overwrite:
                raise CollectCaseError(f"refusing to overwrite existing path: {destination}")
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
        result.written_paths.extend(
            path for path in sorted(destination.rglob("*")) if path.is_file()
        )
        return
    _copy_file(source, destination, overwrite=overwrite, result=result)


def _check_write_path(path: Path, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise CollectCaseError(f"refusing to overwrite existing path: {path}")


def _record_written(path: Path, result: CollectCaseResult) -> None:
    if path not in result.written_paths:
        result.written_paths.append(path)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectCaseError(f"cannot read JSON file {path}: {exc}") from exc
