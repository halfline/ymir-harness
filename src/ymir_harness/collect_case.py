from __future__ import annotations

import base64
import copy
import json
import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
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
    zstream_override: Mapping[str, str] = field(default_factory=dict)
    blocked_original_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class FetchedEvidence:
    jira_issue: Mapping[str, Any] | None = None
    jira_comments: Mapping[str, Any] | None = None
    jira_links: Any = None


@dataclass(frozen=True)
class CollectCaseRequest:
    cases_dir: Path
    case_id: str
    case_type: str
    resolution: str
    package: str
    expected_basis: str = "manual_review"
    ground_truth_confidence: str = "medium"
    answer_leakage: str = "none"
    case_status: str = "quarantined"
    case_status_reason: str | None = "fixture scaffold requires ground-truth review"
    network_mode: str = "network_denied"
    target_branch: str | None = None
    fix_version: str | None = None
    cve_ids: tuple[str, ...] = ()
    patch_urls: tuple[str, ...] = ()
    fix_sources: tuple[str, ...] = ()
    notes: str | None = None
    alternate_acceptable_outcomes: tuple[Mapping[str, Any], ...] = ()
    reference_patch_mode: str | None = None
    mock_repo: MockRepoInput | None = None
    jira_url: str | None = None
    jira_base_url: str | None = None
    jira_token_env: str = "JIRA_TOKEN"
    jira_token_file: Path | None = None
    jira_email: str | None = None
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
    _validate_request(request)
    cases_dir = request.cases_dir.resolve()
    result = CollectCaseResult(case_id=request.case_id, cases_dir=cases_dir)
    fetched = _fetch_evidence(request, result)
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

    if request.jira_url or request.jira_base_url:
        jira_urls = _jira_urls(request)
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

    return FetchedEvidence(
        jira_issue=jira_issue,
        jira_comments=jira_comments,
        jira_links=jira_links,
    )



def _jira_urls(request: CollectCaseRequest) -> dict[str, str]:
    if request.jira_url:
        issue_url = _jira_issue_api_url(request.jira_url, request.case_id)
    elif request.jira_base_url:
        issue_url = _join_url(
            request.jira_base_url,
            f"/rest/api/2/issue/{request.case_id}",
        )
    else:
        raise CollectCaseError("jira URL configuration is missing")

    issue_base = issue_url.split("?", 1)[0].rstrip("/")
    return {
        "issue": issue_url,
        "comments": f"{issue_base}/comment",
        "links": f"{issue_base}/remotelink",
    }


def _jira_issue_api_url(url: str, case_id: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise CollectCaseError(f"Jira URL must be absolute: {url}")

    if "/rest/api/" in parsed.path and "/issue/" in parsed.path:
        return url
    if "/browse/" in parsed.path:
        return _join_url(_origin(url), f"/rest/api/2/issue/{case_id}")
    return _join_url(_origin(url), f"/rest/api/2/issue/{case_id}")


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


def _fetch_json(
    url: str,
    *,
    headers: Mapping[str, str],
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> Mapping[str, Any]:
    body = _fetch_bytes(url, headers=headers, request=request, result=result)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectCaseError(f"fetched URL did not return JSON: {url}") from exc
    if not isinstance(data, Mapping):
        raise CollectCaseError(f"fetched URL returned non-object JSON: {url}")
    return data


def _fetch_json_value(
    url: str,
    *,
    headers: Mapping[str, str],
    request: CollectCaseRequest,
    result: CollectCaseResult,
) -> Any:
    body = _fetch_bytes(url, headers=headers, request=request, result=result)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectCaseError(f"fetched URL did not return JSON: {url}") from exc


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


def _validate_request(request: CollectCaseRequest) -> None:
    _validate_allowed(request.case_type, ALLOWED_CASE_TYPES, "case_type")
    _validate_allowed(request.resolution, ALLOWED_RESOLUTIONS, "resolution")
    _validate_allowed(request.expected_basis, ALLOWED_EXPECTED_BASES, "expected_basis")
    _validate_allowed(
        request.ground_truth_confidence,
        ALLOWED_GROUND_TRUTH_CONFIDENCE,
        "ground_truth_confidence",
    )
    _validate_allowed(request.answer_leakage, ALLOWED_ANSWER_LEAKAGE, "answer_leakage")
    _validate_allowed(request.case_status, ALLOWED_CASE_STATUSES, "case_status")
    _validate_allowed(request.network_mode, ALLOWED_NETWORK_MODES, "network_mode")
    if request.reference_patch_mode is not None:
        _validate_allowed(
            request.reference_patch_mode,
            ALLOWED_REFERENCE_PATCH_MODES,
            "reference_patch_mode",
        )
    if request.resolution in {"backport", "rebase", "rebuild"}:
        if request.target_branch is None and request.fix_version is None:
            msg = "implementation cases should include target_branch or fix_version"
            raise CollectCaseError(msg)
    if request.network_mode == "network_denied" and (
        request.patch_urls or request.web_records
    ):
        msg = "network_denied cases must not declare patch URLs or web records; use replay_only"
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
    if fetched.jira_issue is not None:
        _write_json(
            jira_dir / "issue.json",
            fetched.jira_issue,
            overwrite=request.overwrite,
            result=result,
        )
    elif request.jira_issue_json is not None:
        _copy_file(
            request.jira_issue_json,
            jira_dir / "issue.json",
            overwrite=request.overwrite,
            result=result,
        )
    else:
        _write_json(
            jira_dir / "issue.json",
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": request.case_id,
                "case_type": request.case_type,
                "key": request.case_id,
                "fields": {
                    "summary": f"TODO: collect Jira summary for {request.case_id}",
                    "components": [{"name": request.package}],
                },
            },
            overwrite=request.overwrite,
            result=result,
        )

    if fetched.jira_comments is not None:
        _write_json(
            jira_dir / "comments.json",
            fetched.jira_comments,
            overwrite=request.overwrite,
            result=result,
        )
    elif request.jira_comments_json is not None:
        _copy_file(
            request.jira_comments_json,
            jira_dir / "comments.json",
            overwrite=request.overwrite,
            result=result,
        )
    else:
        _write_json(
            jira_dir / "comments.json",
            {
                "schema_version": SCHEMA_VERSION,
                "case_id": request.case_id,
                "case_type": request.case_type,
                "comments": [],
            },
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

    for attachment in request.attachments:
        _copy_into_dir(
            attachment,
            jira_dir / "attachments",
            overwrite=request.overwrite,
            result=result,
        )


def _jira_links_fixture_payload(request: CollectCaseRequest, links: Any) -> dict[str, Any]:
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
    payload.setdefault("case_id", request.case_id)
    if request.case_type is not None:
        payload.setdefault("case_type", request.case_type)
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
                *request.patch_urls,
                *[record.url for record in request.web_records],
            ]
        )
    )
    recorded_files = {}
    for index, record in enumerate(request.web_records, start=1):
        destination = cache_dir / "recorded" / f"{index:03d}-{record.source_path.name}"
        _copy_file(record.source_path, destination, overwrite=request.overwrite, result=result)
        recorded_files[record.url] = destination.relative_to(cache_dir).as_posix()

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
        recorded_urls = {record.url for record in request.web_records}
        missing = [url for url in request.patch_urls if url not in recorded_urls]
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
    del fetched
    return request.patch_urls


def _effective_fix_sources(
    request: CollectCaseRequest,
    fetched: FetchedEvidence,
) -> tuple[str, ...]:
    del fetched
    return request.fix_sources



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
        result.written_paths.extend(path for path in sorted(destination.rglob("*")) if path.is_file())
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
