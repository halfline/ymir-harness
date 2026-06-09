from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ymir_harness.models import SCHEMA_VERSION
from ymir_harness.scoring import load_json_file

JIRA_REPLAY_MISS_PREFIX = "jira replay miss:"
RESULT_COMMENT_MARKERS = (
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


@dataclass(frozen=True)
class JiraReplayMiss:
    kind: str
    method: str
    url: str
    payload: Mapping[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "method": self.method,
            "url": self.url,
            "payload": dict(self.payload),
        }


def jira_search_fixture_path(cases_dir: Path, case_id: str, payload: Mapping[str, Any]) -> Path:
    return (
        cases_dir
        / "jiras"
        / case_id
        / "api"
        / "search"
        / f"{jira_search_request_digest(payload)}.json"
    )


def jira_search_request_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(_normalized_search_payload(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def load_jira_search_response(
    cases_dir: Path,
    case_id: str,
    payload: Mapping[str, Any],
) -> dict[str, Any] | None:
    path = jira_search_fixture_path(cases_dir, case_id, payload)
    if not path.is_file():
        return None
    data = load_json_file(path)
    response = data.get("response") if isinstance(data, Mapping) else None
    return copy.deepcopy(dict(response)) if isinstance(response, Mapping) else None


def write_jira_search_fixture(
    cases_dir: Path,
    case_id: str,
    *,
    url: str,
    payload: Mapping[str, Any],
    response: Mapping[str, Any],
    as_of: str | None,
    overwrite: bool,
) -> Path:
    path = jira_search_fixture_path(cases_dir, case_id, payload)
    if path.exists() and not overwrite:
        return path

    fixture = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "kind": "jira_search",
        "request": {
            "method": "POST",
            "url": url,
            "payload": _normalized_search_payload(payload),
        },
        "response": response,
        "reconstruction": {
            "as_of": as_of,
            "method": "captured_jira_search",
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def jira_dev_status_path(cases_dir: Path, case_id: str, issue_key: str) -> Path:
    return cases_dir / "jiras" / case_id / "linked" / issue_key / "dev-status.json"


def write_jira_dev_status_fixture(
    cases_dir: Path,
    case_id: str,
    issue_key: str,
    *,
    summary: Mapping[str, Any],
    details: Mapping[str, Any],
    as_of: str | None,
    overwrite: bool,
) -> Path:
    path = jira_dev_status_path(cases_dir, case_id, issue_key)
    if path.exists() and not overwrite:
        return path

    payload = {
        "schema_version": SCHEMA_VERSION,
        "case_id": issue_key,
        "summary": dict(summary),
        "details": dict(details),
        "reconstruction": {
            "as_of": as_of,
            "method": "captured_jira_dev_status",
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def jira_replay_miss_line(miss: JiraReplayMiss) -> str:
    return f"{JIRA_REPLAY_MISS_PREFIX} {json.dumps(miss.to_json(), sort_keys=True)}"


def jira_search_replay_miss(url: str, payload: Mapping[str, Any]) -> str:
    return jira_replay_miss_line(
        JiraReplayMiss(kind="jira_search", method="POST", url=url, payload=payload)
    )


def parse_jira_replay_misses(text: str) -> list[JiraReplayMiss]:
    misses: list[JiraReplayMiss] = []
    for line in text.splitlines():
        _, separator, encoded = line.partition(JIRA_REPLAY_MISS_PREFIX)
        if not separator:
            continue
        try:
            data = json.loads(encoded.strip())
        except json.JSONDecodeError:
            continue
        if not isinstance(data, Mapping):
            continue
        payload = data.get("payload")
        if not isinstance(payload, Mapping):
            continue
        kind = data.get("kind")
        method = data.get("method")
        url = data.get("url")
        if not all(isinstance(value, str) and value for value in (kind, method, url)):
            continue
        misses.append(
            JiraReplayMiss(
                kind=kind,
                method=method.upper(),
                url=url,
                payload=dict(payload),
            )
        )
    return misses


def derive_as_of(cases_dir: Path, case_id: str) -> str | None:
    reconstruction_path = cases_dir / "jiras" / case_id / "reconstruction.json"
    if reconstruction_path.is_file():
        reconstruction = load_json_file(reconstruction_path)
        as_of = reconstruction.get("as_of") if isinstance(reconstruction, Mapping) else None
        if isinstance(as_of, str) and as_of:
            return as_of

    comments = _load_comments(cases_dir / "jiras" / case_id / "comments.json")
    return derive_as_of_from_comments(comments)


def derive_as_of_from_comments(comments: Any) -> str | None:
    source = comments.get("comments", []) if isinstance(comments, Mapping) else comments
    if not isinstance(source, list):
        return None
    timestamps = [
        timestamp
        for comment in source
        if isinstance(comment, Mapping)
        if _is_result_comment(comment)
        for timestamp in [_parse_jira_timestamp(comment.get("created"))]
        if timestamp is not None
    ]
    if not timestamps:
        return None
    return _format_timestamp(min(timestamps) - timedelta(microseconds=1))


def filter_search_response_as_of(
    response: Mapping[str, Any],
    *,
    as_of: str | None,
    issue_details: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if as_of is None:
        return copy.deepcopy(dict(response))

    as_of_timestamp = _parse_jira_timestamp(as_of)
    if as_of_timestamp is None:
        return copy.deepcopy(dict(response))

    details_by_key = issue_details or {}
    filtered = copy.deepcopy(dict(response))
    issues = filtered.get("issues")
    if not isinstance(issues, list):
        return filtered

    kept = []
    for issue in issues:
        if not isinstance(issue, Mapping):
            continue
        detail = details_by_key.get(str(issue.get("key") or ""), issue)
        created = _issue_field(detail, "created")
        created_at = _parse_jira_timestamp(created)
        if created_at is not None and created_at > as_of_timestamp:
            continue
        kept.append(issue)
    filtered["issues"] = kept
    return filtered


def filter_comments_as_of(comments: Any, *, as_of: str | None) -> dict[str, Any]:
    source = comments.get("comments", []) if isinstance(comments, Mapping) else comments
    if not isinstance(source, list):
        source = []
    if as_of is None:
        return _comment_payload(copy.deepcopy(source))

    as_of_timestamp = _parse_jira_timestamp(as_of)
    if as_of_timestamp is None:
        return _comment_payload(copy.deepcopy(source))

    filtered = []
    for comment in source:
        if not isinstance(comment, Mapping):
            continue
        created_at = _parse_jira_timestamp(comment.get("created"))
        if created_at is not None and created_at > as_of_timestamp:
            continue
        filtered.append(copy.deepcopy(dict(comment)))
    return _comment_payload(filtered)


def _normalized_search_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = payload.get("fields")
    normalized_fields = fields if isinstance(fields, list) else ["key", "summary", "fixVersions"]
    return {
        "jql": str(payload.get("jql") or ""),
        "fields": [str(field) for field in normalized_fields if isinstance(field, str)],
        "maxResults": int(payload.get("maxResults") or payload.get("max_results") or 50),
    }


def _load_comments(path: Path) -> list[Mapping[str, Any]]:
    if not path.is_file():
        return []
    data = load_json_file(path)
    source = data.get("comments", []) if isinstance(data, Mapping) else data
    if not isinstance(source, list):
        return []
    return [comment for comment in source if isinstance(comment, Mapping)]


def _is_result_comment(comment: Mapping[str, Any]) -> bool:
    body = comment.get("body")
    text = body if isinstance(body, str) else json.dumps(body, sort_keys=True)
    lowered = text.casefold()
    return any(marker in lowered for marker in RESULT_COMMENT_MARKERS)


def _issue_field(issue: Mapping[str, Any], name: str) -> Any:
    fields = issue.get("fields")
    if isinstance(fields, Mapping):
        return fields.get(name)
    return None


def _parse_jira_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    if len(candidate) >= 5 and candidate[-5] in {"+", "-"} and candidate[-3] != ":":
        candidate = f"{candidate[:-2]}:{candidate[-2:]}"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _comment_payload(comments: list[Any]) -> dict[str, Any]:
    return {
        "comments": comments,
        "maxResults": len(comments),
        "startAt": 0,
        "total": len(comments),
    }
