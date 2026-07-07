from __future__ import annotations

import copy
import hashlib
import json
import re
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
JIRA_FIELD_ALIASES = {
    "fixed in build": ("customfield_10578",),
}
JIRA_DEV_SUMMARY_FIELDS = {"customfield_10000"}
JIRA_EMBEDDED_LINK_VOLATILE_FIELDS = {
    "customfield_10000",
    "resolution",
    "resolutiondate",
    "status",
    "statusCategory",
    "statuscategorychangedate",
    "updated",
}
EMPTY_JQL_PATTERN = re.compile(
    r"(?i)(?:\"(?P<quoted>[^\"]+)\"|(?P<bare>[A-Za-z][A-Za-z0-9_ ]+))\s+is\s+"
    r"(?P<not>not\s+)?empty\b"
)
JIRA_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
)
JIRA_KEY_PATTERN = re.compile(r"(?i)^([A-Z][A-Z0-9]+)-(\d+)$")
JQL_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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


@dataclass(frozen=True)
class _JqlAnd:
    terms: tuple["_JqlNode", ...]


@dataclass(frozen=True)
class _JqlOr:
    terms: tuple["_JqlNode", ...]


@dataclass(frozen=True)
class _JqlPredicate:
    field: str
    operator: str
    values: tuple[str, ...] = ()


_JqlNode = _JqlAnd | _JqlOr | _JqlPredicate


class _UnsupportedJql(ValueError):
    pass


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


def _synthesize_jira_search_response(
    cases_dir: Path,
    case_id: str,
    payload: Mapping[str, Any],
) -> dict[str, Any] | None:
    normalized = _normalized_search_payload(payload)
    jql = normalized["jql"].strip()
    try:
        query = _parse_jql(jql) if jql else None
    except _UnsupportedJql:
        return None

    as_of = derive_as_of(cases_dir, case_id)
    matched_issues = []
    for issue in _load_jira_issue_corpus(cases_dir, case_id):
        candidate = reconstruct_issue_as_of(issue, as_of=as_of)
        if _issue_created_after_as_of(candidate, as_of):
            continue
        try:
            if query is None or _jql_matches(query, candidate):
                matched_issues.append(_project_search_issue(candidate, normalized["fields"]))
        except _UnsupportedJql:
            return None

    matched_issues.sort(key=_issue_sort_key)
    start_at = int(payload.get("startAt") or payload.get("start_at") or 0)
    max_results = normalized["maxResults"]
    return {
        "issues": matched_issues[start_at : start_at + max_results],
        "maxResults": max_results,
        "startAt": start_at,
        "total": len(matched_issues),
    }


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


def reconstruct_issue_as_of(issue: Mapping[str, Any], *, as_of: str | None) -> dict[str, Any]:
    payload = copy.deepcopy(dict(issue))
    if as_of is None:
        return payload

    as_of_timestamp = _parse_jira_timestamp(as_of)
    if as_of_timestamp is None:
        return payload

    fields = payload.get("fields")
    if not isinstance(fields, Mapping):
        fields = {}
    fields = copy.deepcopy(dict(fields))
    payload["fields"] = fields

    changelog = payload.get("changelog")
    histories = changelog.get("histories") if isinstance(changelog, Mapping) else None
    if not isinstance(histories, list):
        _scrub_future_issue_fields(fields, as_of_timestamp)
        return payload

    future_histories = []
    for history in histories:
        if not isinstance(history, Mapping):
            continue
        created_at = _parse_jira_timestamp(history.get("created"))
        if created_at is not None and created_at > as_of_timestamp:
            future_histories.append((created_at, history))

    for _, history in sorted(future_histories, key=lambda item: item[0], reverse=True):
        items = history.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, Mapping):
                _rewind_field_from_changelog_item(fields, item)

    updated_at = _parse_jira_timestamp(fields.get("updated"))
    if updated_at is not None and updated_at > as_of_timestamp:
        fields["updated"] = as_of
    resolution_date = _parse_jira_timestamp(fields.get("resolutiondate"))
    if resolution_date is not None and resolution_date > as_of_timestamp:
        fields["resolutiondate"] = None
    _scrub_future_issue_fields(fields, as_of_timestamp)
    return payload


def filter_issue_for_search_as_of(
    issue: Mapping[str, Any],
    *,
    as_of: str | None,
    jql: str,
    detail: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    detail_source = detail if isinstance(detail, Mapping) else issue
    reconstructed_detail = reconstruct_issue_as_of(detail_source, as_of=as_of)
    if not _matches_empty_jql_predicates(reconstructed_detail, jql):
        return None

    projected = copy.deepcopy(dict(issue))
    issue_fields = projected.get("fields")
    detail_fields = reconstructed_detail.get("fields")
    if isinstance(issue_fields, Mapping) and isinstance(detail_fields, Mapping):
        projected_fields = copy.deepcopy(dict(issue_fields))
        for field_name in list(projected_fields):
            if field_name in detail_fields:
                projected_fields[field_name] = copy.deepcopy(detail_fields[field_name])
        projected["fields"] = projected_fields
    return projected


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


def filter_dev_status_as_of(
    summary: Mapping[str, Any],
    details: Mapping[str, Any],
    *,
    as_of: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    filtered_summary = copy.deepcopy(dict(summary))
    filtered_details = copy.deepcopy(dict(details))
    if as_of is None:
        return filtered_summary, filtered_details

    as_of_timestamp = _parse_jira_timestamp(as_of)
    if as_of_timestamp is None:
        return filtered_summary, filtered_details

    repository_counts: dict[str, int] = {}
    for key, detail in list(filtered_details.items()):
        if not isinstance(key, str) or not key.endswith(":repository"):
            continue
        app_type = key.removesuffix(":repository")
        filtered_detail = _filter_dev_status_detail_as_of(detail, as_of_timestamp)
        filtered_details[key] = filtered_detail
        repository_counts[app_type] = _dev_status_repository_count(filtered_detail)

    _apply_dev_status_repository_counts(filtered_summary, repository_counts, as_of)
    _hide_future_dev_status_summaries(filtered_summary, as_of_timestamp)
    return filtered_summary, filtered_details


def jira_replay_miss_line(miss: JiraReplayMiss) -> str:
    return f"{JIRA_REPLAY_MISS_PREFIX} {json.dumps(miss.to_json(), sort_keys=True)}"


def jira_search_replay_miss(url: str, payload: Mapping[str, Any]) -> str:
    return jira_replay_miss_line(
        JiraReplayMiss(kind="jira_search", method="POST", url=url, payload=payload)
    )


def jira_issue_replay_miss(url: str, issue_key: str) -> str:
    return jira_replay_miss_line(
        JiraReplayMiss(
            kind="jira_issue",
            method="GET",
            url=url,
            payload={"issue_key": issue_key},
        )
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
    jql: str | None = None,
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
        filtered_issue = filter_issue_for_search_as_of(
            issue,
            as_of=as_of,
            jql=jql or "",
            detail=detail,
        )
        if filtered_issue is not None:
            kept.append(filtered_issue)
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


def _load_jira_issue_corpus(cases_dir: Path, case_id: str) -> list[dict[str, Any]]:
    jira_dir = cases_dir / "jiras" / case_id
    issue_paths = []
    root_issue_path = jira_dir / "issue.json"
    starting_issue_path = jira_dir / "starting-issue.json"
    if root_issue_path.is_file():
        issue_paths.append(root_issue_path)
    elif starting_issue_path.is_file():
        issue_paths.append(starting_issue_path)

    linked_dir = jira_dir / "linked"
    if linked_dir.is_dir():
        issue_paths.extend(sorted(linked_dir.glob("*/issue.json")))

    issues = []
    for path in issue_paths:
        data = load_json_file(path)
        if isinstance(data, Mapping):
            issues.append(copy.deepcopy(dict(data)))
    return issues


def _parse_jql(jql: str) -> _JqlNode:
    tokens = _tokenize_jql(jql)
    parser = _JqlParser(tokens)
    return parser.parse()


def _tokenize_jql(jql: str) -> list[str]:
    tokens = []
    index = 0
    while index < len(jql):
        char = jql[index]
        if char.isspace():
            index += 1
            continue
        if char == '"':
            value, index = _read_jql_quoted_value(jql, index + 1)
            tokens.append(value)
            continue
        two_char_operator = jql[index : index + 2]
        if two_char_operator in {"!=", ">=", "<="}:
            tokens.append(two_char_operator)
            index += 2
            continue
        if char in {"(", ")", ",", "=", "~", "<", ">"}:
            tokens.append(char)
            index += 1
            continue

        match = re.match(r"[^\s(),=!~<>]+", jql[index:])
        if match is None:
            raise _UnsupportedJql(jql)
        tokens.append(match.group(0))
        index += len(match.group(0))
    return tokens


def _read_jql_quoted_value(jql: str, index: int) -> tuple[str, int]:
    value = []
    while index < len(jql):
        char = jql[index]
        if char == "\\" and index + 1 < len(jql):
            value.append(jql[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(value), index + 1
        value.append(char)
        index += 1
    raise _UnsupportedJql(jql)


class _JqlParser:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse(self) -> _JqlNode:
        if not self._tokens:
            raise _UnsupportedJql("")
        node = self._parse_or()
        if self._peek() is not None:
            raise _UnsupportedJql(" ".join(self._tokens))
        return node

    def _parse_or(self) -> _JqlNode:
        terms = [self._parse_and()]
        while self._match_keyword("OR"):
            terms.append(self._parse_and())
        return terms[0] if len(terms) == 1 else _JqlOr(tuple(terms))

    def _parse_and(self) -> _JqlNode:
        terms = [self._parse_term()]
        while self._match_keyword("AND"):
            terms.append(self._parse_term())
        return terms[0] if len(terms) == 1 else _JqlAnd(tuple(terms))

    def _parse_term(self) -> _JqlNode:
        if self._match("("):
            node = self._parse_or()
            self._expect(")")
            return node
        return self._parse_predicate()

    def _parse_predicate(self) -> _JqlPredicate:
        field = self._expect_value()
        if self._match_keyword("IS"):
            operator = "is not empty" if self._match_keyword("NOT") else "is empty"
            self._expect_keyword("EMPTY")
            return _JqlPredicate(field=field, operator=operator)
        if self._match_keyword("IN"):
            return _JqlPredicate(field=field, operator="in", values=tuple(self._parse_list()))

        operator = self._next()
        if operator not in {"=", "!=", "~", ">=", "<=", ">", "<"}:
            raise _UnsupportedJql(operator or field)
        value = self._expect_value()
        return _JqlPredicate(field=field, operator=operator, values=(value,))

    def _parse_list(self) -> list[str]:
        values = []
        self._expect("(")
        while True:
            values.append(self._expect_value())
            if self._match(","):
                continue
            self._expect(")")
            return values

    def _expect_value(self) -> str:
        value = self._next()
        if value is None or value in {"(", ")", ","}:
            raise _UnsupportedJql(value or "")
        if value.upper() in {"AND", "OR", "IN", "IS", "NOT", "EMPTY"}:
            raise _UnsupportedJql(value)
        return value

    def _expect(self, value: str) -> None:
        if not self._match(value):
            raise _UnsupportedJql(value)

    def _expect_keyword(self, value: str) -> None:
        if not self._match_keyword(value):
            raise _UnsupportedJql(value)

    def _match(self, value: str) -> bool:
        if self._peek() != value:
            return False
        self._index += 1
        return True

    def _match_keyword(self, value: str) -> bool:
        token = self._peek()
        if token is None or token.casefold() != value.casefold():
            return False
        self._index += 1
        return True

    def _next(self) -> str | None:
        token = self._peek()
        if token is not None:
            self._index += 1
        return token

    def _peek(self) -> str | None:
        if self._index >= len(self._tokens):
            return None
        return self._tokens[self._index]


def _jql_matches(node: _JqlNode, issue: Mapping[str, Any]) -> bool:
    if isinstance(node, _JqlAnd):
        return all(_jql_matches(term, issue) for term in node.terms)
    if isinstance(node, _JqlOr):
        return any(_jql_matches(term, issue) for term in node.terms)
    return _predicate_matches(node, issue)


def _predicate_matches(predicate: _JqlPredicate, issue: Mapping[str, Any]) -> bool:
    values = _issue_jql_values(issue, predicate.field)
    wanted = predicate.values
    operator = predicate.operator
    if operator == "=":
        return any(
            _jql_value_equals(value, wanted_value) for value in values for wanted_value in wanted
        )
    if operator == "!=":
        return bool(values) and all(
            not _jql_value_equals(value, wanted_value)
            for value in values
            for wanted_value in wanted
        )
    if operator == "in":
        return any(
            _jql_value_equals(value, wanted_value) for value in values for wanted_value in wanted
        )
    if operator == "~":
        return any(
            _jql_text_matches(value, wanted_value) for value in values for wanted_value in wanted
        )
    if operator == "is empty":
        return not values or all(_empty_jira_value(value) for value in values)
    if operator == "is not empty":
        return any(not _empty_jira_value(value) for value in values)
    if operator in {">=", "<=", ">", "<"}:
        return any(
            _jql_compare(value, wanted_value, operator)
            for value in values
            for wanted_value in wanted
        )
    raise _UnsupportedJql(operator)


def _issue_jql_values(issue: Mapping[str, Any], field: str) -> list[Any]:
    normalized = _normalize_field_name(field)
    fields = issue.get("fields")
    if not isinstance(fields, Mapping):
        fields = {}
    if normalized == "key":
        return [issue.get("key")]
    if normalized == "project":
        project = fields.get("project")
        values = []
        if isinstance(project, Mapping):
            values.extend([project.get("key"), project.get("name")])
        key = issue.get("key")
        if isinstance(key, str) and "-" in key:
            values.append(key.split("-", 1)[0])
        return [value for value in values if value is not None]
    if normalized in {"component", "components"}:
        return _jira_named_values(fields.get("components"))
    if normalized in {"fixversion", "fixversions", "fix version", "fix versions"}:
        return _jira_named_values(fields.get("fixVersions"))
    if normalized == "labels":
        labels = fields.get("labels")
        return list(labels) if isinstance(labels, list) else []
    if normalized in {"issuetype", "issue type", "type"}:
        return _jira_named_values(fields.get("issuetype"))
    if normalized in {"status", "resolution"}:
        return _jira_named_values(fields.get(normalized))
    if normalized in {"summary", "description", "created", "updated"}:
        value = fields.get(normalized)
        return [] if value is None else [value]
    if normalized == "text":
        return _issue_text_values(issue)
    if normalized and normalized.startswith("customfield_"):
        return _flatten_jira_value(fields.get(normalized))
    raise _UnsupportedJql(field)


def _jira_named_values(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return [item for item in (value.get("name"), value.get("value"), value.get("key")) if item]
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_jira_named_values(item))
        return values
    return [] if value is None else [value]


def _issue_text_values(issue: Mapping[str, Any]) -> list[Any]:
    fields = issue.get("fields")
    if not isinstance(fields, Mapping):
        return []
    values = [fields.get("summary"), fields.get("description")]
    comments = fields.get("comment")
    comment_items = comments.get("comments") if isinstance(comments, Mapping) else None
    if isinstance(comment_items, list):
        values.extend(
            comment.get("body") for comment in comment_items if isinstance(comment, Mapping)
        )
    values.extend(_jira_named_values(fields.get("components")))
    labels = fields.get("labels")
    if isinstance(labels, list):
        values.extend(labels)
    return [value for value in values if value is not None]


def _flatten_jira_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        flattened = []
        for item in value:
            flattened.extend(_flatten_jira_value(item))
        return flattened
    if isinstance(value, Mapping):
        named = _jira_named_values(value)
        return named or list(value.values())
    return [value]


def _jql_value_equals(left: Any, right: str) -> bool:
    if left is None:
        return False
    return str(left).casefold() == right.casefold()


def _jql_text_matches(value: Any, query: str) -> bool:
    if value is None:
        return False
    haystack = str(value).casefold()
    needle = query.casefold()
    if needle in haystack:
        return True
    terms = re.findall(r"[a-z0-9]+(?:\.[a-z0-9]+)?", needle)
    return bool(terms) and all(term in haystack for term in terms)


def _jql_compare(left: Any, right: str, operator: str) -> bool:
    key_left = _parse_jira_key(left)
    key_right = _parse_jira_key(right)
    if key_left is not None and key_right is not None and key_left[0] == key_right[0]:
        comparison = (key_left[1] > key_right[1]) - (key_left[1] < key_right[1])
        return _comparison_matches(comparison, operator)

    date_left = _parse_jql_datetime(left, end_of_day=False)
    date_right = _parse_jql_datetime(right, end_of_day=operator in {"<=", ">"})
    if date_left is not None and date_right is not None:
        comparison = (date_left > date_right) - (date_left < date_right)
        return _comparison_matches(comparison, operator)

    comparison = (str(left).casefold() > right.casefold()) - (
        str(left).casefold() < right.casefold()
    )
    return _comparison_matches(comparison, operator)


def _comparison_matches(comparison: int, operator: str) -> bool:
    if operator == ">=":
        return comparison >= 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == "<":
        return comparison < 0
    raise _UnsupportedJql(operator)


def _parse_jira_key(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str):
        return None
    match = JIRA_KEY_PATTERN.fullmatch(value)
    if match is None:
        return None
    return match.group(1).upper(), int(match.group(2))


def _parse_jql_datetime(value: Any, *, end_of_day: bool) -> datetime | None:
    if not isinstance(value, str):
        return None
    if JQL_DATE_PATTERN.fullmatch(value):
        suffix = "T23:59:59.999999Z" if end_of_day else "T00:00:00Z"
        return _parse_jira_timestamp(f"{value}{suffix}")
    return _parse_jira_timestamp(value)


def _issue_created_after_as_of(issue: Mapping[str, Any], as_of: str | None) -> bool:
    if as_of is None:
        return False
    as_of_timestamp = _parse_jira_timestamp(as_of)
    created_timestamp = _parse_jira_timestamp(_issue_field(issue, "created"))
    return (
        as_of_timestamp is not None
        and created_timestamp is not None
        and created_timestamp > as_of_timestamp
    )


def _project_search_issue(issue: Mapping[str, Any], requested_fields: list[str]) -> dict[str, Any]:
    fields = issue.get("fields")
    if not isinstance(fields, Mapping):
        fields = {}
    projected = {
        key: copy.deepcopy(value)
        for key, value in issue.items()
        if key in {"expand", "id", "key", "self"}
    }
    projected["fields"] = {
        field: copy.deepcopy(fields.get(field)) for field in requested_fields if field != "key"
    }
    return projected


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[int, str]:
    key = issue.get("key")
    parsed = _parse_jira_key(key)
    if parsed is None:
        return (0, str(key or ""))
    return (-parsed[1], parsed[0])


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


def _rewind_field_from_changelog_item(fields: dict[str, Any], item: Mapping[str, Any]) -> None:
    field_id = _string_or_none(item.get("fieldId"))
    field_name = _string_or_none(item.get("field"))
    normalized = _normalize_field_name(field_name)
    target = field_id or _default_field_id(normalized)
    if target is None:
        return

    from_string = _string_or_none(item.get("fromString"))
    if target == "status" or normalized == "status":
        fields["status"] = {"name": from_string} if from_string else None
        return
    if target == "resolution" or normalized == "resolution":
        fields["resolution"] = {"name": from_string} if from_string else None
        return
    if target == "labels" or normalized == "labels":
        fields["labels"] = _parse_labels(from_string)
        return
    if target == "fixVersions" or normalized in {"fix version", "fix versions", "fix version/s"}:
        fields["fixVersions"] = _parse_versions(from_string)
        return
    if target.startswith("customfield_"):
        fields[target] = from_string


def _scrub_future_issue_fields(fields: dict[str, Any], as_of: datetime) -> None:
    for field_name in JIRA_DEV_SUMMARY_FIELDS:
        if _value_contains_timestamp_after(fields.get(field_name), as_of):
            fields[field_name] = None
    _scrub_embedded_issue_links(fields, as_of)


def _scrub_embedded_issue_links(fields: dict[str, Any], as_of: datetime) -> None:
    links = fields.get("issuelinks")
    if not isinstance(links, list):
        return
    scrubbed_links = []
    for link in links:
        if not isinstance(link, Mapping):
            scrubbed_links.append(copy.deepcopy(link))
            continue
        link_payload = copy.deepcopy(dict(link))
        for issue_side in ("inwardIssue", "outwardIssue"):
            issue = link_payload.get(issue_side)
            if not isinstance(issue, Mapping):
                continue
            issue_payload = copy.deepcopy(dict(issue))
            issue_fields = issue_payload.get("fields")
            if isinstance(issue_fields, Mapping):
                field_payload = copy.deepcopy(dict(issue_fields))
                for field_name in JIRA_EMBEDDED_LINK_VOLATILE_FIELDS:
                    field_payload.pop(field_name, None)
                for field_name in list(field_payload):
                    if (
                        field_name.startswith("customfield_")
                        and _value_contains_timestamp_after(field_payload[field_name], as_of)
                    ):
                        field_payload.pop(field_name, None)
                issue_payload["fields"] = field_payload
            link_payload[issue_side] = issue_payload
        scrubbed_links.append(link_payload)
    fields["issuelinks"] = scrubbed_links


def _value_contains_timestamp_after(value: Any, as_of: datetime) -> bool:
    if isinstance(value, str):
        for match in JIRA_TIMESTAMP_PATTERN.finditer(value):
            timestamp = _parse_jira_timestamp(match.group(0))
            if timestamp is not None and timestamp > as_of:
                return True
        return False
    if isinstance(value, Mapping):
        return any(_value_contains_timestamp_after(item, as_of) for item in value.values())
    if isinstance(value, list):
        return any(_value_contains_timestamp_after(item, as_of) for item in value)
    return False


def _matches_empty_jql_predicates(issue: Mapping[str, Any], jql: str) -> bool:
    if not jql:
        return True
    fields = issue.get("fields")
    if not isinstance(fields, Mapping):
        fields = {}
    for match in EMPTY_JQL_PATTERN.finditer(jql):
        field_name = match.group("quoted") or match.group("bare") or ""
        field_id = _field_id_for_display_name(issue, field_name)
        if field_id is None:
            continue
        is_empty = _empty_jira_value(fields.get(field_id))
        expects_not_empty = bool(match.group("not"))
        if expects_not_empty == is_empty:
            return False
    return True


def _field_id_for_display_name(issue: Mapping[str, Any], field_name: str) -> str | None:
    normalized = _normalize_field_name(field_name)
    default = _default_field_id(normalized)
    if default is not None:
        return default
    changelog = issue.get("changelog")
    histories = changelog.get("histories") if isinstance(changelog, Mapping) else None
    if not isinstance(histories, list):
        return None
    for history in histories:
        if not isinstance(history, Mapping):
            continue
        items = history.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping):
                continue
            if _normalize_field_name(_string_or_none(item.get("field"))) == normalized:
                return _string_or_none(item.get("fieldId"))
    return None


def _default_field_id(normalized_field_name: str | None) -> str | None:
    if not normalized_field_name:
        return None
    if normalized_field_name in {"status", "resolution", "labels"}:
        return normalized_field_name
    if normalized_field_name in {"fix version", "fix versions", "fix version/s"}:
        return "fixVersions"
    aliases = JIRA_FIELD_ALIASES.get(normalized_field_name)
    return aliases[0] if aliases else None


def _empty_jira_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return not value
    return False


def _parse_labels(value: str | None) -> list[str]:
    if not value:
        return []
    return [label for label in value.split() if label]


def _parse_versions(value: str | None) -> list[dict[str, str]]:
    if not value:
        return []
    names = [name.strip() for name in re.split(r"[,;]", value) if name.strip()]
    return [{"name": name} for name in names]


def _normalize_field_name(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"\s+", " ", value.strip().casefold())


def _string_or_none(value: Any) -> str | None:
    if isinstance(value, str):
        return value
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


def _filter_dev_status_detail_as_of(detail: Any, as_of: datetime) -> list[Any]:
    if not isinstance(detail, list):
        return []
    output = []
    for entry in detail:
        if not isinstance(entry, Mapping):
            output.append(copy.deepcopy(entry))
            continue
        filtered_entry = copy.deepcopy(dict(entry))
        repositories = filtered_entry.get("repositories")
        if isinstance(repositories, list):
            filtered_repositories = []
            for repository in repositories:
                if not isinstance(repository, Mapping):
                    filtered_repositories.append(copy.deepcopy(repository))
                    continue
                filtered_repository = copy.deepcopy(dict(repository))
                commits = filtered_repository.get("commits")
                if isinstance(commits, list):
                    filtered_commits = [
                        copy.deepcopy(commit)
                        for commit in commits
                        if not _dev_status_item_is_future(commit, as_of)
                    ]
                    filtered_repository["commits"] = filtered_commits
                    if not filtered_commits:
                        continue
                filtered_repositories.append(filtered_repository)
            filtered_entry["repositories"] = filtered_repositories
            if not filtered_repositories:
                continue
        output.append(filtered_entry)
    return output


def _dev_status_item_is_future(item: Any, as_of: datetime) -> bool:
    if not isinstance(item, Mapping):
        return False
    for field in (
        "authorTimestamp",
        "authorTimestampMillis",
        "authored_date",
        "committed_date",
        "created_at",
        "updated_at",
        "date",
    ):
        timestamp = _parse_dev_status_timestamp(item.get(field))
        if timestamp is not None:
            return timestamp > as_of
    author = item.get("author")
    if isinstance(author, Mapping):
        timestamp = _parse_dev_status_timestamp(author.get("timestamp"))
        if timestamp is not None:
            return timestamp > as_of
    return False


def _parse_dev_status_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        candidate = value / 1000 if value > 10_000_000_000 else value
        try:
            return datetime.fromtimestamp(candidate, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    return _parse_jira_timestamp(value)


def _dev_status_repository_count(detail: Any) -> int:
    if not isinstance(detail, list):
        return 0
    count = 0
    for entry in detail:
        if not isinstance(entry, Mapping):
            continue
        repositories = entry.get("repositories")
        if not isinstance(repositories, list):
            continue
        count += sum(1 for repository in repositories if isinstance(repository, Mapping))
    return count


def _apply_dev_status_repository_counts(
    summary: dict[str, Any],
    repository_counts: Mapping[str, int],
    as_of: str,
) -> None:
    if not repository_counts:
        return
    repository = summary.get("repository")
    if not isinstance(repository, Mapping):
        return
    repository_payload = copy.deepcopy(dict(repository))
    summary["repository"] = repository_payload

    by_instance = repository_payload.get("byInstanceType")
    if isinstance(by_instance, Mapping):
        by_instance_payload = copy.deepcopy(dict(by_instance))
    else:
        by_instance_payload = {}
    for app_type, count in repository_counts.items():
        entry = by_instance_payload.get(app_type)
        if isinstance(entry, Mapping):
            entry_payload = copy.deepcopy(dict(entry))
        else:
            entry_payload = {"name": app_type}
        entry_payload["count"] = count
        by_instance_payload[app_type] = entry_payload
    repository_payload["byInstanceType"] = by_instance_payload

    overall = repository_payload.get("overall")
    if isinstance(overall, Mapping):
        overall_payload = copy.deepcopy(dict(overall))
    else:
        overall_payload = {"dataType": "repository"}
    total = sum(repository_counts.values())
    overall_payload["count"] = total
    if total:
        overall_payload["lastUpdated"] = as_of
    else:
        overall_payload.pop("lastUpdated", None)
    repository_payload["overall"] = overall_payload


def _hide_future_dev_status_summaries(summary: dict[str, Any], as_of: datetime) -> None:
    for name, payload in list(summary.items()):
        if not isinstance(payload, Mapping):
            continue
        overall = payload.get("overall")
        if not isinstance(overall, Mapping):
            continue
        last_updated = _parse_jira_timestamp(overall.get("lastUpdated"))
        if last_updated is None or last_updated <= as_of:
            continue
        replacement = copy.deepcopy(dict(payload))
        overall_payload = copy.deepcopy(dict(overall))
        for field in ("count", "stateCount", "open", "merged", "declined"):
            if isinstance(overall_payload.get(field), int):
                overall_payload[field] = 0
        overall_payload.pop("lastUpdated", None)
        replacement["overall"] = overall_payload
        by_instance = replacement.get("byInstanceType")
        if isinstance(by_instance, Mapping):
            by_instance_payload = {}
            for app_type, entry in by_instance.items():
                if isinstance(entry, Mapping):
                    entry_payload = copy.deepcopy(dict(entry))
                    if isinstance(entry_payload.get("count"), int):
                        entry_payload["count"] = 0
                    by_instance_payload[app_type] = entry_payload
                else:
                    by_instance_payload[app_type] = copy.deepcopy(entry)
            replacement["byInstanceType"] = by_instance_payload
        summary[name] = replacement
