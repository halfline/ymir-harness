from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ymir_harness.jira_replay import filter_dev_status_as_of, reconstruct_issue_as_of


class JiraMockMaterializationError(RuntimeError):
    """Raised when structured Jira fixtures cannot be prepared for Ymir."""


def structured_jira_fixture_dir(cases_dir: Path, case_id: str) -> Path:
    return cases_dir / "jiras" / case_id


def has_structured_jira_fixture(cases_dir: Path, case_id: str) -> bool:
    return structured_jira_fixture_dir(cases_dir, case_id).is_dir()


def ymir_jira_mock_dir(results_dir: Path, repetition: int) -> Path:
    return results_dir / f"repeat-{repetition}" / "jira-mock"


def materialize_ymir_jira_mock(
    cases_dir: Path,
    results_dir: Path,
    case_id: str,
    *,
    repetition: int,
) -> Path:
    target_dir = ymir_jira_mock_dir(results_dir, repetition)
    target_dir.mkdir(parents=True, exist_ok=True)

    root_fixture_dir = structured_jira_fixture_dir(cases_dir, case_id)
    root_as_of = _fixture_as_of(root_fixture_dir)
    fixture_dirs = [(case_id, root_fixture_dir)]
    linked_root = root_fixture_dir / "linked"
    if linked_root.is_dir():
        fixture_dirs.extend(
            (path.name, path)
            for path in sorted(linked_root.iterdir())
            if path.is_dir() and (path / "issue.json").is_file()
        )

    payloads: dict[str, dict[str, Any]] = {}
    for fixture_id, fixture_dir in fixture_dirs:
        payloads[fixture_id] = _build_ymir_jira_mock_issue_from_dir(
            fixture_dir,
            fixture_id,
            fallback_as_of=root_as_of,
        )

    for payload in payloads.values():
        _normalize_embedded_issue_links(payload, payloads)

    for fixture_id, payload in payloads.items():
        target_path = target_dir / fixture_id
        target_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return target_dir


def build_ymir_jira_mock_issue(cases_dir: Path, case_id: str) -> dict[str, Any]:
    jira_dir = structured_jira_fixture_dir(cases_dir, case_id)
    return _build_ymir_jira_mock_issue_from_dir(jira_dir, case_id)


def _build_ymir_jira_mock_issue_from_dir(
    jira_dir: Path,
    case_id: str,
    *,
    fallback_as_of: str | None = None,
) -> dict[str, Any]:
    starting_issue_path = jira_dir / "starting-issue.json"
    issue_path = starting_issue_path if starting_issue_path.is_file() else jira_dir / "issue.json"
    uses_starting_issue = issue_path == starting_issue_path
    issue = _load_json(issue_path, required=True)
    if not isinstance(issue, Mapping):
        raise JiraMockMaterializationError(
            f"Jira issue fixture must contain an object: {issue_path}"
        )

    payload = copy.deepcopy(dict(issue))
    key = payload.get("key")
    if key is None:
        payload["key"] = case_id
    elif key != case_id:
        raise JiraMockMaterializationError(
            f"Jira issue key must match case_id {case_id}: {issue_path}"
        )

    fields = payload.get("fields")
    if fields is None:
        fields = {}
    elif not isinstance(fields, Mapping):
        raise JiraMockMaterializationError(f"Jira issue fields must be an object: {issue_path}")
    else:
        fields = copy.deepcopy(dict(fields))
    payload["fields"] = fields
    as_of = _fixture_as_of(jira_dir) or fallback_as_of

    comments_path = jira_dir / "comments.json"
    links_path = jira_dir / "links.json"
    comments = None if uses_starting_issue else _load_json(comments_path, required=False)
    links = None if uses_starting_issue else _load_json(links_path, required=False)
    has_comments_fixture = not uses_starting_issue and comments_path.exists()
    has_links_fixture = not uses_starting_issue and links_path.exists()

    fields["comment"] = _normalized_comment_block(
        comments,
        fields.get("comment"),
        comments_path if has_comments_fixture else issue_path,
        comments_required=has_comments_fixture,
    )
    payload["remote_links"] = _normalized_remote_links(
        links,
        payload.get("remote_links"),
        links_path if has_links_fixture else issue_path,
        links_required=has_links_fixture,
    )
    dev_status = _load_json(jira_dir / "dev-status.json", required=False)
    if isinstance(dev_status, Mapping):
        summary = dev_status.get("summary")
        details = dev_status.get("details")
        filtered_summary, filtered_details = filter_dev_status_as_of(
            summary if isinstance(summary, Mapping) else {},
            details if isinstance(details, Mapping) else {},
            as_of=as_of,
        )
        payload["dev_status"] = {
            key: copy.deepcopy(value)
            for key, value in {
                **dev_status,
                "summary": filtered_summary,
                "details": filtered_details,
            }.items()
            if key not in {"schema_version", "case_id", "case_type", "reconstruction"}
        }
    if as_of:
        payload = reconstruct_issue_as_of(payload, as_of=as_of)
    return payload


def _load_json(path: Path, *, required: bool) -> Any:
    if not path.is_file():
        if required:
            raise JiraMockMaterializationError(f"required Jira fixture is missing: {path}")
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise JiraMockMaterializationError(f"cannot read Jira fixture {path}: {exc}") from exc


def _fixture_as_of(jira_dir: Path) -> str | None:
    for name in ("reconstruction.json", "dev-status.json"):
        data = _load_json(jira_dir / name, required=False)
        if not isinstance(data, Mapping):
            continue
        as_of = data.get("as_of")
        if isinstance(as_of, str) and as_of:
            return as_of
        reconstruction = data.get("reconstruction")
        if isinstance(reconstruction, Mapping):
            as_of = reconstruction.get("as_of")
            if isinstance(as_of, str) and as_of:
                return as_of
    return None


def _normalized_comment_block(
    comments: Any,
    issue_comment: Any,
    path: Path,
    *,
    comments_required: bool,
) -> dict[str, Any]:
    source = comments if comments is not None else issue_comment
    if source is None:
        return _comment_payload([])

    if isinstance(source, list):
        return _comment_payload(copy.deepcopy(source))

    if not isinstance(source, Mapping):
        source_name = "comments fixture" if comments_required else "issue fields.comment"
        raise JiraMockMaterializationError(f"Jira {source_name} must be an object or list: {path}")

    if comments_required and "comments" not in source:
        raise JiraMockMaterializationError(f"Jira comments fixture must contain comments: {path}")

    comment_values = source.get("comments", [])
    if not isinstance(comment_values, list):
        raise JiraMockMaterializationError(f"Jira comments must be a list: {path}")

    payload = {
        key: copy.deepcopy(value)
        for key, value in source.items()
        if key not in {"schema_version", "case_id", "case_type"}
    }
    payload["comments"] = copy.deepcopy(comment_values)
    payload.setdefault("startAt", 0)
    payload.setdefault("maxResults", len(comment_values))
    payload.setdefault("total", len(comment_values))
    return payload


def _comment_payload(comments: list[Any]) -> dict[str, Any]:
    return {
        "comments": comments,
        "maxResults": len(comments),
        "startAt": 0,
        "total": len(comments),
    }


def _normalized_remote_links(
    links: Any,
    issue_links: Any,
    path: Path,
    *,
    links_required: bool,
) -> list[Any]:
    source = links if links is not None else issue_links
    if source is None:
        return []

    if isinstance(source, list):
        return copy.deepcopy(source)

    if not isinstance(source, Mapping):
        source_name = "links fixture" if links_required else "issue remote_links"
        raise JiraMockMaterializationError(f"Jira {source_name} must be an object or list: {path}")

    if "links" in source:
        link_values = source["links"]
    elif "remote_links" in source:
        link_values = source["remote_links"]
    elif links_required:
        raise JiraMockMaterializationError(f"Jira links fixture must contain links: {path}")
    else:
        link_values = []

    if not isinstance(link_values, list):
        raise JiraMockMaterializationError(f"Jira remote links must be a list: {path}")
    return copy.deepcopy(link_values)


def _normalize_embedded_issue_links(
    payload: dict[str, Any],
    payloads_by_key: Mapping[str, Mapping[str, Any]],
) -> None:
    fields = payload.get("fields")
    if not isinstance(fields, Mapping):
        return
    links = fields.get("issuelinks")
    if not isinstance(links, list):
        return

    normalized_links = []
    for link in links:
        if not isinstance(link, Mapping):
            normalized_links.append(copy.deepcopy(link))
            continue
        link_payload = copy.deepcopy(dict(link))
        for issue_side in ("inwardIssue", "outwardIssue"):
            issue = link_payload.get(issue_side)
            if isinstance(issue, Mapping):
                link_payload[issue_side] = _normalize_embedded_issue(issue, payloads_by_key)
        normalized_links.append(link_payload)
    fields["issuelinks"] = normalized_links


def _normalize_embedded_issue(
    issue: Mapping[str, Any],
    payloads_by_key: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    issue_payload = copy.deepcopy(dict(issue))
    issue_key = issue_payload.get("key")
    source = payloads_by_key.get(str(issue_key)) if issue_key is not None else None
    if not isinstance(source, Mapping):
        return issue_payload
    source_fields = source.get("fields")
    if not isinstance(source_fields, Mapping):
        return issue_payload

    embedded_fields = issue_payload.get("fields")
    if isinstance(embedded_fields, Mapping):
        field_payload = copy.deepcopy(dict(embedded_fields))
    else:
        field_payload = {}

    for field_name in (
        "components",
        "fixVersions",
        "issuetype",
        "priority",
        "resolution",
        "resolutiondate",
        "status",
        "summary",
        "updated",
        "versions",
    ):
        if field_name in source_fields:
            field_payload[field_name] = copy.deepcopy(source_fields[field_name])
    issue_payload["fields"] = field_payload
    return issue_payload
