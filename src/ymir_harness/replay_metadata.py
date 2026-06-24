from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any


CHANGELOG_AUTHOR_ENV = "YMIR_BENCHMARK_CHANGELOG_AUTHOR"
CHANGELOG_EMAIL_ENV = "YMIR_BENCHMARK_CHANGELOG_EMAIL"
CHANGELOG_DATE_ENV = "YMIR_BENCHMARK_CHANGELOG_DATE"


@dataclass(frozen=True)
class ReplayChangelogContext:
    author: str
    email: str | None
    timestamp: date
    git_timestamp: str


def replay_metadata_environment(cases_dir: Path, case_id: str) -> dict[str, str]:
    context = recorded_changelog_context(cases_dir, case_id)
    if context is None:
        return {}

    env = {
        CHANGELOG_AUTHOR_ENV: context.author,
        CHANGELOG_DATE_ENV: context.timestamp.isoformat(),
        "GIT_AUTHOR_NAME": context.author,
        "GIT_AUTHOR_DATE": context.git_timestamp,
        "GIT_COMMITTER_NAME": context.author,
        "GIT_COMMITTER_DATE": context.git_timestamp,
    }
    if context.email:
        env[CHANGELOG_EMAIL_ENV] = context.email
        env["GIT_AUTHOR_EMAIL"] = context.email
        env["GIT_COMMITTER_EMAIL"] = context.email
    return env


def recorded_changelog_context(
    cases_dir: Path,
    case_id: str,
) -> ReplayChangelogContext | None:
    commit = _recorded_gitlab_commit(cases_dir, case_id)
    if commit is None:
        return None

    author = _string_or_none(commit.get("author_name") or commit.get("committer_name"))
    if author is None:
        return None
    timestamp_text = _string_or_none(
        commit.get("committed_date") or commit.get("authored_date") or commit.get("created_at")
    )
    if timestamp_text is None:
        return None
    timestamp = _parse_iso_datetime(timestamp_text)
    if timestamp is None:
        return None

    return ReplayChangelogContext(
        author=author,
        email=_string_or_none(commit.get("author_email") or commit.get("committer_email")),
        timestamp=timestamp.date(),
        git_timestamp=timestamp_text,
    )


def changelog_context_from_environment(
    env: Mapping[str, str],
) -> ReplayChangelogContext | None:
    author = _string_or_none(env.get(CHANGELOG_AUTHOR_ENV))
    if author is None:
        return None
    timestamp_text = _string_or_none(env.get(CHANGELOG_DATE_ENV))
    if timestamp_text is None:
        return None
    timestamp = _parse_iso_date(timestamp_text)
    if timestamp is None:
        return None

    return ReplayChangelogContext(
        author=author,
        email=_string_or_none(env.get(CHANGELOG_EMAIL_ENV)),
        timestamp=timestamp,
        git_timestamp=timestamp_text,
    )


def _recorded_gitlab_commit(cases_dir: Path, case_id: str) -> Mapping[str, Any] | None:
    path = cases_dir / "web_cache" / case_id / "gitlab" / "commits.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, list):
        return None
    for item in payload:
        if isinstance(item, Mapping):
            return item
    return None


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_iso_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        parsed = _parse_iso_datetime(value)
        return parsed.date() if parsed is not None else None


def _string_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
