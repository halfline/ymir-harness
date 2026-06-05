from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

GIT_OPTIONS_WITH_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
WRITE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class UnsafeOperation:
    category: str
    detail: str
    source: str | None = None

    def to_json(self) -> dict[str, str]:
        payload = {
            "category": self.category,
            "detail": self.detail,
        }
        if self.source:
            payload["source"] = self.source
        return payload


def detect_unsafe_operations(events: Sequence[Mapping[str, Any]]) -> list[UnsafeOperation]:
    operations = []
    for event in events:
        source = _event_string(event, "tool") or _event_string(event, "source")
        for command in _event_commands(event):
            operations.extend(detect_unsafe_command(command, source=source))

        method = _event_string(event, "method")
        url = _event_string(event, "url")
        if method and url:
            operation = detect_unsafe_http_request(method, url, source=source)
            if operation:
                operations.append(operation)

    return _dedupe_operations(operations)


def detect_unsafe_command(
    command: str | Sequence[str], *, source: str | None = None
) -> list[UnsafeOperation]:
    tokens = _command_tokens(command)
    if not tokens:
        return []

    operations = []
    display = shlex.join(tokens)
    git_subcommand = _git_subcommand(tokens)

    if git_subcommand == "push":
        operations.append(UnsafeOperation("git_push", f"git push: {display}", source))
    if _is_rhpkg_lookaside_upload_command(tokens):
        operations.append(
            UnsafeOperation("lookaside_upload", f"rhpkg lookaside upload: {display}", source)
        )
    if _is_brew_build_submission_command(tokens):
        operations.append(
            UnsafeOperation("build_submission", f"brew build submission: {display}", source)
        )
    if _is_koji_build_submission_command(tokens):
        operations.append(
            UnsafeOperation("build_submission", f"koji build submission: {display}", source)
        )
    if _is_copr_build_submission_command(tokens):
        operations.append(
            UnsafeOperation("build_submission", f"copr build submission: {display}", source)
        )
    if _is_konflux_build_submission_command(tokens):
        operations.append(
            UnsafeOperation("build_submission", f"konflux build submission: {display}", source)
        )

    return _dedupe_operations(operations)


def detect_unsafe_http_request(
    method: str,
    url: str,
    *,
    source: str | None = None,
) -> UnsafeOperation | None:
    normalized_method = method.upper()
    if normalized_method not in WRITE_HTTP_METHODS:
        return None

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    detail = f"{normalized_method} {url}"
    if "jira" in host or "/rest/api/" in path or "/rest/greenhopper/" in path:
        return UnsafeOperation("jira_write", f"Jira write: {detail}", source)
    if "gitlab" in host and any(
        segment in path for segment in ("fork", "labels", "merge_requests")
    ):
        return UnsafeOperation("gitlab_write", f"GitLab write: {detail}", source)
    if "errata" in host:
        return UnsafeOperation("errata_write", f"Errata write: {detail}", source)
    if "testing-farm" in host:
        return UnsafeOperation(
            "testing_farm_submission", f"Testing Farm submission: {detail}", source
        )
    return None


def _event_commands(event: Mapping[str, Any]) -> list[str | Sequence[str]]:
    commands = []
    for key in ("command", "argv"):
        value = event.get(key)
        if isinstance(value, str):
            commands.append(value)
        elif isinstance(value, Sequence) and not isinstance(value, bytes):
            commands.append([str(part) for part in value])
    return commands


def _event_string(event: Mapping[str, Any], key: str) -> str | None:
    value = event.get(key)
    return value if isinstance(value, str) else None


def _command_tokens(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return [str(part) for part in command]


def _git_subcommand(tokens: Sequence[str]) -> str | None:
    if not tokens or _program_name(tokens[0]) != "git":
        return None

    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in GIT_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in GIT_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token

    return None


def _is_rhpkg_lookaside_upload_command(tokens: Sequence[str]) -> bool:
    if len(tokens) < 2 or _program_name(tokens[0]) != "rhpkg":
        return False
    return tokens[1] in {"new-sources", "upload"}


def _is_brew_build_submission_command(tokens: Sequence[str]) -> bool:
    if len(tokens) < 2 or _program_name(tokens[0]) != "brew":
        return False
    return tokens[1] == "build"


def _is_koji_build_submission_command(tokens: Sequence[str]) -> bool:
    if len(tokens) < 2 or _program_name(tokens[0]) != "koji":
        return False
    return tokens[1] == "build"


def _is_copr_build_submission_command(tokens: Sequence[str]) -> bool:
    if len(tokens) < 2 or _program_name(tokens[0]) != "copr":
        return False
    return tokens[1] == "build"


def _is_konflux_build_submission_command(tokens: Sequence[str]) -> bool:
    if len(tokens) < 2 or _program_name(tokens[0]) != "konflux":
        return False
    return tokens[1] == "build"


def _dedupe_operations(operations: Sequence[UnsafeOperation]) -> list[UnsafeOperation]:
    seen = set()
    unique = []
    for operation in operations:
        key = (operation.category, operation.detail, operation.source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(operation)
    return unique


def _program_name(command: str) -> str:
    return PurePosixPath(command).name
