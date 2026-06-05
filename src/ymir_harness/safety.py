from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

GIT_OPTIONS_WITH_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
WRITE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CURL_URL_OPTIONS = {"--url"}
CURL_OPTIONS_WITH_VALUES = {
    "-A",
    "-b",
    "-c",
    "-d",
    "-e",
    "-F",
    "-H",
    "-K",
    "-m",
    "-o",
    "-u",
    "-X",
    "--cacert",
    "--cert",
    "--config",
    "--connect-timeout",
    "--connect-to",
    "--cookie",
    "--cookie-jar",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--header",
    "--interface",
    "--key",
    "--limit-rate",
    "--max-time",
    "--output",
    "--proxy",
    "--proxy-header",
    "--proxy-user",
    "--referer",
    "--request",
    "--resolve",
    "--user",
    "--user-agent",
}
WGET_OPTIONS_WITH_VALUES = {
    "-O",
    "-P",
    "-U",
    "-o",
    "--append-output",
    "--bind-address",
    "--body-data",
    "--body-file",
    "--ca-certificate",
    "--certificate",
    "--config",
    "--directory-prefix",
    "--header",
    "--http-password",
    "--http-user",
    "--load-cookies",
    "--output-document",
    "--output-file",
    "--post-data",
    "--post-file",
    "--referer",
    "--user-agent",
}


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


def detect_replay_violations(
    events: Sequence[Mapping[str, Any]],
    *,
    recorded_urls: Iterable[str],
) -> list[str]:
    recorded_url_set = set(recorded_urls)
    violations = []
    for event in events:
        url = _event_string(event, "url")
        if not url or not _is_external_http_url(url):
            continue
        if url not in recorded_url_set:
            violations.append(f"unrecorded URL: {url}")
    return _dedupe_strings(violations)


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
    if "greenwave" in host or host == "gating-status.osci.redhat.com":
        return UnsafeOperation("greenwave_mutation", f"GreenWave mutation: {detail}", source)
    if "resultsdb" in host:
        return UnsafeOperation("resultsdb_mutation", f"ResultsDB mutation: {detail}", source)
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


def _is_external_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _command_tokens(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return [str(part) for part in command]


def _command_replay_urls(command: str | Sequence[str]) -> list[str]:
    tokens = _command_tokens(command)
    if not tokens:
        return []

    program = _program_name(tokens[0])
    if program not in {"curl", "wget"}:
        return []

    urls = []
    skip_next = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if skip_next:
            skip_next = False
            index += 1
            continue
        if token == "--":
            urls.extend(url for url in tokens[index + 1 :] if _is_external_http_url(url))
            break
        if program == "curl" and _is_curl_url_option(token):
            option_url = _option_value(token, tokens, index)
            if option_url and _is_external_http_url(option_url):
                urls.append(option_url)
            skip_next = "=" not in token
            index += 1
            continue
        if _download_option_consumes_value(program, token):
            skip_next = "=" not in token and _short_option_value(token) is None
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _is_external_http_url(token):
            urls.append(token)
        index += 1
    return urls


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


def _is_curl_url_option(token: str) -> bool:
    option, separator, _ = token.partition("=")
    return token in CURL_URL_OPTIONS or bool(separator and option in CURL_URL_OPTIONS)


def _option_value(tokens_option: str, tokens: Sequence[str], index: int) -> str | None:
    _, separator, value = tokens_option.partition("=")
    if separator:
        return value
    if index + 1 < len(tokens):
        return tokens[index + 1]
    return None


def _download_option_consumes_value(program: str, token: str) -> bool:
    options = CURL_OPTIONS_WITH_VALUES if program == "curl" else WGET_OPTIONS_WITH_VALUES
    option, separator, _ = token.partition("=")
    if separator:
        return option in options
    if token in options:
        return True
    return _short_option_value(token) in options


def _short_option_value(token: str) -> str | None:
    if not token.startswith("-") or token.startswith("--") or len(token) < 3:
        return None
    return token[:2]


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


def _dedupe_strings(values: Sequence[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _program_name(command: str) -> str:
    return PurePosixPath(command).name
