from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

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
        if url and _is_external_http_url(url) and url not in recorded_url_set:
            violations.append(f"unrecorded URL: {url}")
        for command in _event_commands(event):
            for command_url in _command_replay_urls(command):
                if command_url not in recorded_url_set:
                    violations.append(f"unrecorded URL: {command_url}")
    return _dedupe_strings(violations)


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
