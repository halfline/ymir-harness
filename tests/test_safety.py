from __future__ import annotations

from ymir_harness.safety import detect_replay_violations


def test_detect_replay_violations_reports_unrecorded_http_events() -> None:
    violations = detect_replay_violations(
        [
            {
                "tool": "http",
                "method": "GET",
                "url": "https://example.invalid/advisory",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": "https://example.invalid/recorded",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": "https://example.invalid/advisory",
            },
        ],
        recorded_urls={"https://example.invalid/recorded"},
    )

    assert violations == ["unrecorded URL: https://example.invalid/advisory"]


def test_detect_replay_violations_ignores_recorded_and_local_events() -> None:
    violations = detect_replay_violations(
        [
            {
                "tool": "http",
                "method": "GET",
                "url": "https://example.invalid/recorded",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": "file:///tmp/cache/advisory.html",
            },
            {"tool": "http", "method": "GET", "url": "/tmp/cache/advisory.html"},
            {"tool": "shell", "command": "python fetch.py https://example.invalid/advisory"},
        ],
        recorded_urls={"https://example.invalid/recorded"},
    )

    assert violations == []


def test_detect_replay_violations_reports_shell_download_urls() -> None:
    violations = detect_replay_violations(
        [
            {
                "tool": "shell",
                "command": (
                    "curl -fsSL -H 'Referer: https://example.invalid/header' "
                    "https://example.invalid/advisory"
                ),
            },
            {
                "tool": "shell",
                "argv": [
                    "wget",
                    "--output-document",
                    "advisory.html",
                    "https://example.invalid/recorded",
                ],
            },
            {
                "tool": "shell",
                "command": "curl --url https://example.invalid/extra",
            },
            {
                "tool": "shell",
                "argv": [
                    "wget",
                    "--header=Referer: https://example.invalid/header",
                    "https://example.invalid/source.tar.gz",
                ],
            },
        ],
        recorded_urls={"https://example.invalid/recorded"},
    )

    assert violations == [
        "unrecorded URL: https://example.invalid/advisory",
        "unrecorded URL: https://example.invalid/extra",
        "unrecorded URL: https://example.invalid/source.tar.gz",
    ]
