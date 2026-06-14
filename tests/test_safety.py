from __future__ import annotations

from ymir_harness.safety import (
    detect_replay_violations,
    detect_unsafe_operations,
)


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


def test_detect_unsafe_operations_reports_git_push() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "shell",
                "argv": ["git", "-C", "repo", "push", "origin", "HEAD"],
            }
        ]
    )

    assert [operation.category for operation in operations] == ["git_push"]
    assert operations[0].source == "shell"
    assert operations[0].to_json() == {
        "category": "git_push",
        "detail": "git push: git -C repo push origin HEAD",
        "source": "shell",
    }


def test_detect_unsafe_operations_reports_shell_string_git_push() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "source": "run-shell-command",
                "command": "git --git-dir=/tmp/repo/.git push origin HEAD",
            }
        ]
    )

    assert [operation.category for operation in operations] == ["git_push"]
    assert operations[0].source == "run-shell-command"
    assert operations[0].detail == ("git push: git --git-dir=/tmp/repo/.git push origin HEAD")



def test_detect_unsafe_operations_reports_rhpkg_lookaside_uploads() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "shell",
                "argv": ["rhpkg", "new-sources", "source.tar.gz"],
            },
            {
                "source": "run-shell-command",
                "command": "rhpkg upload source.tar.gz",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "lookaside_upload",
        "lookaside_upload",
    ]
    assert operations[0].detail == "rhpkg lookaside upload: rhpkg new-sources source.tar.gz"
    assert operations[1].detail == "rhpkg lookaside upload: rhpkg upload source.tar.gz"


def test_detect_unsafe_operations_reports_brew_build_submissions() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "shell",
                "argv": ["brew", "build", "c9s", "package.src.rpm"],
            },
            {
                "source": "run-shell-command",
                "command": "brew build --scratch c9s package.src.rpm",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "build_submission",
        "build_submission",
    ]
    assert operations[0].detail == "brew build submission: brew build c9s package.src.rpm"
    assert operations[1].detail == (
        "brew build submission: brew build --scratch c9s package.src.rpm"
    )


def test_detect_unsafe_operations_reports_koji_build_submissions() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "shell",
                "argv": ["koji", "build", "c9s", "package.src.rpm"],
            },
            {
                "source": "run-shell-command",
                "command": "koji build --scratch c9s package.src.rpm",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "build_submission",
        "build_submission",
    ]
    assert operations[0].detail == "koji build submission: koji build c9s package.src.rpm"
    assert operations[1].detail == (
        "koji build submission: koji build --scratch c9s package.src.rpm"
    )


def test_detect_unsafe_operations_reports_copr_build_submissions() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "shell",
                "argv": ["copr", "build", "owner/project", "package.src.rpm"],
            },
            {
                "source": "run-shell-command",
                "command": "copr build owner/project package.src.rpm",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "build_submission",
        "build_submission",
    ]
    assert operations[0].detail == (
        "copr build submission: copr build owner/project package.src.rpm"
    )
    assert operations[1].detail == (
        "copr build submission: copr build owner/project package.src.rpm"
    )


def test_detect_unsafe_operations_reports_konflux_build_submissions() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "shell",
                "argv": ["konflux", "build", "component"],
            },
            {
                "source": "run-shell-command",
                "command": "konflux build --namespace tenant component",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "build_submission",
        "build_submission",
    ]
    assert operations[0].detail == "konflux build submission: konflux build component"
    assert operations[1].detail == (
        "konflux build submission: konflux build --namespace tenant component"
    )


def test_detect_unsafe_operations_ignores_read_only_events() -> None:
    operations = detect_unsafe_operations(
        [
            {"tool": "shell", "command": "git status --short"},
            {"tool": "shell", "command": "rhpkg sources"},
            {"tool": "shell", "command": "brew list-tags package"},
            {"tool": "shell", "command": "koji list-tags package"},
            {"tool": "shell", "command": "copr list owner"},
            {"tool": "shell", "command": "konflux list components"},
            {
                "tool": "http",
                "method": "GET",
                "url": "https://jira.example/rest/api/2/issue/RHEL-12345",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": "https://errata.engineering.redhat.com/api/v1/erratum/12345",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": "https://api.testing-farm.io/v0.1/requests/abc-123",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": "https://gating-status.osci.redhat.com/query?nvr=package-1.0-1",
            },
            {
                "tool": "http",
                "method": "GET",
                "url": (
                    "https://resultsdb-api.engineering.redhat.com/api/v2.0/results"
                    "?item=package-1.0-1"
                ),
            },
            {
                "tool": "shell",
                "command": "curl https://gitlab.com/api/v4/projects/1/merge_requests",
            },
        ]
    )

    assert operations == []
