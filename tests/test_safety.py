from __future__ import annotations

from ymir_harness.safety import detect_replay_violations, detect_unsafe_operations


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
            {"tool": "shell", "command": "curl https://example.invalid/advisory"},
        ],
        recorded_urls={"https://example.invalid/recorded"},
    )

    assert violations == []


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


def test_detect_unsafe_operations_reports_jira_write_events() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "http",
                "method": "POST",
                "url": "https://jira.example/rest/api/2/issue/RHEL-12345/comment",
            },
            {
                "tool": "http",
                "method": "PATCH",
                "url": "https://issues.example/rest/api/2/issue/RHEL-12345",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "jira_write",
        "jira_write",
    ]
    assert operations[0].detail == (
        "Jira write: POST https://jira.example/rest/api/2/issue/RHEL-12345/comment"
    )
    assert operations[1].detail == (
        "Jira write: PATCH https://issues.example/rest/api/2/issue/RHEL-12345"
    )


def test_detect_unsafe_operations_reports_gitlab_write_events() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "http",
                "method": "POST",
                "url": "https://gitlab.com/api/v4/projects/1/merge_requests",
            },
            {
                "tool": "http",
                "method": "DELETE",
                "url": "https://gitlab.example/api/v4/projects/1/labels/security",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "gitlab_write",
        "gitlab_write",
    ]
    assert operations[0].detail == (
        "GitLab write: POST https://gitlab.com/api/v4/projects/1/merge_requests"
    )
    assert operations[1].detail == (
        "GitLab write: DELETE https://gitlab.example/api/v4/projects/1/labels/security"
    )


def test_detect_unsafe_operations_reports_errata_write_events() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "http",
                "method": "POST",
                "url": ("https://errata.engineering.redhat.com/api/v1/erratum/12345/change_state"),
            },
            {
                "tool": "http",
                "method": "PUT",
                "url": "https://errata.example/api/v1/erratum/12345",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "errata_write",
        "errata_write",
    ]
    assert operations[0].detail == (
        "Errata write: POST https://errata.engineering.redhat.com/api/v1/erratum/12345/change_state"
    )
    assert operations[1].detail == ("Errata write: PUT https://errata.example/api/v1/erratum/12345")


def test_detect_unsafe_operations_reports_testing_farm_submissions() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "http",
                "method": "POST",
                "url": "https://api.testing-farm.io/v0.1/requests",
            },
            {
                "tool": "http",
                "method": "POST",
                "url": "https://api.dev.testing-farm.io/v0.1/requests",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "testing_farm_submission",
        "testing_farm_submission",
    ]
    assert operations[0].detail == (
        "Testing Farm submission: POST https://api.testing-farm.io/v0.1/requests"
    )
    assert operations[1].detail == (
        "Testing Farm submission: POST https://api.dev.testing-farm.io/v0.1/requests"
    )


def test_detect_unsafe_operations_reports_greenwave_mutations() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "http",
                "method": "POST",
                "url": "https://gating-status.osci.redhat.com/api/v1.0/decision",
            },
            {
                "tool": "http",
                "method": "PATCH",
                "url": "https://greenwave.example/api/v1.0/policies/rhel",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "greenwave_mutation",
        "greenwave_mutation",
    ]
    assert operations[0].detail == (
        "GreenWave mutation: POST https://gating-status.osci.redhat.com/api/v1.0/decision"
    )
    assert operations[1].detail == (
        "GreenWave mutation: PATCH https://greenwave.example/api/v1.0/policies/rhel"
    )


def test_detect_unsafe_operations_reports_resultsdb_mutations() -> None:
    operations = detect_unsafe_operations(
        [
            {
                "tool": "http",
                "method": "POST",
                "url": "https://resultsdb-api.engineering.redhat.com/api/v2.0/results",
            },
            {
                "tool": "http",
                "method": "DELETE",
                "url": "https://resultsdb.example/api/v2.0/results/12345",
            },
        ]
    )

    assert [operation.category for operation in operations] == [
        "resultsdb_mutation",
        "resultsdb_mutation",
    ]
    assert operations[0].detail == (
        "ResultsDB mutation: POST https://resultsdb-api.engineering.redhat.com/api/v2.0/results"
    )
    assert operations[1].detail == (
        "ResultsDB mutation: DELETE https://resultsdb.example/api/v2.0/results/12345"
    )


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
