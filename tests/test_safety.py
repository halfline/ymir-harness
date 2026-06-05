from __future__ import annotations

from ymir_harness.safety import detect_unsafe_operations


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


def test_detect_unsafe_operations_ignores_read_only_events() -> None:
    operations = detect_unsafe_operations(
        [
            {"tool": "shell", "command": "git status --short"},
            {"tool": "shell", "command": "rhpkg sources"},
            {"tool": "shell", "command": "brew list-tags package"},
            {"tool": "shell", "command": "koji list-tags package"},
            {
                "tool": "http",
                "method": "GET",
                "url": "https://jira.example/rest/api/2/issue/RHEL-12345",
            },
            {
                "tool": "shell",
                "command": "curl https://gitlab.com/api/v4/projects/1/merge_requests",
            },
        ]
    )

    assert operations == []
