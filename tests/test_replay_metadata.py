from __future__ import annotations

import json
from pathlib import Path

from specfile import Specfile

from ymir_harness.replay_metadata import (
    CHANGELOG_AUTHOR_ENV,
    CHANGELOG_DATE_ENV,
    CHANGELOG_EMAIL_ENV,
    install_specfile_changelog_replay,
    replay_metadata_environment,
)


def test_replay_metadata_environment_reads_recorded_gitlab_commit(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    commit_path = cases_dir / "web_cache" / "RHEL-12345" / "gitlab" / "commits.json"
    commit_path.parent.mkdir(parents=True)
    commit_path.write_text(
        json.dumps(
            [
                {
                    "author_name": "RHEL Packaging Agent",
                    "author_email": "rhel-se-jotnar@redhat.com",
                    "committed_date": "2026-05-31T07:22:10.000+00:00",
                }
            ]
        ),
        encoding="utf-8",
    )

    env = replay_metadata_environment(cases_dir, "RHEL-12345")

    assert env[CHANGELOG_AUTHOR_ENV] == "RHEL Packaging Agent"
    assert env[CHANGELOG_EMAIL_ENV] == "rhel-se-jotnar@redhat.com"
    assert env[CHANGELOG_DATE_ENV] == "2026-05-31"
    assert env["GIT_AUTHOR_NAME"] == "RHEL Packaging Agent"
    assert env["GIT_AUTHOR_EMAIL"] == "rhel-se-jotnar@redhat.com"
    assert env["GIT_AUTHOR_DATE"] == "2026-05-31T07:22:10.000+00:00"
    assert env["GIT_COMMITTER_NAME"] == "RHEL Packaging Agent"
    assert env["GIT_COMMITTER_EMAIL"] == "rhel-se-jotnar@redhat.com"
    assert env["GIT_COMMITTER_DATE"] == "2026-05-31T07:22:10.000+00:00"


def test_specfile_changelog_replay_injects_recorded_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    spec_path = tmp_path / "redis.spec"
    spec_path.write_text(
        "Name: redis\n"
        "Version: 6.2.20\n"
        "Release: 1%{?dist}.1\n"
        "Summary: Redis\n"
        "License: BSD\n"
        "\n"
        "%description\n"
        "Redis\n"
        "\n"
        "%changelog\n"
        "* Tue Oct  7 2025 Remi Collet <rcollet@redhat.com> - 6.2.20-1\n"
        "- previous\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(CHANGELOG_AUTHOR_ENV, "RHEL Packaging Agent")
    monkeypatch.setenv(CHANGELOG_EMAIL_ENV, "rhel-se-jotnar@redhat.com")
    monkeypatch.setenv(CHANGELOG_DATE_ENV, "2026-05-31")

    install_specfile_changelog_replay()

    with Specfile(spec_path) as spec:
        spec.add_changelog_entry(["- Resolves: RHEL-12345"])

    text = spec_path.read_text(encoding="utf-8")
    assert (
        "* Sun May 31 2026 RHEL Packaging Agent <rhel-se-jotnar@redhat.com> - 6.2.20-1.1"
        in text
    )
