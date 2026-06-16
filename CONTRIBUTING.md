# Contributing to Ymir Harness

Ymir Harness ...

## Development Setup

The project uses Python 3.12 or newer, `uv` for dependency management, and
hatchling as the build backend.

```bash
uv sync
uv run ymir-harness --version
```

Before committing code, run the same checks used during local development:

```bash
uv run ruff format --check src tests
uv run ruff check
uv run pytest
```

Use `uv run ruff format src tests` when formatting changes are needed.

## Coding Guidelines

Keep benchmark logic deterministic. Given the same fixtures, expected result,
actual structured output, replay cache, and validation settings, the same reports
and exit codes should be produced.

Prefer explicit data records over dynamic dictionaries for internal model
state. Stable field names and typed records make validation, scoring, and report
serialization easier to audit.

Keep fixture parsing, validation, scoring, report rendering, and agent-run
adapters separate where possible. A commit that adds a shared model should not
also wire every later consumer unless the intermediate history would be broken.

## Commit Workflow

Keep commits atomic. Each commit should have one purpose that a reviewer can
understand without reading unrelated worktree changes.

Use `git-stage-batch` when staging from an unstaged worktree. If a change fixes
a bug in an already committed slice, make a `fixup!` commit for the original
commit rather than folding the fix into later feature work.

Commit summaries use:

```text
prefix: Capitalized summary
```

The summary must stay under 72 characters. Use a lowercase prefix such as
`project:`, `config:`, `sources:`, `words:`, `symbols:`, `graph:`, or `suggestions:`.

Commit bodies must contain at least three paragraphs:

1. Describe the repository state immediately before the commit is applied in the present tense.
2. Explain the limitation or missing capability in that state.
3. Start with `This commit` and describe the specific change being made.

Use a fourth paragraph for multi-commit series to say what later commits will
do, or to close the series when the final commit reaches the stated goal.

Body lines must wrap at 75 characters. Do not use `Co-Authored-By` trailers for
AI-generated assistance. Use the word `this` only as part of `This commit`.

The local `commit-msg` hook enforces these rules and rejects vague marketing or
bragging words. If a message fails the hook, rewrite the message rather than
bypassing the hook.
