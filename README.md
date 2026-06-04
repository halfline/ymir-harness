# Ymir Harness

Ymir Harness validates replayable benchmark fixtures and scores deterministic
outputs from Ymir agent runs. It is the first slice of the benchmark plan in the
adjacent `ai-workflows/ymir-harness.md` document: validate case fixtures before
execution, then compare an actual structured result against the expected
outcome with field-level detail.

The harness is offline by default. It only checks `pre_fix_ref` resolution when a
mock fixture points at a local repository path or `file://` URL, and it requires
`replay_only` cases to declare recorded web-cache files.

## Commands

```bash
ymir-harness validate-cases benchmark_cases/
ymir-harness score-result \
  benchmark_cases/expected/RHEL-12345.expected.json \
  reports/RHEL-12345.actual.json
ymir-harness score-results benchmark_cases/ reports/actual-results/ \
  --run-id baseline-2026-06-04T120000Z \
  --ymir-sha 6e22912f83d57ddae1031e6207d4716171a99be0 \
  --variant baseline
ymir-harness compare-results \
  reports/baseline-results.json \
  reports/enhanced-results.json \
  --markdown-output reports/comparison.md
```

The `benchmark` script is an alias for the same CLI:

```bash
benchmark validate-cases benchmark_cases/
```

Validation writes:

```text
benchmark_cases/reports/fixture-validation.json
benchmark_cases/reports/fixture-validation.md
benchmark_cases/reports/fixture-validation-errors.md
```

Use `--phase 2` once pilot fixtures are ready for stricter metadata checks.
Phase 2 also checks that an expected `target_branch` or `fix_version` is
declared by a mock repo `branch` or `zstream_override` value.
Phase 2 requires implementation cases to include `source_cache/CASE_ID/` unless
the expected result sets `requires_source_cache` to `false`.
Implementation source caches must include a non-empty `source_cache/CASE_ID/upstream/`.
When expected metadata declares `reference_patch_mode`, Phase 2 accepts
`applies`, `scope_only`, or `semantic_reference`.
Merged MR implementation cases must declare `reference_patch_mode`.
Phase 2 requires `merged_mr` implementation cases to include
`mock_data/*/reference_patches/CASE_ID.patch`.
Reference patch files must parse as git patches.
Phase 2 also requires a touched-file list to be extractable from each reference
patch.
When `reference_patch_mode` is `applies`, the reference patch must apply to a
local mock repo at `pre_fix_ref`.

`score-results` reads every `benchmark_cases/expected/*.expected.json` file and
matches actual outputs named `CASE_ID.actual.json` or `CASE_ID.json` in the
actual-results directory. It writes aggregate JSON to
`benchmark_cases/reports/results.json` unless `--output` is provided. Use
`--run-id`, `--ymir-sha`, and `--variant` to stamp the aggregate report with
benchmark run metadata.

Scoring treats any `unsafe_operations` entries in an actual result as a hard
failure gate. Use that field for blocked write attempts such as Jira mutation,
GitLab push, or build-system submission calls captured during a run.

Scoring also treats any `replay_violations` entries as a hard failure gate. Use
that field for unrecorded external fetches or replay cache misses reported by
the replay layer.

Expected results may declare `required_artifacts`. Scoring compares that list
with `generated_artifacts` in the actual result and fails the case when any
required artifact is missing.

Expected results may declare `fix_sources`. Scoring compares that list with
`fix_sources` in the actual result to check required upstream commits,
advisories, or other declared fix origins.

Expected results may declare `dependency_issues`. Scoring compares that list
with `dependency_issues` in the actual result to check required dependency
issue handling.

Expected results may declare `sibling_issues`. Scoring compares that list with
`sibling_issues` in the actual result to check required sibling issue
handling.

Expected results may declare `affectedness`. Scoring compares that value with
`affectedness` in the actual result and accepts boolean or token values such as
`affected` and `not_affected`.

Expected results may declare `touched_files`. Scoring compares that file list
with `touched_files` or `changed_files` in the actual result and fails on
missing or unexpected paths.

Scoring expects `unrelated_source_changes` in an actual result to be empty. Use
that field for source paths changed outside the expected implementation scope.

Expected results may declare `spec_patches`. Scoring compares that list with
`spec_patches` in the actual result to check expected RPM spec patch
declarations.

Expected results may declare `changelog_entries`. Scoring compares that list
with `changelog_entries` in the actual result to check Jira, CVE, or NVR
references captured from the spec changelog.

Expected results may declare `build_result`. Scoring compares that token with
`build_result` in the actual result to check local prep or build outcomes for
implementation cases.

Expected results may declare `prep_result`. Scoring compares that token with
`prep_result` in the actual result to check local preparation outcomes before
implementation cases build.

Expected results may declare `reference_patch_parse_status`. Scoring compares
that token with `reference_patch_parse_status` in the actual result to check
whether the reference patch parsed as expected.

Expected results may declare `reference_patch_apply_status`. Scoring compares
that token with `reference_patch_apply_status` in the actual result to check
whether the reference patch applied as expected.

`compare-results` reads two aggregate score reports and emits a per-case delta
table in JSON. Use `--markdown-output` to also write a human-readable comparison
report. A headline regression or missing candidate case returns a nonzero exit
status.

## Development

```bash
uv sync
uv run pytest
uv run ymir-harness --version
```
