# Ymir Harness

Ymir Harness validates replayable benchmark fixtures and scores deterministic
outputs from Ymir agent runs. It checks case fixtures, runs configured
workflows in a no-write replay environment, and compares actual structured
results against expected outcomes with field-level detail.

Benchmark replay is offline by default. It only checks `pre_fix_ref` resolution
when a mock fixture points at a local repository path or `file://` URL, and it
requires `replay_only` cases to declare recorded web-cache files. Fixture
collection can make explicit read-only Jira and GitLab requests to build those
offline fixtures when a Jira URL or GitLab MR URL is provided.

## Workflow

Start by installing the harness and the checked-out Ymir submodule:

```bash
uv sync
uv run ymir-harness --version
```

For live Ymir runs, export the model credentials for the `CHAT_MODEL` you want
to use. If `CHAT_MODEL` is unset, the harness defaults to
`vertexai:claude-sonnet-4-6`.

The default model uses Vertex AI. Authenticate with Google application-default
credentials, then point the Vertex client at the Claude project:

```bash
gcloud auth application-default login
export GOOGLE_VERTEX_PROJECT="itpc-gcp-core-pe-eng-claude"
export GOOGLE_VERTEX_LOCATION="global"
export JIRA_TOKEN_FILE="/path/to/redhat-jira-api-token"
export JIRA_EMAIL="you@example.com"
```

To run with Gemini instead, set `CHAT_MODEL` and create or copy an API key from
<https://console.cloud.google.com/apis/credentials> after selecting the
`packit-automated-packaging` project.

```bash
export CHAT_MODEL="gemini:gemini-2.5-pro"
export GEMINI_API_KEY="..."
```


To test a Ymir change, check out the desired revision in `ai-workflows`, run
`uv sync`, and run the same case with a different `--variant` and `--run-id`.
Then compare the run reports:

```bash
uv run ymir-harness compare-results \
  examples/benchmark_cases/reports/runs/RHEL-12345-rerun/run.json \
  examples/benchmark_cases/reports/runs/RHEL-12345-candidate/run.json \
  --markdown-output examples/benchmark_cases/reports/RHEL-12345-comparison.md
```

Use `--provenance KEY=VALUE` with `run` or `score-results` to add explicit
run metadata such as `agentic_skills_sha`, `container_image_digest`, or model
configuration.

`score-results` reads every `benchmark_cases/expected/*.expected.json` file and
matches actual outputs named `CASE_ID.actual.json` or `CASE_ID.json` in the
actual-results directory. It writes aggregate JSON to
`benchmark_cases/reports/results.json` unless `--output` is provided. Use
`--run-id`, `--ymir-sha`, and `--variant` to stamp the aggregate report with
benchmark run metadata.
Aggregate score reports also include the Ymir Harness version that produced
the score.
They include `fixture_checksum` for fixture inputs under `cases.yaml`,
`expected/`, `jiras/`, `mock_data/`, `web_cache/`, and `source_cache/`.
Non-headline aggregate entries include `headline_reason` when case metadata
excludes them from headline correctness counts.

Scoring treats any `unsafe_operations` entries in an actual result as a hard
failure gate. Use that field for blocked write attempts such as Jira mutation,
GitLab push, or build-system submission calls captured during a run.

Scoring also treats any `replay_violations` entries as a hard failure gate. Use
that field for unrecorded external fetches or replay cache misses reported by
the replay layer. Replay violation detection can derive those entries from HTTP
tool events and shell `curl` or `wget` commands whose target URLs are absent
from the recorded replay URL set.

Expected results may declare `required_artifacts`. Scoring compares that list
with `generated_artifacts` in the actual result and fails the case when any
required artifact is missing.

Expected results may declare `fix_sources`. Scoring compares that list with
`fix_sources` in the actual result to check required upstream commits,
advisories, or other declared fix origins.

Expected backport results may declare `backport_source` as `upstream`,
`distgit`, or `mixed`. Scoring compares it with the actual result when present,
and can infer the actual value from patch URLs when the workflow does not emit
the field explicitly.

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

Actual results may include advisory diagnostics such as `runtime_seconds`,
`token_usage`, `iteration_count`, `tool_call_count`, `retry_count`,
`total_cost_usd`, `diff_similarity`, `rationale_quality`, or
`llm_judge_notes`. Scoring reports carry these as `advisory_metrics` without
using them for pass/fail status.

Expected results may declare `alternate_acceptable_outcomes` as a list of
partial expected-result overrides. If the primary expected result fails,
scoring tries each alternate and accepts the first deterministic pass while
recording an `alternate_acceptable_outcome` metric.

`compare-results` reads two aggregate score reports and emits a per-case delta
table in JSON. Use `--markdown-output` to also write a human-readable comparison
report. A headline regression or missing candidate case returns a nonzero exit
status.
Comparison output carries `headline_reason` for non-headline cases when the
aggregate inputs provide it.
When score reports carry `total_cost_usd` advisory metrics, comparison output
adds baseline cost, candidate cost, and cost delta fields. Markdown comparison
tables include matching cost columns only when cost data is present.
When comparison inputs include repeated case entries, `compare-results` groups
them by `case_id`, reports repetition counts and stable/flaky status, and uses
per-case mean runtime, token count, tool-call count, and cost values for
candidate-minus-baseline deltas.

## Development

```bash
uv sync
uv run pytest
uv run ymir-harness --version
```
