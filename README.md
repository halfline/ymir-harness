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

## Commands

```bash
ymir-harness validate-cases benchmark_cases/
ymir-harness collect-case \
  --cases benchmark_cases/ \
  --case-id RHEL-12345 \
  --case-type cve_backport \
  --resolution backport \
  --package dnsmasq \
  --target-branch rhel-8.10.z \
  --expected-basis merged_mr \
  --network-mode replay_only \
  --remote-url https://example.invalid/dnsmasq.git \
  --pre-fix-ref abc123 \
  --branch c9s \
  --reference-patch evidence/fix.patch \
  --reference-patch-mode scope_only \
  --jira-issue-json evidence/issue.json \
  --web-record https://example.invalid/fix.patch=evidence/fix.patch.response
ymir-harness score-result \
  benchmark_cases/expected/RHEL-12345.expected.json \
  reports/RHEL-12345.actual.json
ymir-harness score-results benchmark_cases/ reports/actual-results/ \
  --run-id baseline-2026-06-04T120000Z \
  --ymir-sha 6e22912f83d57ddae1031e6207d4716171a99be0 \
  --variant baseline
ymir-harness run \
  --cases benchmark_cases/ \
  --variant baseline \
  --run-id baseline-2026-06-04T120000Z \
  --case RHEL-12345 \
  --repeat 3 \
  --workflow ymir-triage
ymir-harness prepare-case \
  --cases benchmark_cases/ \
  --case RHEL-12345 \
  --jira-url https://redhat.atlassian.net/browse/RHEL-12345 \
  --workflow ymir-triage \
  --max-iterations 3
ymir-harness compare-results \
  reports/baseline-results.json \
  reports/enhanced-results.json \
  --markdown-output reports/comparison.md
```

The `benchmark` script is an alias for the same CLI:

```bash
benchmark validate-cases benchmark_cases/
```

`benchmark compare` is also accepted as an alias for `benchmark compare-results`.
Use `--provenance KEY=VALUE` with `run` or `score-results` to add explicit
run metadata such as `agentic_skills_sha`, `container_image_digest`, or model
configuration.

`collect-case` scaffolds replayable fixture files from either local evidence or
read-only fetches. Pass `--jira-url` or `--jira-base-url` to import a completed
Jira issue. When omitted, `case_type`, `resolution`, `package`, `fix_version`,
CVEs, and `expected_basis` are derived from Jira fields, Ymir/Jotnar result
labels, and agent result comments when possible. Patch URLs and GitLab MRs found
in result comments are recorded into replay evidence but removed from
`starting-issue.json`. Pass `--gitlab-mr` to fetch GitLab MR
metadata, commits, changes, and patch content into `web_cache/CASE_ID/`; if no
MR is passed, a GitLab MR remote link or comment URL in the fetched Jira is used
automatically.
When fetched GitLab MR metadata includes `diff_refs.base_sha` and
`target_branch`, `collect-case` also derives `mock_data` from the MR: the repo
URL comes from the MR project URL, `pre_fix_ref` comes from the MR base SHA, and
the branch comes from the MR target branch. If the completed Jira fix version is
a z-stream name such as `rhel-9.7.z` and the dist-git branch differs,
`collect-case` writes the corresponding `zstream_override`.
Supplying `--remote-url`, `--pre-fix-ref`, and `--branch` keeps using the
manual mock repo metadata instead.
Use `--mock-repo-cache DIR` to clone or refresh mock repos into a local bare
repo cache during collection. Cached fixtures keep `remote_url` as the original
URL for replay rewrites and blocked-network checks, and add `source_url` with
the local cache path that `run` can clone offline.
The MR patch is also copied to `mock_data/*/reference_patches/CASE_ID.patch`
when mock repo metadata is provided and no local `--reference-patch` is
supplied. Jira fetches use `JIRA_TOKEN` when it is set. Tokens are sent as
bearer tokens by default; pass `--jira-email` or set `JIRA_EMAIL` /
`ATLASSIAN_EMAIL` for Atlassian Basic auth, and use `--jira-token-file` when the
token lives in a file. GitLab fetches use `GITLAB_TOKEN` as a private token when
it is set. Override environment variable names with `--jira-token-env` or
`--gitlab-token-env`.
When `--network-mode` is omitted, `collect-case` keeps Jira-only cases
`network_denied`, but switches to `replay_only` automatically for replay web
evidence such as a GitLab MR, `--patch-url`, or `--web-record`.

`collect-case` still accepts pre-collected local files through
`--jira-issue-json`, `--jira-comments-json`, `--jira-links-json`,
`--reference-patch`, `--web-record`, and source-cache options. It writes
`cases.yaml`, `expected/`, `jiras/`, optional `mock_data/`, optional
`web_cache/`, and optional `source_cache/` entries. New cases default to
`case_status=quarantined` so they do not enter headline results until reviewed.
Use `--overwrite` when intentionally regenerating an existing case scaffold.
Checked-in Jira fixtures stay structured under `jiras/CASE_ID/`; validation
also verifies they can be materialized into the flat mock shape that Ymir reads.
`issue.json`, `comments.json`, and `links.json` preserve the completed Jira
evidence. `starting-issue.json` is a redacted triage starting point that removes
obvious Ymir result labels, closed status, result comments, and final remote
links so triage reruns must rederive the answer.

The repository includes a synthetic offline seed fixture under
`examples/benchmark_cases/`. It is not a historical benchmark case, but it gives
new users a checked-in fixture layout to validate before adding real cases:

```bash
ymir-harness validate-cases examples/benchmark_cases/
ymir-harness run --cases examples/benchmark_cases/ --variant example
```

Validation writes:

```text
benchmark_cases/reports/fixture-validation.json
benchmark_cases/reports/fixture-validation.md
benchmark_cases/reports/fixture-validation-errors.md
```

Pass `--workflow ymir-triage` when validating a triage-only run so validation
does not require implementation-only source cache or reference patch artifacts.
For runnable cases, validation checks that an expected `target_branch` or
`fix_version` is declared by a mock repo `branch` or `zstream_override` value.
Replay web cache manifests must list expected `patch_urls` in `required_urls`.
Recorded web cache files must stay under `web_cache/CASE_ID/`.
`network_denied` cases must not declare expected `patch_urls`.
`network_denied` cases must not include `web_cache/CASE_ID/manifest.json`.
Implementation cases must include `source_cache/CASE_ID/` unless the expected
result sets `requires_source_cache` to `false`.
Implementation source caches must include `source_cache/CASE_ID/upstream/` with
a git clone or source archive.
Upstream source archive files must be readable.
Implementation source caches must include artifact files under
`source_cache/CASE_ID/lookaside/`.
Lookaside artifact files must be readable.
Expected results may declare `required_source_cache_files` as a list of
`source_cache/CASE_ID`-relative file paths.
Expected results may declare `source_cache_checksums` as a mapping from
`source_cache/CASE_ID`-relative paths to `sha256:<hex>` digests.
Validation checks those cached files against their declared digests.
When expected metadata declares `reference_patch_mode`, validation accepts
`applies`, `scope_only`, or `semantic_reference`.
Merged MR implementation cases must declare `reference_patch_mode`.
Merged MR implementation cases must include
`mock_data/*/reference_patches/CASE_ID.patch`.
Reference patch files must parse as git patches.
Validation also requires a touched-file list to be extractable from each
reference patch.
When `reference_patch_mode` is `applies`, the reference patch must apply to a
local mock repo at `pre_fix_ref`.
It must not reverse-apply to `pre_fix_ref`, which indicates the fix is already
present.

When a runnable case has local or `file://` mock repos in `mock_data/*`, `run`
materializes those repos under the run directory, checks out `pre_fix_ref`,
writes a per-case gitconfig with `insteadOf` URL rewrites, exposes that
gitconfig through `GIT_CONFIG_GLOBAL`, and exports `MOCK_BLOCKED_URLS` for the
original URLs.
When a runnable case has structured Jira evidence under `jiras/CASE_ID/`, `run`
generates flat Ymir Jira mock files under `reports/runs/RUN_ID/repeat-N/jira-mock`
and points `JIRA_MOCK_FILES` at that generated directory. If
`starting-issue.json` is present, that redacted issue is what Ymir sees during
triage replay; the completed Jira evidence remains available only as fixture
ground truth.
Live Ymir workflow adapters start a managed MCP gateway when `MCP_GATEWAY_URL`
is not already set. The managed gateway inherits the generated Jira mock
directory, mock gitconfig/repo workspace, and replay/cache policy for the case.
If `MCP_GATEWAY_URL` is set, the harness uses that external gateway instead;
start external gateways with access to the same fixture paths and policy.

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
The `run` command also derives `unsafe_operations` from actual-result
`events`, `tool_events`, `tool_calls`, or `trace` entries before scoring.

Scoring also treats any `replay_violations` entries as a hard failure gate. Use
that field for unrecorded external fetches or replay cache misses reported by
the replay layer. Replay violation detection can derive those entries from HTTP
tool events and shell `curl` or `wget` commands whose target URLs are absent
from the recorded replay URL set.
For `replay_only` cases, `run` reads `web_cache/CASE_ID/manifest.json`, exposes
the manifest path and recorded URL list in the case environment, and derives
`replay_violations` from actual-result event traces. For `network_denied`
cases, any external HTTP URL in the event trace is reported as a replay
violation.
During `run`, executors are also wrapped in a runtime boundary guard. The guard
blocks unsafe subprocess commands, blocks external subprocess URLs in
`network_denied` and `replay_only` modes, blocks direct external socket
connections, and serves recorded responses from `web_cache` to common Python
HTTP clients (`urllib`, `requests`, and `aiohttp`) when the URL is declared in
the replay manifest. Recorded shell `curl`/`wget` downloads made through
`subprocess.run(..., stdout=PIPE)` are satisfied from cache; unsupported shell
download forms are blocked instead of falling through to live network.
Configured model-provider HTTPS calls are allowed so live agents can run while
fixture and service data still comes from replay inputs.

Expected results may declare `required_artifacts`. Scoring compares that list
with `generated_artifacts` in the actual result and fails the case when any
required artifact is missing.
Workflow adapters also expose `YMIR_BENCHMARK_ARTIFACT_DIR` and merge generated
artifacts, touched files, spec patch declarations, changelog entries, and
unrelated source change diagnostics from returned workflow payloads, workflow
state, and files written to that artifact directory.

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

Actual results may include advisory diagnostics such as `runtime_seconds`,
`token_usage`, `iteration_count`, `tool_call_count`, `retry_count`,
`total_cost_usd`, `diff_similarity`, `rationale_quality`, or
`llm_judge_notes`. Scoring reports carry these as `advisory_metrics` without
using them for pass/fail status.

Expected results may declare `alternate_acceptable_outcomes` as a list of
partial expected-result overrides. If the primary expected result fails,
scoring tries each alternate and accepts the first deterministic pass while
recording an `alternate_acceptable_outcome` metric.

Runner reports use `run_id`, `variant`, optional `ymir_sha`,
`harness_version`, `fixture_checksum`, `features`, and `repeat` metadata. Each
case entry includes `case_id`, `case_type`, `status`, `repetition`, optional
`expected_path`, optional `actual_path`, optional `score`, optional
`runtime_seconds`, and optional `reason`. Case status values are `not_run`,
`passed`, `failed`, `timeout`, `skipped`, and `unsupported`.
The default `run` command writes validation reports first, then writes
`benchmark_cases/reports/runs/RUN_ID/run.json` unless `--output` is provided.
Without `--workflow`, it does not invoke Ymir workflows, so each runnable case
repetition is marked `not_run`.
Use `--workflow ymir-triage` to call Ymir's triage `run_workflow()` directly for
each runnable case. The runner applies the per-case no-write environment,
writes the returned structured triage result to the reserved actual result
path, scores it against the expected result, and records the score in the run
entry. A deterministic score mismatch marks the run entry failed.
Use `prepare-case` for fixture preparation loops. It optionally imports the
case first when `--jira-url`, `--jira-base-url`, or `--gitlab-mr` is supplied,
then runs the selected workflow, captures missing replay evidence from the run
artifacts, and repeats until the run succeeds, no new evidence is captured, or
`--max-iterations` is reached. Each iteration writes a normal run report under
`benchmark_cases/reports/runs/RUN_ID-iter-N/`.
Live workflow adapters install Ymir from the checked-out `ui-workflows`
submodule during `uv sync`. To benchmark a different Ymir revision, check out
that revision inside `ui-workflows`, run `uv sync`, and commit the updated
submodule pointer.
Use `--workflow ymir-backport` to call Ymir's backport `run_workflow()` for
implementation cases. The executor reads expected-result fields for the
package, target branch, patch sources, CVE, justification, and fix version,
then writes a normalized backport actual result with build status, backport
status, errors, and generated artifacts for scoring.
Use `--workflow ymir-rebase` to call Ymir's rebase `run_workflow()` for
implementation cases. The executor reads expected-result fields for the
package, target branch, target version, Jira issue, and justification, then
writes a normalized rebase actual result with build status, rebase status,
errors, generated artifacts, and touched files for scoring.
Use `--workflow ymir-rebuild` to call Ymir's rebuild `run_workflow()` for
implementation cases. The executor reads expected-result fields for the
package, target branch, Jira issue, justification, dependency issue,
dependency component, sibling issues, and consolidation summary, then writes a
normalized rebuild actual result with build status, rebuild status, errors,
merge request URL, dependency fields, and sibling issue fields for scoring.
Programmatic runner integrations can pass a case executor to receive resolved
case metadata, the reserved actual result path, enabled feature flags, and the
per-case no-write environment before returning a run status.
Executors may return an `actual_result` payload for the runner to write as JSON
at the reserved actual result path.
If the executor raises, the runner records a failed case entry with the reserved
actual result path and the exception reason.
Workflow adapters start from a no-write environment profile that forces
`DRY_RUN`, `MOCK_JIRA`, and `JIRA_DRY_RUN`, disables auto-chaining, and strips
known write credentials and Kerberos keytab paths from the process environment.
Default live Ymir workflow adapters use `gemini:gemini-2.5-pro` when
`CHAT_MODEL` is not set. Model provider credentials still need to come from
the user environment, such as `GEMINI_API_KEY` for Gemini models.
Run reports include a `provenance` object populated from explicit
`--provenance` entries and recognized environment variables such as
`AGENTIC_SKILLS_SHA`, `AGENTIC_SKILLS_CHECKSUM`, `CONTAINER_IMAGE_DIGEST`,
`CHAT_MODEL*`, `REASONING_EFFORT`, `BEEAI_MAX_ITERATIONS`,
`BENCHMARK_PROMPT_CONFIG`, and `BENCHMARK_MODEL_SETTINGS`.
Set `BENCHMARK_MAX_ITERATIONS_OVERRIDE` to pass a lower
`BEEAI_MAX_ITERATIONS` value into each workflow environment. Set
`BENCHMARK_MAX_COST_PER_RUN` to mark cases whose `total_cost_usd` exceeds the
cap as `timeout`. Set `BENCHMARK_COST_ALERT_THRESHOLD` to record a run entry
warning when a case exceeds an advisory cost threshold without exceeding the
hard cap.
Unsafe-operation detection currently classifies git push attempts, Jira write
attempts, GitLab write attempts, Errata write attempts, Testing Farm
submissions, GreenWave mutations, ResultsDB mutations, and `rhpkg` lookaside
upload attempts from tool events. It also classifies `brew build`, `koji build`,
`copr build`, and `konflux build` submissions.
When `cases.yaml` is present, `run` uses it as the default case list. It accepts
a top-level list of case ids or a `cases:` list containing case ids or objects
with `case_id`.
Use `--case CASE_ID` more than once to limit a run report to selected cases.
Runnable entries reserve `actual_path` under
`benchmark_cases/reports/runs/RUN_ID/repeat-N/actual-results/CASE_ID.actual.json`.

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
