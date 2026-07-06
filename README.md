# Ymir Harness

Replay Ymir changes against known package-maintenance cases before they reach
real Jira issues, dist-git branches, or release machinery.

Ymir Harness is the benchmark layer around the
[Packit AI Workflows](https://github.com/packit/ai-workflows) project. The Ymir
agents live in this repository as the `ai-workflows` submodule. The harness
gives those agents a controlled place to run:

- fixture data instead of live, drifting service state
- no-write guardrails around Jira, GitLab, build systems, and shell tools
- replayed web, Jira, Git, and source inputs
- deterministic scoring against expected outcomes
- reports that make candidate-vs-baseline changes reviewable

The point is simple: when Ymir changes, we should be able to say which known
cases got better, which got worse, and why.

## Start here

Prerequisites:

- Python 3.13
- `uv`
- initialized submodules
- model credentials only when running live Ymir workflows
- Jira and GitLab read tokens only when collecting evidence or materializing
  private fixture source submodules

```bash
git submodule update --init --recursive
uv sync
uv run ymir-harness --version
```

Run a fixture-only smoke check. This validates the checked-in synthetic example
root, then writes the normal report layout for the model-free seed case without
calling a live agent. The run entry is expected to be `not_run`; this is a
plumbing check, not an agent benchmark.

```bash
uv run ymir-harness validate-cases examples/benchmark_cases --workflow ymir-triage
uv run ymir-harness run \
  --cases examples/benchmark_cases \
  --case RHEL-00001 \
  --variant fixture-smoke \
  --run-id fixture-smoke
```

Reports appear under:

```text
examples/benchmark_cases/reports/
```

Once model credentials are configured, use the real case submodule for a Ymir
benchmark run:

```bash
uv run ymir-harness run \
  --cases ymir-harness-cases/ymir-triage \
  --workflow ymir-triage \
  --variant baseline \
  --run-id triage-baseline
```

## What this repo is for

Ymir automates RHEL package-maintenance work. Today that includes triage,
backports, rebases, rebuilds, and the testing/release work that follows from
those decisions. Those workflows use model calls plus integrations with Jira,
GitLab dist-git, build tooling, and supporting services.

That is exactly why a harness is needed. A live workflow can produce useful
work, but it is hard to use as a regression test:

- Jira state changes.
- Web pages move or disappear.
- Agents may try writes unless every path is guarded.
- A passing-looking result can still choose the wrong package, branch, patch,
  artifact, CVE, or source scope.
- Model changes can improve one case while quietly regressing another.

Ymir Harness turns those moving pieces into repeatable cases. It does not make
agent output trusted by default. It makes the output inspectable.

## The benchmark loop

Most work follows the same loop:

1. Prepare or update a case fixture.
2. Run a baseline.
3. Run a candidate with the Ymir change under test.
4. Compare the reports.
5. Promote only the cases whose ground truth has been reviewed.

### 1. Prepare a case

`prepare-case` is the easiest path for a new Jira issue. It can import read-only
evidence, run the chosen workflow, capture missing replay inputs, and repeat
until the case is replayable or the iteration limit is reached.

```bash
export JIRA_TOKEN_FILE="/path/to/redhat-jira-api-token"
export JIRA_EMAIL="you@example.com"
export GITLAB_TOKEN="..."

uv run ymir-harness prepare-case \
  --cases ymir-harness-cases/ymir-triage \
  --case RHEL-12345 \
  --jira-url https://redhat.atlassian.net/browse/RHEL-12345 \
  --jira-token-file "$JIRA_TOKEN_FILE" \
  --jira-email "$JIRA_EMAIL" \
  --mock-repo-cache .cache/mock-repos \
  --workflow ymir-triage \
  --variant prepare \
  --run-id RHEL-12345-prepare \
  --max-iterations 3 \
  --overwrite \
  --json > prepare.json
```

Read `prepare.json` before trusting the fixture. The status tells you whether
preparation succeeded, stopped on validation, hit the iteration limit, or failed
while capturing evidence.

For Jira Cloud instances such as `redhat.atlassian.net`, create an Atlassian API
token from <https://id.atlassian.com/manage-profile/security/api-tokens>. Select
`Create API token`, give it a descriptive name, choose an expiration date, copy
the token, and save it somewhere outside the repository. Point
`JIRA_TOKEN_FILE` at that file and set `JIRA_EMAIL` to the Atlassian account
email for the token. The harness sends Jira credentials as Basic auth when
`JIRA_EMAIL` is set; without an email, it treats `JIRA_TOKEN` or the token file
as a bearer token.

GitLab evidence collection uses `GITLAB_TOKEN` by default. That token is needed
when `collect-case`, `prepare-case`, or `capture-missing` fetches GitLab merge
request metadata, commits, changes, patches, or other recorded GitLab responses.
Use `--gitlab-token-env NAME` if the token is stored in a different environment
variable.

Benchmark runs also use GitLab credentials to initialize private source fixture
submodules on demand. Set `GITLAB_TOKEN`, `GITLAB_API_TOKEN`, or one of
`GITLAB_TOKEN_FILE`, `GITLAB_API_TOKEN_FILE`, or `YMIR_GITLAB_TOKEN_FILE` before
`run` or `prepare-case`. The harness passes the credential to the individual Git
command through temporary environment-backed config and does not write it into
repository config.

For GitLab.com, create a personal access token from your avatar menu:
`Edit profile` -> `Access` -> `Personal access tokens` -> `Generate token`.
Give it an expiration date and the narrow read scopes the harness needs:
`read_api` for GitLab API evidence and `read_repository` for private repository
reads or Git-over-HTTPS fixture collection. Save the token when GitLab displays
it; it is not shown again.

When you only want to import fixture data and skip the workflow run, use
`collect-case` directly:

```bash
uv run ymir-harness collect-case \
  --cases ymir-harness-cases/ymir-triage \
  --case-id RHEL-12345 \
  --jira-url https://redhat.atlassian.net/browse/RHEL-12345 \
  --jira-token-file "$JIRA_TOKEN_FILE" \
  --jira-email "$JIRA_EMAIL" \
  --mock-repo-cache .cache/mock-repos \
  --overwrite
```

New collected cases default to `case_status=quarantined`. That is intentional:
fixtures should not count toward headline results until someone has reviewed
the expected outcome.

### 2. Run the baseline

Live workflow runs need model credentials. The default model is
`vertexai:claude-sonnet-4-6`, so Vertex users normally need:

```bash
gcloud auth application-default login
export GOOGLE_VERTEX_PROJECT="your-vertex-project"
export GOOGLE_VERTEX_LOCATION="global"
```

Gemini runs can use:

```bash
export CHAT_MODEL="gemini:gemini-2.5-pro"
export GEMINI_API_KEY="..."
```

Run the baseline against a case root:

```bash
uv run ymir-harness run \
  --cases ymir-harness-cases/ymir-triage \
  --workflow ymir-triage \
  --variant baseline \
  --run-id triage-baseline \
  --provenance agentic_skills_sha="$(git -C ai-workflows rev-parse HEAD)"
```

The run report is written to:

```text
ymir-harness-cases/ymir-triage/reports/runs/triage-baseline/run.json
```

Actual per-case results are written under:

```text
ymir-harness-cases/ymir-triage/reports/runs/triage-baseline/repeat-1/actual-results/
```

### 3. Run the candidate

Check out or edit the Ymir revision under `ai-workflows`, then sync so the
editable dependencies point at the revision you intend to test.

```bash
git -C ai-workflows checkout <candidate-ref>
uv sync

uv run ymir-harness run \
  --cases ymir-harness-cases/ymir-triage \
  --workflow ymir-triage \
  --variant candidate \
  --run-id triage-candidate \
  --provenance agentic_skills_sha="$(git -C ai-workflows rev-parse HEAD)"
```

Use `--case RHEL-12345` one or more times to limit a run while iterating.

### 4. Score and compare

`run` scores each case as it executes. To get comparison-friendly aggregate
reports, score the actual-result directories explicitly:

```bash
uv run ymir-harness score-results \
  ymir-harness-cases/ymir-triage \
  ymir-harness-cases/ymir-triage/reports/runs/triage-baseline/repeat-1/actual-results \
  --run-id triage-baseline \
  --variant baseline \
  --output ymir-harness-cases/ymir-triage/reports/triage-baseline.results.json

uv run ymir-harness score-results \
  ymir-harness-cases/ymir-triage \
  ymir-harness-cases/ymir-triage/reports/runs/triage-candidate/repeat-1/actual-results \
  --run-id triage-candidate \
  --variant candidate \
  --output ymir-harness-cases/ymir-triage/reports/triage-candidate.results.json

uv run ymir-harness compare-results \
  ymir-harness-cases/ymir-triage/reports/triage-baseline.results.json \
  ymir-harness-cases/ymir-triage/reports/triage-candidate.results.json \
  --markdown-output ymir-harness-cases/ymir-triage/reports/triage-comparison.md
```

`compare-results` exits nonzero when a headline case regresses or disappears.
That makes it suitable for CI gates once the case set is mature enough.

## Case roots

A case root is a directory that contains one workflow's fixtures. For example:

```text
ymir-harness-cases/ymir-triage/
  cases.yaml
  expected/
  jiras/
  mock_data/
  web_cache/
  source_cache/
  reports/
```

The important pieces:

| Path | Role |
| --- | --- |
| `cases.yaml` | Optional ordered case list. `run` uses it when no `--case` filter is supplied. |
| `expected/*.expected.json` | Ground truth: case type, resolution, package, branch or fix version, CVEs, patch URLs, artifacts, and metadata. |
| `jiras/CASE_ID/` | Structured Jira evidence. `starting-issue.json` is the redacted issue shown to triage replay. |
| `mock_data/AGENT/CASE_ID.json` | Mock repository metadata for dist-git and implementation workflows. |
| `web_cache/CASE_ID/` | Recorded HTTP responses plus `manifest.json` for `replay_only` cases. |
| `source_cache/CASE_ID/` | Upstream source and lookaside inputs for implementation cases. |
| `reports/` | Validation reports, run reports, actual results, traces, and comparisons. |

The synthetic `examples/benchmark_cases/` root is useful for layout checks. It
is not a historical Red Hat benchmark case.

## Replay and safety

Benchmark replay is built to let a live model reason over fixed evidence while
keeping service data and side effects bounded.

Network modes:

| Mode | Meaning |
| --- | --- |
| `network_denied` | The case should not perform external fixture-data fetches. External HTTP activity is reported as a replay violation. |
| `replay_only` | The case may read only URLs declared in `web_cache/CASE_ID/manifest.json`. Recorded responses are served from cache. |
| `live_non_reproducible` | The case may depend on live data and should not be treated as a deterministic benchmark case. |

During `run`, the harness:

- strips known write credentials and Kerberos paths from the workflow
  environment
- forces dry-run flags such as `DRY_RUN`, `MOCK_JIRA`, and `JIRA_DRY_RUN`
- materializes mock repos under the run directory and rewrites configured Git
  remotes to local paths
- materializes structured Jira fixtures into the flat mock shape that Ymir reads
- blocks direct external sockets and unsupported shell download forms in replay
  modes
- serves recorded responses to common Python HTTP clients when the URL is in the
  replay manifest
- builds a source-specific isolated worker image from the local seed worker
  image when replay modes need container isolation
- records unsafe operations and replay violations as hard scoring failures

Configured model-provider HTTPS calls are still allowed. The model can run; the
case evidence should not drift.

Replay and `network_denied` runs never cold-build the Ymir base image from
external package repositories. They require a local seed worker image such as
`localhost/ymir-harness-worker:c10s`, then automatically build a
`*-source-*` worker image tagged from the current harness and `ai-workflows`
source contents. Set `YMIR_HARNESS_WORKER_IMAGE` to bypass that automatic
source image selection.

## Interception architecture

The harness enforces its sandbox by **monkey-patching** Python's I/O subsystems
at runtime. The context manager `enforce_benchmark_boundaries()` in
`enforcement.py` saves every original function, installs guarded replacements,
runs the workflow, and restores the originals on exit.

### What gets patched

Eight subsystems are replaced before the workflow starts:

| Subsystem | Original | What the guard does |
| --- | --- | --- |
| Sync subprocesses | `subprocess.run`, `subprocess.Popen` | Screen commands for unsafe operations; return cached output when available; block or pass through otherwise |
| Async subprocesses | `asyncio.create_subprocess_exec`, `asyncio.create_subprocess_shell` | Same screening, returning `_AsyncReplayProcess` objects with stored stdout/stderr |
| Sockets | `socket.socket.connect`, `socket.socket.connect_ex` | Allow localhost and the configured model provider; raise `BenchmarkBoundaryViolation` for everything else |
| urllib | `urllib.request.urlopen` | Serve cached responses as `addinfourl` objects; return synthetic 404 for cache misses in replay mode |
| requests | `requests.Session.request` | Serve cached responses as `requests.Response` objects with stored body, status, and headers |
| aiohttp | `aiohttp.ClientSession._request` | Serve cached responses as `ReplayResponse` async context managers |

### Subprocess interception

`guarded_run()` and `guarded_popen` wrap every shell command:

1. `_check_command()` inspects the command line for unsafe operations: `git push`,
   `koji`/`brew` builds, `rhpkg` lookaside uploads, `copr`/`konflux` submissions.
   A match records the violation and short-circuits execution.
2. `_subprocess_replay()` checks the replay cache for stored output. Matches
   include `curl`/`wget` downloads served from the web cache, recorded git
   failures, and synthetic 404 responses for replay misses.
3. If replay returns a hit, `guarded_run()` returns a synthetic
   `CompletedProcess`. `guarded_popen` sets `_child_created = False` and provides
   fake pipe readers so no real process is forked.
4. Otherwise the command runs against the real (but sandboxed) environment.

### HTTP interception

Every HTTP call is checked against a `ReplayCache` loaded from the case's
`manifest.json`. The cache maps URLs to local files, with stored status codes
and response headers.

Two sources are synthesized on the fly rather than pre-recorded:

- **Source patches**: URLs matching a GitLab commit `.patch` path are generated
  via `git format-patch` from the local `source_cache`.
- **Source files**: URLs matching a Pagure `raw/.../f/<path>` pattern are
  generated via `git show` from the `source_cache`.

`canonicalize_replay_url()` normalizes URLs before lookup so that trailing
punctuation, URL-encoded slashes, and similar noise do not cause false cache
misses.

### Unsafe operation detection

`safety.py` classifies every subprocess command and HTTP request:

**Blocked as unsafe:**

- `git push` in any form
- Jira API writes (POST, PUT, DELETE to `/rest/api/`)
- GitLab fork, label, or merge-request creation
- Errata tool write operations
- Testing Farm submissions
- GreenWave and ResultsDB mutations
- Koji, Brew, and Copr build submissions

**Allowed or replayed:**

- `git clone`, `fetch`, `log`, `show`
- `curl`/`wget` downloads (served from the replay cache)
- Jira issue reads (served from local JSON fixtures)
- GitLab read operations

When an unsafe operation is detected during a run, it is recorded in the
`unsafe_operations` list and treated as a hard scoring failure.

### Environment sandboxing

Before entering the patched context, `runner.py` constructs an isolated
environment via `build_no_write_environment()`:

- Sets `DRY_RUN`, `MOCK_JIRA`, and `JIRA_DRY_RUN` flags
- Points `YMIR_BENCHMARK_REPLAY_MANIFEST` at the case's manifest
- Installs dry-run command shims for tools such as `rhpkg` and `patch`
- Writes a temporary `GIT_CONFIG_GLOBAL` with `insteadOf` rules that redirect
  configured Git remote URLs to local mock repositories
- Materializes structured Jira fixtures into the flat mock format that Ymir reads
- Strips write credentials (`JIRA_API_TOKEN`, `JIRA_PASSWORD`, `KOJI_CONFIG`,
  `KEYTAB_FILE`, and similar) from the process environment
- Redirects stdout and stderr to files via `_capture_workflow_output()`

The only traffic that escapes the sandbox is HTTPS to the configured model
provider, identified from the `CHAT_MODEL` environment variable. A context
variable temporarily unblocks model-provider sockets during the request.

### End-to-end flow

```text
CLI  →  runner.build_run_report()
          │
          ├─ per case / repetition:
          │    build_no_write_environment()      ← sandbox env
          │    _mock_repo_environment()          ← git URL rewrites
          │    _jira_mock_directory()            ← Jira fixtures
          │    ┌─────────────────────────────────────────────┐
          │    │ enforce_benchmark_boundaries()              │
          │    │   patch subprocess, asyncio, socket,        │
          │    │   urllib, requests, aiohttp                 │
          │    │                                             │
          │    │   executor(RunCaseRequest)                  │
          │    │     └─ ymir workflow runs here              │
          │    │                                             │
          │    │   _apply_run_policies()                     │
          │    │     └─ detect violations and unsafe ops     │
          │    │                                             │
          │    │   [restore originals]                       │
          │    └─────────────────────────────────────────────┘
          │    score result, capture artifacts
          │
          └─ write run report
```

## Scoring

Scoring answers one question: did the actual structured output satisfy the
expected outcome for this fixture?

Hard failure gates:

- `unsafe_operations` is nonempty
- `replay_violations` is nonempty
- `unrelated_source_changes` is nonempty
- a required artifact or required artifact kind is missing
- the workflow crashes or returns an error field

Deterministic comparisons include:

| Area | Examples |
| --- | --- |
| Identity | `case_id`, `jira_issue`, `case_type` |
| Decision | `resolution`, `affectedness`, `package`, `target_branch`, `fix_version` |
| Security data | `cve_ids`, `patch_urls`, `fix_sources`, `backport_source` |
| Implementation scope | `touched_files`, reference-patch touched files, spec patches, changelog entries |
| Build behavior | `prep_result`, `build_result`, reference-patch parse/apply status |
| Issue handling | dependency issues and sibling issues |
| Artifacts | generated files, patch filename patterns, semantic artifact kinds |

Advisory metrics such as runtime, token usage, tool-call count, retry count,
cost, diff similarity, and LLM judge notes are carried in reports. They do not
decide pass/fail unless an explicit guardrail, such as a cost cap, says they
should.

Optional backport judging is available when artifact manifests exist:

```bash
export YMIR_HARNESS_LLM_JUDGE=true
export YMIR_HARNESS_LLM_JUDGE_MODEL="$CHAT_MODEL"
```

The judge writes a `judge_verdict.json` artifact and reports advisory findings
about patch correctness, RPM spec changes, unrelated changes, completeness, and
reference-patch similarity.

## Validation

Validate fixtures before treating a case as signal:

```bash
uv run ymir-harness validate-cases ymir-harness-cases/ymir-triage --workflow ymir-triage
```

Validation writes:

```text
reports/fixture-validation.json
reports/fixture-validation.md
reports/fixture-validation-errors.md
```

Validation catches common benchmark problems before an agent run burns model
time:

- missing required metadata
- invalid schema values
- inconsistent mock repo branch or fix-version data
- incomplete replay manifests
- `network_denied` cases that declare web-cache evidence
- implementation cases without required source cache inputs
- reference patches that do not parse, do not apply when they must, or appear
  already present at `pre_fix_ref`
- structured Jira fixtures that cannot be materialized into Ymir's mock format

Pass `--workflow ymir-triage` for triage-only validation. That keeps validation focused on triage requirements and avoids requiring implementation-only source
cache artifacts.

## Command map

| Command | Use it when |
| --- | --- |
| `validate-cases` | You want to know whether a case root is structurally safe to run. |
| `collect-case` | You want to scaffold fixture files from Jira, GitLab, local files, or recorded web responses. |
| `prepare-case` | You want the collect-run-capture loop for one replayable case. |
| `capture-missing` | A run found replay misses and you want to capture allowed read-only evidence. |
| `run` | You want to validate fixtures, execute a workflow, write actual results, and score each case. |
| `score-result` | You want to compare one expected JSON file with one actual JSON file. |
| `score-results` | You want an aggregate score report for a directory of actual results. |
| `compare-results` | You want a baseline-vs-candidate delta report, optionally in Markdown. |

All commands expose `--help`:

```bash
uv run ymir-harness run --help
```

## Provenance and budgets

Use `--provenance KEY=VALUE` on `run`, `prepare-case`, or `score-results` to
record information reviewers need later, such as:

- `agentic_skills_sha`
- `container_image_digest`
- prompt configuration
- model settings

The harness also records recognized environment values such as `CHAT_MODEL`,
`REASONING_EFFORT`, `BEEAI_MAX_ITERATIONS`, `BENCHMARK_PROMPT_CONFIG`, and
`BENCHMARK_MODEL_SETTINGS`.

Useful run controls:

```bash
export BENCHMARK_MAX_ITERATIONS_OVERRIDE=8
export BENCHMARK_MAX_COST_PER_RUN=5.00
export BENCHMARK_COST_ALERT_THRESHOLD=2.50
```

`BENCHMARK_MAX_COST_PER_RUN` marks over-budget cases as `timeout`.
`BENCHMARK_COST_ALERT_THRESHOLD` records a warning without failing the case.

## Developing

```bash
uv sync
uv run ruff format --check src tests
uv run ruff check
uv run pytest
uv run ymir-harness --version
```

Use the local patterns already in the codebase:

- keep validation, replay, scoring, and workflow adapters separate
- prefer explicit structured records over loose dictionaries
- keep benchmark behavior deterministic for the same fixtures and actual output
- make new fixture requirements visible in validation before relying on them in
  scoring or reports

## License

MIT. See [LICENSE](LICENSE).
