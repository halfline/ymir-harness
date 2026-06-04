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
ymir-harness score-results benchmark_cases/ reports/actual-results/
ymir-harness compare-results reports/baseline-results.json reports/enhanced-results.json
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

`score-results` reads every `benchmark_cases/expected/*.expected.json` file and
matches actual outputs named `CASE_ID.actual.json` or `CASE_ID.json` in the
actual-results directory. It writes aggregate JSON to
`benchmark_cases/reports/results.json` unless `--output` is provided.

`compare-results` reads two aggregate score reports and emits a per-case delta
table in JSON. A headline regression or missing candidate case returns a nonzero
exit status.

## Development

```bash
uv sync
uv run pytest
uv run ymir-harness --version
```
