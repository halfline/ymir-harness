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


## Development

```bash
uv sync
uv run pytest
uv run ymir-harness --version
```
