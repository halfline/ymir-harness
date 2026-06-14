from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any


PROVENANCE_ENV_NAMES = (
    "AGENTIC_SKILLS_SHA",
    "AGENTIC_SKILLS_CHECKSUM",
    "CONTAINER_IMAGE_DIGEST",
    "CHAT_MODEL",
    "CHAT_MODEL_TRIAGE",
    "CHAT_MODEL_BACKPORT",
    "CHAT_MODEL_REBASE",
    "CHAT_MODEL_REBUILD",
    "REASONING_EFFORT",
    "BEEAI_MAX_ITERATIONS",
    "BENCHMARK_PROMPT_CONFIG",
    "BENCHMARK_MODEL_SETTINGS",
)


def collect_provenance(
    *,
    base_env: Mapping[str, str] | None = None,
    ymir_sha: str | None = None,
    features: Sequence[str] = (),
    overrides: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    env = os.environ if base_env is None else base_env
    provenance: dict[str, Any] = {}

    if ymir_sha:
        provenance["ymir_sha"] = ymir_sha
    if features:
        provenance["feature_flags"] = list(features)

    for name in PROVENANCE_ENV_NAMES:
        value = env.get(name)
        if value:
            provenance[_provenance_key(name)] = value

    model_overrides = {
        key: env[key]
        for key in (
            "CHAT_MODEL_TRIAGE",
            "CHAT_MODEL_BACKPORT",
            "CHAT_MODEL_REBASE",
            "CHAT_MODEL_REBUILD",
        )
        if env.get(key)
    }
    if model_overrides:
        provenance["agent_model_overrides"] = model_overrides

    if overrides:
        provenance.update(
            {key: value for key, value in overrides.items() if value not in (None, "")}
        )

    return provenance


def parse_provenance_items(items: Sequence[str]) -> dict[str, str]:
    parsed = {}
    for item in items:
        key, separator, value = item.partition("=")
        if not separator or not key:
            msg = f"provenance entries must use KEY=VALUE: {item}"
            raise ValueError(msg)
        parsed[key] = value
    return parsed


def _provenance_key(name: str) -> str:
    return name.lower()
