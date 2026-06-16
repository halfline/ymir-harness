from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

JUDGE_ENABLE_ENV = ("YMIR_HARNESS_LLM_JUDGE", "RUN_LLM_JUDGE")
JUDGE_MODEL_ENV = ("YMIR_HARNESS_LLM_JUDGE_MODEL", "LLM_JUDGE_MODEL", "CHAT_MODEL")
MAX_TEXT_CHARS = 4000


async def evaluate_backport_llm_judge(
    *,
    actual_result: Mapping[str, Any],
    cases_dir: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    if not _llm_judge_enabled(environment):
        return {}

    model_name = _first_environment_value(environment, JUDGE_MODEL_ENV)
    if model_name is None:
        return {"llm_judge_error": "LLM judge enabled but no judge model is configured"}

    artifact_manifest = _path_or_none(actual_result.get("artifact_manifest"))
    if artifact_manifest is None or not artifact_manifest.is_file():
        return {"llm_judge_error": "LLM judge enabled but artifact manifest is missing"}

    try:
        prompt = _build_backport_judge_prompt(
            actual_result=actual_result,
            cases_dir=cases_dir,
            artifact_manifest=artifact_manifest,
        )
        raw_response = await _run_judge_model(model_name, prompt)
        verdict = _parse_judge_response(raw_response)
    except Exception as exc:
        return {"llm_judge_error": f"{type(exc).__name__}: {exc}"}

    artifact_dir = artifact_manifest.parent
    verdict_path = artifact_dir / "judge_verdict.json"
    try:
        verdict_path.write_text(
            json.dumps(
                {
                    "passed": verdict["passed"],
                    "reasoning": verdict["reasoning"],
                    "raw_response": raw_response,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        return {"llm_judge_error": f"could not write LLM judge verdict: {exc}"}

    return {
        "llm_judge_passed": verdict["passed"],
        "llm_judge_notes": verdict["reasoning"],
        "llm_judge_artifact": str(verdict_path),
    }


def _llm_judge_enabled(environment: Mapping[str, str]) -> bool:
    return any(
        environment.get(name, "").lower() in {"1", "true", "yes"} for name in JUDGE_ENABLE_ENV
    )


def _first_environment_value(environment: Mapping[str, str], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = environment.get(name)
        if value:
            return value
    return None


def _build_backport_judge_prompt(
    *,
    actual_result: Mapping[str, Any],
    cases_dir: Path,
    artifact_manifest: Path,
) -> str:
    manifest = _read_json_object(artifact_manifest)
    captured_files = manifest.get("captured_files")
    captured = captured_files if isinstance(captured_files, Mapping) else {}
    sections = [
        "You are evaluating an automated RPM backport.",
        "",
        "Return a JSON object with exactly these keys:",
        '- "passed": boolean',
        '- "reasoning": concise explanation of each criterion',
        "",
        "Evaluation criteria:",
        "1. The generated patch addresses the requested backport.",
        "2. The spec file adds and applies the patch without unrelated packaging changes.",
        "3. The generated patch only touches files in the reference patch scope when a reference patch is available.",
        "4. The workflow reported success and produced the expected artifacts.",
        "",
        "Task context:",
        _json_block("actual_result", actual_result),
    ]

    commit_diff = _read_manifest_text(captured.get("commit_diff"))
    if commit_diff:
        sections.append(_text_block("commit.diff", commit_diff))

    spec_file = _read_manifest_text(captured.get("spec_file"))
    if spec_file:
        sections.append(_text_block("spec_file.spec", spec_file))

    for patch_path in _manifest_path_list(captured.get("patch_files")):
        text = _read_text(Path(patch_path))
        if text:
            sections.append(_text_block(Path(patch_path).name, text))

    reference_patch = _reference_patch_text(cases_dir, str(actual_result.get("case_id") or ""))
    if reference_patch:
        sections.append(_text_block("reference patch", reference_patch))

    backport_result = _read_manifest_text(captured.get("backport_result"))
    if backport_result:
        sections.append(_text_block("backport_result.json", backport_result))

    return "\n\n".join(sections)


async def _run_judge_model(model_name: str, prompt: str) -> str:
    try:
        from beeai_framework.backend import ChatModel, ChatModelParameters
        from beeai_framework.backend.message import UserMessage
        from pydantic import BaseModel, Field
    except ImportError as exc:
        raise RuntimeError("beeai_framework is required for the LLM judge") from exc

    class VerdictSchema(BaseModel):
        passed: bool = Field(description="Whether the backport passes all criteria")
        reasoning: str = Field(description="Concise explanation for the verdict")

    model = ChatModel.from_name(model_name, ChatModelParameters(temperature=0.2))
    response = await model.run([UserMessage(prompt)], response_format=VerdictSchema)
    return str(response.get_text_content())


def _parse_judge_response(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match is None:
            raise ValueError("judge response did not contain JSON") from None
        payload = json.loads(match.group(0))

    if not isinstance(payload, Mapping):
        raise ValueError("judge response JSON must be an object")
    if not isinstance(payload.get("passed"), bool):
        raise ValueError("judge response must contain boolean 'passed'")
    reasoning = payload.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise ValueError("judge response must contain non-empty 'reasoning'")
    return {"passed": payload["passed"], "reasoning": reasoning.strip()}


def _reference_patch_text(cases_dir: Path, case_id: str) -> str | None:
    if not case_id:
        return None
    for patch_path in sorted(
        (cases_dir / "mock_data").glob(f"*/reference_patches/{case_id}.patch")
    ):
        text = _read_text(patch_path)
        if text:
            return text
    return None


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_manifest_text(value: Any) -> str | None:
    path = _path_or_none(value)
    if path is None:
        return None
    return _read_text(path)


def _manifest_path_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple):
        return [str(item) for item in value if item]
    return []


def _read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _path_or_none(value: Any) -> Path | None:
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value:
        return Path(value)
    return None


def _json_block(label: str, value: Mapping[str, Any]) -> str:
    return f"## {label}\n\n```json\n{_truncate(json.dumps(value, indent=2, sort_keys=True))}\n```"


def _text_block(label: str, text: str) -> str:
    return f"## {label}\n\n```\n{_truncate(text)}\n```"


def _truncate(text: str) -> str:
    if len(text) <= MAX_TEXT_CHARS:
        return text
    return text[:MAX_TEXT_CHARS] + "\n... [truncated]"
