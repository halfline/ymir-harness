from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ymir_harness.enforcement import enforce_benchmark_boundaries
from ymir_harness.runner import (
    RunCaseExecution,
    execution_to_payload,
    request_from_payload,
    timeout_failure,
    workflow_timeout_reason,
)
from ymir_harness.ymir_workflows import (
    make_ymir_backport_executor,
    make_ymir_rebase_executor,
    make_ymir_rebuild_executor,
    make_ymir_triage_executor,
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        sys.stderr.write("usage: python -m ymir_harness.workflow_worker REQUEST RESULT\n")
        return 2

    request_path = Path(args[0])
    result_path = Path(args[1])
    payload = json.loads(request_path.read_text(encoding="utf-8"))
    workflow = str(payload["workflow"])
    request = request_from_payload(payload["request"])

    executor = _executor_for_workflow(workflow)
    with enforce_benchmark_boundaries(request.environment):
        try:
            execution = executor(request)
        except BaseException as exc:
            if not timeout_failure(exc, request.environment):
                raise
            execution = RunCaseExecution(
                status="timeout",
                reason=workflow_timeout_reason(workflow, request.environment, exc),
            )

    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps(execution_to_payload(execution), default=str, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def _executor_for_workflow(workflow: str) -> Any:
    if workflow == "ymir-triage":
        return make_ymir_triage_executor()
    if workflow == "ymir-backport":
        return make_ymir_backport_executor()
    if workflow == "ymir-rebase":
        return make_ymir_rebase_executor()
    if workflow == "ymir-rebuild":
        return make_ymir_rebuild_executor()
    return _unsupported_executor(workflow)


def _unsupported_executor(workflow: str) -> Any:
    def executor(_request: object) -> RunCaseExecution:
        return RunCaseExecution(status="failed", reason=f"unsupported Ymir workflow: {workflow}")

    return executor


if __name__ == "__main__":
    raise SystemExit(main())
