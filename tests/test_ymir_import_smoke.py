from __future__ import annotations

import pytest


def test_real_ymir_workflow_modules_are_importable_when_installed() -> None:
    pytest.importorskip("ymir")

    from ymir.agents import backport_agent, rebuild_agent, rebase_agent, triage_agent

    assert callable(triage_agent.run_workflow)
    assert callable(backport_agent.run_workflow)

    missing = [
        name
        for name, module, class_names in (
            ("rebase", rebase_agent, ("RebaseAgent", "RebaseWorkflow")),
            ("rebuild", rebuild_agent, ("RebuildAgent", "RebuildWorkflow")),
        )
        if not _has_class_workflow(module, *class_names)
    ]
    if missing:
        pytest.skip("installed Ymir does not expose class workflow API for " + ", ".join(missing))


def _has_class_workflow(module, *class_names: str) -> bool:
    for class_name in class_names:
        workflow_class = getattr(module, class_name, None)
        if isinstance(workflow_class, type) and callable(
            getattr(workflow_class, "run_workflow", None)
        ):
            return True

    return any(
        isinstance(value, type) and callable(getattr(value, "run_workflow", None))
        for value in vars(module).values()
    )
