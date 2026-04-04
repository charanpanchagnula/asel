# tests/test_controller.py
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from asel.controller import IterationController
from asel.models import (
    RunConfig, RunStatus, IterationSnapshot, BuildResult,
    BuildPhase, ScanFinding, ScannerType, Severity,
)
from pathlib import Path


def make_config(**kwargs) -> RunConfig:
    defaults = dict(
        repo_url="https://github.com/x/y",
        output_dir=Path("/tmp"),
        max_remediation_iterations=10,
        min_findings_per_iteration=3,
        stall_threshold=2,
        min_delta_to_continue=1,
        max_runtime_minutes=60,
    )
    defaults.update(kwargs)
    return RunConfig(**defaults)


def make_build() -> BuildResult:
    return BuildResult(success=True, phase=BuildPhase.FULL_BUILD, output="", duration_seconds=1.0)


def make_finding(rule_id: str) -> ScanFinding:
    return ScanFinding(
        scanner=ScannerType.SEMGREP, severity=Severity.HIGH,
        rule_id=rule_id, file_path="App.java", title="t", description="d",
    )


def make_snapshot(iteration: int, finding_count: int) -> IterationSnapshot:
    return IterationSnapshot(
        iteration=iteration,
        findings=[make_finding(f"rule-{i}") for i in range(finding_count)],
        build_result=make_build(),
    )


def test_effective_max_scales_with_findings():
    ctrl = IterationController(make_config(max_remediation_iterations=10, min_findings_per_iteration=3))
    assert ctrl.effective_max_iterations(9) == 3    # 9//3 = 3
    assert ctrl.effective_max_iterations(30) == 10  # 30//3 = 10, capped at 10
    assert ctrl.effective_max_iterations(1) == 3    # minimum is 3


def test_converges_when_no_findings():
    ctrl = IterationController(make_config())
    ctrl.start()
    snapshots = [make_snapshot(0, 5), make_snapshot(1, 0)]
    should_continue, status = ctrl.decide(1, snapshots)
    assert should_continue is False
    assert status == RunStatus.CONVERGED


def test_stalls_after_no_delta():
    ctrl = IterationController(make_config(stall_threshold=2, min_delta_to_continue=1))
    ctrl.start()
    # Two consecutive iterations with same finding count
    snapshots = [make_snapshot(0, 5), make_snapshot(1, 5), make_snapshot(2, 5)]
    ctrl.decide(1, snapshots[:2])
    should_continue, status = ctrl.decide(2, snapshots)
    assert should_continue is False
    assert status == RunStatus.STALLED


def test_continues_while_making_progress():
    ctrl = IterationController(make_config(stall_threshold=2))
    ctrl.start()
    snapshots = [make_snapshot(0, 10), make_snapshot(1, 7)]
    should_continue, status = ctrl.decide(1, snapshots)
    assert should_continue is True
    assert status == RunStatus.RUNNING


def test_stops_at_max_iterations():
    ctrl = IterationController(make_config(max_remediation_iterations=3, min_findings_per_iteration=3))
    ctrl.start()
    snapshots = [make_snapshot(i, 10 - i) for i in range(4)]
    should_continue, status = ctrl.decide(3, snapshots)
    assert should_continue is False
    assert status == RunStatus.MAX_ITERATIONS


def test_timeout():
    ctrl = IterationController(make_config(max_runtime_minutes=1))
    past_time = datetime.now(timezone.utc) - timedelta(minutes=2)
    ctrl._start_time = past_time
    snapshots = [make_snapshot(0, 5), make_snapshot(1, 4)]
    should_continue, status = ctrl.decide(1, snapshots)
    assert should_continue is False
    assert status == RunStatus.TIMEOUT
