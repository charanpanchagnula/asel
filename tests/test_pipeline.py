# tests/test_pipeline.py
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch
from asel.pipeline import PipelineOrchestrator, MAX_TRIES_PER_FINDING, MAX_BUILD_REPAIR_ATTEMPTS
from asel.models import (
    RunConfig, RunState, RunStatus, BuildResult, BuildPhase,
    ScanFinding, ScannerType, Severity, Language, IterationSnapshot,
)


def make_config(tmp_path, **overrides) -> RunConfig:
    defaults = dict(
        repo_url="https://github.com/example/demo",
        output_dir=tmp_path,
        max_build_attempts=3,
        stall_threshold=2,
    )
    defaults.update(overrides)
    return RunConfig(**defaults)


def make_build_ok() -> BuildResult:
    return BuildResult(success=True, phase=BuildPhase.FULL_BUILD, output="BUILD SUCCESS", duration_seconds=1.0)


def make_build_fail() -> BuildResult:
    return BuildResult(success=False, phase=BuildPhase.FULL_BUILD, output="BUILD FAILURE", duration_seconds=1.0)


def make_finding(rule_id: str = "CVE-2021-1234") -> ScanFinding:
    return ScanFinding(
        scanner=ScannerType.TRIVY, severity=Severity.HIGH,
        rule_id=rule_id, file_path="pom.xml", title="t", description="d",
    )


def test_run_fails_on_unsupported_language(tmp_path):
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", side_effect=ValueError("Unsupported")):
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.UNSUPPORTED_LANGUAGE


def test_dependency_resolve_alone_does_not_satisfy_build(tmp_path):
    """dependency:resolve succeeding must not count as a successful build — compile must also pass."""
    cfg = make_config(tmp_path, max_build_attempts=2)
    mock_engine = MagicMock()
    mock_engine.run_phase.side_effect = [
        BuildResult(success=True, phase=BuildPhase.DEPENDENCY_RESOLVE, output="OK", duration_seconds=1.0),
        BuildResult(success=False, phase=BuildPhase.COMPILE, output="COMPILE ERROR", duration_seconds=1.0),
        BuildResult(success=False, phase=BuildPhase.FULL_BUILD, output="COMPILE ERROR", duration_seconds=1.0),
    ]
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"):
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.BUILD_FAILED


def test_run_fails_when_build_never_succeeds(tmp_path):
    cfg = make_config(tmp_path)
    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = make_build_fail()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent") as mock_build_agent:
        mock_build_agent.return_value.run.return_value = MagicMock(content="tried a fix")
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.BUILD_FAILED


def test_run_converges_when_no_findings(tmp_path):
    cfg = make_config(tmp_path)
    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = make_build_ok()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"):
        mock_scanner_cls.return_value.run.return_value = []
        mock_scanner_cls.return_value.had_timeout = False
        mock_scanner_cls.return_value.scanner_times = {}
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.CONVERGED


def test_patch_rolled_back_when_build_fails(tmp_path):
    """When a remediation patch breaks the build and repairs are exhausted, files must be rolled back."""
    cfg = make_config(tmp_path)
    finding = make_finding()
    # run_phase calls per iteration: 1 initial + MAX_BUILD_REPAIR_ATTEMPTS repairs
    calls_per_iter = 1 + MAX_BUILD_REPAIR_ATTEMPTS
    # total: 1 stabilization success + (MAX_TRIES_PER_FINDING iters × calls_per_iter fails)
    fail_count = MAX_TRIES_PER_FINDING * calls_per_iter + 5
    mock_engine = MagicMock()
    mock_engine.run_phase.side_effect = [make_build_ok(), make_build_ok()] + [make_build_fail()] * fail_count
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"), \
         patch("asel.pipeline.PipelineOrchestrator._snapshot_repo") as mock_snap, \
         patch("asel.pipeline.PipelineOrchestrator._rollback_repo") as mock_rollback, \
         patch("asel.pipeline.PipelineOrchestrator._capture_diff", return_value=("diff", ["pom.xml"])):
        mock_scanner_cls.return_value.run.return_value = [finding]
        mock_scanner_cls.return_value.had_timeout = False
        mock_scanner_cls.return_value.scanner_times = {}
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert mock_snap.call_count >= 1
    assert mock_rollback.call_count >= 1
    # Finding set must not advance when patch is rejected
    assert state.findings == [finding]


def test_patch_rolled_back_when_net_negative(tmp_path):
    """When a patch introduces more findings than it fixes, files must be rolled back."""
    cfg = make_config(tmp_path)
    original_finding = make_finding("CVE-2021-1234")
    new_finding = make_finding("CVE-2022-9999")
    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = make_build_ok()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"), \
         patch("asel.pipeline.PipelineOrchestrator._snapshot_repo"), \
         patch("asel.pipeline.PipelineOrchestrator._rollback_repo") as mock_rollback, \
         patch("asel.pipeline.PipelineOrchestrator._capture_diff", return_value=("diff", ["pom.xml"])):
        # Baseline: 1 finding. Every post-patch scan: net-negative (2 findings).
        # Provide enough results for MAX_TRIES_PER_FINDING iterations.
        mock_scanner_cls.return_value.run.side_effect = (
            [[original_finding]]  # baseline
            + [[original_finding, new_finding]] * MAX_TRIES_PER_FINDING  # each re-scan
        )
        mock_scanner_cls.return_value.had_timeout = False
        mock_scanner_cls.return_value.scanner_times = {}
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert mock_rollback.call_count >= 1
    # Finding set must stay at pre-patch state
    assert len(state.findings) == 1


def test_converges_when_finding_fixed(tmp_path):
    """When the agent resolves the only finding, status must be CONVERGED."""
    cfg = make_config(tmp_path)
    finding = make_finding()
    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = make_build_ok()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"), \
         patch("asel.pipeline.PipelineOrchestrator._snapshot_repo"), \
         patch("asel.pipeline.PipelineOrchestrator._rollback_repo"), \
         patch("asel.pipeline.PipelineOrchestrator._capture_diff", return_value=("diff", ["pom.xml"])):
        mock_scanner_cls.return_value.run.side_effect = [
            [finding],  # baseline
            [],         # after patch: finding gone
        ]
        mock_scanner_cls.return_value.had_timeout = False
        mock_scanner_cls.return_value.scanner_times = {}
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.CONVERGED
    assert state.findings == []


def test_skips_stuck_finding_and_moves_on(tmp_path):
    """After MAX_TRIES_PER_FINDING failed attempts, the finding is skipped and the next is tried."""
    cfg = make_config(tmp_path)
    stuck = make_finding("STUCK-001")
    fixable = make_finding("FIXABLE-002")
    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = make_build_ok()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"), \
         patch("asel.pipeline.PipelineOrchestrator._snapshot_repo"), \
         patch("asel.pipeline.PipelineOrchestrator._rollback_repo"), \
         patch("asel.pipeline.PipelineOrchestrator._capture_diff", return_value=("diff", ["pom.xml"])):
        mock_scanner_cls.return_value.run.side_effect = [
            [stuck, fixable],          # baseline
            [stuck, fixable],          # iter 1: stuck finding unchanged
            [stuck, fixable],          # iter 2: stuck finding unchanged (now skipped)
            [stuck],                   # iter 3: fixable resolved
        ]
        mock_scanner_cls.return_value.had_timeout = False
        mock_scanner_cls.return_value.scanner_times = {}
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    # fixable should be gone; stuck remains (was skipped, not rolled back)
    remaining_ids = {f.id for f in state.findings}
    assert fixable.id not in remaining_ids
    assert stuck.id in remaining_ids


def test_run_state_is_written_to_disk(tmp_path):
    cfg = make_config(tmp_path)
    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = make_build_ok()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"):
        mock_scanner_cls.return_value.run.return_value = []
        mock_scanner_cls.return_value.had_timeout = False
        mock_scanner_cls.return_value.scanner_times = {}
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    run_dir = tmp_path / state.run_id
    assert (run_dir / "run-state.json").exists()


def test_run_detects_gradle_and_uses_create_engine(tmp_path):
    """Pipeline must call create_engine with the detected language."""
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_GRADLE), \
         patch("asel.pipeline.select_image", return_value="gradle:8-jdk21"), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.create_engine") as mock_ce, \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_sc:
        mock_engine = MagicMock()
        mock_engine.run_phase.return_value = make_build_ok()
        mock_ce.return_value = mock_engine
        mock_sc.return_value.run.return_value = []
        state = PipelineOrchestrator(cfg).run()
    mock_ce.assert_called_once()
    assert mock_ce.call_args[0][0] == Language.JAVA_GRADLE
    assert state.status == RunStatus.CONVERGED


def test_run_passes_language_to_build_agent(tmp_path):
    """create_build_agent must receive language= kwarg."""
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_GRADLE), \
         patch("asel.pipeline.select_image", return_value="gradle:8-jdk21"), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.create_engine") as mock_ce, \
         patch("asel.pipeline.create_build_agent") as mock_cba, \
         patch("asel.pipeline.ScannerOrchestrator") as mock_sc:
        mock_engine = MagicMock()
        mock_engine.run_phase.return_value = make_build_fail()
        mock_ce.return_value = mock_engine
        mock_cba.return_value.run.return_value = MagicMock(content="fix")
        mock_sc.return_value.run.return_value = []
        PipelineOrchestrator(cfg).run()
    _, kwargs = mock_cba.call_args
    assert kwargs.get("language") == Language.JAVA_GRADLE
