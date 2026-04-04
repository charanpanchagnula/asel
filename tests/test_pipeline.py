# tests/test_pipeline.py
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch
from asel.pipeline import PipelineOrchestrator
from asel.models import (
    RunConfig, RunState, RunStatus, BuildResult, BuildPhase,
    ScanFinding, ScannerType, Severity, Language, IterationSnapshot,
)


def make_config(tmp_path) -> RunConfig:
    return RunConfig(
        repo_url="https://github.com/example/demo",
        output_dir=tmp_path,
        max_build_attempts=3,
        max_remediation_iterations=2,
        stall_threshold=2,
    )


def make_build_ok() -> BuildResult:
    return BuildResult(success=True, phase=BuildPhase.FULL_BUILD, output="BUILD SUCCESS", duration_seconds=1.0)


def make_build_fail() -> BuildResult:
    return BuildResult(success=False, phase=BuildPhase.FULL_BUILD, output="BUILD FAILURE", duration_seconds=1.0)


def make_finding() -> ScanFinding:
    return ScanFinding(
        scanner=ScannerType.TRIVY, severity=Severity.HIGH,
        rule_id="CVE-2021-1234", file_path="pom.xml", title="t", description="d",
    )


def test_run_fails_on_unsupported_language(tmp_path):
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", side_effect=ValueError("Unsupported")):
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.UNSUPPORTED_LANGUAGE


def test_run_fails_when_build_never_succeeds(tmp_path):
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment") as mock_env_cls, \
         patch("asel.pipeline.MavenBuildEngine") as mock_engine_cls, \
         patch("asel.pipeline.create_build_agent") as mock_build_agent:
        mock_engine_cls.return_value.progressive_phases.return_value = [BuildPhase.FULL_BUILD]
        mock_engine_cls.return_value.run_phase.return_value = make_build_fail()
        mock_build_agent.return_value.run.return_value = MagicMock(content="tried a fix")
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.BUILD_FAILED


def test_run_converges_when_no_findings(tmp_path):
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine") as mock_engine_cls, \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"):
        mock_engine_cls.return_value.progressive_phases.return_value = [BuildPhase.FULL_BUILD]
        mock_engine_cls.return_value.run_phase.return_value = make_build_ok()
        mock_scanner_cls.return_value.run.return_value = []  # no findings
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert state.status == RunStatus.CONVERGED


def test_patch_rolled_back_when_build_fails(tmp_path):
    """When a remediaiton patch breaks the build, files must be rolled back."""
    cfg = make_config(tmp_path)
    finding = make_finding()
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine") as mock_engine_cls, \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"), \
         patch("asel.pipeline.PipelineOrchestrator._snapshot_repo") as mock_snap, \
         patch("asel.pipeline.PipelineOrchestrator._rollback_repo") as mock_rollback:
        # run_phase: stabilization succeeds, every remediation rebuild fails
        mock_engine_cls.return_value.progressive_phases.return_value = [BuildPhase.FULL_BUILD]
        mock_engine_cls.return_value.run_phase.side_effect = [make_build_ok()] + [make_build_fail()] * 10
        mock_scanner_cls.return_value.run.return_value = [finding]
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    assert mock_snap.call_count >= 1
    assert mock_rollback.call_count >= 1
    # Finding set must not advance when patch is rejected
    assert state.findings == [finding]


def test_patch_rolled_back_when_net_negative(tmp_path):
    """When a patch introduces more findings than it fixes, files must be rolled back."""
    cfg = make_config(tmp_path)
    original_finding = make_finding()
    new_finding = ScanFinding(
        scanner=ScannerType.TRIVY, severity=Severity.HIGH,
        rule_id="CVE-2022-9999", file_path="pom.xml", title="new", description="new",
    )
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine") as mock_engine_cls, \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"), \
         patch("asel.pipeline.PipelineOrchestrator._snapshot_repo"), \
         patch("asel.pipeline.PipelineOrchestrator._rollback_repo") as mock_rollback:
        mock_engine_cls.return_value.progressive_phases.return_value = [BuildPhase.FULL_BUILD]
        mock_engine_cls.return_value.run_phase.return_value = make_build_ok()
        # Baseline: 1 finding. After patch: 2 findings (net-negative)
        mock_scanner_cls.return_value.run.side_effect = [
            [original_finding],           # baseline scan
            [original_finding, new_finding],  # post-patch scan: worse
        ]
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    mock_rollback.assert_called_once()
    # Finding set must stay at pre-patch state
    assert len(state.findings) == 1


def test_run_state_is_written_to_disk(tmp_path):
    cfg = make_config(tmp_path)
    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine") as mock_engine_cls, \
         patch("asel.pipeline.create_build_agent"), \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent"):
        mock_engine_cls.return_value.progressive_phases.return_value = [BuildPhase.FULL_BUILD]
        mock_engine_cls.return_value.run_phase.return_value = make_build_ok()
        mock_scanner_cls.return_value.run.return_value = []
        orchestrator = PipelineOrchestrator(cfg)
        state = orchestrator.run()
    run_dir = tmp_path / state.run_id
    assert (run_dir / "run-state.json").exists()
