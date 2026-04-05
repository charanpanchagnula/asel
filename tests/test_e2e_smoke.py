# tests/test_e2e_smoke.py
"""
Smoke test: full pipeline with all external calls mocked.
Verifies the pipeline runs end-to-end and produces run-state.json.
"""
import json
from unittest.mock import MagicMock, patch
from asel.pipeline import PipelineOrchestrator
from asel.models import BuildResult, BuildPhase, RunConfig, RunStatus, Language


def make_config(tmp_path) -> RunConfig:
    return RunConfig(
        repo_url="https://github.com/example/demo",
        output_dir=tmp_path,
        max_build_attempts=2,
        max_remediation_iterations=2,
        stall_threshold=2,
    )


def test_full_pipeline_produces_run_state(tmp_path):
    config = make_config(tmp_path)

    # Use a real BuildResult to avoid JSON serialization failures when
    # state.model_dump_json() is called inside _save().
    mock_build_result_ok = BuildResult(
        success=True,
        phase=BuildPhase.FULL_BUILD,
        output="BUILD SUCCESS",
        duration_seconds=1.0,
    )
    mock_run_output = MagicMock(content="Fixed the pom.xml")

    mock_engine = MagicMock()
    mock_engine.run_phase.return_value = mock_build_result_ok

    with patch("asel.pipeline.clone_repo"), \
         patch("asel.pipeline.detect_language", return_value=Language.JAVA_MAVEN), \
         patch("asel.pipeline.ExecutionEnvironment"), \
         patch("asel.pipeline.MavenBuildEngine"), \
         patch("asel.pipeline.create_engine", return_value=mock_engine), \
         patch("asel.pipeline.create_build_agent") as mock_build_agent_fn, \
         patch("asel.pipeline.ScannerOrchestrator") as mock_scanner_cls, \
         patch("asel.pipeline.create_remediation_agent") as mock_rem_agent_fn:

        mock_build_agent_fn.return_value.run.return_value = mock_run_output
        mock_scanner_cls.return_value.run.return_value = []  # no findings -> converge
        mock_rem_agent_fn.return_value.run.return_value = mock_run_output

        orchestrator = PipelineOrchestrator(config)
        state = orchestrator.run()

    assert state.status == RunStatus.CONVERGED
    assert state.run_id is not None

    run_dir = tmp_path / state.run_id
    state_file = run_dir / "run-state.json"
    assert state_file.exists()

    data = json.loads(state_file.read_text())
    assert data["status"] == "converged"
    assert data["repo_url"] == "https://github.com/example/demo"
