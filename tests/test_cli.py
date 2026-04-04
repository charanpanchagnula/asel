# tests/test_cli.py
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from asel.cli import app
from asel.models import RunState, RunStatus
from datetime import datetime, timezone

runner = CliRunner()


def test_cli_run_invokes_orchestrator():
    mock_state = RunState(
        run_id="abc123",
        repo_url="https://github.com/x/y",
        started_at=datetime.now(timezone.utc),
        status=RunStatus.CONVERGED,
    )
    with patch("asel.cli.PipelineOrchestrator") as mock_cls:
        mock_cls.return_value.run.return_value = mock_state
        result = runner.invoke(app, ["run", "https://github.com/x/y"])
    assert result.exit_code == 0
    mock_cls.return_value.run.assert_called_once()


def test_cli_exits_nonzero_on_build_failure():
    mock_state = RunState(
        run_id="abc123",
        repo_url="https://github.com/x/y",
        started_at=datetime.now(timezone.utc),
        status=RunStatus.BUILD_FAILED,
    )
    with patch("asel.cli.PipelineOrchestrator") as mock_cls:
        mock_cls.return_value.run.return_value = mock_state
        result = runner.invoke(app, ["run", "https://github.com/x/y"])
    assert result.exit_code == 1
