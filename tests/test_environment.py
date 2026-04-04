# tests/test_environment.py
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from asel.environment import ExecutionEnvironment

MAVEN_IMAGE = "maven:3.9-eclipse-temurin-17"


def make_env(tmp_path):
    return ExecutionEnvironment(repo_path=tmp_path, image=MAVEN_IMAGE)


def test_start_creates_container(tmp_path):
    mock_container = MagicMock()
    with patch("asel.environment.docker.from_env") as mock_docker:
        mock_docker.return_value.containers.run.return_value = mock_container
        env = make_env(tmp_path)
        env.start()
        mock_docker.return_value.containers.run.assert_called_once()
        call_kwargs = mock_docker.return_value.containers.run.call_args
        assert call_kwargs[0][0] == MAVEN_IMAGE
        assert call_kwargs[1]["detach"] is True


def test_run_returns_exit_code_and_output(tmp_path):
    mock_container = MagicMock()
    mock_container.exec_run.return_value = MagicMock(
        exit_code=0,
        output=(b"BUILD SUCCESS", b""),
    )
    with patch("asel.environment.docker.from_env"):
        env = make_env(tmp_path)
        env._container = mock_container
        exit_code, output = env.run(["mvn", "clean", "install"])
        assert exit_code == 0
        assert "BUILD SUCCESS" in output


def test_run_raises_if_not_started(tmp_path):
    with patch("asel.environment.docker.from_env"):
        env = make_env(tmp_path)
        with pytest.raises(RuntimeError, match="not started"):
            env.run(["mvn", "--version"])


def test_stop_removes_container(tmp_path):
    mock_container = MagicMock()
    with patch("asel.environment.docker.from_env"):
        env = make_env(tmp_path)
        env._container = mock_container
        env.stop()
        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once()
        assert env._container is None
