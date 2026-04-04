# tests/test_ingestor.py
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from asel.ingestor import clone_repo, detect_language
from asel.models import Language


def test_clone_repo_success(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = clone_repo("https://github.com/x/y", tmp_path / "repo")
        assert result == tmp_path / "repo"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "git"
        assert "https://github.com/x/y" in args


def test_clone_repo_failure(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: repo not found")
        with pytest.raises(RuntimeError, match="git clone failed"):
            clone_repo("https://github.com/bad/repo", tmp_path / "repo")


def test_detect_language_java_maven(tmp_repo):
    assert detect_language(tmp_repo) == Language.JAVA_MAVEN


def test_detect_language_unsupported(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(ValueError, match="Unsupported"):
        detect_language(tmp_path)
