# tests/test_ingestor.py
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from asel.ingestor import clone_repo, detect_language, detect_java_version, select_maven_image
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


def test_detect_java_version_java_version_tag(tmp_path):
    (tmp_path / "pom.xml").write_text("<project><properties><java.version>21</java.version></properties></project>")
    assert detect_java_version(tmp_path) == 21


def test_detect_java_version_compiler_source(tmp_path):
    (tmp_path / "pom.xml").write_text("<project><properties><maven.compiler.source>17</maven.compiler.source></properties></project>")
    assert detect_java_version(tmp_path) == 17


def test_detect_java_version_missing(tmp_path):
    (tmp_path / "pom.xml").write_text("<project></project>")
    assert detect_java_version(tmp_path) is None


@pytest.mark.parametrize("java_ver,expected_tag", [
    (8,  "temurin-8"),
    (11, "temurin-11"),
    (17, "temurin-17"),
    (21, "temurin-21"),
    (25, "temurin-25"),
])
def test_select_maven_image_exact_match(tmp_path, java_ver, expected_tag):
    (tmp_path / "pom.xml").write_text(f"<project><properties><java.version>{java_ver}</java.version></properties></project>")
    assert expected_tag in select_maven_image(tmp_path)


@pytest.mark.parametrize("java_ver,expected_tag", [
    (9,  "temurin-11"),   # between 8 and 11 → picks 11
    (15, "temurin-17"),   # between 11 and 17 → picks 17
    (18, "temurin-21"),   # between 17 and 21 → picks 21
    (22, "temurin-25"),   # between 21 and 25 → picks 25
    (99, "temurin-25"),   # exceeds all available → falls back to highest
])
def test_select_maven_image_rounds_up(tmp_path, java_ver, expected_tag):
    (tmp_path / "pom.xml").write_text(f"<project><properties><java.version>{java_ver}</java.version></properties></project>")
    assert expected_tag in select_maven_image(tmp_path)


def test_select_maven_image_unknown_version_uses_default(tmp_path):
    (tmp_path / "pom.xml").write_text("<project></project>")
    image = select_maven_image(tmp_path)
    assert "maven:" in image


def test_detect_language_java_gradle_groovy_dsl(tmp_path):
    (tmp_path / "build.gradle").write_text('plugins { id "java" }')
    from asel.models import Language
    assert detect_language(tmp_path) == Language.JAVA_GRADLE


def test_detect_language_java_gradle_kotlin_dsl(tmp_path):
    (tmp_path / "build.gradle.kts").write_text('plugins { java }')
    from asel.models import Language
    assert detect_language(tmp_path) == Language.JAVA_GRADLE
