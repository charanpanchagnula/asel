from pathlib import Path
import pytest

@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """A temp directory that looks like a minimal Maven project."""
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0"?>\n'
        '<project>\n'
        '  <modelVersion>4.0.0</modelVersion>\n'
        '  <groupId>com.example</groupId>\n'
        '  <artifactId>demo</artifactId>\n'
        '  <version>1.0.0</version>\n'
        '</project>\n'
    )
    (tmp_path / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)
    return tmp_path

@pytest.fixture
def tmp_gradle_repo(tmp_path: Path) -> Path:
    """A temp directory that looks like a minimal Gradle project."""
    (tmp_path / "build.gradle").write_text(
        'plugins {\n'
        '    id "java"\n'
        '}\n\n'
        'group = "com.example"\n'
        'version = "1.0.0"\n'
        'sourceCompatibility = "17"\n'
    )
    (tmp_path / "gradlew").write_text("#!/bin/sh\nexec gradle \"$@\"\n")
    (tmp_path / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)
    return tmp_path
