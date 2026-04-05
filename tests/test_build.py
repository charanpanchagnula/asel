# tests/test_build.py
from unittest.mock import MagicMock
from asel.build import MavenBuildEngine, categorize_error
from asel.models import BuildPhase, ErrorCategory


def make_env(exit_code: int, output: str) -> MagicMock:
    env = MagicMock()
    env.run.return_value = (exit_code, output)
    return env


def test_successful_full_build():
    env = make_env(0, "BUILD SUCCESS")
    engine = MavenBuildEngine(env)
    result = engine.run_phase(BuildPhase.FULL_BUILD)
    assert result.success is True
    assert result.phase == BuildPhase.FULL_BUILD
    assert result.error_category is None


def test_failed_build_has_error_category():
    env = make_env(1, "Could not resolve dependency: com.example:missing:1.0")
    engine = MavenBuildEngine(env)
    result = engine.run_phase(BuildPhase.DEPENDENCY_RESOLVE)
    assert result.success is False
    assert result.error_category == ErrorCategory.DEPENDENCY_CONFLICT


def test_categorize_java_version_mismatch():
    output = "source release 17 requires target release 17"
    assert categorize_error(output) == ErrorCategory.JAVA_VERSION_MISMATCH


def test_categorize_compile_error():
    output = "cannot find symbol\n  symbol: method foo()"
    assert categorize_error(output) == ErrorCategory.COMPILE_ERROR


def test_categorize_test_failure():
    output = "Tests run: 5, Failures: 2, Errors: 0\nBUILD FAILURE"
    assert categorize_error(output) == ErrorCategory.TEST_FAILURE


def test_progressive_phases_order():
    engine = MavenBuildEngine(MagicMock())
    phases = engine.progressive_phases()
    assert phases[0] == BuildPhase.DEPENDENCY_RESOLVE
    assert phases[1] == BuildPhase.COMPILE
    assert BuildPhase.FULL_BUILD not in phases  # stabilization never runs tests


import pytest
from pathlib import Path
from asel.build import BuildEngine
from asel.models import Language


def test_maven_engine_implements_build_engine():
    engine = MavenBuildEngine(MagicMock())
    assert isinstance(engine, BuildEngine)


def test_create_engine_returns_maven_for_java_maven():
    from asel.build import create_engine
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        engine = create_engine(Language.JAVA_MAVEN, MagicMock(), Path(d))
    assert isinstance(engine, MavenBuildEngine)


def test_create_engine_raises_for_unknown_language():
    from asel.build import create_engine
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="No build engine"):
            create_engine(Language.AUTO_DETECT, MagicMock(), Path(d))


from asel.build_gradle import GradleBuildEngine, categorize_gradle_error


def test_gradle_engine_implements_build_engine():
    engine = GradleBuildEngine(MagicMock(), Path("/repo"))
    assert isinstance(engine, BuildEngine)


def test_gradle_progressive_phases_order():
    engine = GradleBuildEngine(MagicMock(), Path("/repo"))
    phases = engine.progressive_phases()
    assert phases[0] == BuildPhase.DEPENDENCY_RESOLVE
    assert phases[1] == BuildPhase.COMPILE
    assert BuildPhase.FULL_BUILD not in phases


def test_gradle_successful_compile():
    env = make_env(0, "BUILD SUCCESSFUL")
    engine = GradleBuildEngine(env, Path("/repo"))
    result = engine.run_phase(BuildPhase.COMPILE)
    assert result.success is True
    assert result.phase == BuildPhase.COMPILE
    assert result.error_category is None


def test_gradle_failed_build_has_error_category():
    env = make_env(1, "Could not resolve com.example:missing:1.0")
    engine = GradleBuildEngine(env, Path("/repo"))
    result = engine.run_phase(BuildPhase.DEPENDENCY_RESOLVE)
    assert result.success is False
    assert result.error_category == ErrorCategory.DEPENDENCY_CONFLICT


def test_gradle_uses_wrapper_when_present(tmp_path):
    (tmp_path / "gradlew").write_text("#!/bin/sh")
    env = make_env(0, "BUILD SUCCESSFUL")
    engine = GradleBuildEngine(env, tmp_path)
    engine.run_phase(BuildPhase.COMPILE)
    call_args = env.run.call_args[0][0]
    assert call_args[0] == "./gradlew"


def test_gradle_falls_back_to_gradle_command(tmp_path):
    # No gradlew file present
    env = make_env(0, "BUILD SUCCESSFUL")
    engine = GradleBuildEngine(env, tmp_path)
    engine.run_phase(BuildPhase.COMPILE)
    call_args = env.run.call_args[0][0]
    assert call_args[0] == "gradle"


def test_categorize_gradle_error_dependency():
    assert categorize_gradle_error("Could not resolve com.example:lib:1.0") == ErrorCategory.DEPENDENCY_CONFLICT


def test_categorize_gradle_error_compile():
    assert categorize_gradle_error("error: cannot find symbol\nCompilation failed") == ErrorCategory.COMPILE_ERROR


def test_categorize_gradle_error_java_version():
    assert categorize_gradle_error("source compatibility with Java 8 requires class file version") == ErrorCategory.JAVA_VERSION_MISMATCH


def test_categorize_gradle_error_test_failure():
    assert categorize_gradle_error("2 tests failed\nBUILD FAILED") == ErrorCategory.TEST_FAILURE


def test_create_engine_returns_gradle_for_java_gradle(tmp_path):
    from asel.build import create_engine
    engine = create_engine(Language.JAVA_GRADLE, MagicMock(), tmp_path)
    assert isinstance(engine, GradleBuildEngine)
