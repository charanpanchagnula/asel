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
    assert phases[2] == BuildPhase.FULL_BUILD
