# asel/build_gradle.py
import time
from pathlib import Path

from .build import BuildEngine
from .environment import ExecutionEnvironment
from .models import BuildResult, BuildPhase, ErrorCategory


def categorize_gradle_error(output: str) -> ErrorCategory:
    """Classify a Gradle build failure from its output."""
    lower = output.lower()
    if "could not resolve" in lower or ("dependency" in lower and "not found" in lower):
        return ErrorCategory.DEPENDENCY_CONFLICT
    if "cannot find symbol" in lower or "compilation failed" in lower:
        return ErrorCategory.COMPILE_ERROR
    if "source compatibility" in lower or "class file version" in lower:
        return ErrorCategory.JAVA_VERSION_MISMATCH
    if "tests failed" in lower or ("test" in lower and "failed" in lower and "build failed" in lower):
        return ErrorCategory.TEST_FAILURE
    if "plugin" in lower and ("not found" in lower or "could not resolve" in lower):
        return ErrorCategory.PLUGIN_INCOMPATIBILITY
    return ErrorCategory.UNKNOWN


class GradleBuildEngine(BuildEngine):
    # Map logical phases to Gradle task names
    _TASKS: dict[BuildPhase, list[str]] = {
        BuildPhase.DEPENDENCY_RESOLVE: ["dependencies"],
        BuildPhase.COMPILE:            ["compileJava"],
        BuildPhase.UNIT_TEST:          ["test"],
        BuildPhase.FULL_BUILD:         ["build"],
    }
    _COMMON_FLAGS = ["--no-daemon", "--console=plain"]

    def __init__(self, env: ExecutionEnvironment, repo_path: Path):
        self._env = env
        # Prefer the wrapper (pins Gradle version); fall back to system gradle.
        self._gradle = "./gradlew" if (repo_path / "gradlew").exists() else "gradle"

    def progressive_phases(self) -> list[BuildPhase]:
        return [BuildPhase.DEPENDENCY_RESOLVE, BuildPhase.COMPILE]

    def run_phase(self, phase: BuildPhase, timeout_seconds: int | None = None) -> BuildResult:
        tasks = self._TASKS[phase]
        command = [self._gradle, *tasks, *self._COMMON_FLAGS]
        start = time.monotonic()
        exit_code, output = self._env.run(command, timeout_seconds=timeout_seconds)
        duration = time.monotonic() - start
        if timeout_seconds is not None and exit_code == 124:
            output += f"\n[ASEL] Phase timed out after {timeout_seconds}s"
        success = exit_code == 0
        return BuildResult(
            success=success,
            phase=phase,
            output=output,
            duration_seconds=round(duration, 2),
            error_category=None if success else categorize_gradle_error(output),
        )
