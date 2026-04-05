# asel/build.py
import time
from abc import ABC, abstractmethod
from pathlib import Path

from .environment import ExecutionEnvironment
from .models import BuildResult, BuildPhase, ErrorCategory, Language


# Maven commands for each build phase
PHASE_COMMANDS: dict[BuildPhase, list[str]] = {
    BuildPhase.DEPENDENCY_RESOLVE: ["mvn", "dependency:resolve", "--batch-mode"],
    BuildPhase.COMPILE:            ["mvn", "compile", "-DskipTests", "--batch-mode"],
    BuildPhase.UNIT_TEST:          ["mvn", "test", "-DskipITs", "--batch-mode"],
    BuildPhase.FULL_BUILD:         ["mvn", "clean", "install", "--batch-mode"],
}


class BuildEngine(ABC):
    """Interface all build tools must implement. Add new build systems by subclassing this."""

    @abstractmethod
    def progressive_phases(self) -> list[BuildPhase]:
        """Ordered phases for build stabilization — must never include test execution."""
        ...

    @abstractmethod
    def run_phase(self, phase: BuildPhase, timeout_seconds: int | None = None) -> BuildResult:
        """Execute one logical phase and return the result. Never raises."""
        ...


def categorize_error(output: str) -> ErrorCategory:
    """Classify a Maven build failure from its output."""
    lower = output.lower()
    if "could not resolve" in lower or ("artifact" in lower and "not found" in lower):
        return ErrorCategory.DEPENDENCY_CONFLICT
    if "cannot find symbol" in lower or "does not compile" in lower:
        return ErrorCategory.COMPILE_ERROR
    if "source release" in lower or "target release" in lower:
        return ErrorCategory.JAVA_VERSION_MISMATCH
    if "tests run:" in lower and "failure" in lower:
        return ErrorCategory.TEST_FAILURE
    if "failed to execute goal" in lower and "plugin" in lower:
        return ErrorCategory.PLUGIN_INCOMPATIBILITY
    return ErrorCategory.UNKNOWN


class MavenBuildEngine(BuildEngine):
    def __init__(self, env: ExecutionEnvironment):
        self._env = env

    def progressive_phases(self) -> list[BuildPhase]:
        """Phases used during build stabilization — never runs tests."""
        return [
            BuildPhase.DEPENDENCY_RESOLVE,
            BuildPhase.COMPILE,
        ]

    def run_phase(self, phase: BuildPhase, timeout_seconds: int | None = None) -> BuildResult:
        """Run a single Maven build phase and return the result.

        If timeout_seconds is set and the phase exceeds it, the result is marked
        as failed with error_category UNKNOWN and the output notes the timeout.
        """
        start = time.monotonic()
        exit_code, output = self._env.run(PHASE_COMMANDS[phase], timeout_seconds=timeout_seconds)
        duration = time.monotonic() - start
        if timeout_seconds is not None and exit_code == 124:
            output += f"\n[ASEL] Phase timed out after {timeout_seconds}s"
        success = exit_code == 0
        return BuildResult(
            success=success,
            phase=phase,
            output=output,
            duration_seconds=round(duration, 2),
            error_category=None if success else categorize_error(output),
        )


def create_engine(language: Language, env: ExecutionEnvironment, repo_path: Path) -> BuildEngine:
    """Factory — returns the right BuildEngine for a detected language.

    Extending to a new language: add an elif branch pointing at your BuildEngine subclass.
    """
    if language == Language.JAVA_MAVEN:
        return MavenBuildEngine(env)
    if language == Language.JAVA_GRADLE:
        from .build_gradle import GradleBuildEngine
        return GradleBuildEngine(env, repo_path)
    raise ValueError(f"No build engine for language: {language}")
