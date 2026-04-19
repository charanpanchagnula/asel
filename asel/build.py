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
    BuildPhase.PACKAGE:            ["mvn", "package", "-DskipTests", "--batch-mode"],
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


def categorize_build_error(output: str) -> ErrorCategory:
    """Classify a JVM build failure (Maven or Gradle) from its output.

    Priority order matters: network before plugin, plugin before generic dep.
    """
    lower = output.lower()
    # 1. Network failures first — "failed to execute goal" can appear in INFO download
    #    lines and would otherwise trigger the plugin check below.
    if any(p in lower for p in ("could not transfer", "failed to respond",
                                 "network is unreachable", "could not collect")):
        return ErrorCategory.DEPENDENCY_CONFLICT
    # 2. Plugin missing — Gradle surfaces this before the generic dep error
    if "plugin" in lower and any(p in lower for p in ("not found", "could not resolve")):
        return ErrorCategory.PLUGIN_INCOMPATIBILITY
    # 3. Generic dependency resolution failure
    if "could not resolve" in lower or (
        any(kw in lower for kw in ("artifact", "dependency")) and "not found" in lower
    ):
        return ErrorCategory.DEPENDENCY_CONFLICT
    # 4. Compile errors
    if any(p in lower for p in ("cannot find symbol", "does not compile", "compilation failed")):
        return ErrorCategory.COMPILE_ERROR
    # 5. Java version mismatch
    if any(p in lower for p in ("source release", "target release",
                                  "source compatibility", "class file version")):
        return ErrorCategory.JAVA_VERSION_MISMATCH
    # 6. Test failures
    if ("tests run:" in lower and "failure" in lower) or "tests failed" in lower:
        return ErrorCategory.TEST_FAILURE
    # 7. Maven plugin execution failure (more specific than the generic plugin check above)
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
            error_category=None if success else categorize_build_error(output),
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
