# asel/build.py
import time
from .environment import ExecutionEnvironment
from .models import BuildResult, BuildPhase, ErrorCategory


# Maven commands for each build phase
PHASE_COMMANDS: dict[BuildPhase, list[str]] = {
    BuildPhase.DEPENDENCY_RESOLVE: ["mvn", "dependency:resolve", "--batch-mode"],
    BuildPhase.COMPILE: ["mvn", "compile", "-DskipTests", "--batch-mode"],
    BuildPhase.FULL_BUILD: ["mvn", "clean", "install", "--batch-mode"],
}


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


class MavenBuildEngine:
    def __init__(self, env: ExecutionEnvironment):
        self._env = env

    def progressive_phases(self) -> list[BuildPhase]:
        """The ordered sequence of build phases to attempt."""
        return [
            BuildPhase.DEPENDENCY_RESOLVE,
            BuildPhase.COMPILE,
            BuildPhase.FULL_BUILD,
        ]

    def run_phase(self, phase: BuildPhase) -> BuildResult:
        """Run a single Maven build phase and return the result."""
        start = time.monotonic()
        exit_code, output = self._env.run(PHASE_COMMANDS[phase])
        duration = time.monotonic() - start
        success = exit_code == 0
        return BuildResult(
            success=success,
            phase=phase,
            output=output,
            duration_seconds=round(duration, 2),
            error_category=None if success else categorize_error(output),
        )
