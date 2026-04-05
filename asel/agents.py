# asel/agents.py
import itertools
import shlex
from pathlib import Path

from agno.agent import Agent
from agno.tools import tool

from .environment import ExecutionEnvironment
from .models import Language

_MAX_OUTPUT_LINES = 120
_MAX_FILE_CHARS = 8_000


def _tail(text: str, max_lines: int = _MAX_OUTPUT_LINES) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return f"[... {len(lines) - max_lines} lines truncated ...]\n" + "\n".join(lines[-max_lines:])


def _make_model(model_id: str, provider: str):
    if provider == "deepseek":
        from agno.models.deepseek import DeepSeek
        return DeepSeek(id=model_id)
    if provider == "openai":
        from agno.models.openai import OpenAIChat
        return OpenAIChat(id=model_id)
    if provider == "anthropic":
        from agno.models.anthropic import Claude
        return Claude(id=model_id)
    raise ValueError(f"Unknown LLM provider: {provider}")


def _make_file_tools(repo_path: Path) -> list:
    @tool
    def read_file(path: str) -> str:
        """Read a file from the repository by its relative path."""
        full = repo_path / path
        if not full.exists():
            return f"File not found: {path}"
        content = full.read_text()
        if len(content) > _MAX_FILE_CHARS:
            return content[:_MAX_FILE_CHARS] + f"\n[... truncated at {_MAX_FILE_CHARS} chars ...]"
        return content

    @tool
    def edit_file(path: str, old_text: str, new_text: str) -> str:
        """Replace old_text with new_text in a file. old_text must match exactly."""
        full = repo_path / path
        if not full.exists():
            return f"File not found: {path}"
        content = full.read_text()
        if old_text not in content:
            return f"Text not found in {path} — check for whitespace differences"
        full.write_text(content.replace(old_text, new_text, 1))
        return f"Edited {path} successfully"

    @tool
    def create_file(path: str, content: str) -> str:
        """Create a new file in the repository. Fails if the file already exists."""
        full = repo_path / path
        if full.exists():
            return f"File already exists: {path} — use edit_file instead"
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
        return f"Created {path}"

    @tool
    def list_files(subdir: str = ".") -> str:
        """List files in a subdirectory of the repo (max 50 results)."""
        target = repo_path / subdir
        if not target.is_dir():
            return f"Not a directory: {subdir}"
        files = sorted(
            str(p.relative_to(repo_path))
            for p in itertools.islice((p for p in target.rglob("*") if p.is_file()), 50)
        )
        return "\n".join(files)

    return [read_file, edit_file, create_file, list_files]


_BUILD_INSTRUCTIONS: dict[Language, str] = {
    Language.JAVA_MAVEN: """\
You are a Maven build repair expert. Your job is to fix build failures in Java/Maven projects.

Available tools:
- read_file(path)       — read a file by repo-relative path (e.g. "pom.xml")
- edit_file(path, old_text, new_text) — replace exact text in an existing file
- create_file(path, content) — create a new file that does not yet exist
- list_files(subdir)    — list files under a subdirectory
- run_maven(args)       — run Maven inside the build container

File paths are always relative to the repository root (no leading slash).

When given a build error:
1. Read the relevant files (pom.xml, settings files)
2. Diagnose the root cause
3. Apply the minimal fix — use edit_file for existing files, create_file for new ones
4. Verify by running Maven with run_maven
5. Report what you changed

Fix only what is needed. Do not refactor or make unrelated changes.
NEVER change <java.version>, <maven.compiler.source>, or <maven.compiler.release>.
""",
    Language.JAVA_GRADLE: """\
You are a Gradle build repair expert. Your job is to fix build failures in Java/Gradle projects.

Available tools:
- read_file(path)       — read a file by repo-relative path (e.g. "build.gradle")
- edit_file(path, old_text, new_text) — replace exact text in an existing file
- create_file(path, content) — create a new file that does not yet exist
- list_files(subdir)    — list files under a subdirectory
- run_gradle(args)      — run Gradle inside the build container

File paths are always relative to the repository root (no leading slash).

When given a build error:
1. Read the relevant files (build.gradle or build.gradle.kts, settings.gradle, gradle.properties)
2. Diagnose the root cause
3. Apply the minimal fix — use edit_file for existing files, create_file for new ones
4. Verify by running Gradle with run_gradle
5. Report what you changed

Fix only what is needed. Do not refactor or make unrelated changes.
NEVER change sourceCompatibility or targetCompatibility.
""",
}

_REMEDIATION_INSTRUCTIONS: dict[Language, str] = {
    Language.JAVA_MAVEN: """\
You are a security vulnerability remediation expert for Java/Maven projects.

Available tools:
- read_file(path), edit_file(path, old_text, new_text), create_file(path, content), list_files(subdir)
- run_maven_compile()   — quick compile check inside the build container

Fix ONE security finding per invocation with the minimal change. Never remove security checks.
""",
    Language.JAVA_GRADLE: """\
You are a security vulnerability remediation expert for Java/Gradle projects.

Available tools:
- read_file(path), edit_file(path, old_text, new_text), create_file(path, content), list_files(subdir)
- run_gradle_compile()  — quick compile check inside the build container

Fix ONE security finding per invocation with the minimal change. Never remove security checks.
""",
}


def _gradle_cmd(repo_path: Path) -> str:
    return "./gradlew" if (repo_path / "gradlew").exists() else "gradle"


def create_build_agent(
    env: ExecutionEnvironment,
    repo_path: Path,
    model_id: str = "deepseek-chat",
    provider: str = "deepseek",
    language: Language = Language.JAVA_MAVEN,
) -> Agent:
    if language == Language.JAVA_GRADLE:
        gradle = _gradle_cmd(repo_path)

        @tool
        def run_gradle(args: str) -> str:
            """Run Gradle inside the build container. Pass args as space-separated string."""
            exit_code, output = env.run([gradle] + shlex.split(args))
            return _tail(output)

        extra_tools = [run_gradle]
    else:
        @tool
        def run_maven(args: str) -> str:
            """Run Maven inside the build container. Pass args as a space-separated string."""
            exit_code, output = env.run(["mvn"] + shlex.split(args))
            return _tail(output)

        extra_tools = [run_maven]

    instructions = _BUILD_INSTRUCTIONS.get(language, _BUILD_INSTRUCTIONS[Language.JAVA_MAVEN])
    return Agent(
        model=_make_model(model_id, provider),
        tools=[*extra_tools, *_make_file_tools(repo_path)],
        instructions=instructions,
        markdown=False,
    )


def create_remediation_agent(
    repo_path: Path,
    model_id: str = "deepseek-chat",
    provider: str = "deepseek",
    env: ExecutionEnvironment | None = None,
    language: Language = Language.JAVA_MAVEN,
) -> Agent:
    if language == Language.JAVA_GRADLE:
        gradle = _gradle_cmd(repo_path)

        @tool
        def run_gradle_compile() -> str:
            """Quick compile check — runs './gradlew compileJava --no-daemon'."""
            if env is None:
                return "No build environment available for compile check"
            exit_code, output = env.run([gradle, "compileJava", "--no-daemon", "--console=plain"])
            return _tail(output)

        extra_tools = [run_gradle_compile]
    else:
        @tool
        def run_maven_compile() -> str:
            """Quick compile check — runs 'mvn compile -DskipTests'."""
            if env is None:
                return "No build environment available for compile check"
            exit_code, output = env.run(["mvn", "compile", "-DskipTests", "--batch-mode"])
            return _tail(output)

        extra_tools = [run_maven_compile]

    instructions = _REMEDIATION_INSTRUCTIONS.get(language, _REMEDIATION_INSTRUCTIONS[Language.JAVA_MAVEN])
    return Agent(
        model=_make_model(model_id, provider),
        tools=[*_make_file_tools(repo_path), *extra_tools],
        instructions=instructions,
        markdown=False,
    )
