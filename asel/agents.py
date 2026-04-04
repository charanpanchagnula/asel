# asel/agents.py
from pathlib import Path

from agno.agent import Agent
from agno.tools import tool

from .environment import ExecutionEnvironment

BUILD_AGENT_INSTRUCTIONS = """\
You are a Maven build repair expert. Your job is to fix build failures in Java/Maven projects.

When given a build error:
1. Read the relevant files (pom.xml, settings files)
2. Diagnose the root cause
3. Apply the minimal fix using edit_file
4. Verify by running Maven with run_maven
5. Report what you changed

Fix only what is needed. Do not refactor or make unrelated changes.
Common fixes: update dependency versions, fix java compiler source/target,
add missing properties, update plugin versions.
"""

REMEDIATION_AGENT_INSTRUCTIONS = """\
You are a security vulnerability remediation expert for Java/Maven projects.

When given security findings:
1. Read the affected files with read_file
2. Apply the minimal fix with edit_file
3. Optionally verify compilation with run_maven_compile
4. Report the change as a unified diff description

Priority order: CRITICAL → HIGH → MEDIUM.
Fix ONE logical issue per invocation (may touch multiple files if related).
Do not introduce new dependencies unless absolutely necessary.
Never remove security checks or validation logic.
"""


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


def create_build_agent(
    env: ExecutionEnvironment,
    repo_path: Path,
    model_id: str = "deepseek-chat",
    provider: str = "deepseek",
) -> Agent:
    """Create the BuildAgent with tools scoped to the given env and repo."""

    @tool
    def run_maven(args: str) -> str:
        """Run Maven inside the build container. Pass args as a space-separated string, e.g. 'clean install -DskipTests'."""
        exit_code, output = env.run(["mvn"] + args.split())
        return output

    @tool
    def read_file(path: str) -> str:
        """Read a file from the repository by its relative path."""
        full = repo_path / path
        if not full.exists():
            return f"File not found: {path}"
        return full.read_text()

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
    def list_files(subdir: str = ".") -> str:
        """List files in a subdirectory of the repo (max 50 results)."""
        target = repo_path / subdir
        if not target.is_dir():
            return f"Not a directory: {subdir}"
        files = sorted(str(p.relative_to(repo_path)) for p in target.rglob("*") if p.is_file())
        return "\n".join(files[:50])

    return Agent(
        model=_make_model(model_id, provider),
        tools=[run_maven, read_file, edit_file, list_files],
        instructions=BUILD_AGENT_INSTRUCTIONS,
        markdown=False,
    )


def create_remediation_agent(
    repo_path: Path,
    model_id: str = "deepseek-chat",
    provider: str = "deepseek",
    env: ExecutionEnvironment | None = None,
) -> Agent:
    """Create the RemediationAgent with tools scoped to the given repo."""

    @tool
    def read_file(path: str) -> str:
        """Read a file from the repository by its relative path."""
        full = repo_path / path
        if not full.exists():
            return f"File not found: {path}"
        return full.read_text()

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
    def list_files(subdir: str = ".") -> str:
        """List files in a subdirectory of the repo (max 50 results)."""
        target = repo_path / subdir
        if not target.is_dir():
            return f"Not a directory: {subdir}"
        files = sorted(str(p.relative_to(repo_path)) for p in target.rglob("*") if p.is_file())
        return "\n".join(files[:50])

    @tool
    def run_maven_compile() -> str:
        """Quick compile check — runs 'mvn compile -DskipTests'. Use to verify a patch compiles before finishing."""
        if env is None:
            return "No build environment available for compile check"
        exit_code, output = env.run(["mvn", "compile", "-DskipTests", "--batch-mode"])
        return output

    return Agent(
        model=_make_model(model_id, provider),
        tools=[read_file, edit_file, list_files, run_maven_compile],
        instructions=REMEDIATION_AGENT_INSTRUCTIONS,
        markdown=False,
    )
