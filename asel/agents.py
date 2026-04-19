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


_LLM_REQUEST_TIMEOUT = 600.0  # 10-min hard cap per LLM HTTP call (prevents indefinite API hangs)


def _make_model(model_id: str, provider: str):
    if provider == "deepseek":
        from agno.models.deepseek import DeepSeek
        return DeepSeek(id=model_id, timeout=_LLM_REQUEST_TIMEOUT)
    if provider == "openai":
        from agno.models.openai import OpenAIChat
        return OpenAIChat(id=model_id, timeout=_LLM_REQUEST_TIMEOUT)
    if provider == "anthropic":
        from agno.models.anthropic import Claude
        return Claude(id=model_id, timeout=_LLM_REQUEST_TIMEOUT)
    raise ValueError(f"Unknown LLM provider: {provider}")


def _make_file_tools(repo_path: Path) -> list:
    _repo_root = repo_path.resolve()

    def _safe_resolve(path: str) -> Path | None:
        """Return resolved path if it stays within the repo, else None."""
        full = (_repo_root / path).resolve()
        if not full.is_relative_to(_repo_root):
            return None
        return full

    @tool
    def read_file(
        path: str,
        start_line: int = 0,
        end_line: int = 0,
        start: int = 0,
        end: int = 0,
        substring: bool = False,
    ) -> str:
        """Read a file from the repository by its relative path.

        Optional line range (1-indexed, inclusive):
          - start_line / start: first line to read (1-indexed). 0 means beginning.
          - end_line / end: last line to read (inclusive). 0 means end of file.

        Use start_line/end_line (or start/end) for large files to avoid the 8000-char
        truncation limit. When no range is given, reads the whole file (truncated at 8000 chars).
        """
        full = _safe_resolve(path)
        if full is None:
            return f"Blocked: {path} escapes the repository boundary"
        if not full.exists():
            return f"File not found: {path}"
        content = full.read_text()
        # Accept either start_line/end_line or start/end aliases
        sl = start_line or start
        el = end_line or end
        if sl > 0 or el > 0:
            lines = content.splitlines()
            total = len(lines)
            s = max(0, sl - 1) if sl > 0 else 0
            e = min(total, el) if el > 0 else total
            selected = lines[s:e]
            header = f"[Lines {s+1}-{s+len(selected)} of {total}]\n"
            return header + "\n".join(selected)
        if len(content) > _MAX_FILE_CHARS:
            return content[:_MAX_FILE_CHARS] + f"\n[... truncated at {_MAX_FILE_CHARS} chars ...]"
        return content

    @tool
    def edit_file(path: str, old_text: str, new_text: str) -> str:
        """Replace old_text with new_text in a file. old_text must match exactly.

        IMPORTANT: old_text must be a small, targeted snippet (≤500 chars).
        If you need to edit a dependency version, pass just the <version> tag or the
        2-3 line block containing it — NOT the entire file.
        Use grep_file() first to locate the exact text to pass as old_text.
        """
        if len(old_text) > 500:
            return (
                f"ERROR: old_text is {len(old_text)} chars — too large (max 500). "
                f"Pass a small targeted snippet, not the whole file. "
                f"Use grep_file('{path}', '<search-term>') to locate the exact lines to change."
            )
        full = _safe_resolve(path)
        if full is None:
            return f"Blocked: {path} escapes the repository boundary"
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
        full = _safe_resolve(path)
        if full is None:
            return f"Blocked: {path} escapes the repository boundary"
        if full.exists():
            return f"File already exists: {path} — use edit_file instead"
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
        return f"Created {path}"

    @tool
    def grep_file(path: str, pattern: str, context_lines: int = 3) -> str:
        """Search for a pattern in a file and return matching lines with context.
        Use this to locate the exact text to pass as old_text in edit_file.
        Example: grep_file('pom.xml', 'log4j-core') finds the log4j dependency block.
        """
        import re
        full = _safe_resolve(path)
        if full is None:
            return f"Blocked: {path} escapes the repository boundary"
        if not full.exists():
            return f"File not found: {path}"
        if full.is_dir():
            return f"Path is a directory: {path} — provide a specific file path"
        lines = full.read_text().splitlines()
        try:
            re.compile(pattern)
            def _matches(line: str) -> bool:
                return bool(re.search(pattern, line, re.IGNORECASE))
        except re.error:
            pat_lower = pattern.lower()
            def _matches(line: str) -> bool:
                return pat_lower in line.lower()
        results = []
        emitted_up_to = -1  # last line index already included in output
        for i, line in enumerate(lines):
            if _matches(line):
                lo = max(emitted_up_to + 1, i - context_lines)
                hi = min(len(lines), i + context_lines + 1)
                block = "\n".join(f"{j+1}: {lines[j]}" for j in range(lo, hi))
                results.append(block)
                emitted_up_to = hi - 1
                if len(results) >= 15:
                    results.append(f"[results capped at 15 matches — refine your pattern]")
                    break
        if not results:
            return f"Pattern '{pattern}' not found in {path}"
        return f"\n{'---'*10}\n".join(results)

    @tool
    def list_files(subdir: str = ".") -> str:
        """List files in a subdirectory of the repo (max 50 results)."""
        target = _safe_resolve(subdir)
        if target is None:
            return f"Blocked: {subdir} escapes the repository boundary"
        if not target.is_dir():
            return f"Not a directory: {subdir}"
        abs_repo = repo_path.resolve()
        files = sorted(
            str(p.resolve().relative_to(abs_repo))
            for p in itertools.islice((p for p in target.rglob("*") if p.is_file()), 50)
        )
        return "\n".join(files)

    return [read_file, grep_file, edit_file, create_file, list_files]


_BUILD_INSTRUCTIONS: dict[Language, str] = {
    Language.JAVA_MAVEN: """\
You are a Maven build repair expert. Your job is to fix build failures in Java/Maven projects.

Available tools:
- read_file(path)                        — read a file (truncated at 8000 chars for large files)
- read_file(path, start_line, end_line)  — read a specific line range (1-indexed, inclusive)
- grep_file(path, pattern, context=3)    — find a pattern and see surrounding lines
- edit_file(path, old_text, new_text)    — replace EXACT text in an existing file
- create_file(path, content)             — create a new file that does not yet exist
- list_files(subdir)                     — list files under a subdirectory
- run_maven(args)                        — run Maven inside the build container

CRITICAL: edit_file old_text must be a small targeted snippet, NOT the whole file.
Use grep_file to locate the exact text first, then edit just that section.

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
- read_file(path)                        — read a file (truncated at 8000 chars for large files)
- read_file(path, start_line, end_line)  — read a specific line range (1-indexed, inclusive)
- grep_file(path, pattern, context=3)    — find a pattern and see surrounding lines
- edit_file(path, old_text, new_text)    — replace EXACT text in an existing file
- create_file(path, content)             — create a new file that does not yet exist
- list_files(subdir)                     — list files under a subdirectory
- run_gradle(args)                       — run Gradle inside the build container

CRITICAL: edit_file old_text must be a small targeted snippet, NOT the whole file.
Use grep_file to locate the exact text first, then edit just that section.

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
You are a security vulnerability remediation expert. Your job is to fix security findings in \
any file within a JVM project that uses Maven as its build tool.

The project is primarily Java/Kotlin/Groovy, but the repository may also contain JavaScript, \
TypeScript, Python, HTML, YAML, Dockerfiles, shell scripts, or other files. Fix findings in \
whatever language they appear in — use your knowledge of that language's security best practices.

Available tools:
- read_file(path)                        — read a file (truncated at 8000 chars for large files)
- read_file(path, start_line, end_line)  — read a specific line range (1-indexed, inclusive)
- grep_file(path, pattern, context=3)    — find a pattern and see surrounding lines
- edit_file(path, old_text, new_text)    — replace EXACT text in a file (surgical edit only)
- create_file(path, content)             — create a new file
- list_files(subdir)                     — list files under a directory
- run_maven_compile()                    — quick compile check inside the build container

CRITICAL RULES for edit_file:
- old_text MUST be a small, targeted snippet — the specific line(s) you are changing.
- NEVER use the entire file content as old_text. This will cause a JSON overflow error.
- Always use grep_file first to locate the exact text before calling edit_file.

Workflow for a Trivy CVE (dependency version bump in pom.xml):
1. grep_file('pom.xml', '<artifactId>affected-lib</artifactId>') to find the dependency
2. edit_file with just the version snippet as old_text
3. run_maven_compile() to verify

Workflow for a Semgrep finding in any language file:
1. read_file (with optional start_line/end_line) to see the flagged code
2. edit_file with the minimal fix appropriate for that language
3. run_maven_compile() if the fix touches JVM source files; skip compile check for non-JVM files

Fix ONE security finding per invocation with the minimal change. Never remove security checks.
""",
    Language.JAVA_GRADLE: """\
You are a security vulnerability remediation expert. Your job is to fix security findings in \
any file within a JVM project that uses Gradle as its build tool.

The project is primarily Java/Kotlin/Groovy, but the repository may also contain JavaScript, \
TypeScript, Python, HTML, YAML, Dockerfiles, shell scripts, or other files. Fix findings in \
whatever language they appear in — use your knowledge of that language's security best practices.

Available tools:
- read_file(path)                        — read a file (truncated at 8000 chars for large files)
- read_file(path, start_line, end_line)  — read a specific line range (1-indexed, inclusive)
- grep_file(path, pattern, context=3)    — find a pattern and see surrounding lines
- edit_file(path, old_text, new_text)    — replace EXACT text in a file (surgical edit only)
- create_file(path, content)             — create a new file
- list_files(subdir)                     — list files under a directory
- run_gradle_compile()                   — quick compile check inside the build container

CRITICAL RULES for edit_file:
- old_text MUST be a small, targeted snippet — the specific line(s) you are changing.
- NEVER use the entire file content as old_text. This will cause a JSON overflow error.
- Always use grep_file first to locate the exact text before calling edit_file.

Workflow for a Trivy CVE (dependency version bump in build.gradle / build.gradle.kts):
1. grep_file('build.gradle', 'affected-lib') to find the dependency line
2. edit_file with just that dependency line as old_text
3. run_gradle_compile() to verify

Workflow for a Semgrep finding in any language file:
1. read_file (with optional start_line/end_line) to see the flagged code
2. edit_file with the minimal fix appropriate for that language
3. run_gradle_compile() if the fix touches JVM source files; skip compile check for non-JVM files

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
