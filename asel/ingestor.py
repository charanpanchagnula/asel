# asel/ingestor.py
import subprocess
from pathlib import Path
from .models import Language


def clone_repo(url: str, dest: Path) -> Path:
    """Clone a git repo (shallow) to dest. Raises RuntimeError on failure."""
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    return dest


def detect_language(repo_path: Path) -> Language:
    """Detect the build language. Phase 1 supports Java/Maven only."""
    if (repo_path / "pom.xml").exists():
        return Language.JAVA_MAVEN
    raise ValueError(
        f"Unsupported project in {repo_path} — no pom.xml found. "
        "Phase 1 supports Java/Maven only."
    )
