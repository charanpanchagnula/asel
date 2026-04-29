# asel/ingestor.py
import re
import subprocess
from pathlib import Path
from .models import Language

# ---------------------------------------------------------------------------
# Maven images — ordered lowest to highest JDK version
# ---------------------------------------------------------------------------
_MAVEN_IMAGES: list[tuple[int, str]] = [
    (8,  "maven:3.9-eclipse-temurin-8"),
    (11, "maven:3.9-eclipse-temurin-11"),
    (17, "maven:3.9-eclipse-temurin-17"),
    (21, "maven:3.9-eclipse-temurin-21"),
    (25, "maven:3.9-eclipse-temurin-25"),
]
_DEFAULT_MAVEN_IMAGE = "maven:3.9-eclipse-temurin-21"

# ---------------------------------------------------------------------------
# Gradle images — official Gradle images with bundled JDK
# ---------------------------------------------------------------------------
_GRADLE_IMAGES: list[tuple[int, str]] = [
    (8,  "gradle:8-jdk8"),
    (11, "gradle:8-jdk11"),
    (17, "gradle:8-jdk17"),
    (21, "gradle:8-jdk21"),
]
_DEFAULT_GRADLE_IMAGE = "gradle:8-jdk21"

# ---------------------------------------------------------------------------
# Language detection — ordered list of (signal_fn, Language) pairs.
# Adding a new language = adding one entry here; nothing else changes.
# ---------------------------------------------------------------------------
_DETECTORS: list[tuple] = [
    (lambda p: (p / "pom.xml").exists(),                           Language.JAVA_MAVEN),
    (lambda p: (p / "build.gradle").exists()
             or (p / "build.gradle.kts").exists(),                 Language.JAVA_GRADLE),
]


CLONE_TIMEOUT_SECONDS = 600  # 10 min — large monorepos (hertzbeat, zipkin, yudao-cloud) need time


def clone_repo(url: str, dest: Path, timeout: int = CLONE_TIMEOUT_SECONDS) -> Path:
    """Clone a git repo (shallow) to dest. Raises RuntimeError on failure or timeout."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"git clone timed out after {timeout}s — repo may be too large or network too slow: {url}"
        )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    return dest


def detect_language(repo_path: Path) -> Language:
    """Detect build tool by walking the detector registry in priority order."""
    for signal_fn, language in _DETECTORS:
        if signal_fn(repo_path):
            return language
    raise ValueError(
        f"Unsupported project in {repo_path} — no recognized build file found. "
        "Supported: Java/Maven (pom.xml), Java/Gradle (build.gradle / build.gradle.kts)."
    )


def detect_java_version(repo_path: Path) -> int | None:
    """Parse Java version from pom.xml (Maven). Returns int or None."""
    pom = repo_path / "pom.xml"
    if not pom.exists():
        return None
    text = pom.read_text(encoding="utf-8", errors="replace")
    for tag in ("java.version", "maven.compiler.source", "maven.compiler.release"):
        # Handle both "8" and legacy "1.8" style version strings (Java 8 era)
        m = re.search(rf"<{tag}>\s*(?:1\.)?(\d+)\s*</{tag}>", text)
        if m:
            return int(m.group(1))
    return None


def detect_java_version_gradle(repo_path: Path) -> int | None:
    """Parse Java version from build.gradle or build.gradle.kts. Returns int or None."""
    for fname in ("build.gradle", "build.gradle.kts"):
        f = repo_path / fname
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"sourceCompatibility\s*=\s*['\"]?(\d+)['\"]?", text)
        if m:
            return int(m.group(1))
        m = re.search(r"VERSION_(\d+)", text)
        if m:
            return int(m.group(1))
    return None


def select_maven_image(repo_path: Path) -> str:
    """Return the Maven+JDK Docker image that best matches this Maven project."""
    required = detect_java_version(repo_path)
    if required is None:
        return _DEFAULT_MAVEN_IMAGE
    for jdk_version, image in _MAVEN_IMAGES:
        if jdk_version >= required:
            return image
    return _DEFAULT_MAVEN_IMAGE


def select_gradle_image(repo_path: Path) -> str:
    """Return the Gradle+JDK Docker image that best matches this Gradle project."""
    required = detect_java_version_gradle(repo_path)
    if required is None:
        return _DEFAULT_GRADLE_IMAGE
    for jdk_version, image in _GRADLE_IMAGES:
        if jdk_version >= required:
            return image
    return _DEFAULT_GRADLE_IMAGE


def select_image(repo_path: Path, language: Language) -> str:
    """Dispatch to the right image selector for the detected language.

    Extending to a new language: add an elif branch pointing at your selector.
    """
    if language == Language.JAVA_MAVEN:
        return select_maven_image(repo_path)
    if language == Language.JAVA_GRADLE:
        return select_gradle_image(repo_path)
    raise ValueError(f"No Docker image configured for language: {language}")
