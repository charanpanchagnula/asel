# asel/models.py
import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, model_validator


class Language(str, Enum):
    JAVA_MAVEN = "java-maven"
    AUTO_DETECT = "auto"


class BuildPhase(str, Enum):
    DEPENDENCY_RESOLVE = "dependency_resolve"
    COMPILE = "compile"
    FULL_BUILD = "full_build"


class ErrorCategory(str, Enum):
    DEPENDENCY_CONFLICT = "dependency_conflict"
    MISSING_DEPENDENCY = "missing_dependency"
    JAVA_VERSION_MISMATCH = "java_version_mismatch"
    MISSING_PROPERTY = "missing_property"
    PLUGIN_INCOMPATIBILITY = "plugin_incompatibility"
    TEST_FAILURE = "test_failure"
    COMPILE_ERROR = "compile_error"
    UNKNOWN = "unknown"


class ScannerType(str, Enum):
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PatchTarget(str, Enum):
    BUILD_STABILIZATION = "build_stabilization"
    FINDING_REMEDIATION = "finding_remediation"


class RunStatus(str, Enum):
    RUNNING = "running"
    CONVERGED = "converged"
    STALLED = "stalled"
    MAX_ITERATIONS = "max_iterations"
    BUILD_FAILED = "build_failed"
    TIMEOUT = "timeout"
    UNSUPPORTED_LANGUAGE = "unsupported_language"


class BuildTrack(str, Enum):
    FULL = "full"


class RunConfig(BaseModel):
    repo_url: str
    output_dir: Path
    enabled_scanners: list[ScannerType] = [
        ScannerType.SEMGREP,
        ScannerType.TRIVY,
        ScannerType.GITLEAKS,
    ]
    language: Language = Language.AUTO_DETECT
    llm_model: str = "deepseek-chat"
    llm_provider: str = "deepseek"

    # Build stabilization
    max_build_attempts: int = 5

    # Remediation loop — multi-signal termination
    max_remediation_iterations: int = 10
    min_findings_per_iteration: int = 3
    stall_threshold: int = 2
    min_delta_to_continue: int = 1
    max_runtime_minutes: int = 60


class BuildResult(BaseModel):
    success: bool
    phase: BuildPhase
    output: str  # combined stdout + stderr
    duration_seconds: float
    error_category: Optional[ErrorCategory] = None


class ScanFinding(BaseModel):
    id: str = ""
    scanner: ScannerType
    severity: Severity
    rule_id: str
    file_path: str
    line_number: Optional[int] = None
    title: str
    description: str
    raw: dict = {}

    @model_validator(mode="after")
    def set_id(self) -> "ScanFinding":
        if not self.id:
            key = f"{self.scanner}{self.rule_id}{self.file_path}{self.line_number}"
            self.id = hashlib.md5(key.encode()).hexdigest()[:12]
        return self


class PatchAttempt(BaseModel):
    iteration: int
    target: PatchTarget
    finding_ids: list[str] = []
    files_modified: list[str] = []
    diff: str = ""
    build_result_after: Optional[BuildResult] = None
    findings_before: list[str] = []
    findings_after: list[str] = []
    delta: int = 0
    introduced_new_findings: bool = False
    succeeded: bool = False


class IterationSnapshot(BaseModel):
    iteration: int
    findings: list[ScanFinding]
    build_result: BuildResult
    patch_attempt: Optional[PatchAttempt] = None


class RunState(BaseModel):
    run_id: str
    repo_url: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    build_track: BuildTrack = BuildTrack.FULL
    build_attempts: list[BuildResult] = []
    iterations: list[IterationSnapshot] = []
    findings: list[ScanFinding] = []
    final_finding_count: dict[str, int] = {}
    status: RunStatus = RunStatus.RUNNING
