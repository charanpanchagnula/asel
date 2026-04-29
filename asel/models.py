# asel/models.py
import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, model_validator


class Language(str, Enum):
    JAVA_MAVEN = "java-maven"
    JAVA_GRADLE = "java-gradle"
    AUTO_DETECT = "auto"


class BuildPhase(str, Enum):
    DEPENDENCY_RESOLVE = "dependency_resolve"
    COMPILE = "compile"
    PACKAGE = "package"
    UNIT_TEST = "unit_test"
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


class ServiceType(str, Enum):
    SPRING_BOOT = "spring_boot"
    QUARKUS = "quarkus"
    MICRONAUT = "micronaut"
    SERVLET_WAR = "servlet_war"   # traditional WAR deployed to Tomcat/Jetty
    UNKNOWN = "unknown"


class RuntimeStatus(str, Enum):
    STARTED = "started"
    FAILED_TO_START = "failed_to_start"
    NOT_RUNNABLE = "not_runnable"   # no web service detected
    TIMEOUT = "timeout"             # health poll timed out on all attempts


class RuntimeFidelity(str, Enum):
    HIGH = "high"      # no security or DB stubs applied — full pentest validity
    MEDIUM = "medium"  # DB replaced with H2 — SQLi results less reliable
    LOW = "low"        # security disabled — auth/IDOR probes invalid


class RuntimeFailureClass(str, Enum):
    MISSING_PROPERTY   = "missing_property"    # ${VAR} placeholder unresolved
    MISSING_BEAN       = "missing_bean"         # No qualifying bean of type X
    BEAN_CREATION      = "bean_creation"        # BeanCreationException (re-classify nested)
    DB_CONNECTION      = "db_connection"        # JDBC connection refused / timeout
    API_MIGRATION      = "api_migration"        # WebSecurityConfigurerAdapter, Spring 5→6
    RESOURCE_NOT_FOUND = "resource_not_found"   # FileNotFoundException on classpath resource
    EXTERNAL_API       = "external_api"         # HTTP timeout to external service
    TOMCAT_LISTENER    = "tomcat_listener"      # WAR silent failure
    AUTH_BOOTSTRAP     = "auth_bootstrap"       # JWT/OIDC issuer-uri unreachable
    DB_SCHEMA          = "db_schema"            # Flyway/Liquibase schema validation fails
    MESSAGING          = "messaging"            # Kafka/RabbitMQ broker unavailable
    MISSING_CLASS      = "missing_class"        # NoClassDefFoundError / ClassNotFoundException in bean init
    MISSING_STATIC     = "missing_static"       # Static classpath resource missing at startup (e.g. UI assets)
    NO_MAIN_MANIFEST   = "no_main_manifest"     # JAR has no Main-Class in MANIFEST.MF
    UNKNOWN            = "unknown"


class RunStatus(str, Enum):
    RUNNING = "running"
    CONVERGED = "converged"
    STALLED = "stalled"
    MAX_ITERATIONS = "max_iterations"
    PARTIAL = "partial"          # time budget exhausted but findings were reduced
    BUILD_FAILED = "build_failed"
    TIMEOUT = "timeout"          # time budget exhausted with no progress
    UNSUPPORTED_LANGUAGE = "unsupported_language"


class BuildTrack(str, Enum):
    FULL = "full"


class RunConfig(BaseModel):
    repo_url: str
    output_dir: Path
    enabled_scanners: list[ScannerType] = [
        ScannerType.SEMGREP,
        ScannerType.TRIVY,
    ]
    language: Language = Language.AUTO_DETECT
    llm_model: str = "deepseek-chat"
    llm_provider: str = "deepseek"

    # Build stabilization
    max_build_attempts: int = 5

    # Remediation loop — multi-signal termination
    max_findings_to_remediate: int = 5   # attempt only top-N findings by severity per run
    max_remediation_iterations: Optional[int] = None  # explicit cap; None = bounded by findings × tries and time budget
    min_findings_per_iteration: int = 3
    stall_threshold: int = 2
    min_delta_to_continue: int = 1
    max_runtime_minutes: int = 60

    # Final test health check
    final_test_timeout_minutes: int = 5  # kill unit tests if they exceed this

    # Runtime engine (Phase 2a)
    enable_runtime: bool = True
    runtime_startup_timeout_seconds: int = 600

    # Exploit engine (Phase 2c) — disabled by default, opt-in
    enable_exploit_engine: bool = False
    exploit_model: str = "deepseek-chat"
    exploit_provider: str = "deepseek"


class EndpointParameter(BaseModel):
    name: str
    location: str        # "path" | "query" | "body" | "header"
    required: bool = False
    param_type: str = "string"


class HttpEndpoint(BaseModel):
    method: str          # GET, POST, PUT, DELETE, PATCH
    path: str            # /api/users/{id}
    handler_class: Optional[str] = None    # com.example.UserController
    handler_method: Optional[str] = None   # getUser
    source_file: Optional[str] = None      # relative path in repo
    source_line: Optional[int] = None
    parameters: list[EndpointParameter] = []
    consumes: list[str] = []               # request content types
    produces: list[str] = []               # response content types
    discovery_source: str = ""             # "actuator" | "openapi"


class SurfaceDiscoveryResult(BaseModel):
    endpoints: list[HttpEndpoint] = []
    discovery_source: str = "none"         # "actuator" | "openapi" | "none"
    mapped_to_source: int = 0              # endpoints with source_file resolved


class RuntimeResult(BaseModel):
    service_type: ServiceType
    status: RuntimeStatus
    port: Optional[int] = None
    base_url: Optional[str] = None
    healthy_path: Optional[str] = None     # which path returned a success response
    startup_seconds: float = 0.0
    startup_log: str = ""                  # last N lines from the app's stdout
    stubs_applied: list[str] = []          # what was disabled/overridden to get it running
    startup_strategy: str = ""             # "profile" | "infra_disable" | "h2_override"
    deps_provisioned: list[str] = []       # dep containers started (e.g. ["postgres", "redis"])
    fidelity: RuntimeFidelity = RuntimeFidelity.HIGH
    confidence: float = 1.0               # 0.0–1.0 environment fidelity score
    failure_classes: list[str] = []        # RuntimeFailureClass values observed across attempts


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
    skip_reason: Optional[str] = None  # e.g. "agent_no_changes"


class IterationSnapshot(BaseModel):
    iteration: int
    findings: list[ScanFinding]
    build_result: BuildResult
    patch_attempt: Optional[PatchAttempt] = None
    scanner_times_secs: dict[str, float] = {}   # scanner name → elapsed seconds
    scanner_had_timeout: bool = False            # True if any scanner timed out
    scanner_had_failure: bool = False            # True if any scanner hard-failed


class ProbeStatus(str, Enum):
    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class ProbeResult(BaseModel):
    finding_id: str
    endpoint: HttpEndpoint
    probe_type: str
    request: dict = {}
    response_code: int = 0
    response_snippet: str = ""
    status: ProbeStatus = ProbeStatus.INCONCLUSIVE
    evidence: str = ""
    chain: list[str] = []
    fidelity: str = "high"
    fidelity_notes: str = ""
    confirmed_fixed: Optional[bool] = None


class RunState(BaseModel):
    run_id: str
    repo_url: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    build_track: BuildTrack = BuildTrack.FULL
    language: Optional[Language] = None
    build_attempts: list[BuildResult] = []
    iterations: list[IterationSnapshot] = []
    findings: list[ScanFinding] = []
    final_finding_count: dict[str, int] = {}
    status: RunStatus = RunStatus.RUNNING
    runtime_result: Optional[RuntimeResult] = None
    surface: Optional[SurfaceDiscoveryResult] = None
    probe_results: list[ProbeResult] = []
