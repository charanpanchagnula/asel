# asel/runtime.py
"""
Phase 2a — Runtime Engine

Starts a built JVM web service inside Docker and confirms it is responding
to HTTP. Tries up to three startup strategies, progressively stubbing out
dependencies that block startup (infra services, databases, security).

Usage:
    engine = RuntimeEngine(repo_path, language, build_image)
    if engine.detect():
        result = engine.start(timeout_seconds=120)
    engine.stop()  # always call in finally
"""
import logging
import os
import re
import shlex
import socket
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import docker
import httpx
import yaml

from .models import Language, RuntimeFailureClass, RuntimeFidelity, RuntimeResult, RuntimeStatus, ServiceType

logger = logging.getLogger(__name__)

# ── Registry loading ──────────────────────────────────────────────────────────

_REGISTRY_PATH = Path(__file__).parent / "deps-registry.yaml"


def _load_registry() -> dict:
    """
    Load deps-registry.yaml. Returns an empty registry on any error so the
    engine degrades gracefully rather than crashing at import time.
    """
    try:
        with _REGISTRY_PATH.open() as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("deps-registry.yaml not found at %s — no services will be provisioned", _REGISTRY_PATH)
    except yaml.YAMLError as exc:
        logger.error("deps-registry.yaml is malformed: %s — no services will be provisioned", exc)
    except Exception as exc:
        logger.error("Failed to load deps-registry.yaml: %s", exc)
    return {"services": {}, "infra_overrides": []}


_REGISTRY = _load_registry()

# ── Module-level compiled patterns ───────────────────────────────────────────

_MANIFEST_PLACEHOLDER_RE = re.compile(r"^\$\{[^}]+\}$")

# ── Constants ─────────────────────────────────────────────────────────────────

HEALTH_PATHS = ["/actuator/health", "/actuator/info", "/health", "/api/health", "/q/health", "/"]
POLL_INTERVAL_SECONDS = 3
STARTUP_LOG_LINES = 2000
DEP_SETTLE_SECONDS = 5   # wait after provisioning a dep before retrying app


# ── Dependency specs ──────────────────────────────────────────────────────────

@dataclass
class _DepSpec:
    """Describes a provisionable dependency container."""
    image: str
    env: dict[str, str]
    log_patterns: list[str]     # regex patterns in app startup log → dep is missing
    ready_log_pattern: str = "" # regex in dep container log → dep is ready to accept connections
    port: int = 0               # primary TCP port; used for readiness logging only
    command: list[str] = field(default_factory=list)
    # Override the container's default CMD/entrypoint args. Required for images that are
    # base images without a useful default entrypoint (e.g. google-cloud-cli:emulators,
    # which needs an explicit 'gcloud beta emulators pubsub start ...' command).
    # Leave empty for images that self-start their service (postgres, redis, mongo, etc.).
    app_flags: list[str] = field(default_factory=list)
    # Spring/JVM flags to add to the app's startup command when this dep is provisioned.
    # Used to redirect cloud SDK clients (Azure, GCP) to the emulator endpoint.
    # For DB/broker deps these are empty — the app connects to localhost:<standard-port>
    # without any config override because the dep shares the runtime container's network.


def _apply_registry_prefix(image: str, prefix: str) -> str:
    """
    Prepend prefix to image only when the image doesn't already carry a
    registry hostname (i.e. first path component contains a dot or colon,
    e.g. 'mcr.microsoft.com/...' or 'quay.io/...').
    """
    first_component = image.split("/")[0]
    already_has_registry = "." in first_component or ":" in first_component
    return image if already_has_registry else prefix + image


def _build_deps() -> tuple[dict[str, _DepSpec], dict[str, list[str]]]:
    """
    Build _DEPS and _BUILD_DEP_PATTERNS from the registry YAML.
    The ASEL_IMAGE_REGISTRY prefix is applied here (not in _load_registry) so
    repeated calls to _build_deps() always read the unmodified YAML data and
    never double-prefix image names.
    """
    prefix = os.environ.get("ASEL_IMAGE_REGISTRY", "")
    deps: dict[str, _DepSpec] = {}
    build_patterns: dict[str, list[str]] = {}
    for name, svc in _REGISTRY.get("services", {}).items():
        image = _apply_registry_prefix(svc["image"], prefix) if prefix else svc["image"]
        deps[name] = _DepSpec(
            image=image,
            env=svc.get("env") or {},
            log_patterns=svc.get("log_patterns") or [],
            ready_log_pattern=svc.get("ready_log_pattern", ""),
            port=svc.get("port", 0),
            command=svc.get("command") or [],
            app_flags=svc.get("app_flags") or [],
        )
        if svc.get("build_file_patterns"):
            build_patterns[name] = svc["build_file_patterns"]
    return deps, build_patterns


_DEPS, _BUILD_DEP_PATTERNS = _build_deps()

# ── Infrastructure override flags ─────────────────────────────────────────────
# Loaded from registry YAML. Each entry: (log_regex, [jvm_flags]).
# Applied reactively from the startup log on attempt 2.

_INFRA_OVERRIDES: list[tuple[str, list[str]]] = [
    (entry["pattern"], entry["flags"])
    for entry in _REGISTRY.get("infra_overrides", [])
]

# Always applied to every startup attempt.
# - server.address: bind to all interfaces so Docker port mapping can reach the app.
#   Many Spring Boot apps default to 127.0.0.1 (e.g. WebGoat), which is unreachable
#   via Docker's host-port proxy (which routes to 0.0.0.0 inside the container).
# - server.port: NOT hardcoded here — _run_startup_attempts injects the detected port
#   dynamically so that the app binds to the same port the container has mapped.
#   Spring Boot defaults to 8080 at the ServerProperties level but that default is
#   NOT added to the raw Environment, so ${server.port} fails in beans like JHipster's
#   LoggingConfiguration that inject the port before the server starts.
# - management.endpoints: expose all actuator endpoints so surface discovery can
#   use /actuator/mappings to discover the full HTTP surface.
_BASE_FLAGS = [
    "--server.address=0.0.0.0",
    "--management.endpoints.web.exposure.include=*",
    # Allow multi-module bean overrides (common in larger Spring apps) and
    # circular references introduced by Spring Boot 2.6+ migration gaps.
    "--spring.main.allow-bean-definition-overriding=true",
    "--spring.main.allow-circular-references=true",
    # Tier A flags (research RESEARCH_RUNTIME.md §Angle 3): always inject.
    # lazy-initialization defers bean construction to first-access, converting
    # startup failures into lazy failures that often never trigger for probed
    # endpoints that don't exercise the missing bean.
    # banner-mode=off suppresses the ASCII banner (cosmetic, but cleaner logs).
    "--spring.main.lazy-initialization=true",
    "--spring.main.banner-mode=off",
]

# JVM system properties that route all outbound HTTP/HTTPS through the
# catch-all proxy started by _start_http_proxy().  Applied on every startup
# attempt so external API calls (OAuth2 endpoints, config servers, SDK
# phone-homes) return 200 immediately instead of hanging for 30+ seconds.
# localhost/127.0.0.1 are excluded so provisioned dep containers are
# reached directly without going through the proxy.
_PROXY_JVM_FLAGS = [
    "-Dhttp.proxyHost=127.0.0.1",
    "-Dhttp.proxyPort=18080",
    "-Dhttps.proxyHost=127.0.0.1",
    "-Dhttps.proxyPort=18080",
    "-Dhttp.nonProxyHosts=localhost|127.0.0.1|::1",
]

# Flags applied on attempt 3 — H2 in-memory DB + disable security autoconfiguration
_H2_BASE_FLAGS = [
    "--spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;MODE={mode}",
    "--spring.datasource.username=sa",
    "--spring.datasource.password=",
    "--spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
    "--spring.jpa.hibernate.ddl-auto=create-drop",
    "--spring.liquibase.enabled=false",
    "--spring.flyway.enabled=false",
]

_SECURITY_DISABLE_FLAGS = [
    # Complete Spring Boot 3 security autoconfigure exclusion list
    # (research RESEARCH_RUNTIME.md §Angle 3 Tier B).
    # ManagementWebSecurityAutoConfiguration: critical for actuator-enabled apps.
    # OAuth2ResourceServerAutoConfiguration + OAuth2ClientAutoConfiguration:
    # resolve the eladmin JWT failure class where Spring Security expects an
    # OAuth2 resource server configuration requiring a secret.
    "--spring.autoconfigure.exclude="
    "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,"
    "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration,"
    "org.springframework.boot.actuate.autoconfigure.security.servlet."
    "ManagementWebSecurityAutoConfiguration,"
    "org.springframework.boot.autoconfigure.security.oauth2.resource.servlet."
    "OAuth2ResourceServerAutoConfiguration,"
    "org.springframework.boot.autoconfigure.security.oauth2.client.servlet."
    "OAuth2ClientAutoConfiguration",
]

# ── Runtime startup failure classifier ───────────────────────────────────────
# Ordered by specificity — more specific patterns first to avoid mis-classification.
# Each entry: (regex, RuntimeFailureClass). First match wins.

_FAILURE_PATTERNS: list[tuple[str, RuntimeFailureClass]] = [
    # API migration — structural, must check before MISSING_BEAN
    (r"WebSecurityConfigurerAdapter|HttpSecurity.*not available|authorizeRequests.*deprecated",
     RuntimeFailureClass.API_MIGRATION),
    # Auth bootstrap — JWT/OIDC issuer unreachable or JWT secret null/empty
    (r"issuer-uri|jwk-set-uri|oidcProviderConfiguration|Unable to resolve.*OpenID|JWKS.*fetch|"
     r"ConnectException.*oauth|OpenID.*discovery|"
     r"Decode argument cannot be null|jwt.*base64.*null|base64.*secret.*null",
     RuntimeFailureClass.AUTH_BOOTSTRAP),
    # Missing property placeholder
    (r"Could not resolve placeholder '(.+?)'|Binding to target.*failed.*property|"
     r"No value supplied for the following required keys",
     RuntimeFailureClass.MISSING_PROPERTY),
    # Missing bean
    (r"No qualifying bean of type '(.+?)' available|expected at least 1 bean",
     RuntimeFailureClass.MISSING_BEAN),
    # Bean creation (re-classify from nested cause)
    (r"BeanCreationException.*creating bean.*'(.+?)'",
     RuntimeFailureClass.BEAN_CREATION),
    # DB connection
    (r"Connection refused.*\d+\.\d+\.\d+\.\d+:\d+|Communications link failure|"
     r"FATAL:.*database.*does not exist|Unable to acquire JDBC Connection",
     RuntimeFailureClass.DB_CONNECTION),
    # DB schema migration failure
    (r"LiquibaseException|liquibase\.exception|FlywayException|flyway\.core|"
     r"Table .* doesn't exist|relation .* does not exist|Schema-validation",
     RuntimeFailureClass.DB_SCHEMA),
    # Messaging broker unavailable
    (r"org\.apache\.kafka.*Exception|KafkaException|bootstrap\.servers.*failed|"
     r"AmqpConnectException|RabbitMQ.*connection|ActiveMQ.*connect",
     RuntimeFailureClass.MESSAGING),
    # Missing static classpath resource at startup (e.g. Zipkin Lens UI, bundled SPA assets)
    # Must appear before RESOURCE_NOT_FOUND so the specific pattern wins.
    (r"Could not load.*class path resource|classpath resource.*not found|"
     r"ZipkinUiConfiguration|zipkin-lens",
     RuntimeFailureClass.MISSING_STATIC),
    # Classpath resource inaccessible (WAR/nested JAR)
    (r"ResourceUtils\.getFile|Cannot search.*URL.*war:|FileNotFoundException.*classpath:",
     RuntimeFailureClass.RESOURCE_NOT_FOUND),
    # JAR has no Main-Class manifest attribute (thin/non-repackaged JAR was selected)
    (r"no main manifest attribute",
     RuntimeFailureClass.NO_MAIN_MANIFEST),
    # External HTTP timeout (proxy should catch most; this fires when proxy isn't running yet)
    (r"ConnectTimeoutException|SocketTimeoutException|Connection timed out.*:443|"
     r"UnknownHostException",
     RuntimeFailureClass.EXTERNAL_API),
    # Tomcat WAR silent failure
    (r"Context.*failed.*start|LifecycleException|StandardContext.*startInternal.*FAIL",
     RuntimeFailureClass.TOMCAT_LISTENER),
    # Missing class in fat JAR — autoconfigure tries to load a class not on the classpath
    (r"NoClassDefFoundError|ClassNotFoundException",
     RuntimeFailureClass.MISSING_CLASS),
]


def classify_runtime_failure(log: str) -> RuntimeFailureClass:
    """
    Classify a startup failure log into a named failure class.
    Returns UNKNOWN if no pattern matches. First match wins (ordered by specificity).
    """
    for pattern, cls in _FAILURE_PATTERNS:
        if re.search(pattern, log, re.IGNORECASE):
            return cls
    return RuntimeFailureClass.UNKNOWN


def reclassify_from_cause(log: str) -> RuntimeFailureClass:
    """
    Re-classify a BEAN_CREATION failure by inspecting the nested Caused by: chain.

    Spring Boot wraps root causes in BeanCreationException; the actual failure
    (DB_CONNECTION, MISSING_PROPERTY, DB_SCHEMA, etc.) lives in the exception chain
    that follows. Re-running classification without the BEAN_CREATION pattern lets
    the first matching nested-cause pattern win.

    Returns UNKNOWN if no nested cause maps to a known class.
    """
    inner_patterns = [(p, c) for p, c in _FAILURE_PATTERNS
                      if c is not RuntimeFailureClass.BEAN_CREATION]
    for pattern, cls in inner_patterns:
        if re.search(pattern, log, re.IGNORECASE):
            return cls
    return RuntimeFailureClass.UNKNOWN


def extract_failing_autoconfigs(log: str, jar_path: Path | None = None) -> list[str]:
    """
    Return the top-level Spring Boot autoconfiguration classes to exclude for a
    MISSING_CLASS failure.

    Spring Boot's --spring.autoconfigure.exclude only works for classes registered
    in AutoConfiguration.imports (or legacy spring.factories).  The failing class
    in the stack trace is often a sub-configuration imported via @Import, not a
    registered top-level class.  This function:

    1. Extracts *Configuration / *AutoConfiguration class names from the stack
       trace (restricted to autoconfigure packages).
    2. For each candidate, reads the fat JAR's AutoConfiguration.imports to find
       the registered top-level class in the same package.  Falls back to the
       candidate itself if no match is found (covers cases where the failing class
       IS the registered class, e.g. older Spring Cloud versions).

    Returns a deduplicated list suitable for --spring.autoconfigure.exclude.
    """
    import io
    import zipfile

    _IMPORTS_KEY = (
        "META-INF/spring/"
        "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
    )

    def _read_imports(zf: zipfile.ZipFile) -> list[str]:
        if _IMPORTS_KEY in zf.namelist():
            return [
                ln.strip() for ln in zf.read(_IMPORTS_KEY).decode().splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
        return []

    # Step 1: extract candidate classes from the stack trace
    candidates: list[str] = []
    for m in re.finditer(r"at ([\w.]+(?:AutoConfiguration|Configuration))\.\w+\(", log):
        fqcn = m.group(1)
        if fqcn not in candidates and ("autoconfigure" in fqcn.lower() or "autoconfig" in fqcn.lower()):
            candidates.append(fqcn)

    if not candidates:
        return []

    # Step 2: collect all registered AutoConfiguration classes from the fat JAR.
    # Spring Boot fat JARs nest library JARs under BOOT-INF/lib/ — each may carry
    # its own AutoConfiguration.imports, so we must walk every nested JAR.
    registered: list[str] = []
    if jar_path and jar_path.exists():
        try:
            with zipfile.ZipFile(jar_path) as outer:
                registered.extend(_read_imports(outer))
                for name in outer.namelist():
                    if name.startswith("BOOT-INF/lib/") and name.endswith(".jar"):
                        try:
                            with zipfile.ZipFile(io.BytesIO(outer.read(name))) as inner:
                                registered.extend(_read_imports(inner))
                        except Exception:
                            pass
        except Exception:
            pass

    if not registered:
        return candidates  # fall back: try the candidates directly

    # Step 3: for each candidate, find ALL registered top-level classes in the same package.
    # A single package may export multiple autoconfiguration classes (e.g. blob storage exports
    # both AzureStorageBlobAutoConfiguration and AzureStorageBlobResourceAutoConfiguration).
    result: list[str] = []
    for candidate in candidates:
        pkg = candidate.rsplit(".", 1)[0]
        # Collect all registered classes in the exact same package
        matches = [r for r in registered if r.rsplit(".", 1)[0] == pkg]
        # Widen one package level if no exact match
        if not matches:
            parent_pkg = pkg.rsplit(".", 1)[0]
            matches = [r for r in registered if r.startswith(parent_pkg + ".")]
        # Strip .implementation/.impl segments (Spring Cloud Azure and similar libs nest
        # their @Import-ed configs under an .implementation. sub-package; the registered
        # top-level class lives in the parent package without that segment).
        if not matches:
            stripped_pkg = re.sub(r"\.(?:implementation|impl)\b", "", pkg)
            if stripped_pkg != pkg:
                matches = [r for r in registered if r.rsplit(".", 1)[0] == stripped_pkg]
                if not matches:
                    matches = [r for r in registered if r.startswith(stripped_pkg + ".")]
        result.extend(matches if matches else [candidate])

    return list(dict.fromkeys(result))  # deduplicate preserving order


# ── Recovery action table (Sprint 1 stub — Sprint 2 wires full dispatch) ─────
# Maps each failure class to an ordered sequence of action names (method names
# on RuntimeEngine or module-level functions). Actions are applied cumulatively.
# Currently, only MISSING_PROPERTY / AUTH_BOOTSTRAP / UNKNOWN trigger Attempt 2b
# (synthesize_config) — the concrete recovery implemented in this sprint.
# Full dispatch is Sprint 2 work.
RECOVERY_PLAN: dict[RuntimeFailureClass, list[str]] = {
    RuntimeFailureClass.MISSING_PROPERTY:   ["synthesize_config"],
    RuntimeFailureClass.AUTH_BOOTSTRAP:     ["expand_security_excludes", "inject_jwt_stub", "synthesize_config"],
    RuntimeFailureClass.DB_CONNECTION:      ["provision_dep_from_log", "h2_override"],
    RuntimeFailureClass.DB_SCHEMA:          ["disable_migrations", "h2_override"],
    RuntimeFailureClass.MISSING_BEAN:       ["detect_api_migration", "exclude_autoconfigure"],
    RuntimeFailureClass.API_MIGRATION:      ["run_openrewrite_security6"],
    RuntimeFailureClass.MESSAGING:          ["disable_kafka_listeners", "provision_dep_from_log"],
    RuntimeFailureClass.EXTERNAL_API:       ["verify_proxy_running", "inject_connect_timeout"],
    RuntimeFailureClass.RESOURCE_NOT_FOUND: ["extract_nested_jar_resource"],
    RuntimeFailureClass.TOMCAT_LISTENER:    ["read_tomcat_context_log"],
    RuntimeFailureClass.BEAN_CREATION:      ["reclassify_from_cause"],
    RuntimeFailureClass.MISSING_CLASS:      ["exclude_missing_class_autoconfig"],
    RuntimeFailureClass.MISSING_STATIC:    ["disable_static_resource_bean"],
    RuntimeFailureClass.NO_MAIN_MANIFEST:  [],  # non-recoverable at runtime; signal to skip
    RuntimeFailureClass.UNKNOWN:            ["llm_startup_repair"],
}


# ── Environment confidence scoring ────────────────────────────────────────────
# Each stub applied to achieve startup reduces the confidence that security
# findings are valid in the original production context.

_CONFIDENCE_PENALTIES: dict[str, float] = {
    "security_disabled":   0.20,   # auth/IDOR probes invalid
    "h2_override":         0.15,   # SQLi results may differ by dialect
    "mysql_redirect":      0.05,   # using provisioned MySQL, not original config
    "config_synthesized":  0.10,   # JWT secrets and DB URLs are stubs
    "openrewrite_applied": 0.10,   # source mutated before startup
    "messaging_disabled":  0.05,   # async paths not reachable
    "lazy_init":           0.05,   # some beans never exercised at startup
    "proxy_http":          0.03,   # external API calls return 200 stubs
    "llm_repair":          0.20,   # unknown fix applied
}


def compute_confidence(stubs_applied: list[str]) -> float:
    """Compute environment confidence score (0.0–1.0) from applied stubs."""
    score = 1.0
    for stub in stubs_applied:
        score -= _CONFIDENCE_PENALTIES.get(stub, 0.0)
    return max(0.0, round(score, 2))


# ── JVM startup flags ─────────────────────────────────────────────────────────
# Applied as JVM system properties (before -jar) on every startup attempt.
# These never break apps but reduce cold-start time and pre-empt common
# InaccessibleObjectException failures on JDK 17+.

_JVM_STARTUP_FLAGS = [
    # Disable C2 JIT compiler — cuts cold-start time 40–60%.
    # Apps that timeout at 35s often succeed at 20s. Safe for ASEL because
    # we need the app to respond to a health check, not sustain throughput.
    "-XX:TieredStopAtLevel=1",
    # Suppress JMX bean registration — common startup hang source in older apps.
    "-Dspring.jmx.enabled=false",
]

# --add-opens flags for CGLIB, Hibernate, and Spring internal reflection.
# JDK 9+ only — the module system that blocks these accesses didn't exist in JDK 8,
# so passing them to a JDK 8 JVM produces "Unrecognized option" and kills the process.
# Injected by _launch_app() only when _detect_jdk_major() >= 9.
_ADD_OPENS_FLAGS = [
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/java.math=ALL-UNNAMED",
]


# ── Config synthesizer ────────────────────────────────────────────────────────

def _flatten_yaml(data: object, prefix: str = "") -> dict[str, str]:
    """Recursively flatten a nested YAML dict to Spring-style dot-notation keys."""
    result: dict[str, str] = {}
    if not isinstance(data, dict):
        return result
    for k, v in data.items():
        full_key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            result.update(_flatten_yaml(v, full_key))
        elif v is not None and not isinstance(v, list):
            s = str(v).strip()
            if s and not s.startswith("${"):
                result[full_key] = s
    return result


def _scan_profile_configs(repo_path: Path) -> dict[str, str]:
    """
    Read all application-*.yml/yaml files and return a flat dict of their defined
    properties. Used to recover values that live only in a non-active profile
    (e.g. jwt.header in application-dev.yml while the app runs with test/local).
    Later profiles win over earlier ones when keys conflict.
    """
    collected: dict[str, str] = {}
    for pattern in ("**/application-*.yml", "**/application-*.yaml"):
        for cfg in sorted(repo_path.glob(pattern)):
            try:
                doc = yaml.safe_load(cfg.read_text(errors="replace")) or {}
                collected.update(_flatten_yaml(doc))
            except Exception:
                pass
    return collected


def synthesize_config(startup_log: str, repo_path: Path) -> dict[str, str]:
    """
    Heuristically synthesize Spring Boot property values for unresolved
    placeholders. Returns a flat dict suitable for SPRING_APPLICATION_JSON
    injection (higher precedence than application.yml, lower than CLI args).

    Extraction sources (in order):
    1. Startup log "Could not resolve placeholder 'X'" messages
    2. ${X} / ${X:default} patterns in *.properties and *.yml config files
    3. Literal values from profile-specific application-*.yml files (for keys
       that live only in a non-active profile, e.g. jwt.* in application-dev.yml)

    Synthesis rules (deterministic, no LLM needed for most keys):
    - secret / key / password / token          → 64-char hex string
    - jwt.base64-secret / base64*secret        → base64-encoded 64-char hex
    - host / hostname                          → "localhost"
    - url containing jdbc or datasource        → skip (handled by H2 override)
    - port                                     → "8080"
    - enabled / active / flag (boolean-shaped) → "false"
    - everything else                          → "placeholder-{stem}"
    """
    import secrets as _secrets
    import base64 as _base64

    keys: set[str] = set()

    # Source 1: unresolved placeholders in startup log
    for m in re.finditer(r"Could not resolve placeholder '([^']+)'", startup_log, re.IGNORECASE):
        keys.add(m.group(1).strip())

    # Source 2: ${VAR} patterns in config files (skip ${VAR:default} — defaults resolve)
    config_globs = ["**/*.properties", "**/application*.yml", "**/application*.yaml"]
    for glob_pat in config_globs:
        for cfg in repo_path.glob(glob_pat):
            try:
                text = cfg.read_text(errors="replace")
                # Only match ${KEY} with no default at all.
                # ${KEY:} has an empty default the developer chose — honour it (empty).
                # ${KEY:value} has a non-empty default — also resolves fine.
                # Both forms are skipped here; only truly required placeholders need stubs.
                for m in re.finditer(r"\$\{([^}:]+)\}", text):
                    keys.add(m.group(1).strip())
            except Exception:
                pass

    if not keys:
        return {}

    # Source 3: literal values from profile-specific configs.
    # When a property is defined only in a non-active profile (e.g. application-dev.yml
    # while running with --spring.profiles.active=test,local), Spring cannot resolve it.
    # We pick the value up from the profile file so the app gets the developer's intended
    # value rather than a meaningless "placeholder-X" stub.
    profile_values = _scan_profile_configs(repo_path)

    result: dict[str, str] = {}
    for key in keys:
        lower = key.lower()
        # Skip datasource URLs — H2 override handles these
        if ("url" in lower and ("jdbc" in lower or "datasource" in lower)):
            continue
        # Skip server.port — injected separately
        if lower in ("server.port",):
            continue
        # Use literal value from a non-active profile config when available
        if key in profile_values:
            result[key] = profile_values[key]
            continue
        # Secret / token / password / key → random hex
        if any(w in lower for w in ("secret", "password", "passwd", "token", "apikey", "api-key")):
            if "base64" in lower:
                raw = _secrets.token_hex(32)
                result[key] = _base64.b64encode(raw.encode()).decode()
            else:
                result[key] = _secrets.token_hex(32)
        # JWT validity seconds
        elif "validity" in lower and "second" in lower:
            result[key] = "86400"
        # Host / hostname
        elif lower.endswith(".host") or lower.endswith(".hostname"):
            result[key] = "localhost"
        # Port
        elif lower.endswith(".port"):
            result[key] = "8080"
        # Boolean-shaped flags
        elif any(lower.endswith(w) for w in (".enabled", ".active", ".enable", ".flag")):
            result[key] = "false"
        else:
            stem = key.split(".")[-1].replace("-", "_")
            result[key] = f"placeholder-{stem}"

    # Expand profile-config families to avoid sequential "one placeholder at a time"
    # failures. When jwt.header is needed and lives in application-dev.yml, we should
    # also inject jwt.token-start-with, jwt.online-key, etc. from the same file.
    # Only expand short top-level namespaces (jwt, app, security, ...) to avoid
    # over-injecting from broad namespaces like spring.* or management.*.
    _BROAD_NAMESPACES = frozenset(("spring", "server", "management", "logging", "info", "debug"))
    family_prefixes: set[str] = set()
    for k in list(result.keys()):
        if k in profile_values:
            top = k.split(".")[0]
            if top not in _BROAD_NAMESPACES:
                family_prefixes.add(top)
    for prefix in family_prefixes:
        for pkey, pval in profile_values.items():
            if pkey.startswith(prefix + ".") and pkey not in result:
                result[pkey] = pval
                logger.debug("Config synthesis: expanding family %s.* → %s", prefix, pkey)

    logger.info("Config synthesis: produced %d property stubs for SPRING_APPLICATION_JSON", len(result))
    return result


# Flags used as the attempt-3 datasource override for apps that use Alibaba Druid
# connection pool. Druid ignores Spring Boot's standard H2 datasource override because
# it reads the JDBC URL and tries to instantiate the driver class directly — if H2 is
# not on the classpath the attempt fails immediately. Instead we redirect Druid to the
# MySQL container we already provisioned in attempt 2, with credentials that match our
# provisioned MySQL (root/root). Both the generic spring.datasource.* and Druid-specific
# spring.datasource.druid.* namespaces are set so Druid picks them up.
_MYSQL_JDBC = (
    "jdbc:mysql://localhost:3306/app?"
    "createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
)

_DRUID_MYSQL_REDIRECT_FLAGS = [
    f"--spring.datasource.url={_MYSQL_JDBC}",
    "--spring.datasource.username=root",
    "--spring.datasource.password=root",
    f"--spring.datasource.druid.url={_MYSQL_JDBC}",
    "--spring.datasource.druid.username=root",
    "--spring.datasource.druid.password=root",
    # dynamic-datasource-spring-boot-starter (baomidou): named datasource groups
    f"--spring.datasource.dynamic.datasource.master.url={_MYSQL_JDBC}",
    "--spring.datasource.dynamic.datasource.master.username=root",
    "--spring.datasource.dynamic.datasource.master.password=root",
    f"--spring.datasource.dynamic.datasource.slave.url={_MYSQL_JDBC}",
    "--spring.datasource.dynamic.datasource.slave.username=root",
    "--spring.datasource.dynamic.datasource.slave.password=root",
    "--spring.jpa.hibernate.ddl-auto=create-drop",
    "--spring.liquibase.enabled=false",
    "--spring.flyway.enabled=false",
]

# Map build-file keywords → H2 compatibility mode
_H2_MODES: list[tuple[str, str]] = [
    ("postgresql|postgres", "PostgreSQL"),
    ("mysql|mariadb",       "MySQL"),
    ("db2",                 "DB2"),
    ("oracle|ojdbc",        "Oracle"),
    ("sqlserver|mssql",     "MSSQLServer"),
]


# ── WAR container selection ───────────────────────────────────────────────────
#
# Two axes drive image selection:
#   1. Servlet namespace: javax (Java EE ≤ 8) vs jakarta (Jakarta EE 9+)
#      This is a hard ABI break — a javax WAR will NOT load in Tomcat 10+ or Jetty 12+.
#   2. JDK major version: extracted from the build image tag used to compile the app.
#      We snap down to the nearest image that exists on Docker Hub.
#
# Container engine preference is detected from the build file:
#   - jetty-maven-plugin / jetty-plugin → Jetty
#   - tomcat-maven-plugin / no hint     → Tomcat (default)

def _select_tomcat_image(namespace: str, jdk_major: int) -> str:
    """Return a tomcat Docker image compatible with the given servlet namespace and JDK."""
    major = 9 if namespace == "javax" else 10
    # Snap JDK to nearest image available on Docker Hub for this Tomcat major
    jdk = 21 if jdk_major >= 21 else (17 if jdk_major >= 17 else 11)
    return f"tomcat:{major}-jdk{jdk}"


def _select_jetty_image(namespace: str, jdk_major: int) -> str:
    """Return a Jetty Docker image compatible with the given servlet namespace and JDK."""
    if namespace == "javax":
        # Jetty 10 is the last release supporting javax.servlet; requires JDK 11+
        jdk = 17 if jdk_major >= 17 else 11
        return f"jetty:10-jdk{jdk}"
    else:
        # Jetty 12 requires jakarta.servlet and JDK 17+
        jdk = 21 if jdk_major >= 21 else 17
        return f"jetty:12-jdk{jdk}"


# Webapps directory inside each container engine
_WAR_WEBAPPS: dict[str, str] = {
    "tomcat": "/usr/local/tomcat/webapps",
    "jetty":  "/var/lib/jetty/webapps",
}

# JVM --add-opens flags required to run legacy CGLIB2 (Spring 3.x / Hibernate 4.x)
# on Java 17+. JPMS by default blocks reflective access to java.lang.ClassLoader
# internals, which CGLIB2 uses to define proxy classes. These flags re-open the
# relevant packages to unnamed modules (i.e. classpath code like old CGLIB).
_JDK17_OPENS = (
    "--add-opens=java.base/java.lang=ALL-UNNAMED "
    "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED "
    "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED "
    "--add-opens=java.base/java.io=ALL-UNNAMED "
    "--add-opens=java.base/java.util=ALL-UNNAMED "
    "--add-opens=java.base/sun.reflect=ALL-UNNAMED"
)

# Environment variable used by each container engine to pass extra JVM flags
_WAR_JVM_ENV: dict[str, str] = {
    "tomcat": "JAVA_OPTS",
    "jetty":  "JAVA_OPTIONS",
}

# Log patterns that indicate the WAR deployment failed definitively.
# When any of these appears, there is no point continuing to poll — the app
# will not recover on its own. We bail early so _start_war can read the log
# and provision missing deps for attempt 2.
_WAR_TOMCAT_STARTED_RE = re.compile(
    r"Server startup in \[?\d+\]? millisecond",
    re.IGNORECASE,
)

_FATAL_WAR_PATTERNS: list[str] = [
    r"SEVERE.*Exception sending context initialized",  # Tomcat: Spring ContextLoaderListener failed
    r"SEVERE.*listeners failed to start",              # Tomcat 9+: generic listener failure
    r"SEVERE.*Context .* startup failed",              # Tomcat 9+: context init failure
    r"Error configuring application listener",         # Tomcat: listener init failure
    r"Failed startup of context",                      # Jetty: context failed to start
    r"Unavailable",                                    # Jetty: webapp marked unavailable
    r"InaccessibleObjectException",                    # Java 17+ module restriction (CGLIB2 etc.)
    r"Failed to instantiate WebApplicationInitializer",# Spring Boot WAR entry-point failure
]

# Spring Boot JAR fatal startup patterns — bail the health poll early when seen.
# These indicate the application context failed to load and will never become healthy.
# We bail so the next attempt (with different flags) can start sooner.
_FATAL_JAR_PATTERNS: list[str] = [
    r"APPLICATION FAILED TO START",          # Spring Boot banner for startup failure
    r"Error creating bean with name",         # Spring bean initialization failure
    r"UnsatisfiedDependencyException",        # Missing required bean / @Autowired
    r"BeanCreationException",                 # General bean creation failure
    r"Unable to start.*ApplicationContext",   # Spring context failed to load
    r"java\.lang\.OutOfMemoryError",          # JVM OOM — won't recover
]

# Minimum seconds to wait before checking for fatal WAR patterns.
# Gives the app time to log its startup sequence before we mis-classify
# a transient warning as a fatal deployment failure.
_WAR_FATAL_CHECK_AFTER_SECS = 15


# ── HTTP proxy script ─────────────────────────────────────────────────────────
# Catch-all forward proxy that binds on 127.0.0.1:18080 and returns 200 {} for
# every request (including CONNECT tunnels). Injected via exec_run into the
# runtime container so external HTTP calls never block context load.

_HTTP_PROXY_SCRIPT = """\
import sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
class _P(BaseHTTPRequestHandler):
  def log_message(self, *a): pass
  def do_CONNECT(self):
    self.send_response(200); self.end_headers()
  def _ok(self):
    self.send_response(200)
    self.send_header('Content-Type','application/json')
    self.end_headers(); self.wfile.write(b'{}')
  do_GET=do_POST=do_PUT=do_DELETE=do_PATCH=do_HEAD=do_OPTIONS=_ok
HTTPServer(('127.0.0.1',18080),_P).serve_forever()
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def _jar_has_main_class(path: Path) -> bool:
    """Return True if the JAR manifest declares a Main-Class attribute."""
    try:
        with zipfile.ZipFile(path) as zf:
            if "META-INF/MANIFEST.MF" not in zf.namelist():
                return False
            manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            return "Main-Class:" in manifest
    except Exception:
        return False


def _jar_is_confirmed_thin(path: Path) -> bool:
    """
    Return True only when we can *confirm* the JAR is a thin (non-executable) JAR —
    i.e., it is a valid ZIP file and its MANIFEST.MF explicitly lacks a Main-Class.

    Returns False (= "not confirmed thin") when the file is unreadable, not a valid
    ZIP, or when the MANIFEST is absent (we cannot confirm either way).  Callers
    should treat an unreadable file as a potential executable rather than skipping it.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            if "META-INF/MANIFEST.MF" not in zf.namelist():
                # No manifest at all — cannot confirm; treat as potentially executable
                return False
            manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            return "Main-Class:" not in manifest
    except Exception:
        # Corrupt/non-ZIP file — cannot confirm thin; don't discard it
        return False


def _free_port() -> int:
    """Return an available TCP port on the host."""
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


# ── Startup attempt state ─────────────────────────────────────────────────────

@dataclass
class _StartupState:
    """Mutable state shared across all startup attempt phases."""
    service_type: "ServiceType"
    jar: "Path"
    host_port: int
    timeout: int
    port_flag: str
    infra_flags: list[str] = field(default_factory=list)
    dep_flags: list[str] = field(default_factory=list)
    autoconfig_excl_flags: list[str] = field(default_factory=list)
    ds_override_flags: list[str] = field(default_factory=list)
    deps_provisioned: list[str] = field(default_factory=list)
    stubs: list[str] = field(default_factory=list)
    observed_failures: list[str] = field(default_factory=list)
    log: str = ""
    failure_class: "RuntimeFailureClass" = field(default_factory=lambda: RuntimeFailureClass.UNKNOWN)


# ── Runtime engine ────────────────────────────────────────────────────────────

class RuntimeEngine:
    """
    Starts a JVM web service in an isolated Docker container and confirms
    it is responding to HTTP. Uses the same image as the build container
    (which already has Java) and mounts the same repo volume, so the
    compiled JAR is immediately available without re-downloading deps.

    Startup strategies (tried in order):
      1. Test/local profile  — many apps self-configure for local runs
      2. Infra disable       — turn off Eureka, Vault, Config Server, etc.
                               based on what appeared in the startup log;
                               also provisions postgres/redis/mysql/mongo
                               if the log shows a connection error
      3. H2 + security off   — replace any DB with in-memory H2, disable
                               Spring Security autoconfiguration entirely

    Call stop() in a finally block to clean up all Docker resources.
    """

    def __init__(self, repo_path: Path, language: Language, build_image: str):
        self._repo_path = repo_path.resolve()
        self._language = language
        self._build_image = build_image
        self._client = docker.from_env()
        self._runtime_container = None
        self._dep_containers: list = []
        self._provisioned_dep_names: set[str] = set()  # dep names actually started; guards against re-provision
        self._host_port: Optional[int] = None
        self._manifest_env: dict[str, str] = {}
        self._build_file_cache: Optional[str] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self) -> bool:
        """Return True if this repo looks like a runnable JVM web service."""
        return self._detect_service_type() != ServiceType.UNKNOWN

    def start(self, timeout_seconds: int = 120) -> RuntimeResult:
        """
        Attempt startup. Returns RuntimeResult regardless of outcome —
        caller should check result.status.
        """
        service_type = self._detect_service_type()
        if service_type == ServiceType.UNKNOWN:
            return RuntimeResult(
                service_type=ServiceType.UNKNOWN,
                status=RuntimeStatus.NOT_RUNNABLE,
            )

        # WAR apps use a dedicated Tomcat/Jetty container, not the JAR exec path.
        if service_type == ServiceType.SERVLET_WAR:
            return self._start_war(service_type, timeout_seconds)

        jar = self._find_jar()
        if jar is None:
            return RuntimeResult(
                service_type=service_type,
                status=RuntimeStatus.FAILED_TO_START,
                startup_log=(
                    "No runnable JAR found. Expected: target/*.jar (Maven) "
                    "or build/libs/*.jar (Gradle). Ensure the build produced "
                    "a fat/executable JAR."
                ),
            )

        self._manifest_env = self._read_manifest_env()
        container_port = self._detect_port()

        # Retry port allocation up to 3 times: _free_port() releases the socket before
        # Docker binds it, so the OS may reallocate the port to another process (TOCTOU).
        for _attempt in range(3):
            host_port = _free_port()
            self._host_port = host_port
            try:
                self._start_runtime_container(host_port, container_port)
                break
            except docker.errors.APIError as exc:
                if "address already in use" not in str(exc) or _attempt == 2:
                    raise
                logger.warning("Host port %d already in use — retrying with new port", host_port)
        self._start_http_proxy(self._runtime_container)
        return self._run_startup_attempts(service_type, jar, host_port, container_port, timeout_seconds)

    def stop(self) -> None:
        """Stop and remove all Docker resources created by this engine."""
        for c in self._dep_containers:
            try:
                c.stop(timeout=5)
                c.remove()
            except Exception:
                pass
        self._dep_containers.clear()

        if self._runtime_container:
            try:
                self._runtime_container.stop(timeout=10)
                self._runtime_container.remove()
            except Exception:
                pass
            self._runtime_container = None
        self._host_port = None

    @property
    def base_url(self) -> Optional[str]:
        return f"http://localhost:{self._host_port}" if self._host_port else None

    # ── Service detection ─────────────────────────────────────────────────────

    def _detect_service_type(self) -> ServiceType:
        build_text = self._read_build_file()
        if not build_text:
            return ServiceType.UNKNOWN

        if "spring-boot" in build_text:
            return ServiceType.SPRING_BOOT

        # Annotation scan — cap at 50 files to stay fast
        for java_file in list(self._repo_path.rglob("*.java"))[:50]:
            try:
                if "@SpringBootApplication" in java_file.read_text(errors="replace"):
                    return ServiceType.SPRING_BOOT
            except OSError:
                pass

        if "io.quarkus" in build_text:
            return ServiceType.QUARKUS

        if "io.micronaut" in build_text:
            return ServiceType.MICRONAUT

        # Traditional WAR app — needs an external servlet container (Tomcat/Jetty).
        # Detected by explicit WAR packaging or a servlet API dependency.
        # Spring Boot apps with WAR packaging are already caught above.
        if re.search(r"<packaging>\s*war\s*</packaging>", build_text):
            return ServiceType.SERVLET_WAR
        if re.search(r"""(?:apply plugin|id)\s*['"]war['"]""", build_text):
            return ServiceType.SERVLET_WAR
        if re.search(r"javax\.servlet|jakarta\.servlet-api", build_text):
            return ServiceType.SERVLET_WAR

        return ServiceType.UNKNOWN

    def _read_build_file(self) -> str:
        """
        Return the concatenated text of all build files in the project.

        Cached after first read — called 8+ times per startup attempt across
        service-type detection, dep provisioning, and H2 mode detection.
        """
        if self._build_file_cache is not None:
            return self._build_file_cache
        texts: list[str] = []
        for fname in ("pom.xml", "build.gradle", "build.gradle.kts"):
            root_f = self._repo_path / fname
            if root_f.exists():
                texts.append(root_f.read_text(errors="replace"))
            for child_f in sorted(self._repo_path.glob(f"*/{fname}")):
                texts.append(child_f.read_text(errors="replace"))
            for grandchild_f in sorted(self._repo_path.glob(f"*/*/{fname}")):
                texts.append(grandchild_f.read_text(errors="replace"))
        self._build_file_cache = "\n".join(texts)
        return self._build_file_cache

    def _find_jar(self) -> Optional[Path]:
        """
        Find the fat/executable JAR produced by the build.
        Prefers the largest JAR (fat JARs are much bigger than thin ones).

        For multi-module projects (e.g. eladmin) the runnable JAR lives in a
        sub-module's target/ rather than the root target/, so we search one
        level of sub-directories as well.
        """
        _EXCLUDE_SUFFIXES = (
            "-sources.jar", "-tests.jar", "-original.jar",
            "-javadoc.jar", "-plain.jar",
        )

        if self._language == Language.JAVA_MAVEN:
            glob_pattern = "target/*.jar"
        else:
            glob_pattern = "build/libs/*.jar"

        # Collect candidates from root AND all direct sub-module directories.
        candidates = [
            p for p in self._repo_path.glob(glob_pattern)
            if not any(p.name.endswith(s) for s in _EXCLUDE_SUFFIXES)
        ]
        for subdir in self._repo_path.iterdir():
            if not subdir.is_dir():
                continue
            candidates += [
                p for p in subdir.glob(glob_pattern)
                if not any(p.name.endswith(s) for s in _EXCLUDE_SUFFIXES)
            ]

        if candidates:
            executable = [p for p in candidates if _jar_has_main_class(p)]
            if executable:
                return max(executable, key=lambda p: p.stat().st_size)
            # No JAR with a confirmed Main-Class found.
            # Filter out JARs that are *confirmed* thin (valid ZIP, manifest present,
            # no Main-Class). Keep JARs that are unreadable/non-ZIP — they may be
            # incomplete builds that still contain embedded content.
            not_confirmed_thin = [p for p in candidates if not _jar_is_confirmed_thin(p)]
            if not_confirmed_thin:
                # Fall back to the largest unconfirmed JAR (test stubs and partially
                # written fat JARs land here).
                return max(not_confirmed_thin, key=lambda p: p.stat().st_size)
            # Every candidate is a confirmed thin JAR — running any of them will
            # produce "no main manifest attribute". Return None so the caller emits
            # a clear "No runnable JAR found" diagnostic.
            logger.warning(
                "_find_jar: %d candidate JAR(s) found but all are confirmed thin JARs "
                "(no Main-Class in MANIFEST.MF) — the build likely did not run "
                "spring-boot:repackage. Treating as no runnable JAR.",
                len(candidates),
            )
            return None

        # Spring Boot WAR: <packaging>war</packaging> + spring-boot-starters.
        # The repackaged WAR is executable via 'java -jar app.war' (contains
        # embedded Tomcat). Fall back to finding *.war when no *.jar exists.
        war_pattern = "target/*.war" if self._language == Language.JAVA_MAVEN else "build/libs/*.war"
        war_candidates = list(self._repo_path.glob(war_pattern))
        for subdir in self._repo_path.iterdir():
            if subdir.is_dir():
                war_candidates += list(subdir.glob(war_pattern))
        return max(war_candidates, key=lambda p: p.stat().st_size) if war_candidates else None

    def _find_war(self) -> Optional[Path]:
        """Find the WAR file produced by the build."""
        search_dir = (
            self._repo_path / "target"
            if self._language == Language.JAVA_MAVEN
            else self._repo_path / "build" / "libs"
        )
        if not search_dir.exists():
            return None
        candidates = [
            p for p in search_dir.glob("*.war")
            if not p.name.endswith("-tests.war")
        ]
        return max(candidates, key=lambda p: p.stat().st_size) if candidates else None

    def _detect_port(self) -> int:
        """Read server.port from application config files. Default 8080."""
        for rel in (
            "src/main/resources/application.properties",
            "src/main/resources/application.yml",
            "src/main/resources/application.yaml",
        ):
            f = self._repo_path / rel
            if not f.exists():
                continue
            text = f.read_text(errors="replace")
            # Single-line: server.port=8080 or server.port: 8080
            # Anchored to start-of-line to avoid matching e.g. mcp.server.port
            m = re.search(r"^server[._]port\s*[=:]\s*(\d+)", text, re.MULTILINE)
            if m:
                return int(m.group(1))
            # YAML multi-line: server:\n  port: 8080
            if rel.endswith((".yml", ".yaml")):
                m = re.search(r"^\s*port:\s*(\d+)", text, re.MULTILINE)
                if m:
                    return int(m.group(1))
        return 8080

    def _detect_druid(self) -> bool:
        """Return True if the build file uses Alibaba Druid or dynamic-datasource.

        Both Druid and dynamic-datasource-spring-boot-starter bypass Spring Boot's
        H2 override because they read spring.datasource.url and instantiate drivers
        directly, so H2 override fails. MySQL redirect is substituted for attempt 3.
        dynamic-datasource also needs its own spring.datasource.dynamic.* properties
        added to _DRUID_MYSQL_REDIRECT_FLAGS.
        """
        build = self._read_build_file()
        return "druid-spring-boot-starter" in build or "dynamic-datasource-spring-boot-starter" in build

    def _detect_h2_mode(self) -> str:
        """Pick H2 compatibility mode based on build file dependencies."""
        build_text = self._read_build_file().lower()
        for pattern, mode in _H2_MODES:
            if re.search(pattern, build_text):
                return mode
        return "PostgreSQL"   # safest default — most Spring Boot apps target Postgres

    def _detect_servlet_namespace(self) -> str:
        """Return 'jakarta' or 'javax' based on the servlet API declared in the build file."""
        build_text = self._read_build_file()
        if re.search(r"jakarta\.servlet|jakarta-ee|jakarta\.ee", build_text, re.IGNORECASE):
            return "jakarta"
        return "javax"

    def _detect_jdk_major(self) -> int:
        """Extract the JDK major version from the build image tag (e.g. 'eclipse-temurin-21' → 21)."""
        m = re.search(r"(?:jdk|temurin|openjdk)[^\d]*(\d+)", self._build_image)
        return int(m.group(1)) if m else 21

    def _detect_container_engine(self) -> str:
        """Return 'jetty' if the build file references a Jetty plugin, else 'tomcat'."""
        build_text = self._read_build_file()
        if re.search(r"jetty", build_text, re.IGNORECASE):
            return "jetty"
        return "tomcat"

    def _select_war_container(self) -> tuple[str, str, int]:
        """Return (docker_image, engine_name, jdk_major) for WAR deployment."""
        # Read once — each helper would otherwise re-read the same file.
        build_text = self._read_build_file()
        namespace = "jakarta" if re.search(
            r"jakarta\.servlet|jakarta-ee|jakarta\.ee", build_text, re.IGNORECASE
        ) else "javax"
        jdk_major = self._detect_jdk_major()
        engine = "jetty" if re.search(r"jetty", build_text, re.IGNORECASE) else "tomcat"
        if engine == "jetty":
            return _select_jetty_image(namespace, jdk_major), "jetty", jdk_major
        return _select_tomcat_image(namespace, jdk_major), "tomcat", jdk_major

    def _read_manifest_env(self) -> dict[str, str]:
        """
        Extract concrete environment variables from files the repo ships to
        document its own configuration requirements.  These are free, high-
        confidence values that resolve MISSING_PROPERTY failures without any
        LLM inference.

        Sources (in priority order):
          1. .env.example / .env.sample  — explicitly documented by the author
          2. docker-compose.yml          — environment: blocks for any service

        Values that are pure Shell placeholders (${VAR} with no default) are
        skipped — injecting the literal string "${VAR}" would be worse than
        injecting nothing.
        """
        env: dict[str, str] = {}

        # ── .env.example / .env.sample ────────────────────────────────────────
        for name in (".env.example", ".env.sample", ".env.dist"):
            f = self._repo_path / name
            if not f.exists():
                continue
            for k, v in self._parse_properties(f).items():
                if v and not _MANIFEST_PLACEHOLDER_RE.match(v):
                    env[k] = v
            break  # first match wins

        # ── docker-compose.yml ────────────────────────────────────────────────
        for compose_name in ("docker-compose.yml", "docker-compose.yaml"):
            f = self._repo_path / compose_name
            if not f.exists():
                continue
            try:
                doc = yaml.safe_load(f.read_text(errors="replace")) or {}
                for svc in (doc.get("services") or {}).values():
                    raw_env = svc.get("environment") or {}
                    # environment: may be a dict or a list of "KEY=VAL" strings
                    if isinstance(raw_env, dict):
                        items = raw_env.items()
                    else:
                        items = (
                            (s.split("=", 1)[0], s.split("=", 1)[1])
                            for s in raw_env if "=" in s
                        )
                    for k, v in items:
                        k, v = str(k).strip(), str(v).strip()
                        if k and v and not _MANIFEST_PLACEHOLDER_RE.match(v):
                            env.setdefault(k, v)  # .env.example takes priority
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", compose_name, exc)
            break

        if env:
            logger.info("Manifest env: injecting %d variable(s) from repo manifests", len(env))
        return env

    # ── WAR startup ───────────────────────────────────────────────────────────

    def _launch_war_container(
        self, war: Path, host_port: int, container_image: str, container_engine: str,
        jdk_major: int = 21,
    ) -> None:
        """Start a fresh Tomcat/Jetty container with the WAR mounted into webapps/.

        For JDK 17+ images, passes --add-opens flags so that legacy libraries
        (CGLIB2, old Hibernate, Spring 3.x) can perform reflective access that
        the Java 9+ module system otherwise blocks.
        """
        webapps = _WAR_WEBAPPS[container_engine]
        # Assemble JAVA_OPTS: JDK 17+ module opens (for CGLIB2) + proxy system
        # properties (so the catch-all proxy sidecar intercepts external HTTP calls).
        proxy_flags_str = " ".join(shlex.quote(f) for f in _PROXY_JVM_FLAGS)
        java_opts = f"{_JDK17_OPENS} {proxy_flags_str}" if jdk_major >= 17 else proxy_flags_str
        env: dict[str, str] = {
            _WAR_JVM_ENV[container_engine]: java_opts,
            **self._manifest_env,
        }
        self._runtime_container = self._client.containers.run(
            container_image,
            detach=True,
            ports={"8080/tcp": host_port},
            volumes={str(war): {"bind": f"{webapps}/{war.name}", "mode": "ro"}},
            environment=env,
            mem_limit="1g",
        )

    def _restart_war_container(
        self, war: Path, container_image: str, container_engine: str, jdk_major: int = 21,
    ) -> int:
        """
        Stop the current WAR container and all its dep containers, then start a
        fresh one. Returns the new host port.

        Dep containers are attached to the old container's network namespace via
        network_mode=container:<id>. They become invalid once that container stops,
        so we tear them all down and let _provision_deps_from_log re-provision
        against the new container ID.
        """
        for c in self._dep_containers:
            try:
                c.stop(timeout=5)
                c.remove()
            except Exception:
                pass
        self._dep_containers.clear()
        self._provisioned_dep_names.clear()

        if self._runtime_container:
            try:
                self._runtime_container.stop(timeout=5)
                self._runtime_container.remove()
            except Exception:
                pass
            self._runtime_container = None

        host_port = _free_port()
        self._host_port = host_port
        self._launch_war_container(war, host_port, container_image, container_engine, jdk_major)
        self._start_http_proxy(self._runtime_container)
        return host_port

    def _start_war(self, service_type: ServiceType, timeout_seconds: int) -> RuntimeResult:
        """
        Deploy the built WAR into a Tomcat or Jetty container and confirm it responds.

        Two attempts:
          1. Plain deployment — works for most apps.
          2. If attempt 1 fails, read the container log for DB connection errors,
             provision the required dep (mysql/postgres/etc), restart the container,
             and try again. Same dep-detection logic used by the JAR path.
        """
        war = self._find_war()
        if war is None:
            return RuntimeResult(
                service_type=service_type,
                status=RuntimeStatus.FAILED_TO_START,
                startup_log="No WAR file found in target/ or build/libs/.",
            )

        container_image, container_engine, jdk_major = self._select_war_container()
        self._manifest_env = self._read_manifest_env()
        # Context path = WAR stem (dvja.war → /dvja).
        # ROOT.war is Tomcat/Jetty's convention for the root context — no prefix.
        context_path = "" if war.stem.upper() == "ROOT" else f"/{war.stem}"

        # Pre-flight: provision deps declared in the build file before first attempt.
        # Matches the JAR startup path. Catches cases like WebGoat-Legacy where the
        # WAR context listener fails silently because the DB is missing.
        build_deps = self._provision_deps_from_build()
        if build_deps:
            logger.info("WAR pre-flight: provisioned from build file: %s", build_deps)
            time.sleep(DEP_SETTLE_SECONDS)

        # ── Attempt 1: plain deployment ───────────────────────────────────────
        host_port = _free_port()
        self._host_port = host_port
        logger.info("WAR deployment: %s → %s (engine=%s, jdk=%d, port=%d)",
                    war.name, container_image, container_engine, jdk_major, host_port)
        try:
            self._launch_war_container(war, host_port, container_image, container_engine, jdk_major)
        except Exception as exc:
            return RuntimeResult(
                service_type=service_type,
                status=RuntimeStatus.FAILED_TO_START,
                startup_log=f"Failed to start {container_image}: {exc}",
            )
        self._start_http_proxy(self._runtime_container)

        result = self._poll_war_health(service_type, host_port, context_path,
                                       timeout_seconds, container_image)
        if result.status == RuntimeStatus.STARTED:
            return result

        # ── Attempt 2: provision missing deps, restart ────────────────────────
        log = self._read_war_log()
        new_deps = self._provision_deps_from_log(log)
        if not new_deps:
            return result  # no deps to provision — nothing else to try

        logger.info("WAR: provisioned %s — restarting container for attempt 2", new_deps)
        host_port = self._restart_war_container(war, container_image, container_engine, jdk_major)
        self._provision_deps_from_log(log)   # re-provision deps against the new container ID
        time.sleep(DEP_SETTLE_SECONDS)

        result = self._poll_war_health(service_type, host_port, context_path,
                                       timeout_seconds, container_image)
        result.deps_provisioned = new_deps
        return result

    def _poll_war_health(
        self,
        service_type: ServiceType,
        host_port: int,
        context_path: str,
        timeout: int,
        container_image: str,
    ) -> RuntimeResult:
        """
        Poll health endpoints under the WAR's context path.
        Unlike the JAR path, we know the context path upfront from the WAR filename
        so no log-scraping is needed.
        """
        start = time.monotonic()
        deadline = start + timeout
        # Tomcat/Jetty base images have no TLS — HTTP only, unlike the JAR path.
        base_url = f"http://localhost:{host_port}"

        with httpx.Client(timeout=3.0, follow_redirects=False) as client:
            while time.monotonic() < deadline:
                elapsed = time.monotonic() - start
                for path in HEALTH_PATHS:
                    url = f"{base_url}{context_path}{path}"
                    try:
                        resp = client.get(url)
                        logger.debug("WAR probe t=%.0fs %s → %d", elapsed, url, resp.status_code)
                        if resp.status_code < 500 and resp.status_code != 404:
                            healthy_path = f"{context_path}{path}"
                            return self._make_result(
                                service_type, host_port, healthy_path, elapsed,
                                [], [], "war_deploy", base_url,
                            )
                    except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError):
                        logger.debug("WAR probe t=%.0fs %s → conn error", elapsed, url)

                # After the minimum safe window, check for fatal deployment errors.
                # If Tomcat/Jetty logged a definitive failure, bail early so _start_war
                # can read the log and provision missing deps without burning the full
                # timeout on guaranteed-503 responses.
                if elapsed >= _WAR_FATAL_CHECK_AFTER_SECS:
                    log_snapshot = self._read_war_log()
                    if any(re.search(p, log_snapshot, re.IGNORECASE)
                           for p in _FATAL_WAR_PATTERNS):
                        logger.info(
                            "WAR: fatal deployment error detected at t=%.0fs — bailing poll early",
                            elapsed,
                        )
                        break

                time.sleep(POLL_INTERVAL_SECONDS)

        log = self._read_war_log()
        # If Tomcat started successfully but every probe hit 5xx (e.g. a DB-gated
        # filter like BenchmarkJava's DataBaseFilter), count the app as STARTED —
        # the server is up even if individual endpoints require a connected database.
        if re.search(_WAR_TOMCAT_STARTED_RE, log) and not any(
            re.search(p, log, re.IGNORECASE) for p in _FATAL_WAR_PATTERNS
        ):
            logger.info("WAR: Tomcat started but all probes returned 5xx — marking as STARTED")
            return self._make_result(
                service_type, host_port, context_path or "/", timeout,
                [], [], f"war_deploy ({container_image})", base_url,
            )
        return RuntimeResult(
            service_type=service_type,
            status=RuntimeStatus.FAILED_TO_START,
            startup_log=log,
            startup_strategy=f"war_deploy ({container_image})",
        )

    def _read_war_log(self) -> str:
        """Read the container's own stdout (Tomcat/Jetty write to stdout, not a file)."""
        if not self._runtime_container:
            return ""
        try:
            return self._runtime_container.logs(tail=2000).decode("utf-8", errors="replace")
        except Exception:
            return ""

    # ── Container management ──────────────────────────────────────────────────

    def _start_runtime_container(self, host_port: int, container_port: int) -> None:
        """
        Start a long-lived container with the repo mounted and a host port bound.
        We keep it alive with 'tail -f /dev/null' and launch the app via exec.
        """
        self._runtime_container = self._client.containers.run(
            self._build_image,
            command=["tail", "-f", "/dev/null"],
            volumes={str(self._repo_path): {"bind": "/workspace", "mode": "rw"}},
            working_dir="/workspace",
            detach=True,
            mem_limit="1g",
            ports={f"{container_port}/tcp": host_port},
            environment=self._manifest_env,
        )

    def _launch_app(
        self, jar: Path, extra_flags: list[str],
        extra_env: dict[str, str] | None = None,
    ) -> None:
        """
        Start the JAR inside the runtime container as a background process.
        Output is redirected to /tmp/asel-app.log for later retrieval.
        Flags are individually shell-quoted to handle semicolons in JDBC URLs
        and other special characters without breaking the shell command.

        _PROXY_JVM_FLAGS are always injected as JVM system properties (before
        -jar) so the HTTP proxy sidecar intercepts all outbound HTTP calls.
        Spring Boot args (--key=value) follow -jar as application arguments.

        _ADD_OPENS_FLAGS are injected only for JDK 9+; passing them to JDK 8
        produces "Unrecognized option" and kills the JVM immediately.

        extra_env, when provided, is passed to the Docker exec API so that
        env vars (e.g. SPRING_APPLICATION_JSON) are visible to the process
        without recreating the container.
        """
        jar_rel = str(jar.relative_to(self._repo_path))
        opens = _ADD_OPENS_FLAGS if self._detect_jdk_major() >= 9 else []
        jvm_props = " ".join(shlex.quote(f) for f in _PROXY_JVM_FLAGS + _JVM_STARTUP_FLAGS + opens)
        flags_str = " ".join(shlex.quote(f) for f in extra_flags)
        cmd = ["sh", "-c", f"java {jvm_props} -jar {jar_rel} {flags_str} > /tmp/asel-app.log 2>&1"]
        exec_id = self._client.api.exec_create(
            self._runtime_container.id, cmd, workdir="/workspace",
            environment=extra_env,
        )
        self._client.api.exec_start(exec_id["Id"], detach=True)

    def _kill_app(self) -> None:
        """Kill the running Java process so we can retry with different flags."""
        try:
            self._runtime_container.exec_run(["pkill", "-f", "java"])
        except Exception:
            pass
        time.sleep(2)  # give the process a moment to die

    def _read_startup_log(self) -> str:
        """Read the last N lines of /tmp/asel-app.log from inside the container."""
        if not self._runtime_container:
            return ""
        try:
            result = self._runtime_container.exec_run(
                ["tail", f"-{STARTUP_LOG_LINES}", "/tmp/asel-app.log"]
            )
            return (result.output or b"").decode("utf-8", errors="replace")
        except Exception:
            return ""

    # ── Startup attempts ──────────────────────────────────────────────────────

    def _try_one_startup(
        self, jar: Path, flags: list[str], host_port: int, timeout: int,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[bool, Optional[str], float, str]:
        """
        Launch the JAR with the given flags, poll for health, and return
        (success, healthy_path, elapsed_seconds, base_url).
        If the poll misses a context-rooted app, a rescue probe is attempted.
        extra_env, when provided, is forwarded to the exec API so env vars such
        as SPRING_APPLICATION_JSON reach the process without container recreation.
        """
        self._launch_app(jar, flags, extra_env=extra_env)
        ok, healthy_path, elapsed, base_url = self._poll_health(host_port, timeout)
        if not ok:
            log = self._read_startup_log()
            cps = self._detect_context_paths(log)
            if cps:
                ok, healthy_path, base_url = self._rescue_probe(host_port, cps)
        return ok, healthy_path, elapsed, base_url

    # ── Startup attempt helpers ───────────────────────────────────────────────

    def _assemble_flags(self, state: _StartupState, extra: list[str] | None = None) -> list[str]:
        return (
            _BASE_FLAGS
            + [state.port_flag, "--spring.profiles.active=test,local"]
            + state.infra_flags
            + state.dep_flags
            + state.autoconfig_excl_flags
            + state.ds_override_flags
            + (extra or [])
        )

    def _record_failure(self, label: str, state: _StartupState) -> None:
        state.log = self._read_startup_log()
        state.failure_class = classify_runtime_failure(state.log)
        if state.failure_class is RuntimeFailureClass.BEAN_CREATION:
            state.failure_class = reclassify_from_cause(state.log)
            logger.info("%s BEAN_CREATION reclassified → %s", label, state.failure_class.value)
        state.observed_failures.append(state.failure_class.value)
        logger.info("%s failed: %s", label, state.failure_class.value)
        self._kill_app()

    def _try_attempt(
        self,
        label: str,
        state: _StartupState,
        extra_flags: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> "RuntimeResult | None":
        flags = self._assemble_flags(state, extra_flags)
        ok, healthy_path, elapsed, base_url = self._try_one_startup(
            state.jar, flags, state.host_port, state.timeout, extra_env=extra_env,
        )
        if ok:
            return self._make_result(
                state.service_type, state.host_port, healthy_path, elapsed,
                state.stubs, state.deps_provisioned, label, base_url, state.observed_failures,
            )
        self._record_failure(label, state)
        return None

    def _refresh_infra_and_deps(self, state: _StartupState) -> None:
        for f in self._infra_flags_from_log(state.log):
            if f not in state.infra_flags:
                state.infra_flags.append(f)
                state.stubs.append(f.lstrip("-").split("=")[0])
        new_deps = [d for d in self._provision_deps_from_log(state.log) if d not in state.deps_provisioned]
        state.deps_provisioned += new_deps
        if new_deps:
            time.sleep(DEP_SETTLE_SECONDS)
        state.dep_flags = self._app_flags_for_deps(state.deps_provisioned)

    def _attempt_autoconfig_exclude(self, state: _StartupState) -> "RuntimeResult | None":
        if state.failure_class is not RuntimeFailureClass.MISSING_CLASS:
            return None
        all_excluded: list[str] = []
        for i in range(3):
            new_excl = [c for c in extract_failing_autoconfigs(state.log, jar_path=state.jar)
                        if c not in all_excluded]
            if not new_excl:
                break
            all_excluded.extend(new_excl)
            if i == 0:
                state.stubs.append("missing_class_autoconfig_excluded")
            state.autoconfig_excl_flags = ["--spring.autoconfigure.exclude=" + ",".join(all_excluded)]
            logger.info("Attempt 2b-i iter %d: excluding autoconfigs: %s", i + 1, all_excluded)
            if result := self._try_attempt("autoconfig_exclude", state):
                return result
            if state.failure_class is not RuntimeFailureClass.MISSING_CLASS:
                break
        return None

    def _attempt_config_synthesis(self, state: _StartupState) -> "RuntimeResult | None":
        if state.failure_class not in (
            RuntimeFailureClass.MISSING_PROPERTY,
            RuntimeFailureClass.AUTH_BOOTSTRAP,
            RuntimeFailureClass.UNKNOWN,
        ):
            return None
        synthesized = synthesize_config(state.log, self._repo_path)
        if state.failure_class in (
            RuntimeFailureClass.AUTH_BOOTSTRAP, RuntimeFailureClass.UNKNOWN,
        ) and re.search(
            r"Decode argument cannot be null|jwt.*base64.*null|base64.*secret.*null",
            state.log, re.IGNORECASE,
        ):
            # "Decode argument cannot be null" means jwt.base64-secret is null at runtime.
            # synthesize_config() misses this because the log never says
            # "Could not resolve placeholder 'jwt.base64-secret'" — the secret is just null.
            # Fix: inject a fresh random secret plus all non-broad profile properties so the
            # app gets its intended jwt.*, swagger.*, login.* etc. from the dev profile.
            import secrets as _sec, base64 as _b64
            _BROAD_NS = frozenset(("spring", "server", "management", "logging", "info", "debug"))
            profile_all = _scan_profile_configs(self._repo_path)
            extra_profile = {k: v for k, v in profile_all.items()
                             if k.split(".")[0] not in _BROAD_NS}
            # Override any hardcoded dev secret with a fresh random one.
            extra_profile["jwt.base64-secret"] = _b64.b64encode(_sec.token_hex(32).encode()).decode()
            synthesized = {**(synthesized or {}), **extra_profile}
            logger.info("inject_jwt_stub: injecting profile properties + fresh jwt secret")
        if not synthesized:
            logger.debug("Config synthesis: no unresolved placeholders found — skipping attempt 2b")
            return None
        import json as _json
        state.stubs.append("config_synthesized")
        return self._try_attempt(
            "config_synthesis", state,
            extra_env={"SPRING_APPLICATION_JSON": _json.dumps(synthesized)},
        )

    def _attempt_datasource_override(self, state: _StartupState) -> "RuntimeResult | None":
        state.stubs.append("security_disabled")
        if self._detect_druid():
            state.stubs.append("mysql_redirect")
            ds_flags = _DRUID_MYSQL_REDIRECT_FLAGS
            label = "mysql_redirect"
        else:
            state.stubs.append("h2_override")
            h2_mode = self._detect_h2_mode()
            ds_flags = [f.replace("{mode}", h2_mode) if "{mode}" in f else f for f in _H2_BASE_FLAGS]
            label = "h2_override"
        result = self._try_attempt(label, state, extra_flags=ds_flags + _SECURITY_DISABLE_FLAGS)
        # Persist after the attempt so subsequent attempts (e.g. attempt 4 JWT retry)
        # inherit these overrides without doubling up in attempt 3 itself.
        state.ds_override_flags = ds_flags + _SECURITY_DISABLE_FLAGS
        return result

    def _run_startup_attempts(
        self,
        service_type: ServiceType,
        jar: Path,
        host_port: int,
        container_port: int,
        timeout: int,
    ) -> RuntimeResult:
        state = _StartupState(
            service_type=service_type,
            jar=jar,
            host_port=host_port,
            timeout=timeout,
            port_flag=f"--server.port={container_port}",
        )

        # Pre-flight: provision deps declared in the build file before first attempt.
        # Static detection catches connection-pool wrappers (Druid, P6Spy) that hide
        # the underlying JDBC error, making log-pattern matching miss the dep entirely.
        build_deps = self._provision_deps_from_build()
        state.deps_provisioned += build_deps
        if build_deps:
            logger.info("Pre-flight: provisioned from build file: %s", build_deps)
            time.sleep(DEP_SETTLE_SECONDS)
        state.dep_flags = self._app_flags_for_deps(state.deps_provisioned)

        # Attempt 1: test/local profile
        if result := self._try_attempt("profile", state):
            return result

        # Attempt 2: disable infra + provision deps from log
        state.infra_flags = self._infra_flags_from_log(state.log)
        state.stubs += [f.lstrip("-").split("=")[0] for f in state.infra_flags]
        new_deps = self._provision_deps_from_log(state.log)
        state.deps_provisioned += new_deps
        if new_deps:
            time.sleep(DEP_SETTLE_SECONDS)
        state.dep_flags = self._app_flags_for_deps(state.deps_provisioned)

        if result := self._try_attempt("infra_disable", state):
            return result

        # Absorb any new infra/dep failures exposed by attempt 2 before proceeding
        self._refresh_infra_and_deps(state)

        # Attempt 2b-i: exclude failing autoconfig classes (MISSING_CLASS)
        if result := self._attempt_autoconfig_exclude(state):
            return result

        # Attempt 2b: synthesize config for unresolved placeholders
        if result := self._attempt_config_synthesis(state):
            return result

        # Attempt 3: datasource override + security disable
        if result := self._attempt_datasource_override(state):
            return result

        # Absorb any new infra failures exposed by attempt 3 (e.g. Redis auth error that
        # only surfaces once the datasource is resolved) before attempt 4.
        self._refresh_infra_and_deps(state)

        # Attempt 4: JWT stub — attempt 3 sometimes unmasks an AUTH_BOOTSTRAP failure
        # (e.g. eladmin's jwt.base64-secret=empty) that was hidden by earlier BeanCreation errors.
        if result := self._attempt_config_synthesis(state):
            return result

        logger.debug("All attempts failed. Startup log tail:\n%s", state.log[-2000:])
        return RuntimeResult(
            service_type=service_type,
            status=RuntimeStatus.FAILED_TO_START,
            startup_log=state.log,
            stubs_applied=state.stubs,
            deps_provisioned=state.deps_provisioned,
            failure_classes=state.observed_failures,
        )

    def _infra_flags_from_log(self, log: str) -> list[str]:
        """Return JVM flags that disable infrastructure seen failing in the log."""
        flags: list[str] = []
        for pattern, override_flags in _INFRA_OVERRIDES:
            if re.search(pattern, log, re.IGNORECASE):
                for f in override_flags:
                    if f not in flags:
                        flags.append(f)
        return flags

    def _app_flags_for_deps(self, dep_names: list[str]) -> list[str]:
        """
        Collect Spring property flags that redirect the app to its provisioned dep
        emulators. DB/broker deps need no flags (they share the network namespace and
        take the standard port). Cloud SDK emulators (Azure, GCP) need the app to be
        told where the emulator endpoint is.
        """
        flags: list[str] = []
        for name in dep_names:
            spec = _DEPS.get(name)
            if spec:
                for f in spec.app_flags:
                    if f not in flags:
                        flags.append(f)
        return flags

    def _provision_deps_from_build(self) -> list[str]:
        """
        Inspect the build file for declared artifact IDs and provision any
        required infrastructure before the first startup attempt.

        This is a static, proactive check — far more reliable than reactive
        log-pattern matching, which breaks whenever a connection pool (Druid,
        P6Spy, HikariCP) wraps the underlying JDBC error in its own message.
        Returns names of deps that were newly provisioned.
        """
        build_text = self._read_build_file()
        provisioned: list[str] = []
        for dep_name, patterns in _BUILD_DEP_PATTERNS.items():
            if dep_name in self._provisioned_dep_names:
                continue
            if any(re.search(p, build_text, re.IGNORECASE) for p in patterns):
                if self._provision_dep(dep_name, _DEPS[dep_name]):
                    provisioned.append(dep_name)
        return provisioned

    def _provision_deps_from_log(self, log: str) -> list[str]:
        """
        Spin up dep containers for any dependency whose connection error
        appears in the startup log. Returns names of what was provisioned.
        Each dep container shares the runtime container's network namespace,
        so the app sees it on localhost at the standard port.
        """
        provisioned: list[str] = []
        for dep_name, spec in _DEPS.items():
            if dep_name in self._provisioned_dep_names:
                continue
            if any(re.search(p, log, re.IGNORECASE) for p in spec.log_patterns):
                if self._provision_dep(dep_name, spec):
                    provisioned.append(dep_name)
        return provisioned

    def _provision_dep(self, name: str, spec: _DepSpec) -> bool:
        """
        Start a single dep container sharing the runtime container's network
        namespace, then wait until it signals readiness via its own log output.

        Uses log-pattern polling (same strategy as Testcontainers'
        Wait.forLogMessage) so the app never attempts connection before the
        service is actually accepting it. Falls back to a fixed settle delay
        if no ready_log_pattern is configured for the service.

        For SQL databases, also runs any schema/seed SQL scripts found in the
        repo so the app sees a populated database rather than an empty one.
        """
        try:
            run_kwargs: dict = dict(
                detach=True,
                environment=spec.env,
                network_mode=f"container:{self._runtime_container.id}",
                name=f"asel-dep-{name}-{uuid.uuid4().hex[:6]}",
            )
            if spec.command:
                run_kwargs["command"] = spec.command
            container = self._client.containers.run(spec.image, **run_kwargs)
            self._dep_containers.append(container)
            self._provisioned_dep_names.add(name)
            logger.info("Provisioned %s (%s) — waiting for readiness", name, spec.image)
            self._wait_for_dep_ready(name, container, spec)
            container.reload()
            if container.status != "running":
                logger.warning("%s container exited after readiness wait — skipping SQL init", name)
                return True
            if name in ("mysql", "mariadb", "postgres", "mssql"):
                self._run_sql_init_scripts(name, container, spec)
            return True
        except Exception as exc:
            logger.warning("Could not provision %s: %s", name, exc)
            return False

    # Maps ASEL dep name → common database identifier strings used in
    # Spring config placeholders (${database}) and directory names.
    _DEP_DB_ALIASES: dict[str, list[str]] = {
        "mysql":    ["mysql", "mariadb"],
        "mariadb":  ["mariadb", "mysql"],
        "postgres": ["postgres", "postgresql"],
        "mssql":    ["mssql", "sqlserver"],
        "oracle":   ["oracle"],
    }

    def _find_sql_init_scripts(self, dep_name: str = "") -> list[Path]:
        """
        Locate SQL init scripts using two tiers, stopping at the first that
        yields results:

          1. Config-declared — read application.properties / application.yml
             for Flyway, Liquibase, and Spring SQL init locations. These are
             authoritative: the app tells us exactly where its scripts live.
             Spring property placeholders like ${database} are resolved using
             dep_name (e.g. 'mysql' → tries 'mysql' and 'mariadb' aliases).

          2. Convention glob — scan standard directory conventions (db/,
             sql/, src/main/resources/db/migration/, etc.). When dep_name is
             known, database-specific subdirectories (db/mysql/) are preferred
             and incompatible ones (db/h2/) are excluded.

        Schema-creating files (DDL) are returned before data files so that
        CREATE TABLE always precedes INSERT.
        """
        aliases = self._DEP_DB_ALIASES.get(dep_name, [])
        scripts = self._sql_scripts_from_config(aliases)
        if not scripts:
            scripts = self._sql_scripts_from_glob(aliases)
        return scripts

    # ── Tier 1: config-declared ───────────────────────────────────────────────

    def _sql_scripts_from_config(self, db_aliases: list[str]) -> list[Path]:
        """
        Read Spring Boot application config to find SQL init scripts declared
        by Flyway, Liquibase, or Spring's own SQL initializer.

        Config keys checked (properties or YAML):
          Flyway:    spring.flyway.locations          (default: classpath:db/migration)
          Liquibase: spring.liquibase.change-log
          Spring:    spring.sql.init.schema-locations / data-locations
                     spring.datasource.schema / data   (older Boot)

        Spring property placeholders like ${database} are resolved by trying
        each alias in db_aliases (e.g. ['mysql', 'mariadb'] for a MySQL dep).
        """
        props = self._read_spring_config()
        schema: list[Path] = []
        data: list[Path] = []

        def resolve_with_aliases(location: str) -> list[Path]:
            """Try the location as-is, then with each db alias substituted."""
            candidates_str = [location]
            if "${database}" in location or "${db}" in location:
                for alias in db_aliases:
                    candidates_str.append(
                        location.replace("${database}", alias).replace("${db}", alias)
                    )
            results = []
            for loc in candidates_str:
                p = self._resolve_classpath(loc)
                if p and p.exists():
                    results.append(p)
            return results

        # Flyway migration directory
        flyway_raw = props.get("spring.flyway.locations", "")
        for loc in (flyway_raw.split(",") if flyway_raw else ["classpath:db/migration"]):
            for p in resolve_with_aliases(loc.strip()):
                if p.is_dir():
                    schema.extend(sorted(p.glob("*.sql")))

        # Liquibase changelog (only raw SQL files, not XML/YAML changelogs)
        lb_changelog = props.get("spring.liquibase.change-log", "")
        if lb_changelog:
            for p in resolve_with_aliases(lb_changelog):
                if p.is_file() and p.suffix == ".sql":
                    schema.append(p)

        # Spring Boot SQL initializer
        for key in ("spring.sql.init.schema-locations", "spring.datasource.schema"):
            for loc in props.get(key, "").split(","):
                if loc.strip():
                    for p in resolve_with_aliases(loc.strip()):
                        if p.is_file():
                            schema.append(p)

        for key in ("spring.sql.init.data-locations", "spring.datasource.data"):
            for loc in props.get(key, "").split(","):
                if loc.strip():
                    for p in resolve_with_aliases(loc.strip()):
                        if p.is_file():
                            data.append(p)

        seen: set[Path] = set()
        result: list[Path] = []
        for p in schema + data:
            if p not in seen and p.stat().st_size > 0:
                seen.add(p)
                result.append(p)
        return result

    def _read_spring_config(self) -> dict[str, str]:
        """
        Read application.properties and application.yml from all modules,
        skipping test resources. Returns flattened dot-notation key→value map.
        """
        props: dict[str, str] = {}
        for fname in ("application.properties", "application.yml", "application.yaml"):
            for f in sorted(self._repo_path.glob(f"**/{fname}")):
                if "test" in f.parts:
                    continue
                try:
                    if fname.endswith(".properties"):
                        props.update(self._parse_properties(f))
                    else:
                        props.update(self._parse_yaml_flat(f))
                except Exception:
                    pass
        return props

    def _parse_properties(self, path: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip()
        return result

    def _parse_yaml_flat(self, path: Path) -> dict[str, str]:
        """Flatten a YAML config file into dot-notation keys."""
        def _flatten(node, prefix: str) -> dict[str, str]:
            out: dict[str, str] = {}
            if isinstance(node, dict):
                for k, v in node.items():
                    out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
            elif node is not None:
                out[prefix] = str(node)
            return out
        data = yaml.safe_load(path.read_text(errors="replace"))
        return _flatten(data, "") if isinstance(data, dict) else {}

    def _resolve_classpath(self, location: str) -> Optional[Path]:
        """
        Resolve a Spring classpath: or file: URI to an actual filesystem path.
        Searches src/main/resources/ in the root and all direct sub-modules.
        """
        for prefix in ("classpath*:", "classpath:", "file:"):
            if location.startswith(prefix):
                location = location[len(prefix):]
                break

        candidates = [
            self._repo_path / "src" / "main" / "resources" / location,
            self._repo_path / location,
        ]
        for child in self._repo_path.iterdir():
            if child.is_dir() and not child.name.startswith("."):
                candidates.append(child / "src" / "main" / "resources" / location)

        return next((c for c in candidates if c.exists()), None)

    # ── Tier 2: convention glob ───────────────────────────────────────────────

    # Standard locations used by projects that ship raw SQL dumps without a
    # migration framework. Ordered: schema-like directories before data-like.
    _SQL_SEARCH_GLOBS = [
        # Framework conventions (deepest/most specific first)
        "**/db/migration/*.sql",        # Flyway default (any module)
        "**/db/changelog/*.sql",        # Liquibase SQL changelogs
        "**/db/**/V*__*.sql",           # Flyway versioned naming pattern
        "**/resources/schema.sql",      # Spring Boot auto-init
        "**/resources/data.sql",
        # Common raw-dump conventions (db vendor subdirs, e.g. db/mysql/)
        "**/db/*/*.sql",                # e.g. db/mysql/schema.sql, db/postgres/data.sql
        # Top-level dump directories (language-agnostic convention)
        "sql/*.sql",
        "db/*.sql",
        "database/*.sql",
        "doc/sql/*.sql",
        "docs/sql/*.sql",
        "scripts/*.sql",
        "script/*.sql",
        "**/sql/*.sql",
    ]

    # Known incompatible database names — exclude their scripts when we know
    # the provisioned dep (e.g. don't run H2 DDL against a MySQL container).
    _INCOMPATIBLE_DB_DIRS = {"h2", "hsql", "hsqldb", "derby", "sqlite"}

    def _sql_scripts_from_glob(self, db_aliases: list[str]) -> list[Path]:
        """
        Scan standard directory conventions and return SQL files ordered so
        schema-creating scripts (DDL) run before data-loading scripts (DML).

        When db_aliases is provided (e.g. ['mysql']), paths whose parent
        directory name matches a known incompatible DB (h2, hsql, etc.) are
        excluded, and paths that match a db alias are promoted to schema tier.
        """
        seen: set[Path] = set()
        schema: list[Path] = []
        data: list[Path] = []
        _DDL_KEYWORDS = ("schema", "ddl", "create", "init", "struct", "migration", "changelog")

        for glob_pat in self._SQL_SEARCH_GLOBS:
            for p in sorted(self._repo_path.glob(glob_pat)):
                if p in seen or p.stat().st_size == 0:
                    continue
                # Exclude scripts for incompatible databases
                parent_name = p.parent.name.lower()
                if parent_name in self._INCOMPATIBLE_DB_DIRS:
                    continue
                # If we know the dep, deprioritise scripts for other real DBs
                # (e.g. skip db/postgres/ when we provisioned mysql)
                if db_aliases and parent_name not in db_aliases and parent_name in {
                    "mysql", "mariadb", "postgres", "postgresql", "mssql", "oracle"
                }:
                    continue
                seen.add(p)
                is_ddl = (
                    any(kw in p.stem.lower() for kw in _DDL_KEYWORDS)
                    or (db_aliases and parent_name in db_aliases)
                )
                if is_ddl:
                    schema.append(p)
                else:
                    data.append(p)

        return schema + data

    def _run_sql_init_scripts(self, dep_name: str, container, spec: _DepSpec, **_) -> None:
        """
        Execute SQL init scripts found in the repo against the dep container.
        Tolerates failures — if a script errors (e.g. table already exists),
        we log and continue rather than aborting the startup attempt.
        """
        scripts = self._find_sql_init_scripts(dep_name=dep_name)
        if not scripts:
            return

        logger.info("SQL init: found %d script(s) for %s", len(scripts), dep_name)
        for script in scripts:
            try:
                sql = script.read_text(errors="replace")
                self._exec_sql_via_docker(container, dep_name, spec, sql)
                logger.info("SQL init: executed %s", script.name)
            except Exception as exc:
                logger.warning("SQL init: failed to execute %s: %s", script.name, exc)

    def _exec_sql_via_docker(self, container, dep_name: str, spec: _DepSpec, sql: str) -> None:
        """Stream SQL text into the database CLI running inside the container."""
        import tarfile
        import io

        # Write the SQL to a tar archive and upload it to /tmp inside the container,
        # then exec the CLI reading from that file. This avoids shell escaping issues.
        sql_bytes = sql.encode("utf-8")
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info = tarfile.TarInfo(name="init.sql")
            info.size = len(sql_bytes)
            tar.addfile(info, io.BytesIO(sql_bytes))
        tar_buf.seek(0)
        container.put_archive("/tmp", tar_buf)

        env = spec.env
        if dep_name in ("mysql", "mariadb"):
            cmd = [
                "mysql",
                "-u", "root",
                f"-p{env.get('MYSQL_ROOT_PASSWORD', 'root')}",
                "--force",          # continue on error (e.g. table already exists)
                env.get("MYSQL_DATABASE", "app"),
                "-e", "source /tmp/init.sql",
            ]
        elif dep_name == "postgres":
            cmd = [
                "psql",
                "-U", env.get("POSTGRES_USER", "app"),
                "-d", env.get("POSTGRES_DB", "app"),
                "-f", "/tmp/init.sql",
            ]
        else:
            return

        exit_code, output = container.exec_run(
            cmd,
            environment={"MYSQL_PWD": env.get("MYSQL_ROOT_PASSWORD", "root"),
                         "PGPASSWORD": env.get("POSTGRES_PASSWORD", "asel")},
        )
        if exit_code and exit_code != 0:
            out_str = output.decode("utf-8", errors="replace") if output else ""
            logger.warning("SQL init exit %d: %s", exit_code, out_str[:200])

    def _wait_for_dep_ready(self, name: str, container, spec: _DepSpec) -> None:
        """
        Poll the dep container's own log output until its ready_log_pattern
        matches, indicating the service is accepting connections.

        Exits early if the container crashes (status exited/dead). Uses
        tail=200 so we fetch a bounded slice of logs on every poll rather
        than re-fetching the full log as it grows. Timeout: 60 s. Falls back
        to DEP_SETTLE_SECONDS sleep when no pattern is configured.
        """
        if not spec.ready_log_pattern:
            time.sleep(DEP_SETTLE_SECONDS)
            return

        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                container.reload()
                if container.status in ("exited", "dead"):
                    exit_code = container.attrs.get("State", {}).get("ExitCode", "?")
                    logger.warning("%s container exited (code %s) before signalling readiness", name, exit_code)
                    return
                logs = container.logs(tail=200).decode("utf-8", errors="replace")
                if re.search(spec.ready_log_pattern, logs, re.IGNORECASE):
                    logger.info("%s is ready", name)
                    return
            except Exception:
                pass
            time.sleep(1)

        logger.warning("%s did not signal readiness within 60 s — continuing anyway", name)

    # ── Health polling ────────────────────────────────────────────────────────

    def _poll_health(
        self, host_port: int, timeout: int
    ) -> tuple[bool, Optional[str], float, str]:
        """
        Poll all health paths until one returns a non-5xx response or timeout.
        Treats 401/403 as success — the app is up, just auth-protected.
        Tries both http:// and https:// — some apps (e.g. WebGoat) default to TLS.
        Reads the startup log each tick to detect a context path (e.g. '/WebGoat')
        and prepends it to health paths so context-rooted apps are found correctly.
        Returns (success, healthy_path, elapsed_seconds, base_url).
        """
        start = time.monotonic()
        deadline = start + timeout
        context_paths: list[str] = []

        # Try HTTP first (cheaper), then HTTPS (self-signed certs common in test apps)
        base_urls = [
            f"http://localhost:{host_port}",
            f"https://localhost:{host_port}",
        ]

        with httpx.Client(timeout=2.0, follow_redirects=False, verify=False) as client:
            while time.monotonic() < deadline:
                elapsed = time.monotonic() - start

                # Re-read log each tick to pick up newly logged context paths
                raw_log = self._read_startup_log()
                for cp in self._detect_context_paths(raw_log):
                    if cp not in context_paths:
                        context_paths.append(cp)
                        logger.debug("Context path detected at t=%.0fs: %s", elapsed, cp)

                # Once context paths are known, probe ONLY those paths — no root fallback.
                # Root-path probes return false-positive 404s when the app only listens
                # on a sub-path (e.g. /WebGoat/...). Before any context path is detected,
                # fall back to probing "/" so we don't miss apps with no context path.
                prefixes = context_paths if context_paths else [""]

                for base in base_urls:
                    for prefix in prefixes:
                        for path in HEALTH_PATHS:
                            url = f"{base}{prefix}{path}"
                            try:
                                resp = client.get(url)
                                logger.debug("Health probe t=%.0fs %s → %d", elapsed, url, resp.status_code)
                                # Context-path probes require a non-404 response to avoid
                                # false positives when another app's Tomcat answers with 404
                                # for an unknown context path (e.g. WebGoat returning 404 for
                                # /WebWolf/... paths). Root-path probes accept any <500.
                                # Special case: /actuator/health returns 503 when health checks
                                # fail (e.g. custom indicators, missing DB). 503 still means
                                # the app is alive — treat it as success.
                                is_actuator = "/actuator/" in path
                                is_context_probe = bool(prefix)
                                ok = (
                                    (resp.status_code < 500 or (is_actuator and resp.status_code == 503))
                                    and (not is_context_probe or resp.status_code != 404)
                                )
                                if ok:
                                    return True, f"{prefix}{path}", time.monotonic() - start, base
                            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError) as e:
                                logger.debug("Health probe t=%.0fs %s → %s", elapsed, url, type(e).__name__)

                # After a safe warm-up window, bail early if Spring Boot logged a
                # fatal startup exception. No point burning the rest of the timeout
                # on an app that already announced it will never start.
                if elapsed >= _WAR_FATAL_CHECK_AFTER_SECS:
                    log_snap = self._read_startup_log()
                    if any(re.search(p, log_snap, re.IGNORECASE) for p in _FATAL_JAR_PATTERNS):
                        logger.info(
                            "JAR: fatal startup exception detected at t=%.0fs — bailing poll early",
                            elapsed,
                        )
                        break

                time.sleep(POLL_INTERVAL_SECONDS)

        return False, None, time.monotonic() - start, f"http://localhost:{host_port}"

    def _rescue_probe(self, host_port: int, context_paths: list[str]) -> tuple[bool, Optional[str], str]:
        """
        Post-poll rescue: the app started with a non-root context path that the
        poll loop missed (timing/buffering). Tries all detected context paths so
        apps with multiple embedded servers (e.g. WebGoat + WebWolf) are handled.
        Returns (success, healthy_path, base_url).
        """
        logger.debug("Rescue probe: context_paths=%s port=%d", context_paths, host_port)
        base_urls = [
            f"http://localhost:{host_port}",
            f"https://localhost:{host_port}",
        ]
        with httpx.Client(timeout=5.0, follow_redirects=False, verify=False) as client:
            for cp in context_paths:
                for base in base_urls:
                    for path in HEALTH_PATHS:
                        url = f"{base}{cp}{path}"
                        try:
                            resp = client.get(url)
                            logger.debug("Rescue probe %s → %d", url, resp.status_code)
                            if resp.status_code < 500:
                                return True, f"{cp}{path}", base
                        except (httpx.ConnectError, httpx.TimeoutException,
                                httpx.ReadError, httpx.RemoteProtocolError):
                            pass
        return False, None, f"http://localhost:{host_port}"

    def _detect_context_paths(self, log: str) -> list[str]:
        """
        Extract all servlet context paths from a Tomcat/Undertow startup log.
        e.g. WebGoat 2025 starts both '/WebGoat' and '/WebWolf' — return both.
        Skips root ("/") since we always probe that in the main poll loop.
        """
        matches = re.findall(r"context path '([^']*)'", log)
        seen: list[str] = []
        for p in matches:
            p = p.rstrip("/")
            if p and p != "/" and p not in seen:
                seen.append(p)
        return seen

    # ── HTTP proxy sidecar ────────────────────────────────────────────────────

    def _start_http_proxy(self, container) -> None:
        """
        Start a catch-all HTTP forward proxy inside the given container.

        The proxy binds on 127.0.0.1:18080 and returns 200 {} for every
        request, including CONNECT tunnels (HTTPS).  Combined with
        _PROXY_JVM_FLAGS this converts startup failures caused by unreachable
        external HTTP APIs (OAuth2 token endpoints, config servers, SDK
        phone-homes) into immediate 200 responses so they never block context
        load.

        Requires python3 in the container image.  If unavailable the proxy is
        silently skipped — the worst case is external HTTP calls take their
        normal timeout, which is the pre-existing behaviour.
        """
        try:
            container.exec_run(
                ["python3", "-c", _HTTP_PROXY_SCRIPT],
                detach=True,
                demux=False,
            )
        except Exception:
            return

        time.sleep(0.2)   # give the proxy socket time to bind inside the container
        logger.debug("HTTP proxy: catch-all proxy started on 127.0.0.1:18080")

    # ── Result builder ────────────────────────────────────────────────────────

    def _make_result(
        self,
        service_type: ServiceType,
        host_port: int,
        healthy_path: Optional[str],
        elapsed: float,
        stubs: list[str],
        deps_provisioned: list[str],
        strategy: str,
        base_url: str = "",
        failure_classes: list[str] | None = None,
    ) -> RuntimeResult:
        # Derive context-aware base URL so surface discovery hits the right root.
        # e.g. healthy_path="/WebGoat/actuator/health" → base gets /WebGoat appended.
        effective_base = base_url or f"http://localhost:{host_port}"
        if healthy_path:
            for hp in HEALTH_PATHS:
                if healthy_path.endswith(hp):
                    ctx = healthy_path[: -len(hp)]   # e.g. "/WebGoat"
                    if ctx:
                        effective_base = effective_base.rstrip("/") + ctx
                    break

        if "security_disabled" in stubs:
            fidelity = RuntimeFidelity.LOW
        elif "h2_override" in stubs or "mysql_redirect" in stubs:
            fidelity = RuntimeFidelity.MEDIUM
        else:
            fidelity = RuntimeFidelity.HIGH

        return RuntimeResult(
            service_type=service_type,
            status=RuntimeStatus.STARTED,
            port=host_port,
            base_url=effective_base,
            healthy_path=healthy_path,
            startup_seconds=elapsed,
            startup_log=self._read_startup_log(),
            stubs_applied=stubs,
            deps_provisioned=deps_provisioned,
            startup_strategy=strategy,
            fidelity=fidelity,
            confidence=compute_confidence(stubs),
            failure_classes=failure_classes or [],
        )
