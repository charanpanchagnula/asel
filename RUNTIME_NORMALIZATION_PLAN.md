# ASEL Runtime Normalization — Implementation Plan

**Status:** PLANNED  
**Synthesized from:** RESEARCH_RUNTIME.md + CHAT.md + session analysis (2026-04-14)  
**Goal:** Systematic, non-whackamole runtime startup improvement. Every change addresses a named failure class, not a specific repo's upstream bug.

---

## Guiding Principles (from CHAT.md synthesis)

1. **Hierarchy of mutations:** environment mutation → config mutation → code suppression → source surgery. Never jump to source edits until all environment paths are exhausted.
2. **Classify before acting:** no recovery action is valid without a named failure class. The LLM is a component of last resort for the `UNKNOWN` class only.
3. **Environment confidence is first-class:** every startup result must carry a numeric confidence score so scan findings can be annotated with their fidelity context.
4. **Predictive over reactive:** pre-startup feature detection must run before attempt 1, not after the first crash.
5. **No whackamole:** a fix is only valid if it addresses a failure class that affects multiple repos. Per-repo overrides are forbidden.

---

## Current State (what's already in runtime.py)

| Component | Status | Location |
|---|---|---|
| 3-attempt startup (profile → infra_disable → H2+security) | ✅ built | `_run_startup_attempts()` |
| Dep provisioning from build file (pre-flight) | ✅ built | `_provision_deps_from_build()` |
| Reactive infra flag injection from log | ✅ built | `_infra_flags_from_log()` |
| HTTP proxy (catches all outbound HTTP) | ✅ built | `_start_http_proxy()`, `_PROXY_JVM_FLAGS` |
| Manifest env mining (docker-compose, .env.example) | ✅ built | `_read_manifest_env()` |
| Dep registry (persona library) | ✅ built | `deps-registry.yaml` |
| lazy-initialization, banner-mode, OAuth2 excludes | ✅ added this session | `_BASE_FLAGS`, `_SECURITY_DISABLE_FLAGS` |
| Runtime failure classifier | ❌ missing | — |
| Recovery action table | ❌ missing | — |
| Pre-startup feature map (structured, beyond dep detection) | ❌ missing | — |
| Config synthesizer (Attempt 2b) | ❌ missing | — |
| Environment confidence score (numeric) | ❌ missing | `RuntimeFidelity` enum is too coarse |
| JVM startup flags (TieredStopAtLevel=1, add-opens) | ❌ missing | — |
| Wire-protocol stubs (MySQL/Redis wire protocol) | ❌ missing | — |
| Parallel speculative startup | ❌ missing | — |

---

## Failure Class Taxonomy

The RESEARCH_RUNTIME.md §Unified Failure Taxonomy defines 8 classes. Adding 3 from CHAT.md analysis:

```python
class RuntimeFailureClass(str, Enum):
    MISSING_PROPERTY    = "missing_property"     # ${VAR} placeholder unresolved
    MISSING_BEAN        = "missing_bean"          # No qualifying bean of type X
    BEAN_CREATION       = "bean_creation"         # BeanCreationException (re-classify nested cause)
    DB_CONNECTION       = "db_connection"         # JDBC connection refused / timeout
    API_MIGRATION       = "api_migration"         # WebSecurityConfigurerAdapter, Spring 5→6
    RESOURCE_NOT_FOUND  = "resource_not_found"    # FileNotFoundException on classpath resource
    EXTERNAL_API        = "external_api"          # HTTP timeout to external service
    TOMCAT_LISTENER     = "tomcat_listener"       # WAR silent failure (check Tomcat log)
    AUTH_BOOTSTRAP      = "auth_bootstrap"        # JWT/OIDC issuer-uri unreachable (from CHAT.md)
    DB_SCHEMA           = "db_schema"             # Flyway/Liquibase schema validation fails
    MESSAGING           = "messaging"             # Kafka/RabbitMQ broker unavailable
    UNKNOWN             = "unknown"               # No pattern matched
```

### Classifier implementation

```python
# Ordered by specificity — more specific patterns first
_FAILURE_PATTERNS: list[tuple[str, RuntimeFailureClass]] = [
    # API migration (structural — must check before MISSING_BEAN)
    (r"WebSecurityConfigurerAdapter|HttpSecurity.*not available|authorizeRequests.*deprecated", RuntimeFailureClass.API_MIGRATION),
    # Auth bootstrap
    (r"issuer-uri|jwk-set-uri|oidcProviderConfiguration|Unable to resolve.*OpenID|JWKS.*fetch", RuntimeFailureClass.AUTH_BOOTSTRAP),
    # Missing property (Spring placeholder)
    (r"Could not resolve placeholder '(.+?)'|Binding to target.*failed.*property", RuntimeFailureClass.MISSING_PROPERTY),
    # Missing bean
    (r"No qualifying bean of type '(.+?)' available|expected at least 1 bean", RuntimeFailureClass.MISSING_BEAN),
    # Bean creation (re-classify from nested cause)
    (r"BeanCreationException.*creating bean.*'(.+?)'", RuntimeFailureClass.BEAN_CREATION),
    # DB connection
    (r"Connection refused.*\d+|\bCommunications link failure\b|FATAL:.*database|Unable to acquire JDBC", RuntimeFailureClass.DB_CONNECTION),
    # DB schema
    (r"LiquibaseException|FlywayException|Table .* doesn't exist|relation .* does not exist", RuntimeFailureClass.DB_SCHEMA),
    # Messaging
    (r"org\.apache\.kafka|KafkaException|bootstrap\.servers|AmqpConnectException|RabbitMQ", RuntimeFailureClass.MESSAGING),
    # Resource file
    (r"ResourceUtils\.getFile|Cannot search.*URL.*war:|FileNotFoundException.*classpath:", RuntimeFailureClass.RESOURCE_NOT_FOUND),
    # External API timeout
    (r"ConnectTimeoutException|Connection timed out.*:443|UnknownHostException|SocketTimeoutException", RuntimeFailureClass.EXTERNAL_API),
    # Tomcat silent failure
    (r"Context.*failed|LifecycleException|StandardContext\.startInternal", RuntimeFailureClass.TOMCAT_LISTENER),
]

def classify_runtime_failure(log: str) -> RuntimeFailureClass:
    for pattern, cls in _FAILURE_PATTERNS:
        if re.search(pattern, log, re.IGNORECASE):
            return cls
    return RuntimeFailureClass.UNKNOWN
```

---

## Recovery Action Table

Maps each failure class to an ordered sequence of recovery actions. LLM only for UNKNOWN.

```python
# Each action is a method name on RuntimeEngine or a module-level function.
# Actions are applied cumulatively — later attempts inherit earlier flags.
RECOVERY_PLAN: dict[RuntimeFailureClass, list[str]] = {
    RuntimeFailureClass.MISSING_PROPERTY: [
        "synthesize_config",          # Attempt 2b: LLM reads ${VAR} patterns, synthesizes SPRING_APPLICATION_JSON
    ],
    RuntimeFailureClass.AUTH_BOOTSTRAP: [
        "expand_security_excludes",   # Already done in _SECURITY_DISABLE_FLAGS
        "inject_jwt_stub",            # Inject synthetic JWT secret via SPRING_APPLICATION_JSON
        "synthesize_config",          # Broader config synthesis if stub insufficient
    ],
    RuntimeFailureClass.DB_CONNECTION: [
        "provision_dep_from_log",     # Already done reactively — keep as explicit action
        "h2_override",                # Fallback to H2 if real DB provisioning failed
    ],
    RuntimeFailureClass.DB_SCHEMA: [
        "disable_migrations",         # --spring.flyway.enabled=false, --spring.liquibase.enabled=false
        "h2_override",                # With create-drop DDL
    ],
    RuntimeFailureClass.MISSING_BEAN: [
        "detect_api_migration",       # Check if missing bean is Spring Security 5→6 pattern
        "exclude_autoconfigure",      # Exclude the autoconfigure class that required the bean
    ],
    RuntimeFailureClass.API_MIGRATION: [
        "run_openrewrite_security6",  # mvn rewrite:run with HttpSecurityLambdaDsl recipe
        # Note: requires rebuild after OpenRewrite — not a flag-only fix
    ],
    RuntimeFailureClass.MESSAGING: [
        "disable_kafka_listeners",    # --spring.kafka.listener.auto-startup=false
        "provision_dep_from_log",     # Provision broker if not already running
    ],
    RuntimeFailureClass.EXTERNAL_API: [
        "verify_proxy_running",       # HTTP proxy should already handle this
        "inject_connect_timeout",     # Shorten connect timeout so failures are fast
    ],
    RuntimeFailureClass.RESOURCE_NOT_FOUND: [
        "extract_nested_jar_resource", # jar xf + mount at expected path
    ],
    RuntimeFailureClass.TOMCAT_LISTENER: [
        "read_tomcat_context_log",    # Tail localhost.YYYY-MM-DD.log, re-classify
    ],
    RuntimeFailureClass.BEAN_CREATION: [
        "reclassify_from_cause",      # Parse nested exception, re-run classifier on it
    ],
    RuntimeFailureClass.UNKNOWN: [
        "llm_startup_repair",         # Agent reads log, suggests targeted fix
    ],
}
```

---

## Revised Startup Algorithm

Replace the hardcoded 3-attempt structure with a classify→act loop:

```
Pre-flight:
  1. _read_manifest_env()           [already done]
  2. _provision_deps_from_build()   [already done]
  3. _build_feature_map()           [NEW: structured scan of build + config files]
     → infer auth stack, cloud SDKs, framework version, profile names
     → pre-select startup flags based on detected features

Attempt loop (up to MAX_ATTEMPTS = 4):
  for each attempt:
    1. Assemble flags from: base + accumulated stubs + dep flags
    2. _try_one_startup(flags, timeout)
    3. If success → return result with confidence score
    4. Read startup log
    5. failure_class = classify_runtime_failure(log)
    6. Log: "Attempt N failed: {failure_class}"
    7. Apply recovery actions from RECOVERY_PLAN[failure_class]
       → these update the accumulated stubs / flags / source
    8. Continue to next attempt

If all attempts fail → RuntimeStatus.FAILED_TO_START
```

Key change: the 3-attempt structure becomes a loop driven by classification, not hardcoded steps. Each iteration learns from the previous failure. The number of useful attempts is bounded by the number of distinct failure classes, not by an arbitrary count.

---

## Environment Confidence Score

Replace the 3-value `RuntimeFidelity` enum with a numeric score.

### Model

```python
# In models.py — replaces RuntimeFidelity enum
class EnvironmentConfidence(BaseModel):
    score: float = 1.0              # 0.0 (meaningless) to 1.0 (fully faithful)
    penalties: dict[str, float] = {}  # stub_name → penalty applied
    interpretation: str = "high"    # "high" | "medium" | "low" for human display

# Penalty table (each stub applied subtracts from 1.0)
CONFIDENCE_PENALTIES = {
    "lazy_init":            0.05,   # beans not exercised at startup — low penalty
    "security_disabled":    0.20,   # auth/IDOR probes invalid
    "h2_override":          0.15,   # SQLi results less reliable
    "config_synthesized":   0.10,   # JWT secrets and DB URLs may be wrong values
    "openrewrite_applied":  0.10,   # source was mutated before startup
    "messaging_disabled":   0.05,   # async paths not reachable
    "proxy_http":           0.03,   # external APIs return 200 stubs
    "llm_repair":           0.20,   # unknown fix applied — low confidence in result
}
```

### Why this matters for the paper

When security findings are reported, the confidence score tells readers: "this SQLi finding was confirmed on a runtime with confidence 0.72 — the DB was H2 (not MySQL), so the payload is confirmed to execute but dialect differences may affect exploitability in production." This is a core contribution: honest fidelity annotation on runtime-confirmed findings.

---

## Pre-startup Feature Map

A structured scan before attempt 1 that makes the startup strategy predictive, not reactive.

```python
@dataclass
class RepoFeatureMap:
    framework: str              # "spring-boot" | "quarkus" | "micronaut" | "unknown"
    spring_boot_version: str    # "2.x" | "3.x" | "unknown"
    build_tool: str             # "maven" | "gradle"
    
    # Infrastructure
    db: list[str]               # ["mysql", "postgres", "h2"]
    cache: list[str]            # ["redis", "memcached"]
    messaging: list[str]        # ["kafka", "rabbitmq"]
    cloud: list[str]            # ["aws", "azure", "gcp"]
    
    # Auth / security
    has_spring_security: bool
    has_oauth2_resource_server: bool
    has_oauth2_client: bool
    has_jwt: bool               # jwt artifact or @Value("${jwt.*}")
    has_keycloak: bool
    
    # Schema migration
    has_flyway: bool
    has_liquibase: bool
    
    # Service discovery
    has_eureka: bool
    has_consul: bool
    has_vault: bool
    
    # Config
    has_config_server: bool
    has_actuator: bool
    
    # Profile hints from properties files
    available_profiles: list[str]   # ["dev", "test", "local", "docker"]
    
    # Signals from manifests
    docker_compose_env: dict[str, str]  # env vars from docker-compose.yml
    dotenv_example: dict[str, str]      # from .env.example
```

This map drives attempt 1 flag selection. If `has_oauth2_resource_server=True`, add OAuth2 excludes on attempt 1 (not wait until attempt 3 after the crash). If `has_jwt=True`, synthesize a JWT secret before attempt 1.

**Implementation:** `_build_feature_map(repo_path, build_text, config_files)` — reads pom.xml/build.gradle dependency IDs + property file key patterns. No LLM needed. Takes <1 second.

---

## JVM Startup Flags (Quick Win)

Add to all startup attempts. These never break apps but improve cold-start success rate.

```python
_JVM_STARTUP_FLAGS = [
    # Disable C2 JIT compiler — cuts startup time 40-60% on cold starts.
    # Apps that timeout at 35s often succeed at 20s with this.
    # Safe: C1/interpreted is slower at runtime but ASEL only needs the app to
    # respond to a health check, not sustain high throughput.
    "-XX:TieredStopAtLevel=1",
    
    # Pre-emptively unblock the 5 most common InaccessibleObjectException failures
    # in Spring Boot 3 on JDK 17+. CGLIB, Hibernate, and some Spring internals
    # need reflective access that Java 9+ module system blocks by default.
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/java.math=ALL-UNNAMED",
    
    # Suppress JMX bean registration — common startup hang source.
    "-Dspring.jmx.enabled=false",
]
```

Note: these are JVM flags (go before `-jar`), not Spring Boot args. The existing `_PROXY_JVM_FLAGS` are also JVM flags — these join that list.

---

## Config Synthesizer (Attempt 2b)

Between current attempt 2 (infra disable) and attempt 3 (H2 override), insert a config synthesis attempt.

**Input:** startup log from failed attempt 1 or 2, plus all config files in repo  
**Output:** `SPRING_APPLICATION_JSON` dict with synthesized values  

```python
def synthesize_config(repo_path: Path, startup_log: str) -> dict[str, str]:
    """
    Extract unresolved ${VAR} placeholders from startup log and config files.
    Synthesize plausible stub values. Returns flat dict for SPRING_APPLICATION_JSON.
    
    Rules (deterministic, no LLM needed for most):
    - Keys containing 'secret', 'key', 'password', 'token': 
        → 64-char hex string
    - Keys containing 'url' and ('jdbc' or 'datasource'): 
        → skip (handled by H2 override)
    - Keys containing 'host' or 'url':
        → "localhost"
    - Keys containing 'port':
        → "8080"
    - Boolean-shaped keys (enabled, active, flag):
        → "false"
    - JWT-shaped keys (jwt.secret, jwt.base64-secret, jwt.token-validity-in-seconds):
        → appropriate type (base64 secret, seconds as int string)
    - Everything else:
        → "placeholder-{key_stem}"
    """
```

Inject via `SPRING_APPLICATION_JSON` env var (higher precedence than application.yml, lower than command-line args). No source mutation — pure environment injection.

---

## Wire-Protocol Stubs (Phase 2 followup)

**Not implemented in this sprint.** Documented here for roadmap.

Run tiny servers that speak the MySQL/Redis/Kafka wire protocol but store nothing. Covers apps that use Druid, custom connection pools, or non-H2-compatible drivers.

- MySQL wire stub: ~200 lines Python, completes handshake, returns empty ResultSet for all queries
- Redis RESP stub: ~100 lines, returns +OK for writes, $-1 for reads
- Kafka binary stub: accepts produce requests, returns empty fetch responses

These replace real dep containers for apps that only need the connection to establish (not actual data). Startup succeeds, HTTP binds, security scanner probes endpoints.

---

## Implementation Order

### Sprint 1 (this session — ~4 hours)
1. Add `RuntimeFailureClass` enum to `models.py`
2. Add `classify_runtime_failure()` to `runtime.py`
3. Add `_JVM_STARTUP_FLAGS` to `runtime.py` (30 min)
4. Wire classifier into `_run_startup_attempts()` — log failure class after each failed attempt
5. Add `synthesize_config()` as Attempt 2b in the startup sequence
6. Add numeric `EnvironmentConfidence` scoring replacing `RuntimeFidelity` enum

### Sprint 2 (next session)
1. `_build_feature_map()` — pre-startup feature detection
2. Use feature map to pre-select flags on attempt 1 (predictive, not reactive)
3. Recovery action table wired to classifier output
4. OpenRewrite Spring Security 6 migration path (for `API_MIGRATION` class)

### Sprint 3
1. Wire-protocol MySQL + Redis stubs
2. Parallel speculative startup (race 3 configs simultaneously)
3. `ptrace`-based connect() timeout elimination

---

## What This Delivers (Paper Contribution)

The complete runtime normalization framework = a **4-layer defense-in-depth** system:

| Layer | What it does | Failure classes covered |
|---|---|---|
| **Layer 0: Feature map + manifest mining** | Predictive pre-flight — provision known deps before crash | DB_CONNECTION, AUTH_BOOTSTRAP, MISSING_PROPERTY |
| **Layer 1: JVM/Spring flag injection** | Lazy init, security excludes, infra disable flags | MISSING_BEAN, AUTH_BOOTSTRAP, MESSAGING |
| **Layer 2: Config synthesis (Attempt 2b)** | Synthesize JWT secrets, DB URLs, API keys | MISSING_PROPERTY, AUTH_BOOTSTRAP |
| **Layer 3: H2 override + dep provisioning** | Replace DB with H2, provision real containers | DB_CONNECTION, DB_SCHEMA |
| **Layer 4: LLM repair (UNKNOWN only)** | Last resort for unclassified failures | UNKNOWN |

Each layer is annotated in the confidence score. The classifier tells you which layer fired and why. This is the intellectual core that distinguishes ASEL from "just running scanners."

**Honest expected startup success rate improvement:**  
Current baseline (3 attempts, reactive): ~40–60% on public OSS Spring Boot repos  
After Sprint 1: ~55–70% (config synthesis covers the JWT/auth bootstrap class; JVM flags reduce timeouts)  
After Sprint 2: ~65–80% (predictive feature map eliminates the first-attempt timeout for known dep patterns)
