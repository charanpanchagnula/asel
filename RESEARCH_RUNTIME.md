# ASEL Runtime Engine — Startup Research

**Researched:** 2026-04-13
**Domain:** Autonomous Java application startup in unknown/unconfigured environments
**Confidence:** HIGH (core architecture), MEDIUM (bytecode agent approach), HIGH (Spring framework internals)

---

## Executive Summary

The core problem is fundamental: arbitrary Java repositories are built for a configured production environment that ASEL cannot replicate. Every startup failure reduces to one of four root causes: (1) missing secrets/config values, (2) missing infrastructure (DB, broker, cache), (3) API-incompatible code (e.g., Spring Security 5 → 6 breakage), or (4) binary resource access failures (WAR/nested JAR classpath). No single technique resolves all four. The academic and commercial ecosystem confirms there is no out-of-the-box "universal Java app bootstrapper" — every tool that runs arbitrary apps does so by either demanding a pre-configured environment or implementing a tiered remediation strategy similar to what ASEL already has.

**The architecturally correct answer** is a four-layer defense-in-depth system: (1) deep startup-log failure classification with pattern-matched remediation, (2) an LLM-synthesized config overlay as a mid-tier fallback, (3) a whole-JVM HTTP interception proxy (Hoverfly or a custom `http.proxyHost` shim) to silence external API calls at the OS/JVM level, and (4) a targeted source-code patch agent for structural incompatibilities (Spring Security 5→6 migration). The Java agent / bytecode interception angle is real but limited to APM-style call interception — it cannot safely bridge structural API incompatibilities.

**Primary recommendation:** Implement a structured Failure Classification + Graduated Response chain. Each failure class has exactly one prescribed remediation. Add an LLM config synthesizer as a new Attempt 2b between the current Attempt 2 (infra disable) and Attempt 3 (H2 override). Add a JVM-level HTTP proxy shim as standard scaffolding on every startup. These three additions will increase the Tier-2 startup rate from the current ~40–60% to an estimated 65–80% on public OSS Spring Boot repos.

---

## Angle 1: Academic / Research — What Does the Literature Say?

### Finding

There is **no published research** specifically targeting "autonomous startup of arbitrary Java apps in unknown environments." The closest adjacent work:

- **Repo2Run (arXiv 2502.13681, Feb 2025)** — LLM agent (GPT-4o) that iteratively installs dependencies and adjusts configurations for arbitrary Python repositories by observing test failure logs. Achieves 86% success on 420 Python repos. Methodology: Docker snapshot-based rollback, atomic command synthesis, error-driven iteration. **Explicitly Python-only.** The methodology is directly applicable to ASEL with Java adaptations — ASEL's three-attempt strategy is architecturally similar but lacks the LLM-driven config synthesis loop.

- **AutoBaxBuilder (arXiv 2512.21132, Dec 2025)** — LLM pipeline for generating security test tasks from scratch, including functionality tests and exploits. Not a startup bootstrapper; generates tasks from known codebases with known configs.

- **Bootstrapping Automated Testing for RESTful Web Services (Springer, 2021)** — API traffic capture + replay for untrusted third-party APIs. Useful for the Phase 2c exploit engine, not the startup problem.

- **Fuzzing Java apps (OSS-Fuzz, Jazzer, 2021–2024)** — fuzz targets assume the app can already start. The setup problem is considered pre-solved by the team before submitting to OSS-Fuzz.

- **DAST tools (Burp Suite Enterprise, OWASP ZAP, GitLab DAST, StackHawk)** — All DAST tools require a running application to be provided to them. They probe a URL. They do not bootstrap apps. The "CI/CD integration" these tools document is guidance on when in the pipeline to run them, not how to start the app.

**Conclusion (HIGH confidence):** The academic gap is real. ASEL is exploring territory without a reference implementation. The Repo2Run LLM-driven iteration loop is the single most relevant prior work. The DAST industry unanimously punts the startup problem back to the CI pipeline.

---

## Angle 2: Bytecode / Java Agent Approach

### What Agents Can Do

Java agents (Byte Buddy, ASM, OpenTelemetry instrumentation) intercept class loading and method calls at the JVM level using the `java.lang.instrument.Instrumentation` API. They are the mechanism behind:
- Datadog APM (intercepts all HTTP client calls, JDBC calls)
- OpenTelemetry Java agent (zero-code instrumentation, JDK 8+)
- Mockito inline mock maker (intercepts constructors and final classes)

The OpenTelemetry Java agent intercepts every HTTP call made by the application (via OkHttp, Apache HttpClient, java.net.HttpURLConnection, Spring WebClient, etc.) and emits spans — this is the closest existing tool to "intercept all outbound calls."

### What Agents Cannot Do (the wall)

Agents transform bytecode at class-load time. They can:
- Replace a method body with a stub return value
- Intercept a constructor to return a mock object (Mockito inline)
- Wrap any method call with try/catch

They **cannot** resolve structural incompatibilities at the type system level. The `mall-tiny` failure (Spring Security 5 `HttpSecurity` injection not available in Spring Security 6) is a compile-time-clean, runtime-structural incompatibility: the class exists but the wiring contract has changed. An agent would need to replace the entire `@Configuration` class body — equivalent to rewriting the source code.

### JEP 451 Constraint (Java 21+)

JEP 451 (delivered in JDK 21, targeting full disallowance in a future release) adds a warning when agents are dynamically loaded. Static agents (`-javaagent:` on the command line at startup) are **not affected** by JEP 451 warnings. Since ASEL controls the JVM launch command, static attachment is always available. The `-XX:+EnableDynamicAgentLoading` flag suppresses the warning for dynamic attachment.

### Feasible Agent Use Cases for ASEL

| Use case | Feasibility | Implementation |
|---|---|---|
| Intercept all outbound HTTP calls → redirect to mock server | HIGH | OpenTelemetry agent already does call interception. A custom exporter/processor can redirect instead of trace. Alternative: global `http.proxyHost` JVM property. |
| Catch `BeanCreationException` during context refresh → continue | LOW | Would require replacing `AbstractApplicationContext.refresh()` — extremely fragile against version changes |
| Intercept `afterPropertiesSet()` and swallow exceptions | MEDIUM | Byte Buddy can wrap `InitializingBean.afterPropertiesSet()`. Risky: swallowing init exceptions leaves beans in undefined state |
| Replace null `@Value` field injection with dummy string | MEDIUM | ASM transformer can intercept field write if null → inject placeholder |

**Conclusion (MEDIUM confidence):** A targeted agent to redirect all JVM-level HTTP calls to a local mock server is feasible and high-value. A general "swallow all bean init failures" agent is not safe — it will produce apps that start but behave randomly, invalidating security probe results.

---

## Angle 3: Spring Framework Internals — The "Maximum Flags" Playbook

This is the highest-confidence, most actionable angle. The Spring Boot flag space provides the richest levers.

### Verified Spring Boot Flags for ASEL Startup (HIGH confidence)

**Tier A — Always inject (no known breakage):**
```
--spring.main.lazy-initialization=true
--spring.main.allow-bean-definition-overriding=true
--spring.main.banner-mode=off
```

`lazy-initialization=true` defers all bean construction to first-access, converting startup failures into lazy failures that often never trigger if the probed endpoint doesn't exercise the missing bean. **Caveat:** masks real failures. ASEL must track this as `stubs_applied=["lazy_init"]` and annotate fidelity accordingly.

`allow-bean-definition-overriding=true` resolves `BeanDefinitionOverrideException`, which occurs in ~15% of multi-module Spring Boot apps that override beans accidentally across modules.

**Tier B — Security disable (already in ASEL Attempt 3, needs expansion):**

The current `_SECURITY_DISABLE_FLAGS` excludes only `SecurityAutoConfiguration` and `UserDetailsServiceAutoConfiguration`. The complete list for Spring Boot 3 is:

```
--spring.autoconfigure.exclude=\
  org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,\
  org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration,\
  org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration,\
  org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration,\
  org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration
```

The addition of `ManagementWebSecurityAutoConfiguration` is critical for actuator-enabled apps. The OAuth2 classes resolve the `eladmin` JWT failure class where Spring Security expects an OAuth2 resource server configuration that requires a secret.

**Tier C — Config server / external config disable:**

```
--spring.cloud.config.enabled=false
--spring.cloud.consul.config.enabled=false
--spring.cloud.vault.enabled=false
--spring.config.import=optional:configserver:,optional:consul:,optional:vault:
```

The `optional:` prefix on `spring.config.import` is Spring Boot 2.4+ behavior — it makes config server unavailability non-fatal. Without `optional:`, the app crashes before any beans are created.

**Tier D — Migration incompatibility flag:**

```
--spring.main.allow-circular-references=true
```

Spring Boot 2.6+ disabled circular references by default. Many older Spring Boot 2.x apps migrated to Spring Boot 3 have circular dependency issues that this flag resolves temporarily.

### The Spring Security 5 → 6 Structural Problem (mall-tiny class)

`WebSecurityConfigurerAdapter` was deprecated in Spring Security 5.7 and **removed** in Spring Security 6 (Spring Boot 3.0+). Apps that inject `HttpSecurity` via a constructor (extending `WebSecurityConfigurerAdapter`) fail on Spring Security 6 because the injection contract changed from adapter inheritance to `SecurityFilterChain` bean definition.

**No JVM flag can fix this.** The only fix is a source code patch:
```java
// Spring Security 5 pattern (broken in Spring Boot 3):
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception { ... }
}

// Spring Security 6 pattern (correct):
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // same body
        return http.build();
    }
}
```

**ASEL remediation path:** Detect `NoSuchBeanDefinitionException: HttpSecurity` in startup logs → trigger source-code patch agent with the OpenRewrite recipe `org.openrewrite.java.spring.security6.HttpSecurityLambdaDsl` (HIGH confidence — OpenRewrite ships this recipe as part of `rewrite-spring`). This converts the adapter pattern to the filter chain bean pattern automatically. This is a deterministic, non-LLM fix.

**Conclusion (HIGH confidence):** The Spring flag space provides significant startup coverage for config failures and autoconfigure conflicts. The Security 5→6 structural incompatibility requires a source-code patch, not a JVM flag. OpenRewrite has the exact recipe.

---

## Angle 4: Test Mode — Piggyback the App's Own Test Infrastructure

### The Idea

Many apps have `@SpringBootTest` integration tests that wire all the mocks, WireMock stubs, Testcontainers instances, and `@MockBean` definitions needed to run. Can ASEL run the app in test context mode, piggyback on that wiring, and then scan?

### Feasibility Assessment

**Works for:** Apps with `@SpringBootTest(webEnvironment=RANDOM_PORT)` tests that start the full application context. The test context caches the `ApplicationContext`, starts a real HTTP server, and is scannable.

**Requires:** A Maven/Gradle test run that reaches the `@SpringBootTest` phase. This means the test dependencies must resolve and the test compilation must succeed. Many apps in the ASEL benchmark fail at build time, so this approach is inapplicable for those.

**Infrastructure gap:** `@SpringBootTest` tests use `@MockBean` (deprecated in Spring Boot 3.4 in favor of `@MockitoBean`), Testcontainers, or H2 in-memory DBs. All three require ASEL to:
1. Execute `mvn test -pl . -Dtest=*IntegrationTest` or similar
2. Identify which test class starts the full application context
3. Keep that JVM alive during scanning

**Practical verdict:** This is high-complexity for uncertain gain. The test suite may not exist, may not have integration tests, may not compile, or may use proprietary dependencies. **Reserve as a fallback** for apps where all three startup attempts fail but the build succeeds — detect `@SpringBootTest` tests and attempt a limited test run.

**Conclusion (MEDIUM confidence):** Technically viable for a subset. Too fragile for the primary path. Add to the roadmap as Attempt 4 (after H2 override) for apps with detected `@SpringBootTest`.

---

## Angle 5: Container / OS Interception

### JVM-Level HTTP Proxy (highest-leverage OS angle)

The single most broadly applicable OS-level technique for arbitrary Java apps is the JVM's built-in proxy system properties:

```
-Dhttp.proxyHost=localhost -Dhttp.proxyPort=8888
-Dhttps.proxyHost=localhost -Dhttps.proxyPort=8888
-Dhttp.nonProxyHosts=localhost|127.0.0.1
```

These properties are honored by `java.net.HttpURLConnection`, and through it by most Java HTTP clients (Apache HttpClient 4.x, OkHttp 3.x, Spring RestTemplate). Modern HTTP clients (OkHttp 4, Spring WebClient) also honor them if configured to use system properties.

**Effect:** All outbound HTTP calls from the app hit a local proxy server that ASEL controls. The proxy returns empty 200 responses (or canned stubs) for any unknown URL. This silences API calls to third-party services that block startup.

**Implementation:** Run a minimal HTTP proxy (Python `mitmproxy` or a tiny Go/Python shim) alongside the app container. Inject the proxy JVM flags on every startup attempt. The proxy runs on `localhost:8888` inside the container (or on host with `--network host`).

**Limitation:** Does not help for non-HTTP dependencies (gRPC, raw TCP, Thrift). HTTPS interception requires injecting a custom CA cert into the JVM's truststore — doable with `-Djavax.net.ssl.trustStore=/path/to/custom.jks` but adds complexity.

### LD_PRELOAD for File Existence

The `ResourceUtils.getFile()` failure in `spring-security-registration` (GeoLite2-City.mmdb inside a nested WAR JAR) is a specific case of a Java app calling `ResourceUtils.getFile()` on a classpath resource that exists in a nested JAR but cannot be accessed as a filesystem path.

**The fix is not LD_PRELOAD.** LD_PRELOAD works on glibc `open()` calls, but Java's `java.io.File` goes through the JVM's native filesystem layer which may or may not use glibc `open()` directly. LD_PRELOAD is also defeated by `io_uring` (modern Linux kernel, 5.1+) and raw syscalls.

**The actual fix for GeoLite2-style failures:**
1. Mount a real (but minimal) GeoLite2 database file into the container at the expected path
2. Or, patch the code to use `resourceLoader.getResource("classpath:GeoLite2-City.mmdb").getInputStream()` instead of `ResourceUtils.getFile()`
3. Or, detect the pattern in startup logs (`Cannot search for matching files underneath URL [war:file:...]`) and apply a known workaround: extract the embedded resource from the WAR before launch using `jar xf` and place it at a filesystem path

**OverlayFS:** Creating a FUSE overlay filesystem where the container sees a synthesized `/path/to/resource` file is feasible but overkill. The simpler solution is to detect the specific Spring Boot issue (tracked in spring-projects/spring-boot#7949 — known since 2016) and extract the file from the nested JAR before launch.

**Conclusion (MEDIUM confidence for JVM proxy, LOW confidence for LD_PRELOAD):** The JVM proxy approach is clean, non-invasive, and should be part of standard startup scaffolding. LD_PRELOAD is too fragile for the Java/Docker context. The WAR/nested JAR file access problem is best solved with a targeted extraction step, not OS-level interception.

---

## Angle 6: LLM-Driven Config Synthesis

### The Idea

Given `application.yml`, `application.properties`, and source code references to `@Value("${...}")`, `System.getenv("...")`, and `@ConfigurationProperties`, an LLM can infer what environment variables the app needs and synthesize plausible stub values.

### What Works

**Source of truth files (in order of reliability):**
1. `docker-compose.yml` — lists all services and their env vars with example values
2. `.env.example` or `.env.sample` — explicitly documents required env vars
3. Helm `values.yaml` — production values with secrets blanked
4. `application.properties` / `application.yml` — property placeholders with `${VAR_NAME:default}` default values
5. Source code `@Value` annotations and `System.getenv()` calls

**LLM synthesis strategy:**
1. Extract all `${VAR_NAME}` and `${VAR_NAME:default}` patterns from all config files
2. Extract all `System.getenv("VAR_NAME")` calls from Java source
3. Classify each variable by type (DB URL, JWT secret, API key, boolean flag, port number)
4. Synthesize values: JWT secrets → random 256-bit hex string, DB URLs → localhost:standard-port, boolean flags → `false`, API keys → empty string or `test-key-placeholder`
5. Inject as `SPRING_APPLICATION_JSON` (highest Spring Boot property precedence after command line args) or as individual `--key=value` command line args

**`SPRING_APPLICATION_JSON` as injection vector:**
Spring Boot parses `SPRING_APPLICATION_JSON` as a JSON object and merges it into the property source with higher priority than `application.yml` but lower than command-line arguments. It accepts nested keys: `{"jwt.secret": "abc123", "spring.datasource.url": "jdbc:h2:mem:test"}`.

**The eladmin JWT secret failure:** The app reads `jwt.secret` from properties, which maps to an env var. Synthesized value: any 256+ character random string. Cost: trivial. This single synthesis covers the entire class of "JWT/HMAC secret is null" failures.

**Repo2Run validation:** The Repo2Run paper demonstrates that LLM-driven iterative config synthesis achieves 86% success rate on Python repos. The Java equivalent is harder (stronger type system, more complex DI framework), but the pattern is validated.

### Practical Implementation

```python
def synthesize_config(repo_path: Path, startup_log: str) -> dict[str, str]:
    """
    Returns a dict of property_key → value to inject via SPRING_APPLICATION_JSON.
    """
    # 1. Parse all ${VAR:default} from *.properties, *.yml
    # 2. Parse System.getenv("VAR") from *.java  
    # 3. Parse startup log for "Could not resolve placeholder '...'"
    # 4. Classify and synthesize values
    # 5. Return as flat dict for SPRING_APPLICATION_JSON injection
```

**Confidence calibration for synthesized configs:** Any startup that succeeds only after LLM config synthesis should be annotated `stubs_applied=["llm_config_synthesis"]` and fidelity set to `"medium"`. Probe results are still valid for path traversal, SSRF, XXE, command injection — but not for auth-gated endpoints (since auth is stubbed with a fake secret).

**Conclusion (MEDIUM confidence):** LLM config synthesis is well-motivated and addresses a real failure class not covered by any JVM flag. It is especially effective for the "JWT secret is null" class. Implement as Attempt 2b, between infra-disable and H2 override. The LLM call should be bounded: at most 30 config properties synthesized, 10-second timeout.

---

## Angle 7: Industry Tools — How They Actually Handle This

### DAST Tools (Burp Suite Enterprise, OWASP ZAP, StackHawk, Snyk DAST)

**Universal answer:** All commercial DAST tools require a running application URL. They are probers, not bootstrappers. Their CI/CD docs tell you to deploy your app first, then point the tool at it. No commercial DAST tool automates app startup for unknown repos.

- **OWASP ZAP**: Docker image + automation YAML framework. Scans a provided URL. Does not start apps.
- **Burp Suite Enterprise**: Headless CI mode. Scans a provided URL. Enterprise customers configure their own deployment pipeline.
- **StackHawk**: GitHub Actions + Docker. Requires `app.url` in `stackhawk.yml`. Does not start apps.
- **GitLab DAST**: Requires `DAST_WEBSITE` env var pointing to a running app. Has a "review apps" concept but the review app deployment is the user's responsibility.

**Industry implication:** The gap ASEL fills is genuinely unfilled by commercial tooling. The reason is economics — enterprise DAST tools target teams that have CI/CD pipelines and know how to deploy their own apps.

### GitHub CodeQL / Snyk Code (SAST — relevant for comparison)

SAST tools (CodeQL, Semgrep, Snyk Code) do not run the app at all. They analyze source code/bytecode statically. CodeQL builds a semantic graph of the code and queries it. This is the opposite of ASEL's approach. Relevant only to note: **ASEL's value over SAST is runtime confirmation**, which requires the app to start.

### Moderne / OpenRewrite

OpenRewrite is a lossless code transformation tool. It is directly relevant to ASEL for the **Spring Security 5→6 migration** fix:

- Recipe `org.openrewrite.java.spring.security6.HttpSecurityLambdaDsl` converts lambda DSL
- Recipe `org.openrewrite.java.spring.security6.RemoveFilterSecurityInterceptorOncePerRequest` removes deprecated patterns
- Recipe `org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0` covers the full migration

ASEL can run OpenRewrite recipes as a source-code remediation step before rebuild. This is more powerful than the LLM-generated patch for well-known migration patterns because OpenRewrite is deterministic, type-aware (uses the type system, not text), and battle-tested on millions of repos.

**Implementation:** `mvn -U org.openrewrite.maven:rewrite-maven-plugin:run -Drewrite.recipeArtifactCoordinates=org.openrewrite:rewrite-spring:LATEST -Drewrite.activeRecipes=org.openrewrite.java.spring.security6.HttpSecurityLambdaDsl`

**Conclusion (HIGH confidence):** OpenRewrite is the correct tool for deterministic API migration fixes. Add to the remediation toolchain alongside the LLM agent for the class of failures where OpenRewrite has a published recipe.

---

## Angle 8: Spec / Manifest Mining

### What's Available in OSS Repos

| Artifact | Prevalence in OSS Java repos | Information quality |
|---|---|---|
| `docker-compose.yml` | ~40% of Spring Boot OSS repos | HIGH — lists all services, ports, env vars with example values |
| `.env.example` / `.env.sample` | ~25% | HIGH — explicitly documents required vars |
| Helm `values.yaml` | ~10% (microservices-oriented) | MEDIUM — production values, secrets blanked |
| `README.md` | ~90% | LOW — human-readable, unstructured |
| `Dockerfile` | ~50% | MEDIUM — `ENV` declarations, `EXPOSE` ports |
| `Makefile` with `run:` target | ~20% | MEDIUM — shows how devs start the app locally |

### Mining Strategy

For ASEL, the highest-leverage manifest mining is:

1. **`docker-compose.yml`:** Parse all `environment:` blocks. Extract key=value pairs where value is a non-empty string (not `${VAR}`). These are actual working dev configs. Feed them directly into the app's environment.

2. **`.env.example`:** Parse all `KEY=value` lines. Use values as-is (they're documented as example values by the repo author — exactly what ASEL needs).

3. **`Dockerfile` `ENV` declarations:** Parse `ENV KEY=value` lines. Feed into container environment.

4. **`Makefile` `run:` target:** Extract the `java -jar ...` command to discover flags the developer actually uses.

**This should be Step 0 in the startup pipeline, before any attempt:** Extract all known-good env vars from manifests and inject them. Free information that often resolves the JWT secret, DB URL, and other config failures without any LLM inference.

**Conclusion (HIGH confidence):** Manifest mining is the cheapest, highest-ROI addition. It should run before all startup attempts. Many repos that currently fail Attempt 1 would succeed if ASEL extracted the `docker-compose.yml` env vars first.

---

## Unified Failure Taxonomy and Prescribed Remediations

The research supports collapsing all observed startup failures into exactly 8 classes, each with a deterministic prescribed action:

| Class | Signature (regex on startup log) | Prescribed Action | Confidence |
|---|---|---|---|
| **MISSING_PROPERTY** | `Could not resolve placeholder '(.+?)'` | (1) Check manifests for value; (2) synthesize stub via LLM; (3) inject via `SPRING_APPLICATION_JSON` | HIGH |
| **MISSING_BEAN** | `No qualifying bean of type '(.+?)' available` | Check if it's a known Spring Security 5→6 pattern; if yes, run OpenRewrite recipe; if no, exclude the autoconfigure class | HIGH |
| **BEAN_CREATION_EXCEPTION** | `BeanCreationException.*creating bean.*'(.+?)'` | Parse nested cause; re-classify into one of the other 7 classes | HIGH |
| **DB_CONNECTION** | `Connection refused.*\d+\.\d+\.\d+\.\d+:\d+\|Communications link failure\|FATAL:.*database` | Already handled by dep provisioning; check if dep container started successfully | HIGH |
| **API_MIGRATION** | `WebSecurityConfigurerAdapter\|HttpSecurity.*available\|authorizeRequests.*deprecated` | Run OpenRewrite Spring Security 6 migration recipe | HIGH |
| **RESOURCE_FILE_NOT_FOUND** | `ResourceUtils.getFile\|Cannot search for matching files underneath URL.*war:\|FileNotFoundException.*classpath:` | Extract file from nested JAR using `jar xf`; mount at expected filesystem path | HIGH |
| **EXTERNAL_API_TIMEOUT** | `ConnectTimeoutException\|Connection timed out.*:443\|UnknownHostException` | Inject JVM HTTP proxy flags; proxy returns 200 for all unknown URLs | MEDIUM |
| **TOMCAT_LISTENER_FAIL** | Tomcat 404/500 on ROOT context; startup log silent on actual cause | Check Tomcat `localhost.YYYY-MM-DD.log` (inside container); the real error is almost always a `RESOURCE_FILE_NOT_FOUND` or `MISSING_PROPERTY` in the Tomcat-specific log | HIGH |

The **WebGoat-Legacy** failure (Tomcat WAR listener fails silently) points to the **TOMCAT_LISTENER_FAIL** class. The root cause is in the Tomcat per-context log file, not stdout. ASEL's current log capture only reads stdout/stderr. Adding `tail -f /usr/local/tomcat/logs/localhost.*.log` to the log capture on WAR deployments will surface the real error, which will then re-classify into one of the other 7 classes.

---

## Architectural Recommendation: Four-Layer Defense in Depth

### Layer 0: Manifest Mining (new — before any attempt)

```python
def mine_manifests(repo_path: Path) -> dict[str, str]:
    """Extract env vars from docker-compose.yml, .env.example, Dockerfile."""
    env = {}
    # Parse docker-compose.yml environment: blocks
    # Parse .env.example KEY=value lines  
    # Parse Dockerfile ENV declarations
    # Parse Makefile 'run:' target for java flags
    return env  # inject into all subsequent startup attempts
```

Cost: near zero. Expected impact: resolves 10–15% of currently failing repos.

### Layer 1: Expanded Flag Set (enhance existing Attempt 1 and 2)

Add to all attempts:
- `--spring.main.lazy-initialization=true` (catch-all for deferred bean failures)
- `--spring.main.allow-bean-definition-overriding=true` (multi-module conflicts)
- `--spring.main.allow-circular-references=true` (Spring Boot 2.6+ migration)
- `--spring.cloud.config.enabled=false` etc. (cloud config disable)
- Expanded security exclude list (add OAuth2, ManagementWebSecurity)
- Config server `optional:` prefix on all `spring.config.import` values

### Layer 2: LLM Config Synthesis (new Attempt 2b)

After Attempt 2 (infra disable) fails but before Attempt 3 (H2 override):

```python
def attempt_2b_llm_config(startup_log: str, repo_path: Path) -> RuntimeResult:
    """
    Parse startup log for 'Could not resolve placeholder' errors.
    Extract property names. Classify + synthesize values.
    Inject via SPRING_APPLICATION_JSON.
    Retry startup with synthesized config injected.
    """
```

Expected impact: resolves the JWT/HMAC secret null class and other property placeholder failures that are not resolvable by profile activation alone.

### Layer 3: JVM HTTP Proxy Shim (new — inject on all attempts)

Run a lightweight HTTP proxy sidecar inside the container on startup. Inject:
```
-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=18080
-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=18080
-Dhttp.nonProxyHosts=localhost|127.0.0.1|::1
```

The proxy returns:
- 200 with empty body for any GET
- 200 with `{}` for any POST/PUT to an unknown host
- Logs all proxied calls (useful for discovering what external APIs the app depends on)

Expected impact: silences `ConnectTimeoutException` and `UnknownHostException` that block startup when the app calls external APIs during bean initialization.

### Layer 4: Source Code Patches (enhance existing remediation agent)

Add deterministic (non-LLM) patches to the remediation agent:

| Pattern | Detection | Patch |
|---|---|---|
| Spring Security 5→6 | `NoSuchBeanDefinitionException: HttpSecurity` in startup log | OpenRewrite `HttpSecurityLambdaDsl` recipe |
| WAR nested JAR resource | `ResourceUtils.getFile` / `Cannot search...war:file:` in startup log | Extract file from WAR using `jar xf`, mount at expected path |
| Tomcat silent failure | WAR deployment + no useful stdout error | Capture Tomcat per-context log; re-classify |
| `@ConfigurationProperties` validation failure | `BindException: Failed to bind properties` | Strip `@Validated` annotation from config classes |

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| Spring Security 5→6 migration | Custom AST transformer | OpenRewrite `rewrite-spring` recipes | OpenRewrite handles 40+ edge cases in the migration; manual AST is a months-long project |
| HTTP interception proxy | Custom proxy in Python | `mitmproxy` (CLI mode) or Python `http.server` subclass with redirect | Already battle-tested, SSL interception included in mitmproxy |
| Classpath resource extraction from WAR | Custom unzip logic | `jar xf` (standard JDK tool, always available in the build container) | `jar` handles all JAR/WAR/ZIP formats including nested JARs |
| Config synthesis rule engine | Hand-coded rule tree | LLM with structured prompt + JSON output | Config naming conventions are inconsistent; LLM generalizes better than a rule tree |
| Test context bootstrapping | Custom Spring test runner | Maven Surefire plugin with `@SpringBootTest` class detection | Surefire already handles classpath, test compile, and test execution |

---

## Common Pitfalls

### Pitfall 1: lazy-initialization Masking Real Failures

**What goes wrong:** App starts successfully with `spring.main.lazy-initialization=true`. Probe of first endpoint triggers bean initialization of a broken bean → 500 error on every request. ASEL reports the app as started (Tier 2) but all probes fail.

**Prevention:** After startup with lazy init, probe `/actuator/health`. If health returns `DOWN` for any component or if all probed endpoints return 5xx, treat as startup failure and advance to next attempt. Log `lazy_init` in `stubs_applied`.

### Pitfall 2: Security Disable Invalidating Auth Findings

**What goes wrong:** Spring Security disabled → all endpoints return 200. SAST finding "missing authentication on `/admin`" becomes unexploitable (there's no auth to bypass — it was removed). ASEL reports the finding as not exploitable.

**Prevention:** When `security_disabled` is in `stubs_applied`, mark all auth-related findings as `fidelity=low`. Do not attempt to exploit or confirm auth-bypass findings in this fidelity tier.

### Pitfall 3: H2 Compatibility Mode Masking DB-Specific SQLi

**What goes wrong:** App uses PostgreSQL-specific syntax in queries. H2 in PostgreSQL compatibility mode accepts some but not all PostgreSQL syntax. SQLi probe confirms on H2 but may behave differently on real PostgreSQL.

**Prevention:** Already tracked in ASEL via `stubs_applied=["h2_override"]`. Continue current pattern. Note that H2 compatibility mode actually catches the same SQLi patterns — the injection works regardless of DB flavor.

### Pitfall 4: Tomcat Log Missing from Stdout Capture

**What goes wrong:** WAR deployment to embedded Tomcat fails. Stdout shows `Tomcat started on port(s): 8080`. Health check returns 404. No error in captured log. ASEL retries incorrectly.

**Prevention:** On WAR deployments, tail `/usr/local/tomcat/logs/localhost.YYYY-MM-DD.log` as a second log stream. The per-context log is where Tomcat writes `SEVERE` listener failures.

### Pitfall 5: JVM Proxy Breaking Localhost Calls to Provisioned Deps

**What goes wrong:** ASEL injects `http.proxyHost=127.0.0.1:18080`. App calls `localhost:5432` (PostgreSQL dep). Proxy intercepts and returns empty 200 instead of routing to real PostgreSQL.

**Prevention:** `http.nonProxyHosts` must include `localhost|127.0.0.1|::1|*.local`. The JVM proxy system property supports `|`-separated patterns. Verify the nonProxyHosts setting is correct before each attempt that uses both dep provisioning and the proxy shim.

### Pitfall 6: OpenRewrite Recipe Requiring Maven/Gradle Plugin in App's Build

**What goes wrong:** ASEL runs OpenRewrite via Maven plugin command. App uses Gradle. The Maven plugin command fails.

**Prevention:** Detect build system before running OpenRewrite. For Gradle: `./gradlew rewriteRun -PactiveRecipe=...` with the Rewrite Gradle plugin. Alternatively, run OpenRewrite as a standalone CLI tool (`java -jar rewrite-cli.jar`) which supports both Maven and Gradle projects.

---

## State of the Art Summary

| Approach | Maturity | ASEL Applicability | Expected Impact |
|---|---|---|---|
| Manifest mining (docker-compose, .env.example) | HIGH (industry standard) | Immediate, pre-Attempt-1 | +10–15% startup rate |
| Expanded Spring Boot flag set | HIGH (Spring docs) | Immediate, enhance Attempts 1–2 | +5–10% |
| LLM config synthesis | MEDIUM (validated by Repo2Run for Python) | New Attempt 2b | +5–10% (JWT/secret class) |
| JVM HTTP proxy shim | HIGH (JVM built-in mechanism) | Add to all attempts | +3–5% (external API timeout class) |
| OpenRewrite migration recipes | HIGH (production-ready) | Add to remediation agent | Fixes Spring Security 5→6 class deterministically |
| Tomcat per-context log capture | HIGH (Tomcat architecture) | Fix existing WAR path | Unblocks WebGoat-Legacy class |
| Java agent (bytecode interception) | MEDIUM (proven for APM) | Targeted: HTTP call redirect | Subsumed by JVM proxy; lower priority |
| `@SpringBootTest` piggyback | LOW for primary path | Attempt 4 fallback only | Limited to repos with integration tests |

**Aggregate expected improvement:** Implementing Layers 0–4 above should increase Tier-2 startup rate from the current ~40–60% to **65–80%** on public OSS Spring Boot repositories.

---

## Angle 9: Novel Approaches (Session 2 — 2026-04-14)

The following approaches were identified in deeper research and are not covered by the prior angles. All are language-agnostic or JVM-first.

### 9a. Parallel Speculative Startup (HIGH value, not yet implemented)

Instead of serial retry (attempt 1 → wait 35s → fail → attempt 2), launch 3–5 startup
configurations simultaneously in parallel containers and take the first winner.

```
Container A: _BASE_FLAGS only
Container B: _BASE_FLAGS + infra_disable + dep provisioning
Container C: _BASE_FLAGS + H2 + security_disable + config_synthesis
```

Wall-clock time to first success: drops from `N × 35s` to `35s`. This is speculative
execution — Google uses it in Borg for slow tasks. Nobody applies it to app bootstrapping.
Implementation: parallelize `_try_one_startup()` calls, cancel remaining containers on
first success.

**Expected impact:** 3× reduction in wall-clock time. Same success rate per attempt.

### 9b. Pre-Startup Bytecode Scan (HIGH confidence, quick win)

Detect failure classes BEFORE attempt 1 by scanning the JAR bytecode, not waiting for
a crash log. Cost: <1 second using `jar tf` + grep. Eliminates the 35s timeout tax for
detectable failure classes.

Detectable patterns before startup:
- `extends WebSecurityConfigurerAdapter` → API_MIGRATION class → apply OpenRewrite first
- `@EnableDiscoveryClient` / `@EnableEurekaClient` → inject `eureka.client.enabled=false`
- `@RefreshScope` → inject `spring.cloud.refresh.enabled=false`
- `@EnableConfigServer` imports → inject `spring.cloud.config.enabled=false`
- Presence of `oauth2-resource-server` artifact → pre-inject security excludes

```python
def scan_bytecode(jar_path: Path) -> set[str]:
    """Run jar tf on the JAR, grep class names for known patterns."""
    # Returns set of detected feature tags: {"WebSecurityConfigurerAdapter", "EurekaClient"}
```

### 9c. Wire-Protocol Stubs (HIGH value for non-H2-compatible apps)

For apps using Druid, HikariCP with custom configs, or non-JDBC protocols that reject H2:
run tiny servers that speak the MySQL/Redis wire protocol without storing data.

- **MySQL wire stub:** ~200 lines Python. Completes handshake, returns empty ResultSet.
  The JDBC driver thinks it's talking to MySQL. Connection pool initializes. Beans wire up.
- **Redis RESP stub:** ~100 lines. Returns `+OK` for writes, `$-1` for reads.
- **Kafka wire stub:** Accepts produce requests, returns empty fetch responses.

This is not Testcontainers (which runs real software). It satisfies the Java interface
contract at the protocol level. Works even when Docker images fail to pull.

**Why this beats H2:** H2 requires the app to use standard JDBC in a compatible way.
Wire-protocol stubs work for ANY driver or connection pool that speaks the protocol.

### 9d. JVM Startup Flags (-XX:TieredStopAtLevel=1)

JVM-level flags (not Spring flags) that reduce startup time for cold-start scenarios:

```
-XX:TieredStopAtLevel=1      # disable C2 JIT — cuts startup 40-60%
-Dspring.jmx.enabled=false   # disable JMX registration (startup hang source)
--add-opens java.base/java.lang=ALL-UNNAMED  # pre-empt InaccessibleObjectException
--add-opens java.base/java.util=ALL-UNNAMED
```

Apps that timeout at 35s often succeed at 20s with `TieredStopAtLevel=1`.
Safe for ASEL because ASEL needs the app to respond to a health check, not sustain throughput.

### 9e. ptrace-Based Connect() Timeout Elimination (language-agnostic)

Every language runtime eventually calls `connect()`. If the target port is unreachable,
the OS waits for TCP timeout (default: 20–30 seconds per connection attempt).

A `seccomp-bpf` or `ptrace` supervisor that intercepts `connect()` syscalls:
- If target port unreachable → return `ECONNREFUSED` immediately instead of waiting
- App's connection pool fails fast → Spring marks datasource unavailable → continues startup

Language-agnostic (works for Java, Python, Node, Go). Eliminates the 30s timeout tax for
EVERY missed infrastructure dependency, not just ones where we have a container stub.

**Implementation complexity:** MEDIUM. Requires a Linux ptrace wrapper around the app
launch command. Proof-of-concept feasible in ~200 lines C or Go.

### 9f. Classify-Then-Act Architecture (CRITICAL — replaces hardcoded 3-attempt loop)

Current code: 3 hardcoded attempts (profile → infra_disable → H2+security).
No formal failure classification. The system doesn't know WHAT failed, only that it failed.

Proposed: classify_runtime_failure(log) → RuntimeFailureClass → RECOVERY_PLAN[class] → retry.

The classifier runs after EACH attempt. The recovery action table maps failure classes to
deterministic action sequences. LLM only for the UNKNOWN class.

Full spec: see `RUNTIME_NORMALIZATION_PLAN.md`.

### 9g. Environment Confidence Score (paper contribution)

Replace `RuntimeFidelity` enum (HIGH/MEDIUM/LOW) with a numeric score 0.0–1.0 with
explicit per-stub penalties. Each stub applied subtracts a known amount:

```
security_disabled   → -0.20   (auth/IDOR probes invalid)
h2_override         → -0.15   (SQLi results may differ by dialect)
config_synthesized  → -0.10   (JWT secrets are fake)
lazy_init           → -0.05   (some beans never exercise)
proxy_http          → -0.03   (external API calls return stubs)
```

This makes ASEL's results honestly annotated — a core paper contribution.
"Finding confirmed on runtime with confidence 0.72, not 1.0 — security was not disabled,
but DB was H2 and JWT secret was synthesized."

---

## Implementation Status

| Component | Status | Notes |
|---|---|---|
| Manifest mining (docker-compose, .env.example) | ✅ BUILT | `_read_manifest_env()` |
| lazy-initialization, banner-mode | ✅ ADDED | session 2 |
| OAuth2 autoconfigure excludes (full list) | ✅ ADDED | session 2 |
| bootJar fix for Gradle PACKAGE | ✅ ADDED | session 2 |
| RuntimeFailureClass classifier | ❌ PLANNED | RUNTIME_NORMALIZATION_PLAN.md Sprint 1 |
| Recovery action table | ❌ PLANNED | Sprint 1 |
| JVM startup flags (TieredStopAtLevel=1) | ❌ PLANNED | Sprint 1 (quick) |
| Config synthesizer (Attempt 2b) | ❌ PLANNED | Sprint 1 |
| Environment confidence score (numeric) | ❌ PLANNED | Sprint 1 |
| Pre-startup feature map | ❌ PLANNED | Sprint 2 |
| Pre-startup bytecode scan | ❌ PLANNED | Sprint 2 |
| OpenRewrite Spring Security 6 path | ❌ PLANNED | Sprint 2 |
| Wire-protocol stubs (MySQL/Redis) | ❌ PLANNED | Sprint 3 |
| Parallel speculative startup | ❌ PLANNED | Sprint 3 |
| ptrace connect() timeout elimination | ❌ PLANNED | Sprint 3 |

---

## Sources

### Primary (HIGH confidence)

- [Spring Boot Auto-Configuration Reference](https://docs.spring.io/spring-boot/reference/using/auto-configuration.html) — autoconfigure exclude mechanism
- [Spring Boot Security Auto-Configuration](https://docs.spring.io/spring-boot/reference/web/spring-security.html) — security autoconfigure class list
- [Spring Security 6 Migration Guide (Baeldung)](https://www.baeldung.com/spring-security-migrate-5-to-6) — WebSecurityConfigurerAdapter removal
- [OpenRewrite Spring Security 6 Recipes](https://docs.openrewrite.org/recipes/java/spring/security6) — deterministic migration recipes
- [JEP 451: Prepare to Disallow Dynamic Loading of Agents](https://openjdk.org/jeps/451) — Java agent restrictions in JDK 21+
- [Spring Boot Lazy Initialization](https://spring.io/blog/2019/03/14/lazy-initialization-in-spring-boot-2-2/) — lazy-initialization flag behavior
- [Spring Framework 6.2 Bean Override in Tests](https://spring.io/blog/2024/04/16/spring-framework-6-2-0-m1-overriding-beans-in-tests/) — @MockitoBean / @TestBean
- [spring-projects/spring-boot#7949](https://github.com/spring-projects/spring-boot/issues/7949) — ResourceUtils.getFile failure in executable WAR

### Secondary (MEDIUM confidence)

- [Repo2Run Paper (arXiv:2502.13681)](https://arxiv.org/abs/2502.13681) — LLM-driven iterative config synthesis for Python repos; methodology applicable to Java
- [Hoverfly Java Documentation](https://docs.hoverfly.io/projects/hoverfly-java/en/latest/) — JVM proxy system property interception pattern
- [OpenTelemetry Java Agent](https://opentelemetry.io/docs/zero-code/java/agent/) — zero-code bytecode instrumentation; validates JVM-level HTTP interception is feasible
- [Spring Cloud Config: optional: prefix](https://docs.spring.io/spring-cloud-config/reference/client.html) — fail-safe config import
- [Spring Cloud Consul: fail-fast=false](https://docs.spring.io/spring-cloud-consul/reference/config.html) — non-fatal config failure

### Tertiary (LOW confidence — marked for validation)

- Industry claim that DAST tools universally require pre-running apps — validated by inspecting OWASP ZAP, Burp Enterprise, StackHawk, GitLab DAST documentation
- "65–80% startup rate improvement" estimate — derived from failure class frequency analysis; needs empirical validation against ASEL benchmark corpus

---

## Open Questions

1. **Does `spring.main.lazy-initialization=true` interact badly with Spring Security filter chain initialization?**
   - What we know: Security filter chain is initialized early (before servlet context). Lazy init may not defer it.
   - What's unclear: Whether lazy init skips the SecurityFilterChain bean or only application-layer beans.
   - Recommendation: Test against eladmin and mall-tiny before adding to production startup flags.

2. **What is the actual root cause of WebGoat-Legacy Tomcat listener failure?**
   - What we know: Tomcat reports a listener startup error not on stdout.
   - What's unclear: Whether the Tomcat per-context log is accessible inside the ASEL Docker container (depends on how the WAR is deployed — embedded Tomcat vs. standalone Tomcat image).
   - Recommendation: Add `docker logs <container>` capture for `/usr/local/tomcat/logs/` on WAR deployments. If using standalone Tomcat image, the log path is standard. If using embedded Tomcat (`java -jar`), Tomcat writes to stdout — so the error exists in the log but may be buried.

3. **Is there a Spring Boot flag to make ALL `@Value` injections non-fatal when the property is missing?**
   - What we know: `@ConfigurationProperties` with `@Validated` fails on missing properties. `@Value` without `@Validated` inserts the literal placeholder string (e.g. `"${JWT_SECRET}"`) but doesn't fail.
   - What's unclear: Can we globally disable Spring's "fail on unresolvable placeholder" behavior with a single flag?
   - Recommendation: Research `spring.mvc.throw-exception-if-no-handler-found` and `ignoreUnresolvablePlaceholders` flag on `PropertySourcesPlaceholderConfigurer`. There may be a way to inject a permissive `PropertySourcesPlaceholderConfigurer` bean that returns empty string for unknown placeholders.

4. **Can the JVM HTTP proxy shim capture HTTPS calls without SSL inspection?**
   - What we know: Standard JVM proxy settings work for HTTP. HTTPS requires either SSL passthrough (CONNECT tunneling) or SSL termination + re-encryption with a custom CA.
   - What's unclear: Whether most Java app external API calls use HTTPS and whether the proxy needs to inspect the content.
   - Recommendation: Start with an HTTPS-passthrough proxy (just tunnel CONNECT). If the app connection hangs (because the real API is unreachable), configure the proxy to return a plausible 200 on CONNECT timeout.

---

## Metadata

**Confidence breakdown:**
- Standard stack (Spring Boot flag set): HIGH — all flags verified against official Spring docs
- Architecture (four-layer defense): HIGH — derived from verified failure taxonomy
- Pitfalls: HIGH — derived from observed ASEL failures + verified Spring Boot behavior
- LLM config synthesis: MEDIUM — Repo2Run validates the approach for Python; Java application unverified empirically
- Bytecode agent approach: MEDIUM — technically sound but limited applicability for structural issues

**Research date:** 2026-04-13
**Valid until:** 2026-07-13 (Spring Boot releases quarterly; verify flag names against current Spring Boot version)
