# ASEL Phase 2 — Design Document

## Goal

After a successful build, detect if the repo is a runnable web service, start it
in Docker, discover its HTTP surface, probe it to confirm SAST findings are
genuinely exploitable, then confirm patches actually eliminate the exploit surface.
Not just "scanner found X" — "here is the HTTP request that exploits X, and here
is proof the patch stopped it."

## Architecture

```
Phase 1 (done):  Clone → Build → Scan → Agent patches → Rebuild → Rescan
Phase 2:         ... → RuntimeEngine → SurfaceDiscovery → ExploitEngine → ProbeReport
```

Phase 2 runs after a successful build, before the remediation loop. The runtime
result and surface map are stored in `RunState` and inform which findings to
prioritise for exploit confirmation.

---

## Phase 2a — Runtime Engine  (`asel/runtime.py`) ✅ BUILT

### What it does

Starts the compiled JVM application inside Docker and confirms it is responding
to HTTP. Uses the same image as the build container (Java already installed) and
mounts the same repo volume so the compiled JAR is immediately available.

### Service detection

Priority order:
1. `docker-compose.yml` — most authoritative (TODO)
2. `Dockerfile` — EXPOSE port, ENTRYPOINT (TODO)
3. Framework heuristics — build file keywords + source annotations (BUILT)

Framework registry (heuristic path):
- **Spring Boot** — `spring-boot` in build file OR `@SpringBootApplication` in source
- **Quarkus** — `io.quarkus` in build file
- **Micronaut** — `io.micronaut` in build file

### JAR discovery

- Maven: largest `*.jar` in `target/` excluding `-sources`, `-tests`, `-original`, `-javadoc`
- Gradle: largest `*.jar` in `build/libs/` excluding `-plain`, `-sources`, `-javadoc`
- Largest-by-size heuristic reliably identifies fat JARs vs thin/helper JARs

### Startup strategy — three attempts

```
Attempt 1 — test/local profile
  java -jar app.jar --spring.profiles.active=test,local
  Many apps self-configure for local runs. Cheapest win.

Attempt 2 — disable optional infrastructure + provision provisionable deps
  Parse startup log for known failure signatures.
  Disable: Eureka, Config Server, Vault, Consul, Zookeeper, Liquibase, Flyway, Kafka listeners
  Provision: postgres, mysql, redis, mongodb
  Dep containers share the runtime container's network namespace so the app
  sees them at localhost:<standard-port> with no config changes needed.

Attempt 3 — H2 override + Spring Security disabled
  Replace datasource with H2 in compatibility mode (PostgreSQL/MySQL/DB2/Oracle/MSSQLServer)
  Disable Spring Security autoconfiguration entirely — all endpoints become public
  Last resort before giving up.
```

### Execution environment normalization — design philosophy

The key insight driving Phase 2 architecture: **standardize the failure-class response, not the full app semantics.**

Most runtime startup failures collapse into a small set of repeatable classes. Each class has a reusable primitive answer:

| Failure class | Primitive | Implementation |
|---|---|---|
| Missing infrastructure dep (DB, cache, broker) | Dep provisioning container | `deps-registry.yaml` + network_mode sharing |
| External HTTP API dependency | API virtualization (WireMock-style) | Planned — Phase 2 next gap |
| Service registry / discovery agent | JVM flag disable | `_INFRA_OVERRIDES` in registry |
| Cloud SDK (AWS/GCP/Azure) | Cloud-compatible emulator | LocalStack in registry |
| Auth/OIDC dependency | Auth mock or security disable | Keycloak in registry + security exclude flag |
| DB migration blocking startup | Migration flag disable | `--spring.liquibase.enabled=false` etc. |
| Security auth blocking local run | Security autoconfigure exclude | `_SECURITY_DISABLE_FLAGS` |
| DB not compatible with local override | H2 in compatibility mode | `_H2_BASE_FLAGS` with dialect detection |
| App expects prod-ish config | Profile overlay | `--spring.profiles.active=test,local` |
| Missing seed state (schema, fixtures) | H2 create-drop + migration disable | Attempt 3 strategy |

**What cannot be standardized:**
- Apps requiring domain-specific seed data to function beyond schema
- Proprietary internal services (GS internal APIs, proprietary message buses)
- Kerberos KDC without access to a real realm
- CyberArk / Thycotic (no emulators exist)
- GraalVM native images (binary, not JVM — fundamentally different execution model)
- Mandatory OAuth handshake flows beyond what Keycloak can stub

**Runtime normalization tiers** (target: reach Tier 2 on 50–60% of repos):
```
Tier 0  build succeeds
Tier 1  process starts, port binds
Tier 2  health/readiness endpoint responds, logs show stable startup
Tier 3  core endpoint path works, dependency wiring alive
Tier 4  enough surface for meaningful runtime scanning
```

Fidelity degrades as we stub more. High fidelity = no stubs. Medium = security disabled or
H2 override. Tracked per run in `RuntimeResult.stubs_applied`.

### Dep provisioning

Network namespace sharing pattern:
```python
docker.containers.run(
    "postgres:16-alpine",
    network_mode=f"container:{runtime_container.id}",
    ...
)
```
The dep container shares the runtime container's network stack. From inside the
app, `localhost:<standard-port>` reaches the dep with no config override needed.

All dep service definitions are externalized to `asel/deps-registry.yaml`.
Inspired by the Testcontainers module catalog — same coverage goals, implemented
as Docker containers managed directly by ASEL (no Java/Python Testcontainers lib
needed; we run Python and manage Docker containers ourselves).

**Set `ASEL_IMAGE_REGISTRY=gs-docker.example.com/` to prefix all images for
enterprise mirror use. No code change needed.**

### Dependency coverage (all implemented in deps-registry.yaml)

**Relational databases:**
| Service | Image | Testcontainers module equivalent |
|---|---|---|
| MySQL | `mysql:8-debian` | `org.testcontainers:mysql` |
| MariaDB | `mariadb:11` | `org.testcontainers:mariadb` |
| PostgreSQL | `postgres:16-alpine` | `org.testcontainers:postgresql` |
| SQL Server | `mcr.microsoft.com/mssql/server:2022-latest` | `org.testcontainers:mssqlserver` |
| Oracle XE | `gvenzl/oracle-xe:21-slim` | `org.testcontainers:oracle-xe` |

**Caches / key-value:**
| Service | Image | Notes |
|---|---|---|
| Redis | `redis:7-alpine` | Jedis, Lettuce, Redisson |
| Memcached | `memcached:1.6-alpine` | Spymemcached, XMemcached |

**Document stores:**
| Service | Image | Notes |
|---|---|---|
| MongoDB | `mongo:7` | Spring Data MongoDB |
| Elasticsearch | `elasticsearch:8.13.0` | security disabled, single-node |
| Cassandra | `cassandra:4` | Spring Data Cassandra |
| Neo4j | `neo4j:5` | Spring Data Neo4j |

**Message brokers:**
| Service | Image | Notes |
|---|---|---|
| Kafka | `confluentinc/cp-kafka:7.6.0` | Also covered by infra override (listener.auto-startup=false) |
| RabbitMQ | `rabbitmq:3.13-management-alpine` | Spring AMQP |
| ActiveMQ Artemis | `apache/activemq-artemis:latest` | |

**Cloud SDK stubs:**
| Service | Image | Coverage | Redirect mechanism |
|---|---|---|---|
| LocalStack (AWS) | `localstack/localstack:3` | S3, SQS, SNS, DynamoDB, SecretsManager, SSM — ~50 AWS services | Spring Cloud AWS properties |
| Azurite (Azure Storage) | `mcr.microsoft.com/azure-storage/azurite` | Blob, Queue, Table | `app_flags` → Spring Cloud Azure endpoint properties |
| Azure Cosmos DB | `mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator` | Cosmos DB (heavy image, ~60s start) | `app_flags` → endpoint + key |
| Azure Service Bus | `mcr.microsoft.com/azure-messaging/servicebus-emulator` | Service Bus (2024 release) | `app_flags` → connection string |
| GCP Pub/Sub | `gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators` | Pub/Sub | `app_flags` → Spring Cloud GCP emulator-host |
| GCP Spanner | `gcr.io/cloud-spanner-emulator/emulator` | Spanner (official Google image) | `app_flags` → Spring Cloud GCP emulator enabled |
| GCP Firestore | `gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators` | Firestore | `app_flags` → Spring Cloud GCP host-port |
| GCP BigQuery | `ghcr.io/goccy/bigquery-emulator:latest` | BigQuery (community) | `app_flags` → dataset name |
| GCP Cloud Storage | `fsouza/fake-gcs-server` | GCS (community) | `app_flags` → storage host |

**OCI — not yet covered:**
No LocalStack-equivalent exists for OCI. Partial workarounds:
- OCI Streaming → reuse `kafka` entry (Kafka-compatible protocol)
- OCI Autonomous DB → reuse `oracle` entry (Oracle XE)
- OCI Object Storage, Queue, Functions → no emulators; record as NOT_STARTABLE for affected endpoints

**`app_flags` mechanism:**
DB/broker deps share the runtime container's network namespace, so `localhost:<standard-port>` just works with no config override. Cloud SDK emulators need the app to be told where the emulator is. `app_flags` in `_DepSpec` holds the Spring property flags that get injected into the app's JVM command when the dep is provisioned. Applied in all three startup attempts.

For apps using raw GCP/Azure SDKs without Spring Cloud (env vars like `PUBSUB_EMULATOR_HOST` needed, not Spring properties): a future `app_env` mechanism is required.

**Auth / identity:**
| Service | Image | Notes |
|---|---|---|
| Keycloak | `quay.io/keycloak/keycloak:24.0` | OAuth2 / OIDC; Spring Security OAuth2 |

**Infra overrides (JVM flag stubs — no container needed):**
- Eureka / Spring Cloud Discovery
- Spring Cloud Config Server
- HashiCorp Vault
- Consul
- ZooKeeper
- JHipster JWT secret
- JavaMailSender (localhost SMTP stub)
- Liquibase
- Flyway
- Kafka listener auto-startup

### Fidelity tracking

Every `RuntimeResult` records what was applied:
- `stubs_applied` — list of what was disabled/overridden (e.g. `["h2_override", "security_disabled"]`)
- `deps_provisioned` — list of dep containers started (e.g. `["postgres", "redis"]`)
- `startup_strategy` — which attempt succeeded (`"profile"` | `"infra_disable"` | `"h2_override"`)

Used in Phase 2c to annotate probe results with fidelity level. A path traversal
confirmed on a fully-stubbed app is still valid. A SQLi on H2 is flagged as
lower-confidence.

---

## Phase 2b — Surface Discovery  (`asel/surface.py`) ✅ BUILT

### What it does

Discovers every HTTP endpoint the running app exposes and resolves each one back
to its source file and line number in the repo. This is the bridge between SAST
findings (file + line) and the exploit engine (HTTP route + parameter).

### Discovery strategies

**Strategy 1 — Spring Actuator** (`/actuator/mappings`)

Spring's internal route registry. Returns every handler with:
- HTTP method(s)
- URL pattern(s)
- Handler class + method name (fully qualified)
- Consumes / produces content types

From handler class → source file resolution:
```
com.example.UserController → src/main/java/com/example/UserController.java
```
Tries Java, Kotlin, Groovy. Handles inner class suffixes (`Outer$Inner`).

From source file + method name → line number resolution:
Scans for the method definition line via regex.

From source file + line → parameter extraction:
Reads the method signature for `@PathVariable`, `@RequestParam`, `@RequestBody`,
`@RequestHeader` annotations.

**Strategy 2 — OpenAPI** (`/v3/api-docs`, `/v2/api-docs`, `/api-docs`)

Handles both OpenAPI 3.x (Springdoc) and 2.x (Swagger). Has full parameter
metadata including types and required flags. Handler class extracted from
`operationId` (Springdoc generates `ClassName_methodName` format).

**Strategy 3 — None**

Returns empty result. Pipeline continues with SAST findings only.

### Output

`SurfaceDiscoveryResult` stored in `RunState.surface`:
```python
endpoints: list[HttpEndpoint]   # all discovered routes
discovery_source: str           # "actuator" | "openapi" | "none"
mapped_to_source: int           # routes with source_file resolved
```

Each `HttpEndpoint`:
```python
method: str                     # GET, POST, PUT, DELETE, PATCH
path: str                       # /api/users/{id}
handler_class: str              # com.example.UserController
handler_method: str             # getUser
source_file: str                # src/main/java/com/example/UserController.java
source_line: int                # 45
parameters: list[EndpointParameter]
consumes: list[str]
produces: list[str]
discovery_source: str           # "actuator" | "openapi"
```

---

## Phase 2c — Exploit Engine  (PLANNED)

### Vision

An agentic pentester that uses SAST findings as high-confidence leads and
goes beyond them. Not just "scanner found X" — "here is the HTTP request chain
that exploits X, and here is what the attacker gains."

### What it is NOT

Not a DAST scanner confirming a finding list. That is limited to what the scanner
already found. Phase 2c finds what scanners miss and chains what they find.

### Real pentester loop

```
1. Recon       — understand attack surface (from SurfaceDiscovery)
2. Lead-driven — use SAST findings as first targets (high confidence)
3. Probe       — craft HTTP requests, observe responses
4. Chain       — use one finding to enable another
5. Escalate    — push each finding as far as it goes
6. Report      — full PoC chain with evidence
```

### Tools the agent has

| Tool | Purpose |
|---|---|
| `http_request(method, url, headers, body)` | Core probe primitive |
| `callback_listener()` | Local HTTP server for SSRF confirmation |
| `run_sqlmap(url, param)` | Deep SQLi exploitation |
| `run_nuclei(url, templates)` | CVE-specific template matching (Trivy findings) |
| `read_source(file, line)` | Read the vulnerable code for context |
| `read_finding(id)` | SAST finding detail |

### Route → finding linkage

The exploit engine links `SurfaceDiscovery` endpoints to `ScanFinding` objects by
matching `source_file` and `source_line`. A finding at `UserController.java:45`
maps to the endpoint whose `source_file == "...UserController.java"` and
`source_line` is near 45. This is the core of what makes Phase 2 more than
just DAST — we know exactly which code path to hit.

### Probe types

| Finding type | Payload | Confirmation signal | Fidelity risk if stubbed |
|---|---|---|---|
| SQLi | `' OR '1'='1--`, sleep-based | SQL error or response time | H2 may differ from prod DB |
| Path traversal | `../../../etc/passwd` | File contents in response | None — filesystem is real |
| SSRF | URL to callback listener | Callback received | None |
| XXE | DOCTYPE with SYSTEM entity | File contents in response | None |
| Command injection | `; sleep 5`, `\| whoami` | Response time / output | None |
| Open redirect | `?next=https://evil.com` | Location header | None if auth disabled |
| SSTI | `{{7*7}}`, `${7*7}` | `49` in response | None |

### Chaining example

```
SSRF confirmed on POST /api/payment/process
  → probe http://169.254.169.254/latest/meta-data/
  → AWS instance metadata returned
  → extract IAM credentials from iam/security-credentials/
  → attempt S3 ListBuckets with extracted credentials
  → report: SSRF → metadata → credential theft → S3 access
```

### ProbeResult model

```python
class ProbeResult(BaseModel):
    finding_id: str           # links to ScanFinding
    endpoint: HttpEndpoint    # what was probed
    probe_type: str           # "sqli" | "ssrf" | "path_traversal" | ...
    request: dict             # method, url, headers, body
    response_code: int
    response_snippet: str     # first 500 chars of response
    exploitable: bool
    evidence: str             # what in the response proves exploitability
    chain: list[str]          # subsequent steps taken after initial confirmation
    fidelity: str             # "high" | "medium" | "low"
    fidelity_notes: str       # what was stubbed that might affect this result
    confirmed_fixed: bool     # after patch: was the exploit path eliminated
```

---

## Phase 2d — Exploit Report  (PLANNED)

Full PoC report per confirmed finding:
- The HTTP request(s) that trigger the vulnerability
- The response proving exploitability
- The full chain if one was discovered
- Before/after patch comparison
- Fidelity annotation

Output format: Markdown report in `run-dir/exploit-report.md` alongside existing
`run-state.json`.

---

## Pipeline position

```
Clone (1)
  ↓
Language detection (2)
  ↓
Container start (3)
  ↓
Build stabilization (4)
  ↓
RuntimeEngine.start()      ← Phase 2a
  ↓
SurfaceDiscovery.discover() ← Phase 2b
  ↓
Scanner Orchestrator (6)
  ↓
ExploitEngine.probe()      ← Phase 2c (planned)
  ↓
Remediation loop (7)
  ↓
ExploitEngine.confirm()    ← Phase 2c post-patch (planned)
  ↓
Report
```

---

## Goldman Sachs context

The GS AI team wants the full pipeline: build → exploit confirm → patch → PR.
Phase 2 runtime engine is the key missing piece. Specific GS considerations:

- **DB2** — covered by H2 DB2 compatibility mode; full DB2 community image planned
- **Internal SSO** — Spring Security autoconfigure exclude is the fallback
- **Internal services** — cannot emulate; record as `NOT_STARTABLE` component,
  continue probing endpoints that don't require those services
- **No docker-compose** — direct JAR startup is the primary strategy
- **Target repos** — internal Spring Boot services, likely on AWS or on-prem

Expected runtime start rate on GS repos with current implementation: ~40-60%.
Each dep provisioning expansion (RabbitMQ, Kafka, auth mock) adds ~5-10%.

---

## Implementation status

| Component | Status | Tests |
|---|---|---|
| RuntimeEngine — detection | ✅ Done | ✅ |
| RuntimeEngine — JAR finding | ✅ Done | ✅ |
| RuntimeEngine — startup + retry | ✅ Done | ✅ (mocked Docker) |
| RuntimeEngine — dep provisioning (all services in registry) | ✅ Done | ✅ (mocked Docker) |
| RuntimeEngine — WAR deploy (Tomcat/Jetty, javax/jakarta) | ✅ Done | ✅ |
| RuntimeEngine — JDK17 CGLIB opens flags | ✅ Done | ✅ |
| RuntimeEngine — Druid MySQL redirect | ✅ Done | ✅ |
| RuntimeEngine — deps-registry.yaml externalization | ✅ Done | — |
| RuntimeEngine — ASEL_IMAGE_REGISTRY prefix support | ✅ Done | — |
| RuntimeEngine — docker-compose path | ✅ Detection done | — |
| RuntimeEngine — Dockerfile parsing | ❌ Planned | — |
| RuntimeEngine — API virtualization (WireMock-style) | ❌ Planned — next gap | — |
| RuntimeEngine — cloud SDK detection from build file | ❌ Planned | — |
| SurfaceDiscovery — actuator | ✅ Done | ✅ |
| SurfaceDiscovery — OpenAPI | ✅ Done | ✅ |
| SurfaceDiscovery — source resolution | ✅ Done | ✅ |
| SurfaceDiscovery — parameter extraction | ✅ Done | ✅ |
| ExploitEngine | ❌ Planned | — |
| ProbeResult model | ❌ Planned | — |
| Exploit report | ❌ Planned | — |
