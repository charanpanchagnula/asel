# ASEL Phase 1 Design — Autonomous Security Execution Lab

**Date:** 2026-04-03  
**Scope:** Phase 1 POC — Java/Maven, local execution, open-source scanners  
**Status:** Approved

---

## 1. What ASEL Is

ASEL is an execution-aware security remediation system. Its differentiator from every existing tool — including source-only SAST/SCA pipelines — is that it **builds the project first**, validates patches by rebuilding, and re-runs scanners after every patch to confirm findings are genuinely fixed and no regressions introduced.

The user already operates a source-only multi-turn agentic remediation loop. ASEL is its execution-aware extension, not a replacement. The two are complementary.

**The ASEL contract:**

> ASEL either builds your project and scans it, or it tells you why it couldn't build it. There are no partial scan results on unbuildable projects.

---

## 2. Phase 1 Constraints

- Java/Maven projects only
- Local execution only (no cloud runners, no Kubernetes)
- Open-source scanners only (Semgrep, Trivy, Gitleaks)
- No UI, no RBAC, no vendor API integrations
- Build is a hard gate — scans only run after a successful build

The 95% build/runtime success rate is the long-term north star. Phase 1 realistically targets ~40%. Every build failure pattern the `BuildAgent` learns to fix directly expands scan coverage.

---

## 3. CLI

Built with **Typer**. Project managed with **uv** + `pyproject.toml`.

```bash
asel run <repo-url> [OPTIONS]

Options:
  --max-build-attempts     INT   Max build stabilization attempts [default: 5]
  --max-remediation-iters  INT   Hard ceiling on remediation iterations [default: 10]
  --stall-threshold        INT   Stop after N zero-delta iterations [default: 2]
  --max-runtime-minutes    INT   Wall clock limit for entire run [default: 60]
  --scanners               LIST  Scanners to enable [default: semgrep,trivy,gitleaks]
  --output-dir             PATH  Where to write run artifacts [default: ./asel-runs]
  --model                  STR   LLM model identifier [default: deepseek-chat]
  --provider               STR   LLM provider [default: deepseek]
```

**The CLI has no business logic.** It parses args, constructs `RunConfig`, calls `PipelineOrchestrator.run()`, and exits. This keeps the path clear for a future FastAPI server entry point that does the exact same thing via HTTP.

---

## 4. Architecture

### 4.1 Component Map

```
CLI (Typer)
     │
     ▼
RunConfig (Pydantic)
     │
     ▼
PipelineOrchestrator          ← Python, owns the pipeline
     │
     ├── RepoIngestor          ← git clone + language/runtime detection
     ├── ExecutionEnvironment  ← docker-py, thin abstraction over container lifecycle
     ├── BuildEngine           ← MavenBuildEngine (first implementation)
     ├── ScannerOrchestrator   ← routes findings to registered scanners
     │     ├── SemgrepScanner
     │     ├── TrivyScanner
     │     └── GitleaksScanner
     ├── IterationController   ← Python, loop control + convergence logic
     └── RemediationEngine     ← Agno agents (BuildAgent + RemediationAgent)
```

### 4.2 Docker Strategy

The only host dependency is Docker. All tools run as containers:

| What | Docker image |
|---|---|
| Build target repo | `maven:3.9-eclipse-temurin-17` |
| SAST | `returntoembed/semgrep` |
| SCA + container | `aquasec/trivy` |
| Secrets | `zricethezav/gitleaks` |

ASEL never installs scanner binaries on the host. Every scanner runs by mounting the cloned repo as a volume, executing, and capturing JSON output. Adding a new scanner is dropping a new image reference into a new `BaseScanner` implementation — no host changes.

`ExecutionEnvironment` is a docker-py backed abstraction with a clean interface (`start`, `exec`, `stop`, `get_logs`). Phase 2 can swap in a Compose-backed implementation for multi-container setups (app + DB stubs) without touching the orchestration layer.

### 4.3 Scanner Plug-in Contract

```python
class BaseScanner(ABC):
    name: ScannerType
    requires_build: bool  # always True in Phase 1 (build is a hard gate)

    @abstractmethod
    def run(
        self,
        repo_path: Path,
        container: ExecutionEnvironment,
    ) -> list[ScanFinding]: ...
```

Adding any future scanner (Checkov, Grype, Bandit, Trivy container mode) means implementing `BaseScanner` and registering the `ScannerType` enum value. Nothing else changes.

---

## 5. Pipeline Flow

```
asel run <url>
     │
     ▼
1. INGEST
   └── clone repo, detect language/runtime
       if language != Java/Maven → run terminates immediately with UNSUPPORTED_LANGUAGE
       initialize RunState

     │
     ▼
2. ENVIRONMENT
   └── pull maven:3.9 image, spin up container, mount repo volume

     │
     ▼
3. BUILD STABILIZATION LOOP  ← hard gate
   progressive sequence (first 3 attempts):
   ├── attempt 1: mvn dependency:resolve       (isolate dep issues)
   ├── attempt 2: mvn compile -DskipTests      (does source compile?)
   ├── attempt 3: mvn clean install            (full build)
   subsequent attempts (4..max_build_attempts):
   ├── always: mvn clean install
   │   (progressive sequence complete, BuildAgent now has full error context)
   │
   on each failure at any attempt:
   └── BuildAgent analyzes error → categorizes → patches → retry
   │
   ├── SUCCESS (any attempt) → proceed to scanning
   └── MAX ATTEMPTS HIT → run terminates, build error report only

     │ (success only)
     ▼
4. SCAN
   └── ScannerOrchestrator runs all enabled scanners
       each scanner: mount repo → run container → parse JSON → ScanFinding[]
       baseline findings recorded in RunState (iteration 0)

     │
     ▼
5. REMEDIATION LOOP  (max N iterations)
   ├── RemediationAgent receives: current findings + affected file contents
   ├── Agent proposes patch: fix highest-severity finding(s) per iteration;
   │   may batch multiple findings in the same file; one logical change per patch
   ├── Patch applied to repo files (unified diff recorded)
   ├── REBUILD → if build fails: patch rejected (rollback), attempt logged
   ├── RE-SCAN → all scanners re-run
   ├── VALIDATE DELTA:
   │     targeted finding gone? ✓
   │     new findings introduced? → patch rejected if net-negative
   │     net delta recorded in IterationSnapshot
   └── DECIDE:
         CONTINUE   → findings remain, delta positive, iterate
         CONVERGE   → no actionable findings remain
         STALL      → delta zero for 2 consecutive iterations
         MAX_ITERS  → limit hit, report current state

     │
     ▼
6. OUTPUT
   └── finalize RunState → write to disk → print summary
```

---

## 6. Agentic Design

### 6.1 Principle

**Python controls the loop. Agno agents do the cognitive work.**

The `IterationController` is deterministic Python — loop counting, convergence detection, patch accept/reject, delta calculation. It is auditable and testable without LLMs. Agents are invoked for tasks that require language understanding: reading error output and writing fixes.

### 6.2 Two Agents (Phase 1)

**BuildAgent**
- Invoked when a build attempt fails
- Context: build logs (last 100 lines), current `pom.xml`, project structure, previous attempt summaries
- Goal: converge to a successful build through its own inner verification loop
- Knows nothing about: scan findings

Tools:

| Tool | Purpose |
|---|---|
| `read_file(path)` | Read `pom.xml`, Maven settings, any config file |
| `edit_file(path, old, new)` | Apply targeted edits to `pom.xml` or config files |
| `list_directory(path)` | Explore multi-module project structure |
| `run_maven(args)` | Run Maven inside the container — e.g. `dependency:resolve`, `compile -DskipTests`, `clean install` — captures stdout/stderr |
| `get_dependency_versions(group_id, artifact_id)` | Query available versions from Maven Central (avoids guessing version strings) |

`run_maven` is the critical tool. Without it the BuildAgent edits blindly and waits for the controller to validate — slow and wasteful. With it, the agent can edit `pom.xml` → run `mvn dependency:resolve` → read the output → edit again, all within a single agent invocation. The controller only sees the final result.

**RemediationAgent**
- Invoked each remediation iteration
- Context: current findings (filtered to actionable severity), contents of affected files only
- Goal: fix the highest-impact finding(s) without breaking the build
- Knows nothing about: build internals, previous iteration diffs (unless stalling)

Tools:

| Tool | Purpose |
|---|---|
| `read_file(path)` | Read source files referenced in findings |
| `edit_file(path, old, new)` | Apply patch to source files |
| `list_directory(path)` | Explore surrounding code for context (e.g. how a dep is used before upgrading) |
| `run_maven_compile()` | Quick compile check — scoped to `mvn compile -DskipTests` only |
| `search_cve(cve_id)` | Look up CVE details for richer remediation context (stubbed in Phase 1) |

The `RemediationAgent` does not own rebuild + rescan validation — that stays in the Python `IterationController`. `run_maven_compile()` is an optional sanity check the agent can call before handing back to the controller for the full rebuild + rescan cycle.

### 6.3 Tool Execution Model

All `run_*` tools dispatch commands **inside the Docker container** via the `ExecutionEnvironment`, never directly on the host. Container isolation means agent-driven command execution carries no host-level risk.

```
BuildAgent
    └── run_maven("dependency:resolve")
            │
            ▼
        ExecutionEnvironment.run_in_container(["mvn", "dependency:resolve"])
            │
            ▼
        Docker container → stdout/stderr → returned to agent
```

The agent sees exactly the same output a developer would see running Maven locally — no translation layer. Commands are passed as argument lists (not shell strings) to prevent injection.

### 6.4 Iteration Termination Logic

The `IterationController` uses four signals evaluated in priority order after each remediation iteration:

```
effective_max = min(max_remediation_iterations, max(3, finding_count // min_findings_per_iteration))

after each iteration:
  if delta < min_delta_to_continue → stall_count += 1
  else                             → stall_count = 0

  CONVERGE      if no actionable findings remain
  STALL         if stall_count >= stall_threshold   (exit early, stop burning budget)
  TIMEOUT       if elapsed_minutes >= max_runtime_minutes
  MAX_ITERATIONS if iteration >= effective_max
  CONTINUE      otherwise
```

**Why dynamic scaling matters:** a repo with 30 findings needs more iterations than one with 3. Static limits either waste budget on simple repos or give up too early on complex ones. The effective max scales with the problem size while the hard ceiling prevents runaway runs.

**Why stall detection matters:** the agent may genuinely be unable to fix remaining findings (e.g. a complex SAST pattern it doesn't understand). Stall detection exits cleanly rather than burning all remaining iterations producing zero-delta patches.

### 6.5 Context Discipline

Each agent invocation receives a **distilled, task-specific context** — never the full `RunState`. The `IterationController` is responsible for this filtering. Dumping full context degrades patch quality as iterations accumulate.

### 6.6 Build Failure Categories (BuildAgent)

| Category | Fix strategy |
|---|---|
| `DEPENDENCY_CONFLICT` | Update version in `pom.xml`, re-resolve |
| `MISSING_DEPENDENCY` | Add/correct dependency declaration |
| `JAVA_VERSION_MISMATCH` | Switch JDK image or update `maven.compiler.*` |
| `MISSING_PROPERTY` | Inject default property values |
| `PLUGIN_INCOMPATIBILITY` | Update plugin version |
| `TEST_FAILURE` | Retry with `-DskipTests` as last resort |

### 6.7 Phase 2 Extension

```
RemediationAgent  →  RemediationTeam
                        ├── SastAgent
                        ├── ScaAgent
                        └── SecretsAgent
```

Agno's team primitives make this a natural extension. The `IterationController` interface does not change.

---

## 7. Data Models

All models are Pydantic. Serialized to JSON on disk. Schema is the source of truth — not raw dicts.

```python
class RunConfig(BaseModel):
    repo_url: str
    enabled_scanners: list[ScannerType]
    output_dir: Path
    language: Language = Language.AUTO_DETECT
    llm_model: str = "deepseek-chat"
    llm_provider: str = "deepseek"

    # Build stabilization
    max_build_attempts: int = 5

    # Remediation loop — termination is multi-signal, not just a counter
    max_remediation_iterations: int = 10  # hard ceiling, never exceeded
    min_findings_per_iteration: int = 3   # dynamic scale: effective_max = max(3, findings // this)
    stall_threshold: int = 2              # stop after N consecutive iterations with insufficient delta
    min_delta_to_continue: int = 1        # delta must reduce findings by at least this to not count as stall

    # Safety net
    max_runtime_minutes: int = 60         # wall clock limit for the entire run

class BuildResult(BaseModel):
    success: bool
    phase: BuildPhase           # DEPENDENCY_RESOLVE | COMPILE | FULL_BUILD
    stdout: str
    stderr: str
    duration_seconds: float
    error_category: ErrorCategory | None

class ScanFinding(BaseModel):
    id: str                     # stable hash of scanner+rule+file+line
    scanner: ScannerType
    severity: Severity          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    rule_id: str
    file_path: str
    line_number: int | None
    title: str
    description: str
    raw: dict                   # original scanner JSON, preserved verbatim

class PatchAttempt(BaseModel):
    iteration: int
    target: PatchTarget         # BUILD_STABILIZATION | FINDING_REMEDIATION
    finding_ids: list[str]
    files_modified: list[str]
    diff: str
    build_result_after: BuildResult | None
    findings_before: list[str]
    findings_after: list[str]
    delta: int                  # negative = net improvement
    introduced_new_findings: bool
    succeeded: bool

class IterationSnapshot(BaseModel):
    iteration: int
    findings: list[ScanFinding]
    build_result: BuildResult
    patch_attempt: PatchAttempt | None

class RunState(BaseModel):
    run_id: str
    repo_url: str
    started_at: datetime
    completed_at: datetime | None
    build_track: BuildTrack     # FULL only in Phase 1
    build_attempts: list[BuildResult]
    iterations: list[IterationSnapshot]
    findings: list[ScanFinding] # current (latest iteration) findings
    final_finding_count: dict[Severity, int]
    status: RunStatus           # RUNNING | CONVERGED | STALLED | MAX_ITERATIONS | BUILD_FAILED | TIMEOUT
```

---

## 8. Run Output Structure

```
<output-dir>/<run-id>/
├── run-state.json          # full RunState, updated after every iteration
├── build-logs/
│   ├── attempt-1.txt
│   └── attempt-2.txt
├── scan-results/
│   ├── iteration-0/        # baseline (pre-remediation)
│   │   ├── semgrep.json
│   │   ├── trivy.json
│   │   └── gitleaks.json
│   └── iteration-1/
│       └── ...
├── patches/
│   ├── attempt-1.diff
│   └── attempt-2.diff
└── summary.txt             # human-readable final summary
```

`run-state.json` is written after every iteration — a mid-run crash preserves the full audit trail up to that point.

---

## 9. Technology Stack

| Concern | Choice |
|---|---|
| Language | Python |
| Package manager | uv |
| CLI framework | Typer |
| Data models | Pydantic |
| Container management | docker-py |
| Agent framework | Agno |
| LLM (default) | DeepSeek (`deepseek-chat`), provider-agnostic via Agno — OpenAI and Anthropic available via `--provider` flag |
| Scanners | Semgrep, Trivy, Gitleaks (Docker images) |

---

## 10. What Phase 1 Does Not Include

- Runtime execution (app startup, DAST) — Phase 2
- Multi-language support (Python, Node, Go) — Phase 2+
- Multi-container stubs (Postgres, Redis, mocks) — Phase 2
- UI, server mode, REST API — future
- Vendor scanner integrations — future
- Pull request generation — future
- Per-scanner-type specialist agents — Phase 2

---

## 11. Success Criteria

Phase 1 is successful if:
- It builds at least some real-world Maven repos (~40% target)
- It runs all three scanners against the built artifact
- It applies at least one dependency upgrade (Trivy SCA finding)
- It detects when a patch breaks the build and rejects it
- It detects when a patch introduces a new finding and rejects it
- It produces a clean audit trail (run-state.json + diffs) for every run
