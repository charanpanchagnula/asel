# Autonomous Security Execution Lab (ASEL)

## 1. Vision

Build an autonomous, multi-turn security execution lab that:

1. Clones arbitrary repositories.
2. Attempts to build and run them in an isolated environment.
3. Executes multiple security scanners (SAST, SCA, Secrets, basic DAST).
4. Applies automated remediation attempts.
5. Rebuilds and re-validates until convergence or termination.

The system is NOT:

* A new SAST engine
* A new DAST scanner
* A replacement for vendor security tools
* An enterprise compliance platform (yet)

The system IS:

* An orchestration engine
* A runtime-aware remediation loop
* A security experimentation harness
* A self-healing validation sandbox

This project explores how far autonomous multi-turn agents can go in:

* Runtime stabilization
* Dependency upgrade validation
* Stacktrace-driven code repair
* Security remediation validation

---

# 2. Core Concept

Traditional security tools:

* Scan → Report → Human fixes → Re-run

ASEL:

* Scan → Agent proposes fix → Applies fix → Builds → Runs → Re-scans → Iterates

The key differentiator:

> Execution-aware remediation validation.

Not just "patch the code".
But:

* Patch
* Build
* Run
* Detect runtime breakage
* Repair breakage
* Validate security state

---

# 3. High-Level Architecture

## Components

1. **Repository Ingestor**

   * Git clone
   * Detect language/runtime (Java, Node, Python initially)

2. **Ephemeral Execution Environment**

   * Docker-based isolated container
   * Controlled network egress (not fully air-gapped)
   * Resource-limited

3. **Build Engine**

   * Maven / Gradle / npm / pip support (initially focus on Maven)
   * Captures logs + structured error output

4. **Runtime Engine**

   * Attempts application startup
   * Detects crash loops
   * Captures stacktraces

5. **Scanner Orchestrator**

   * Runs:

     * SAST (e.g., Semgrep)
     * SCA (e.g., Trivy)
     * Secrets scanner (e.g., Gitleaks)
   * Future: basic DAST if app is reachable

6. **Agentic Remediation Engine**

   * Analyzes findings
   * Applies minimal patches
   * Analyzes build/runtime errors
   * Attempts compatibility fixes

7. **Iteration Controller**

   * Controls loop depth
   * Prevents infinite cycles
   * Tracks improvement delta

---

# 4. Development Layer Model

Before expanding scope, each layer below should be characterized before treating the next as stable. The system currently operates at Layer 4, but Layers 1–3 are not yet fully characterized.

| Layer | Goal | Signal |
|---|---|---|
| **1 — Environment Normalization** | Can arbitrary projects be reliably built in a container? | % of projects that reach a clean compile with no agent involvement |
| **2 — Patch Generation Quality** | Are generated patches syntactically valid and minimal? | % of patches that apply cleanly and parse without errors |
| **3 — Compile-Only Validation** | Does the patch survive a rebuild? | Compile success rate after first patch attempt |
| **4 — Full Closed Loop** | Does the system converge with rollback and rescan? | Remediation success rate, rollback frequency, loops per vuln |

Skipping ahead to Layer 4 before Layer 1 is stable is a major source of token burn and noise. Characterize each layer before expanding the next.

---

# 5. Phase 1 – Minimal Viable Execution Lab (POC)

Goal:

> Prove that build + scan + autonomous rebuild loop is feasible.

### Scope

Focus on:

* Java (Maven) projects only
* Local machine execution
* Open-source scanners only
* No vendor integrations

### Phase 1 Capabilities

1. Clone repository
2. Spin up Docker container
3. Run `mvn clean install`
4. If build succeeds:

   * Run SAST
   * Run SCA
   * Run secrets scan
5. Apply simple automated SCA upgrade
6. Rebuild
7. If runtime failure occurs:

   * Capture stacktrace
   * Send to agent
   * Apply minimal patch
   * Rebuild once more

### Non-Goals (Phase 1)

* No enterprise compliance features
* No RBAC
* No vendor APIs (Checkmarx, etc.)
* No complex distributed services
* No Kubernetes
* No UI

Deliverable:

A CLI tool that:

```bash
asel run https://github.com/example/project
```

And produces:

* Build logs
* Scan results
* Patch attempts
* Final state summary

---

# 6. Phase 2 – Runtime Stabilization & Surface Expansion

Goal:

> Increase percentage of repos that can reach a runnable state.

### Additions

1. Basic dependency stubbing:

   * Inject dummy environment variables
   * Provide default DB containers (Postgres, Redis)
   * Support "local" Spring profile injection

2. Controlled service substitution:

   * Spin up mock services (WireMock-like behavior)

3. Runtime-based DAST (if service starts):

   * Launch lightweight scanner against localhost

4. Multi-iteration repair loop:

   * Upgrade dependency
   * Fix compile errors
   * Fix runtime bean/config failures

5. Scoring Model

   * Build success score
   * Runtime success score
   * Security delta score

Deliverable:

A system that can:

* Partially stabilize applications
* Increase scan surface area
* Demonstrate autonomous compatibility repair

---

# 7. Long-Term Vision (Beyond Phase 2)

Not for immediate implementation.

Potential directions:

* Vendor scanner integration via REST APIs
* Cloud-based ephemeral runners
* Pull request auto-generation
* Enterprise policy integration
* Risk scoring engine
* Security regression prevention

---

# 8. Differentiation Hypothesis

Existing tools:

* Detect vulnerabilities
* Suggest patches
* Sometimes auto-create PRs

Few tools:

* Attempt runtime stabilization after upgrades
* Iteratively repair compile/runtime breakage
* Expand scanning surface through execution recovery

ASEL explores:

> Autonomous security remediation validated by execution.

---

# 9. Constraints & Design Principles

1. Keep orchestration simple.
2. Prefer Docker over complex infra.
3. Favor iteration depth limits.
4. Avoid enterprise complexity early.
5. Accept partial success (30–40% build rate is acceptable).

---

# 10. Success Criteria (Phase 1)

The POC is successful if:

* It can build at least some real-world Maven repos.
* It can apply at least one dependency upgrade.
* It can detect resulting build/runtime failure.
* It can attempt at least one automated repair.

Even if imperfect.

### Target Metrics

To claim progressive improvement, track these across runs:

| Metric | Description |
|---|---|
| Build normalization rate | % of repos that reach a clean compile |
| Patch survival rate | % of first patch attempts that compile without repair |
| Rollback frequency | % of remediation iterations that end in rollback |
| Average loops per vuln | How many iterations before a finding is resolved or abandoned |
| Token cost per successful fix | Total LLM tokens consumed per resolved finding |

---

# 11. Strategic Optionality

If successful, this system can later be positioned as:

* Autonomous remediation engine
* Secure build validation harness
* Risk-aware CI augmentation layer
* Runtime-aware SCA validation engine

But initially:

It is a technical experiment.

---

# 12. Final Framing

This is not an enterprise product.
This is not a replacement for security tools.
This is an exploration of autonomous, execution-aware remediation loops.

Even partial success yields deep insight into:

* Agent reliability
* Build system recovery
* Security automation boundaries

Failure is acceptable.
Iteration is the goal.
