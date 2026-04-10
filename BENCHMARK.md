# JVM ASEL Benchmark Plan

## Purpose

This document defines an initial benchmark plan for evaluating ASEL (Autonomous Security Execution Lab) on public, intentionally vulnerable JVM projects.

The goal is not to create a perfect benchmark immediately. The goal is to create a **repeatable, curated starting set** for running ASEL against Maven and Gradle projects, capturing build/remediation behavior, and iterating systematically.

---

## Benchmark Strategy

### Goals

1. Start with **public, intentionally vulnerable JVM repositories**
2. Cover both **Maven** and **Gradle**
3. Include projects that are:
   - deliberately vulnerable
   - security-focused
   - useful for SAST/SCA experimentation
   - representative enough to stress build/remediation loops
4. Use this benchmark to:
   - validate build normalization
   - evaluate patch survival
   - measure scanner revalidation success
   - identify failure taxonomies
   - improve ASEL iteratively

---

## Scope (Initial)

### Ecosystem
- JVM only
- Java only
- Maven and Gradle only

### Scanners
- Semgrep
- Trivy

### Validation
- Build / compile validation first
- Runtime validation later
- No full DAST requirement in the first benchmark phase

---

## Curated Repository Set

### Tier 1: Core Benchmark Targets

#### 1. OWASP Benchmark / BenchmarkJava
- **Build system:** Maven
- **Why include it:** Closest thing to a formal benchmark backbone for Java security evaluation
- **Usefulness:** Large CWE-oriented vulnerable test suite; useful for structured SAST/DAST/IAST-style evaluation
- **ASEL role:** Primary benchmark anchor for repeatable remediation experiments

#### 2. OWASP WebGoat
- **Build system:** Gradle
- **Why include it:** Deliberately insecure Java web application with realistic app behavior
- **Usefulness:** More realistic than synthetic micro-benchmarks; good for Gradle support and broader security case coverage
- **ASEL role:** Realistic vulnerable app target

#### 3. OWASP VulnerableApp
- **Build system:** Gradle
- **Why include it:** Purpose-built vulnerable app for evaluating security tooling
- **Usefulness:** Strong fit for scanner + remediation validation
- **ASEL role:** Gradle-first vulnerable tool-evaluation target

#### 4. OWASP WrongSecrets
- **Build system:** Maven
- **Why include it:** Broadens benchmark beyond classic code vulns into secrets/security misconfiguration territory
- **Usefulness:** Good for Trivy/secrets-style coverage and remediation thought process
- **ASEL role:** Secret/security anti-pattern testbed

#### 5. DVJA (Damn Vulnerable Java Application)
- **Build system:** Maven
- **Why include it:** Deliberately vulnerable Java app with classic web/security issues
- **Usefulness:** Older, messier, and useful for handling noisy real-world-ish failures
- **ASEL role:** Legacy-style vulnerable app stress case

---

### Tier 2: Supplemental Targets

#### 6. DataDog vulnerable-java-application
- **Build system:** Gradle
- **Why include it:** More modern vulnerable Java app target
- **Usefulness:** Good for Gradle workflow and contemporary app patterns
- **ASEL role:** Supplemental modern Gradle case

#### 7. Snyk java-woof
- **Build system:** Maven/demo style target
- **Why include it:** Vendor-created intentionally vulnerable app
- **Usefulness:** Useful as an additional practical target after core set is stable
- **ASEL role:** Supplemental external benchmark case

---

## Benchmark Tiers

### Tier 1
Use for frequent overnight and iterative runs:
- BenchmarkJava
- WebGoat
- VulnerableApp
- WrongSecrets
- DVJA

### Tier 2
Use after Tier 1 becomes stable:
- DataDog vulnerable-java-application
- Snyk java-woof

---

## Execution Plan

### Batch Strategy
Run in batches of 5–10 repos overnight.

Do not try to process the entire corpus every time.

### Run Mode
For each repo:
1. Clone repo
2. Detect build system
3. Detect / infer Java version
4. Build in isolated container
5. Run Semgrep + Trivy
6. Select top-N findings
7. Attempt controlled remediation
8. Rebuild after each mutation
9. Re-scan / revalidate
10. Log all outcomes

---

## Success Criteria (Early Phase)

The benchmark is useful if it allows ASEL to measure:

- build normalization success
- number of vulnerabilities attempted
- build survival after patch
- rollback frequency
- scanner delta after patch
- cost/time per remediation attempt

This phase does **not** require:
- perfect runtime startup
- complete OWASP Top 10 mapping
- exhaustive benchmark completeness

---

## Logging Requirements

For each run, store at minimum:

- repo name
- repo URL
- commit SHA
- build tool
- Java version used
- scanner outputs
- findings considered
- findings attempted
- patch diffs
- build log
- remediation-agent log
- build-agent log
- build success / failure
- rollback count
- elapsed time
- token cost estimate
- engine version

---

## Suggested Run Summary Schema

```json
{
  "run_id": "2026-04-06-webgoat-001",
  "engine_version": "0.4.0",
  "repo": "WebGoat",
  "repo_url": "https://github.com/...",
  "commit_sha": "abc123",
  "build_tool": "gradle",
  "java_version": "17",
  "scanner_set": ["semgrep", "trivy"],
  "findings_total": 35,
  "findings_selected": 10,
  "findings_attempted": 6,
  "patches_applied": 4,
  "build_success": true,
  "rollback_count": 2,
  "scan_status": "partial_pass",
  "iterations": 7,
  "elapsed_minutes": 48,
  "token_cost_usd": 1.87,
  "failure_category": null
}