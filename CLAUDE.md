# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ASEL (Autonomous Security Execution Lab) is a Python-based CLI tool that autonomously clones repositories, builds them in Docker containers, runs security scanners, applies automated remediations, and iterates until convergence. It is an **orchestration engine**, not a new scanner.

Core loop: Clone → Build → Scan → Agent proposes fix → Apply fix → Rebuild → Re-scan → Iterate

## Phase 1 Scope (POC)

- **Target only Java/Maven projects** — no Node, Python, Go yet
- **Local execution only** — no cloud runners, no Kubernetes
- **Open-source scanners only** — Semgrep (SAST), Trivy (SCA), Gitleaks (secrets)
- **No UI, no RBAC, no vendor API integrations**

The CLI entry point:
```bash
asel run https://github.com/example/project
```

Outputs: build logs, scan results, patch attempts, final state summary.

## Architecture

Seven components (in pipeline order):

1. **Repository Ingestor** — git clone + language/runtime detection
2. **Ephemeral Execution Environment** — Docker container, resource-limited, controlled egress
3. **Build Engine** — Maven execution, captures structured logs and errors
4. **Runtime Engine** — app startup attempt, crash loop detection, stacktrace capture
5. **Scanner Orchestrator** — runs Semgrep, Trivy, Gitleaks in sequence (DAST deferred to Phase 2)
6. **Agentic Remediation Engine** — analyzes findings, applies minimal patches, fixes build/runtime errors
7. **Iteration Controller** — enforces loop depth limits, prevents infinite cycles, tracks improvement delta

## Design Principles

- Keep orchestration simple; prefer Docker over complex infra
- Always enforce iteration depth limits (no unbounded repair loops)
- Accept partial success — a 30–40% build success rate is a valid POC outcome
- Avoid enterprise complexity early (no compliance features, no distributed services)
- Minimal patches only — the remediation engine should make the smallest viable change

## Python Stack

The `.gitignore` is Python-standard. Use `uv` or `pip` for dependency management. Ruff is expected for linting (`.ruff_cache/` is gitignored).

When implementing, structure code around the 7 components above as distinct modules. The Iteration Controller is the top-level orchestrator that calls the others.
