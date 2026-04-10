#!/usr/bin/env python3
"""
Generate benchmark-summary.json for all completed runs and update the wiki benchmark table.

Extracts what the current run-state.json contains. Fields not yet stored in the pipeline
(commit_sha, engine_version, token_cost_usd) are marked as null.

Usage:
    uv run scripts/benchmark_capture.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ASEL_ROOT = Path(__file__).parent.parent
RUNS_ROOT = ASEL_ROOT / "asel-runs"
WIKI_ROOT = ASEL_ROOT.parent / "asel-wiki"

# Known build tools for repos we've already run (before language was stored in RunState)
_KNOWN_BUILD_TOOLS: dict[str, str] = {
    "WebGoat": "gradle",
    "OWASP-Java": "maven",
    "spring-petclinic": "maven",
    "wrongsecrets": "maven",
    "securityshepherd": "maven",
    "VulnerableApp": "gradle",
}


def _infer_build_tool(repo_url: str, build_attempts: list) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name in _KNOWN_BUILD_TOOLS:
        return _KNOWN_BUILD_TOOLS[name]
    # Infer from build output
    for a in build_attempts:
        out = a.get("output", "")
        if "mvn" in out or "maven" in out.lower():
            return "maven"
        if "gradle" in out.lower() or "gradlew" in out:
            return "gradle"
    return "unknown"


def _elapsed_minutes(started: str, completed: str | None) -> float | None:
    if not completed:
        return None
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in started else "%Y-%m-%dT%H:%M:%S%z"
    try:
        s = datetime.fromisoformat(started.replace("Z", "+00:00"))
        c = datetime.fromisoformat(completed.replace("Z", "+00:00"))
        return round((c - s).total_seconds() / 60, 1)
    except Exception:
        return None


def _dominant_failure(build_attempts: list) -> str | None:
    cats = [a.get("error_category") for a in build_attempts if not a.get("success") and a.get("error_category")]
    if not cats:
        return None
    return max(set(cats), key=cats.count)


def summarize_run(run_dir: Path) -> dict:
    state = json.loads((run_dir / "run-state.json").read_text())

    build_attempts = state.get("build_attempts", [])
    iterations = state.get("iterations", [])
    findings = state.get("findings", [])
    final_counts = state.get("final_finding_count", {})

    patches = [it["patch_attempt"] for it in iterations if it.get("patch_attempt")]
    patches_succeeded = sum(1 for pa in patches if pa.get("succeeded"))
    patches_attempted = len(patches)

    # Rollbacks: failed patches that didn't succeed (build broke or net-negative)
    rollback_count = sum(1 for pa in patches if not pa.get("succeeded"))

    initial_findings = len(iterations[0]["findings"]) if iterations else len(findings)
    final_findings = sum(final_counts.values()) if final_counts else len(findings)
    scan_delta = initial_findings - final_findings

    build_tool = state.get("language") or _infer_build_tool(state["repo_url"], build_attempts)
    if build_tool and "gradle" in build_tool:
        build_tool = "gradle"
    elif build_tool and "maven" in build_tool:
        build_tool = "maven"

    return {
        "run_id": state["run_id"],
        "repo": state["repo_url"].rstrip("/").split("/")[-1],
        "repo_url": state["repo_url"],
        "date": state["started_at"][:10],
        "status": state["status"],
        "build_tool": build_tool,
        "build_attempts": len(build_attempts),
        "build_succeeded": any(a["success"] for a in build_attempts),
        "findings_total": initial_findings,
        "patches_attempted": patches_attempted,
        "patches_succeeded": patches_succeeded,
        "rollback_count": rollback_count,
        "scan_delta": scan_delta,
        "fix_rate_pct": round(scan_delta / initial_findings * 100, 1) if initial_findings else 0,
        "final_findings": final_findings,
        "elapsed_minutes": _elapsed_minutes(state.get("started_at", ""), state.get("completed_at")),
        "dominant_failure_category": _dominant_failure(build_attempts),
        # Not yet tracked in pipeline — will be populated in future runs
        "commit_sha": None,
        "engine_version": None,
        "token_cost_usd": None,
    }


def write_summary(run_dir: Path, summary: dict) -> None:
    out = run_dir / "benchmark-summary.json"
    out.write_text(json.dumps(summary, indent=2))


def update_wiki_benchmark_table(summaries: list[dict]) -> None:
    """Append a results table to project/benchmark.md under a ## Results section."""
    benchmark_file = WIKI_ROOT / "project" / "benchmark.md"
    if not benchmark_file.exists():
        print("  WARNING: project/benchmark.md not found in wiki, skipping table update")
        return

    content = benchmark_file.read_text()

    # Replace or append the results section
    results_header = "\n---\n\n## Run Results\n\n"
    results_table = (
        "| Run ID | Repo | Date | Status | Build | Findings | Patches | Succeeded | Delta | Fix% | Time |\n"
        "|--------|------|------|--------|-------|----------|---------|-----------|-------|------|------|\n"
    )
    for s in sorted(summaries, key=lambda x: x["date"]):
        run_link = f"[[runs/{s['run_id']}\\|{s['run_id'][:8]}]]"
        repo_link = f"[[repos/{s['repo_url'].rstrip('/').split('/')[-2].lower()}-{s['repo'].lower()}\\|{s['repo']}]]"
        elapsed = f"{s['elapsed_minutes']}m" if s['elapsed_minutes'] else "?"
        fix_pct = f"{s.get('fix_rate_pct', 0):.1f}%"
        results_table += (
            f"| {run_link} | {repo_link} | {s['date']} | {s['status']} | {s['build_tool']} "
            f"| {s['findings_total']} | {s['patches_attempted']} | {s['patches_succeeded']} "
            f"| {s['scan_delta']:+d} | {fix_pct} | {elapsed} |\n"
        )

    # Remove existing results section if present, then append fresh
    if "## Run Results" in content:
        content = content[:content.index("\n---\n\n## Run Results")]

    benchmark_file.write_text(content + results_header + results_table)
    print(f"  Updated: project/benchmark.md (Run Results table)")


def main() -> None:
    completed_statuses = {"timeout", "converged", "max_iterations", "stalled", "partial"}
    summaries = []

    for run_dir in sorted(RUNS_ROOT.iterdir()):
        state_file = run_dir / "run-state.json"
        if not state_file.exists():
            continue

        state = json.loads(state_file.read_text())
        if state.get("status") not in completed_statuses:
            print(f"  Skipping {run_dir.name}: status={state.get('status')}")
            continue

        print(f"Capturing {run_dir.name} ({state['repo_url'].split('/')[-1]})...")
        summary = summarize_run(run_dir)
        write_summary(run_dir, summary)
        summaries.append(summary)
        print(f"  Written: {run_dir.name}/benchmark-summary.json")

    if summaries:
        update_wiki_benchmark_table(summaries)
        print(f"\nCaptured {len(summaries)} run(s).")
    else:
        print("No completed runs found.")


if __name__ == "__main__":
    main()
