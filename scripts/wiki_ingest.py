#!/usr/bin/env python3
"""
Ingest an ASEL run into the asel-wiki Obsidian vault.

Usage:
    uv run scripts/wiki_ingest.py <run-id>
    uv run scripts/wiki_ingest.py <path/to/run-dir>
"""

import json
import sys
from pathlib import Path

ASEL_ROOT = Path(__file__).parent.parent
WIKI_ROOT = ASEL_ROOT.parent / "asel-wiki"
RUNS_ROOT = ASEL_ROOT / "asel-runs"


def repo_slug(url: str) -> str:
    parts = url.rstrip("/").split("/")
    return f"{parts[-2]}-{parts[-1]}".lower()


def severity_summary(counts: dict) -> str:
    parts = []
    for label, key in [("H", "high"), ("M", "medium"), ("I", "info")]:
        n = counts.get(key, 0)
        if n:
            parts.append(f"{n}{label}")
    return " ".join(parts) if parts else "0"


def _findings_by_id(state: dict) -> dict:
    """Build a map of finding_id → finding from the full findings list."""
    return {f["id"]: f for f in state.get("findings", [])}


def _rule_ids_for_ids(finding_ids: list, id_map: dict) -> list[str]:
    """Return unique rule_ids for a list of finding IDs."""
    seen, rules = set(), []
    for fid in finding_ids:
        f = id_map.get(fid)
        if f and f["rule_id"] not in seen:
            seen.add(f["rule_id"])
            rules.append(f["rule_id"])
    return rules


def write_run_page(state: dict, runs_dir: Path) -> None:
    run_id = state["run_id"]
    repo_url = state["repo_url"]
    slug = repo_slug(repo_url)
    date = state["started_at"][:10]
    status = state["status"].upper()

    build_attempts = state.get("build_attempts", [])
    build_succeeded = any(a["success"] for a in build_attempts)
    build_errors = [a for a in build_attempts if not a["success"]]
    n_attempts = len(build_attempts)

    final_counts = state.get("final_finding_count", {})
    findings = state.get("findings", [])
    iterations = state.get("iterations", [])
    id_map = _findings_by_id(state)

    rule_counts: dict[str, int] = {}
    for f in findings:
        rule_counts[f["rule_id"]] = rule_counts.get(f["rule_id"], 0) + 1

    scanner_counts: dict[str, int] = {}
    for f in findings:
        scanner_counts[f["scanner"]] = scanner_counts.get(f["scanner"], 0) + 1

    lines = [
        "---",
        f"run_id: {run_id}",
        f"repo: {repo_url}",
        f"date: {date}",
        f"status: {status}",
        f"build_attempts: {n_attempts}",
        f"build_succeeded: {'true' if build_succeeded else 'false'}",
        "---",
        "",
        f"# Run {run_id} — {slug}",
        "",
        f"- **Date**: {date}",
        f"- **Repo**: [{repo_url.split('/')[-1]}]({repo_url})",
        f"- **Status**: {status}",
        f"- **Build**: {n_attempts} attempt(s), {'succeeded' if build_succeeded else 'FAILED'}",
        "",
        "## Final Findings",
        "",
        f"- HIGH: {final_counts.get('high', 0)}",
        f"- MEDIUM: {final_counts.get('medium', 0)}",
        f"- INFO: {final_counts.get('info', 0)}",
    ]

    if scanner_counts:
        lines += ["", "## By Scanner", ""]
        for scanner, count in sorted(scanner_counts.items()):
            lines.append(f"- `{scanner}`: {count}")

    if rule_counts:
        lines += ["", "## Finding Breakdown", ""]
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- `{rule}`: {count}")

    if build_errors:
        lines += ["", "## Build Errors", ""]
        for a in build_errors:
            cat = a.get("error_category") or "unknown"
            lines.append(f"- Phase `{a['phase']}`: `{cat}`")

    patch_iters = [it for it in iterations if it.get("patch_attempt")]
    if patch_iters:
        lines += ["", "## Patch Attempts", ""]
        for it in patch_iters:
            pa = it["patch_attempt"]
            rules = _rule_ids_for_ids(pa.get("finding_ids", []), id_map)
            # Fall back: infer resolved rules from findings_before vs findings_after
            if not rules and pa.get("succeeded") and pa.get("findings_before") and pa.get("findings_after"):
                resolved = set(pa["findings_before"]) - set(pa["findings_after"])
                rules = _rule_ids_for_ids(list(resolved), id_map)
            rule_str = ", ".join(f"`{r}`" for r in rules) if rules else "unknown rule"
            outcome = "SUCCESS" if pa.get("succeeded") else "FAILED"
            delta = pa.get("delta", 0)
            lines.append(
                f"- Iteration {it['iteration']}: {outcome} | {rule_str} | delta={delta}"
            )

    lines += [
        "",
        "## Links",
        "",
        f"- [[repos/{slug}|{slug}]]",
        f"- Run artifacts: `asel-runs/{run_id}/`",
        "",
        "## Notes",
        "",
        "<!-- Add post-run observations here -->",
    ]

    (runs_dir / f"{run_id}.md").write_text("\n".join(lines))
    print(f"  Written: runs/{run_id}.md")


def write_or_update_repo_page(state: dict, repos_dir: Path) -> None:
    repo_url = state["repo_url"]
    slug = repo_slug(repo_url)
    run_id = state["run_id"]
    date = state["started_at"][:10]
    status = state["status"].upper()
    final_counts = state.get("final_finding_count", {})
    build_attempts = state.get("build_attempts", [])
    build_succeeded = any(a["success"] for a in build_attempts)

    repo_file = repos_dir / f"{slug}.md"
    run_entry = (
        f"\n### [{date}] run [[runs/{run_id}|{run_id}]]\n"
        f"- Status: **{status}** | Build: {'OK' if build_succeeded else 'FAILED'} "
        f"({len(build_attempts)} attempt(s)) | Findings: {severity_summary(final_counts)}\n"
    )

    if repo_file.exists():
        repo_file.write_text(repo_file.read_text() + run_entry)
    else:
        content = "\n".join([
            "---",
            f"repo: {repo_url}",
            f"slug: {slug}",
            "---",
            "",
            f"# {slug}",
            "",
            f"- **URL**: [{repo_url}]({repo_url})",
            f"- **First run**: {date}",
            "",
            "## Run History",
            run_entry,
            "## Notes",
            "",
            "<!-- Recurring patterns, things to investigate, repo-specific heuristics -->",
        ])
        repo_file.write_text(content)

    print(f"  Written: repos/{slug}.md")


def update_build_failures(state: dict, wiki_root: Path) -> None:
    """Append new build error categories to failures/build-failures.md."""
    failed = [a for a in state.get("build_attempts", []) if not a["success"]]
    if not failed:
        return

    run_id = state["run_id"]
    slug = repo_slug(state["repo_url"])
    bf_file = wiki_root / "failures" / "build-failures.md"
    existing = bf_file.read_text() if bf_file.exists() else ""

    added = False
    for a in failed:
        cat = a.get("error_category") or "unknown"
        entry = (
            f"\n<!-- auto: {run_id} -->\n"
            f"- `{cat}` in phase `{a['phase']}` — [[repos/{slug}]] run [[runs/{run_id}|{run_id}]]\n"
        )
        # Append only if this run hasn't been recorded for this category
        marker = f"<!-- auto: {run_id} -->"
        if marker not in existing:
            existing += entry
            added = True

    if added:
        bf_file.write_text(existing)
        print(f"  Updated: failures/build-failures.md")


def update_remediation_knowledge(state: dict, wiki_root: Path) -> None:
    """
    For each patch attempt in the run:
    - succeeded=True  → append to patterns/remediation-patterns.md
    - succeeded=False → append to failures/remediation-failures.md
    """
    run_id = state["run_id"]
    slug = repo_slug(state["repo_url"])
    id_map = _findings_by_id(state)

    patterns_file = wiki_root / "patterns" / "remediation-patterns.md"
    failures_file = wiki_root / "failures" / "remediation-failures.md"

    patterns_text = patterns_file.read_text() if patterns_file.exists() else ""
    failures_text = failures_file.read_text() if failures_file.exists() else ""

    marker = f"<!-- auto: {run_id} -->"
    if marker in patterns_text and marker in failures_text:
        print(f"  Skipped: remediation knowledge already recorded for {run_id}")
        return

    patterns_added = failures_added = False

    for it in state.get("iterations", []):
        pa = it.get("patch_attempt")
        if not pa:
            continue

        # Resolve rule_ids: prefer recorded finding_ids, fall back to diff
        rules = _rule_ids_for_ids(pa.get("finding_ids", []), id_map)
        if not rules and pa.get("succeeded") and pa.get("findings_before") and pa.get("findings_after"):
            resolved = set(pa["findings_before"]) - set(pa["findings_after"])
            rules = _rule_ids_for_ids(list(resolved), id_map)

        rule_str = ", ".join(f"`{r}`" for r in rules) if rules else "unknown rule"
        delta = pa.get("delta", 0)
        iter_num = it["iteration"]

        if pa.get("succeeded"):
            entry = (
                f"\n{marker}\n"
                f"## {rule_str}\n\n"
                f"- **Run**: [[runs/{run_id}|{run_id}]] | **Repo**: [[repos/{slug}]]\n"
                f"- **Iteration**: {iter_num} | **Delta**: {delta} findings reduced\n"
                f"- **Scanner**: {_scanner_for_rules(rules, id_map)}\n"
                f"- **Notes**: *(add what the patch did)*\n"
            )
            if marker not in patterns_text:
                patterns_text += entry
                patterns_added = True
        else:
            entry = (
                f"\n{marker}\n"
                f"## {rule_str}\n\n"
                f"- **Run**: [[runs/{run_id}|{run_id}]] | **Repo**: [[repos/{slug}]]\n"
                f"- **Iteration**: {iter_num} | **Delta**: {delta}\n"
                f"- **Scanner**: {_scanner_for_rules(rules, id_map)}\n"
                f"- **Why failed**: *(investigate — check llm-remediation-agent.md in run dir)*\n"
            )
            if marker not in failures_text:
                failures_text += entry
                failures_added = True

    if patterns_added:
        patterns_file.write_text(patterns_text)
        print(f"  Updated: patterns/remediation-patterns.md")
    if failures_added:
        failures_file.write_text(failures_text)
        print(f"  Updated: failures/remediation-failures.md")


def _scanner_for_rules(rules: list[str], id_map: dict) -> str:
    for f in id_map.values():
        if f.get("rule_id") in rules:
            return f.get("scanner", "unknown")
    return "unknown"


def append_log(state: dict, wiki_root: Path) -> None:
    slug = repo_slug(state["repo_url"])
    run_id = state["run_id"]
    date = state["started_at"][:10]
    status = state["status"].upper()
    final_counts = state.get("final_finding_count", {})
    build_attempts = state.get("build_attempts", [])
    build_succeeded = any(a["success"] for a in build_attempts)
    iterations = state.get("iterations", [])

    log_file = wiki_root / "log.md"
    if not log_file.exists():
        log_file.write_text(
            "# Run Log\n\nAppend-only chronological record of all ASEL runs.\n"
            "Format: `## [YYYY-MM-DD] operation | Title`\n\n"
        )

    entry = (
        f"## [{date}] run | {slug} ([[runs/{run_id}|{run_id}]])\n"
        f"- Status: **{status}** | Build: {'OK' if build_succeeded else 'FAILED'} "
        f"({len(build_attempts)} attempt(s))\n"
        f"- Findings: {severity_summary(final_counts)} | Iterations: {len(iterations)}\n\n"
    )

    log_file.write_text(log_file.read_text() + entry)
    print(f"  Appended: log.md")


def ingest(run_dir: Path) -> None:
    state_file = run_dir / "run-state.json"
    if not state_file.exists():
        print(f"ERROR: {state_file} not found")
        sys.exit(1)

    state = json.loads(state_file.read_text())

    (WIKI_ROOT / "runs").mkdir(exist_ok=True)
    (WIKI_ROOT / "repos").mkdir(exist_ok=True)

    write_run_page(state, WIKI_ROOT / "runs")
    write_or_update_repo_page(state, WIKI_ROOT / "repos")
    update_build_failures(state, WIKI_ROOT)
    update_remediation_knowledge(state, WIKI_ROOT)
    append_log(state, WIKI_ROOT)

    print(f"Done. Wiki: {WIKI_ROOT}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    arg = sys.argv[1]
    run_dir = Path(arg) if Path(arg).exists() else RUNS_ROOT / arg

    if not run_dir.exists():
        print(f"ERROR: run directory not found: {run_dir}")
        sys.exit(1)

    print(f"Ingesting {run_dir.name}...")
    ingest(run_dir)
