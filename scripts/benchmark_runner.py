#!/usr/bin/env python3
"""
Overnight benchmark runner for ASEL.

Runs ASEL sequentially on each benchmark repo, ingests results into the wiki,
and writes a session log. Safe to interrupt — completed repos are not re-run
unless --force is passed.

Usage:
    uv run scripts/benchmark_runner.py                        # run all tier-1 repos
    uv run scripts/benchmark_runner.py --tier 2               # tier-2 only
    uv run scripts/benchmark_runner.py --tier all             # all tiers
    uv run scripts/benchmark_runner.py --force                # re-run even if already done
    uv run scripts/benchmark_runner.py --dry-run              # print plan without running
    uv run scripts/benchmark_runner.py --max-findings 10 --max-runtime 90
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ASEL_ROOT = Path(__file__).parent.parent
RUNS_ROOT = ASEL_ROOT / "asel-runs"
WIKI_ROOT = ASEL_ROOT.parent / "asel-wiki"
INGEST_SCRIPT = ASEL_ROOT / "scripts" / "wiki_ingest.py"
CAPTURE_SCRIPT = ASEL_ROOT / "scripts" / "benchmark_capture.py"

# ---------------------------------------------------------------------------
# Benchmark repo registry
# ---------------------------------------------------------------------------
# Format: (url, build_tool, short_name, tier)
BENCHMARK_REPOS = [
    # Tier 1 — core benchmark
    ("https://github.com/OWASP-Benchmark/BenchmarkJava",    "maven",  "BenchmarkJava",               1),
    ("https://github.com/WebGoat/WebGoat",                  "gradle", "WebGoat",                     1),
    ("https://github.com/SasanLabs/VulnerableApp",          "gradle", "VulnerableApp",               1),
    ("https://github.com/OWASP/wrongsecrets",               "maven",  "wrongsecrets",                1),
    ("https://github.com/appsecco/dvja",                    "maven",  "dvja",                        1),
    # Tier 2 — supplemental
    ("https://github.com/DataDog/vulnerable-java-application", "gradle", "vulnerable-java-application", 2),
    # Tier 3 — Vul4J corpus (real OSS projects with known CVEs, for paper benchmarking)
    # Sourced from tuhh-softsec/vul4j — repos with multiple CVEs prioritised
    ("https://github.com/apache/struts",                       "maven",  "apache-struts",               3),
    ("https://github.com/apache/commons-compress",             "maven",  "commons-compress",            3),
    ("https://github.com/spring-projects/spring-framework",    "gradle", "spring-framework",            3),
    ("https://github.com/spring-projects/spring-security",     "gradle", "spring-security",             3),
    ("https://github.com/apache/camel",                        "maven",  "apache-camel",                3),
    ("https://github.com/FasterXML/jackson-dataformat-xml",    "maven",  "jackson-dataformat-xml",      3),
    ("https://github.com/apache/commons-fileupload",           "maven",  "commons-fileupload",          3),
    ("https://github.com/jhy/jsoup",                           "maven",  "jsoup",                       3),
    ("https://github.com/alibaba/fastjson",                    "maven",  "fastjson",                    3),
    ("https://github.com/apache/shiro",                        "maven",  "apache-shiro",                3),
    ("https://github.com/x-stream/xstream",                    "maven",  "xstream",                    3),
    ("https://github.com/ESAPI/esapi-java-legacy",             "maven",  "esapi-java-legacy",           3),
]


def _already_run(repo_url: str) -> str | None:
    """Return the most recent completed run_id for this repo URL, or None."""
    completed = {"timeout", "converged", "max_iterations", "stalled", "partial"}
    candidates = []
    for run_dir in RUNS_ROOT.iterdir():
        sf = run_dir / "run-state.json"
        if not sf.exists():
            continue
        try:
            state = json.loads(sf.read_text())
        except Exception:
            continue
        if state.get("repo_url") == repo_url and state.get("status") in completed:
            candidates.append((state.get("started_at", ""), run_dir.name))
    if candidates:
        return sorted(candidates)[-1][1]  # most recent
    return None


def _latest_run_id() -> str | None:
    """Return the run_id of the most recently modified run directory."""
    dirs = [d for d in RUNS_ROOT.iterdir() if (d / "run-state.json").exists()]
    if not dirs:
        return None
    return max(dirs, key=lambda d: d.stat().st_mtime).name


def _run_asel(repo_url: str, max_findings: int, max_runtime: int, model: str, provider: str) -> tuple[bool, str | None]:
    """Run asel and return (success, run_id)."""
    cmd = [
        "uv", "run", "asel", repo_url,
        "--max-findings-to-remediate", str(max_findings),
        "--max-runtime-minutes", str(max_runtime),
        "--model", model,
        "--provider", provider,
    ]
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=ASEL_ROOT)
    # Find the run_id by looking at what appeared in asel-runs/ since we started
    run_id = _latest_run_id()
    return result.returncode in (0, 1), run_id  # exit 1 = non-converged but completed


def _ingest(run_id: str) -> None:
    subprocess.run(["uv", "run", str(INGEST_SCRIPT), run_id], cwd=ASEL_ROOT)


def _capture() -> None:
    subprocess.run(["uv", "run", str(CAPTURE_SCRIPT)], cwd=ASEL_ROOT)


def _write_session_log(session: list[dict], log_path: Path) -> None:
    log_path.write_text(json.dumps(session, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="ASEL overnight benchmark runner")
    parser.add_argument("--tier", default="1", choices=["1", "2", "3", "all"], help="Which tier to run (default: 1)")
    parser.add_argument("--max-findings", type=int, default=10, help="Max findings to remediate per run")
    parser.add_argument("--max-runtime", type=int, default=90, help="Max runtime minutes per repo")
    parser.add_argument("--model", default="deepseek-chat", help="LLM model")
    parser.add_argument("--provider", default="deepseek", help="LLM provider")
    parser.add_argument("--force", action="store_true", help="Re-run repos that already have completed runs")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without running anything")
    args = parser.parse_args()

    # Filter repos by tier
    if args.tier == "all":
        repos = BENCHMARK_REPOS
    else:
        tier = int(args.tier)
        repos = [r for r in BENCHMARK_REPOS if r[3] == tier]

    session_start = datetime.now(timezone.utc)
    session_log: list[dict] = []
    log_path = RUNS_ROOT / f"benchmark-session-{session_start.strftime('%Y%m%d-%H%M%S')}.json"

    print(f"\nASEL Benchmark Runner — {session_start.strftime('%Y-%m-%d %H:%M')} UTC")
    print(f"Tier: {args.tier} | Repos: {len(repos)} | Max findings: {args.max_findings} | Max runtime: {args.max_runtime}m\n")

    for url, build_tool, name, tier in repos:
        print(f"{'='*60}")
        print(f"Repo: {name} ({build_tool}, tier {tier})")
        print(f"URL:  {url}")

        existing = _already_run(url)
        if existing and not args.force:
            print(f"  Already run: {existing} — skipping (use --force to re-run)")
            session_log.append({"repo": name, "url": url, "skipped": True, "existing_run": existing})
            continue

        if args.dry_run:
            print(f"  [dry-run] would run: uv run asel {url} --max-findings-to-remediate {args.max_findings} --max-runtime-minutes {args.max_runtime}")
            continue

        t_start = time.monotonic()
        print(f"  Starting at {datetime.now().strftime('%H:%M:%S')}...")

        ok, run_id = _run_asel(url, args.max_findings, args.max_runtime, args.model, args.provider)

        elapsed = round((time.monotonic() - t_start) / 60, 1)
        print(f"  Finished in {elapsed}m — run_id: {run_id}")

        if run_id:
            print(f"  Ingesting into wiki...")
            _ingest(run_id)

        session_log.append({
            "repo": name,
            "url": url,
            "tier": tier,
            "run_id": run_id,
            "elapsed_minutes": elapsed,
            "asel_exit_ok": ok,
            "skipped": False,
        })

        # Save session log after each repo so partial progress is preserved
        _write_session_log(session_log, log_path)
        print()

    print(f"{'='*60}")
    print(f"Session complete. Updating benchmark summaries...")
    _capture()

    total = sum(1 for e in session_log if not e.get("skipped"))
    skipped = sum(1 for e in session_log if e.get("skipped"))
    print(f"\nDone: {total} run(s), {skipped} skipped.")
    print(f"Session log: {log_path}")


if __name__ == "__main__":
    main()
