# asel/pipeline.py
import logging
import re
import signal
import subprocess
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from .agents import create_build_agent, create_remediation_agent
from .build import MavenBuildEngine, create_engine
from .environment import ExecutionEnvironment
from .ingestor import clone_repo, detect_language, select_image
from .llm_trace import append_turn, init_log
from .models import (
    BuildPhase, BuildResult, IterationSnapshot, Language,
    PatchAttempt, PatchTarget, RunConfig, RunState, RunStatus, RuntimeStatus, ScanFinding, ScannerType,
)
from .exploit import ExploitEngine
from .runtime import RuntimeEngine
from .surface import SurfaceDiscovery
from .reporting import print_summary
from .scanners import ScannerOrchestrator

logger = logging.getLogger(__name__)
_console = Console()

MAX_TRIES_PER_FINDING = 2    # give up on a finding after this many failed attempts
MAX_BUILD_REPAIR_ATTEMPTS = 2   # how many times to ask the agent to fix its own broken patch
AGENT_REFRESH_INTERVAL = 15  # create a fresh agent every N iterations to avoid context bloat
BUILD_AGENT_TIMEOUT_SECONDS = 20 * 60    # 20 min cap per build-agent call
REMEDIATION_AGENT_TIMEOUT_SECONDS = 9 * 60   # 9 min cap per remediation-agent call

# Per-phase build timeouts — large monorepos (hertzbeat, zipkin, yudao-cloud, mall-swarm)
# can hang indefinitely if dep:resolve fetches hundreds of artifacts over a slow link.
DEPENDENCY_RESOLVE_TIMEOUT_SECONDS = 15 * 60   # 15 min
COMPILE_TIMEOUT_SECONDS = 20 * 60              # 20 min
# When compile times out and output still shows active Maven/Gradle progress,
# grant one extension of this fraction of the original timeout before giving up.
COMPILE_TIMEOUT_EXTENSION_FACTOR = 0.5   # 50% extension → 30 min total for a 20-min base

_COMPILE_PROGRESS_RE = re.compile(
    r"\[INFO\] Building |\[INFO\] --- .*:compile|Compiling \d+ source",
    re.IGNORECASE,
)


def _compile_still_in_progress(output: str) -> bool:
    """Return True if the last 50 lines of compile output show active Maven/Gradle progress."""
    if not output:
        return False
    tail = "\n".join(output.splitlines()[-50:])
    return bool(_COMPILE_PROGRESS_RE.search(tail))


# Paths excluded from remediation — non-source files the agent can't fix reliably.
_EXCLUDED_PREFIXES = (".github/", ".gitlab-ci", ".circleci/", ".mvn/")
_EXCLUDED_SUFFIXES = (".tf", ".md", ".adoc", ".rst", ".txt", ".csv", ".sql", ".sh", ".bash", "wrapper/")

# Path segments that signal intentionally-vulnerable code (challenge files, exploit samples, etc.).
# These are SUB-PATHS within a repo, not whole-repo names — so WebGoat's lessons/ or dvja's
# controller/ are unaffected.  Only files whose path contains one of these segments are skipped.
# Rationale for each segment:
#   challenges/     — wrongsecrets, OWASP challenge suites; each file IS the vulnerability
#   vulnerable/     — sub-directories explicitly named to hold insecure reference implementations
#   intentional/    — code that is deliberately insecure by design
#   exploit-samples/ — sample payloads / PoC code bundled alongside the scanner or app
#   insecure-examples/ — tutorial directories showing what NOT to do
_EXCLUDED_SEGMENTS = (
    "challenges/",
    "vulnerable/",
    "intentional/",
    "exploit-samples/",
    "insecure-examples/",
)

_PRIORITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SCANNER_ORDER = {ScannerType.TRIVY: 0, ScannerType.GITLEAKS: 1, ScannerType.SEMGREP: 2}


def _finding_priority(f: ScanFinding) -> int:
    return _PRIORITY_ORDER.index(f.severity.value)


def _group_priority(group: list[ScanFinding]) -> tuple:
    return (min(_finding_priority(f) for f in group), _SCANNER_ORDER.get(group[0].scanner, 9))


def _is_excluded(file_path: str) -> bool:
    return (
        any(file_path.startswith(p) for p in _EXCLUDED_PREFIXES)
        or any(file_path.endswith(s) for s in _EXCLUDED_SUFFIXES)
        or any(seg in file_path for seg in _EXCLUDED_SEGMENTS)
    )


def _step(msg: str) -> None:
    """Print a timestamped pipeline step to the console."""
    _console.print(f"[dim]{datetime.now(timezone.utc).strftime('%H:%M:%S')}[/dim]  {msg}")


def _run_agent_with_timeout(agent, prompt: str, timeout_seconds: int):
    """Run agent.run(prompt) with a hard wall-clock timeout.

    Raises TimeoutError if the call doesn't return within timeout_seconds.

    Uses a daemon thread + threading.Event rather than ThreadPoolExecutor so that
    a timed-out call never blocks the pipeline.  ThreadPoolExecutor.__del__ calls
    shutdown(wait=True), which blocks until the worker thread exits — exactly what
    we must avoid when the LLM API stalls indefinitely.
    """
    result_holder: list = [None]
    exc_holder: list = [None]
    done = threading.Event()

    def _run() -> None:
        try:
            result_holder[0] = agent.run(prompt)
        except Exception as exc:  # noqa: BLE001
            exc_holder[0] = exc
        finally:
            done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    if not done.wait(timeout=timeout_seconds):
        raise TimeoutError(f"Agent call exceeded {timeout_seconds // 60}m timeout")

    if exc_holder[0] is not None:
        raise exc_holder[0]
    return result_holder[0]


class PipelineOrchestrator:
    def __init__(self, config: RunConfig):
        self._config = config

    def run(self) -> RunState:
        run_id = str(uuid.uuid4())[:8]
        run_dir = self._config.output_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        state = RunState(
            run_id=run_id,
            repo_url=self._config.repo_url,
            started_at=datetime.now(timezone.utc),
        )
        self._save(state, run_dir)

        repo_path = run_dir / "repo"
        env = None
        engine = None
        runtime_engine = None
        exploit_engine = None

        # Install signal handlers so that SIGTERM/SIGINT flushes the run-state
        # before the process exits.  Without this, if the process is killed (e.g.
        # by an OS OOM reaper, Ctrl-C, or a benchmark runner timeout), the state
        # file stays at its initial values (status=running, language=null) because
        # the try/finally block never runs.
        _orig_sigterm = signal.getsignal(signal.SIGTERM)
        _orig_sigint  = signal.getsignal(signal.SIGINT)

        def _flush_and_exit(signum, frame):
            """Best-effort state flush on signal — mark as partial then re-raise."""
            if state.status == RunStatus.RUNNING:
                state.status = RunStatus.PARTIAL
            state.completed_at = state.completed_at or datetime.now(timezone.utc)
            state.final_finding_count = self._count_by_severity(state.findings)
            try:
                self._save(state, run_dir)
            except Exception:
                pass
            # Restore original handler and re-raise so the process exits normally
            signal.signal(signum, _orig_sigterm if signum == signal.SIGTERM else _orig_sigint)
            signal.raise_signal(signum)

        signal.signal(signal.SIGTERM, _flush_and_exit)
        signal.signal(signal.SIGINT, _flush_and_exit)

        try:
            # 1. Clone
            _step(f"[bold]Cloning[/bold] {self._config.repo_url}")
            try:
                clone_repo(self._config.repo_url, repo_path)
            except RuntimeError as e:
                _step(f"[red]Clone failed:[/red] {e}")
                state.status = RunStatus.BUILD_FAILED
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state
            _step("[green]Clone complete[/green]")

            # 2. Detect language
            try:
                language = detect_language(repo_path)
                state.language = language
                self._save(state, run_dir)  # persist language before container start (guards against SIGKILL)
            except ValueError as e:
                _step(f"[red]Unsupported language:[/red] {e}")
                state.status = RunStatus.UNSUPPORTED_LANGUAGE
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            # 3. Start container — pick image that matches the project's build tool + Java version
            image = select_image(repo_path, language)
            _step(f"[bold]Starting container[/bold] ({image})")
            env = ExecutionEnvironment(repo_path, image)
            env.start()
            _step("[green]Container ready[/green]")

            # 4. Build stabilization loop
            _step("[bold]Build stabilization[/bold] starting...")
            engine = create_engine(language, env, repo_path)
            build_succeeded = self._stabilize_build(state, env, engine, run_dir, repo_path, language)
            if not build_succeeded:
                _step(f"[red]Build failed after {len(state.build_attempts)} attempt(s)[/red]")
                state.status = RunStatus.BUILD_FAILED
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            _step(f"[green]Build succeeded[/green] (attempt {len(state.build_attempts)})")
            self._save(state, run_dir)

            # 5. Package — produce the fat JAR needed by the runtime engine.
            # Compile only produces .class files; package runs the spring-boot-maven-plugin
            # (or Gradle bootJar) to repackage them into a runnable fat JAR.
            runtime_enabled = self._config.enable_runtime
            if runtime_enabled:
                _step("[bold]Packaging application[/bold] (producing runnable JAR)...")
                package_result = engine.run_phase(BuildPhase.PACKAGE, timeout_seconds=15 * 60)
                if not package_result.success:
                    _step("[yellow]Packaging failed — skipping runtime engine[/yellow]")
                    runtime_enabled = False
                else:
                    _step("[green]Package succeeded[/green]")

            # 6. Runtime engine — attempt to start the service and confirm it responds
            if runtime_enabled:
                runtime_engine = RuntimeEngine(
                    repo_path, language, image,
                    llm_model=self._config.llm_model,
                    llm_provider=self._config.llm_provider,
                )
                if runtime_engine.detect():
                    _step("[bold]Runtime engine:[/bold] web service detected — attempting startup...")
                    runtime_result = runtime_engine.start(
                        timeout_seconds=self._config.runtime_startup_timeout_seconds
                    )
                    state.runtime_result = runtime_result
                    self._save(state, run_dir)

                    if runtime_result.status == RuntimeStatus.STARTED:
                        stubs = (
                            f"  stubs: {', '.join(runtime_result.stubs_applied)}"
                            if runtime_result.stubs_applied else ""
                        )
                        deps = (
                            f"  deps: {', '.join(runtime_result.deps_provisioned)}"
                            if runtime_result.deps_provisioned else ""
                        )
                        _step(
                            f"[green]Service started[/green] ({runtime_result.service_type.value}) "
                            f"on :{runtime_result.port} via {runtime_result.healthy_path} "
                            f"in {runtime_result.startup_seconds:.0f}s "
                            f"[strategy: {runtime_result.startup_strategy}]{stubs}{deps}"
                        )

                        # Phase 2b: surface discovery
                        _step("[bold]Surface discovery...[/bold]")
                        disc = SurfaceDiscovery(runtime_result.base_url, repo_path)
                        surface = disc.discover()
                        state.surface = surface
                        self._save(state, run_dir)
                        if surface.discovery_source == "none":
                            _step("[dim]Surface discovery: no actuator or OpenAPI endpoint found[/dim]")
                        else:
                            _step(
                                f"[bold]Surface:[/bold] {len(surface.endpoints)} endpoint(s) "
                                f"via {surface.discovery_source} "
                                f"({surface.mapped_to_source} mapped to source)"
                            )

                        # Phase 2c: exploit engine (opt-in)
                        if self._config.enable_exploit_engine and surface.discovery_source != "none":
                            _step("[bold]Exploit engine:[/bold] probing for exploitable findings...")
                            exploit_engine = ExploitEngine(
                                base_url=runtime_result.base_url,
                                repo_path=repo_path,
                                runtime_result=runtime_result,
                                model_id=self._config.exploit_model,
                                provider=self._config.exploit_provider,
                            )
                    else:
                        _step(
                            f"[yellow]Service did not start[/yellow] "
                            f"({runtime_result.status.value}) — continuing without runtime"
                        )
                else:
                    _step("[dim]Runtime engine: no runnable web service detected[/dim]")

            # 6. Initial scan
            _step("[bold]Running scanners...[/bold]")
            build_file = "build.gradle" if language == Language.JAVA_GRADLE else "pom.xml"
            scanner = ScannerOrchestrator(self._config.enabled_scanners, build_file=build_file, language=language.value)
            _scan_start = datetime.now(timezone.utc)
            findings = scanner.run(repo_path)
            baseline_scan_seconds = (datetime.now(timezone.utc) - _scan_start).total_seconds()
            if scanner.had_timeout:
                _step("[yellow]Warning: one or more scanners timed out on baseline — findings may be incomplete[/yellow]")
            if scanner.had_failure:
                _step("[yellow]Warning: one or more scanners hard-failed on baseline — findings may be incomplete[/yellow]")
            _step(f"[bold]Baseline scan:[/bold] {len(findings)} finding(s) ({baseline_scan_seconds/60:.1f}min)")

            baseline = IterationSnapshot(
                iteration=0,
                findings=findings,
                build_result=state.build_attempts[-1],
                scanner_times_secs={k.value: v for k, v in scanner.scanner_times.items()},
                scanner_had_timeout=scanner.had_timeout,
                scanner_had_failure=scanner.had_failure,
            )
            state.iterations.append(baseline)
            state.findings = findings
            self._save(state, run_dir)

            if not findings:
                _step("[green]No findings — converged.[/green]")
                state.status = RunStatus.CONVERGED
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            # Phase 2c: probe (after scan, before remediation)
            if exploit_engine is not None:
                try:
                    state.probe_results = exploit_engine.probe(state.surface, findings)
                    exploitable = sum(1 for r in state.probe_results if r.status.value == "exploitable")
                    _step(
                        f"[bold]Exploit engine:[/bold] {exploitable}/{len(state.probe_results)} "
                        f"finding(s) confirmed exploitable"
                    )
                    self._save(state, run_dir)
                except Exception as exc:
                    _step(f"[yellow]Exploit engine error — skipping: {exc}[/yellow]")
                    logger.exception("ExploitEngine.probe failed")

            # 7. Remediation loop — one (rule_id, file_path) group at a time
            remediation_trace_path = run_dir / "llm-remediation-agent.md"
            init_log(remediation_trace_path, "Remediation Agent", state.run_id, state.repo_url)
            remediation_agent = create_remediation_agent(
                repo_path, self._config.llm_model, self._config.llm_provider, env,
                language=language,
            )

            # Group findings by (rule_id, file_path) — all instances of a pattern in one file
            # are fixed together in a single agent call. Preserves priority order.
            raw_groups: dict[tuple[str, str], list[ScanFinding]] = defaultdict(list)
            excluded_count = 0
            for f in sorted(findings, key=_finding_priority):
                if _is_excluded(f.file_path):
                    excluded_count += 1
                    continue
                raw_groups[(f.rule_id, f.file_path)].append(f)
            if excluded_count:
                _step(f"[dim]Skipping {excluded_count} finding(s) in non-source files (infra, docs, data, CI configs)[/dim]")

            all_groups = sorted(raw_groups.values(), key=_group_priority)
            in_scope_groups = all_groups[: self._config.max_findings_to_remediate]
            in_scope_keys: set[tuple[str, str]] = {
                (g[0].rule_id, g[0].file_path) for g in in_scope_groups
            }
            total_in_scope = sum(len(g) for g in in_scope_groups)

            elapsed_before_loop = (datetime.now(timezone.utc) - state.started_at).total_seconds() / 60
            remaining_minutes = self._config.max_runtime_minutes - elapsed_before_loop

            # Per-iteration rescan cost: only the relevant scanner reruns, not all three.
            # Use per-scanner baseline times (weighted by how many in-scope groups use each scanner)
            # so we don't overestimate when e.g. Semgrep was slow but targets are all Trivy CVEs.
            scanner_times_secs = scanner.scanner_times  # dict[ScannerType, float]
            if not isinstance(scanner_times_secs, dict):
                scanner_times_secs = {}
            if in_scope_groups and scanner_times_secs:
                # Fallback for scanners absent from scanner_times (timeout/failure):
                # use the per-scanner average rather than the full parallel wall-clock time.
                per_scanner_avg = baseline_scan_seconds / max(1, len(scanner_times_secs))
                scanner_group_counts: dict[ScannerType, int] = defaultdict(int)
                for g in in_scope_groups:
                    scanner_group_counts[g[0].scanner] += 1
                weighted_rescan_secs = sum(
                    scanner_times_secs.get(s, per_scanner_avg) * cnt
                    for s, cnt in scanner_group_counts.items()
                ) / len(in_scope_groups)
            else:
                weighted_rescan_secs = baseline_scan_seconds
            estimated_iter_minutes = (weighted_rescan_secs / 60) + 3.0
            time_budget_max = max(1, int(remaining_minutes / estimated_iter_minutes))

            # Upper bounds on iteration count: findings × retries and time budget.
            # max_remediation_iterations is an optional explicit override (None = no override).
            iter_bounds = [len(in_scope_groups) * MAX_TRIES_PER_FINDING, time_budget_max]
            if self._config.max_remediation_iterations is not None:
                iter_bounds.append(self._config.max_remediation_iterations)
            effective_max = min(iter_bounds)
            _step(
                f"[bold]Remediation loop:[/bold] {len(findings)} finding(s) across "
                f"{len(all_groups)} group(s), remediating top {len(in_scope_groups)} group(s) "
                f"({total_in_scope} finding(s)), up to {effective_max} iteration(s) "
                f"(~{estimated_iter_minutes:.1f}min/iter, {remaining_minutes:.0f}min budget)"
            )

            if effective_max == 0:
                _step("[yellow]No remediation iterations available (empty scope or zero time budget)[/yellow]")
                state.status = RunStatus.CONVERGED
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            skip_keys: set[tuple[str, str]] = set()
            tries: dict[tuple[str, str], int] = {}
            iterations_since_refresh = 0

            for iteration in range(1, effective_max + 1):
                elapsed_min = (
                    datetime.now(timezone.utc) - state.started_at
                ).total_seconds() / 60
                if elapsed_min >= self._config.max_runtime_minutes:
                    made_progress = len(state.findings) < len(findings)
                    state.status = RunStatus.PARTIAL if made_progress else RunStatus.TIMEOUT
                    _step("[yellow]Time budget reached.[/yellow]")
                    break

                # Rebuild live groups from current findings
                live_groups: dict[tuple[str, str], list[ScanFinding]] = defaultdict(list)
                for f in state.findings:
                    key = (f.rule_id, f.file_path)
                    if key in in_scope_keys and key not in skip_keys:
                        live_groups[key].append(f)

                if not live_groups:
                    state.status = RunStatus.CONVERGED
                    _step("[green]All actionable findings resolved — converged.[/green]")
                    break

                target_key, target_group = min(
                    live_groups.items(), key=lambda kv: _group_priority(kv[1])
                )
                tries[target_key] = tries.get(target_key, 0) + 1
                current_try = tries[target_key]
                rep = target_group[0]

                _step(
                    f"[bold cyan]Iteration {iteration}/{effective_max}[/bold cyan]  "
                    f"[{rep.severity.value.upper()}] {rep.rule_id} "
                    f"in {rep.file_path} "
                    f"({len(target_group)} instance(s), try {current_try}/{MAX_TRIES_PER_FINDING})"
                )

                # Refresh agent periodically to prevent context window exhaustion
                if iterations_since_refresh >= AGENT_REFRESH_INTERVAL:
                    remediation_agent = create_remediation_agent(
                        repo_path, self._config.llm_model, self._config.llm_provider, env,
                        language=language,
                    )
                    iterations_since_refresh = 0
                    _step("[dim]Agent context refreshed[/dim]")

                state = self._remediation_iteration(
                    state, iteration, env, engine, remediation_agent, target_group, repo_path, run_dir,
                    language=language,
                    trace_path=remediation_trace_path,
                )
                self._save(state, run_dir)
                iterations_since_refresh += 1

                # No-change early skip — agent touched no files, structurally unfixable
                last_patch = state.iterations[-1].patch_attempt
                if last_patch and last_patch.skip_reason == "agent_no_changes":
                    skip_keys.add(target_key)
                    groups_remaining = len(live_groups) - 1
                    _step(
                        f"  [yellow]Skipping[/yellow] {rep.rule_id} — agent made no changes "
                        f"| {groups_remaining} group(s) remaining"
                    )
                    continue

                # Was the group resolved? (all target finding IDs gone from new scan)
                current_ids = {f.id for f in state.findings}
                group_resolved = not any(f.id in current_ids for f in target_group)
                groups_remaining = len(live_groups) - (1 if group_resolved else 0)

                if group_resolved:
                    _step(
                        f"  [green]Fixed:[/green] {rep.rule_id} "
                        f"({len(target_group)} instance(s)) | "
                        f"{groups_remaining} group(s) remaining"
                    )
                    tries.pop(target_key, None)
                else:
                    if current_try >= MAX_TRIES_PER_FINDING:
                        skip_keys.add(target_key)
                        _step(
                            f"  [yellow]Giving up on[/yellow] {rep.rule_id} "
                            f"after {current_try} tries | "
                            f"{groups_remaining - 1} group(s) remaining"
                        )
                    else:
                        _step(f"  No progress on {rep.rule_id} — will retry")
            else:
                state.status = RunStatus.MAX_ITERATIONS

            # Phase 2c: confirm patches eliminated exploit paths
            if exploit_engine is not None and state.probe_results:
                try:
                    _step("[bold]Exploit engine:[/bold] confirming patches...")
                    state.probe_results = exploit_engine.confirm(state.probe_results, state.findings)
                    fixed = sum(1 for r in state.probe_results if r.confirmed_fixed is True)
                    _step(f"[bold]Exploit engine:[/bold] {fixed}/{len(state.probe_results)} exploit path(s) confirmed fixed")
                    self._save(state, run_dir)
                except Exception as exc:
                    _step(f"[yellow]Exploit engine confirm error — skipping: {exc}[/yellow]")
                    logger.exception("ExploitEngine.confirm failed")

            # Final test health check — runs unit tests (no integration tests), with a hard timeout
            if env and state.status != RunStatus.BUILD_FAILED:
                timeout_s = self._config.final_test_timeout_minutes * 60
                _step(
                    f"[bold]Final test run[/bold] "
                    f"(unit tests only, {self._config.final_test_timeout_minutes}m timeout — "
                    f"does not affect results)..."
                )
                test_result = engine.run_phase(BuildPhase.UNIT_TEST, timeout_seconds=timeout_s)
                self._save_build_log(test_result, "final-test", run_dir)
                if test_result.success:
                    _step("[green]Unit tests passed[/green] on patched codebase")
                elif "timed out" in test_result.output:
                    _step(
                        f"[yellow]Unit tests timed out[/yellow] after "
                        f"{self._config.final_test_timeout_minutes}m — "
                        f"check build-logs/attempt-final-test.txt"
                    )
                else:
                    _step("[yellow]Unit tests failed[/yellow] on patched codebase (may be pre-existing) — check build-logs/attempt-final-test.txt")

        except Exception as e:
            logger.exception("[ASEL] Unexpected error: %s", e)
            if state.status == RunStatus.RUNNING:
                state.status = RunStatus.PARTIAL
        finally:
            if runtime_engine:
                runtime_engine.stop()
            if env:
                env.stop()
            state.completed_at = state.completed_at or datetime.now(timezone.utc)
            state.final_finding_count = self._count_by_severity(state.findings)
            self._save(state, run_dir)
            print_summary(state, run_dir)

        return state

    def _stabilize_build(
        self, state: RunState, env: ExecutionEnvironment, engine, run_dir: Path, repo_path: Path, language: Language
    ) -> bool:
        trace_path = run_dir / "llm-build-agent.md"
        init_log(trace_path, "Build Agent", state.run_id, state.repo_url)

        attempt = 0

        def _agent_fix(result: BuildResult, phase_label: str) -> None:
            _step(
                f"  Attempt {attempt} [red]failed[/red] "
                f"({result.error_category.value if result.error_category else 'unknown'}) "
                f"— asking BuildAgent..."
            )
            agent = create_build_agent(
                env, repo_path, self._config.llm_model, self._config.llm_provider,
                language=language,
            )
            prompt = self._build_prompt(result, attempt)
            try:
                run_output = _run_agent_with_timeout(agent, prompt, BUILD_AGENT_TIMEOUT_SECONDS)
            except TimeoutError as exc:
                print(f"  BuildAgent timed out ({BUILD_AGENT_TIMEOUT_SECONDS // 60}m) — continuing without fix")
                run_output = str(exc)
            append_turn(trace_path, label=f"Build stabilization — attempt {attempt} ({phase_label})", prompt=prompt, run_output=run_output)

        # Step 1: resolve deps (one attempt — if it fails, agent fixes then we move straight to compile)
        if attempt < self._config.max_build_attempts:
            _step(f"  Build attempt {attempt + 1}/{self._config.max_build_attempts} (phase: dependency_resolve)...")
            result = engine.run_phase(BuildPhase.DEPENDENCY_RESOLVE, timeout_seconds=DEPENDENCY_RESOLVE_TIMEOUT_SECONDS)
            attempt += 1
            state.build_attempts.append(result)
            self._save_build_log(result, str(attempt), run_dir)
            if not result.success:
                _agent_fix(result, "dependency_resolve")

        # Step 2: compile with agent-assisted retries and one progress-based timeout extension.
        extended = False
        while attempt < self._config.max_build_attempts:
            _step(f"  Build attempt {attempt + 1}/{self._config.max_build_attempts} (phase: compile)...")
            result = engine.run_phase(BuildPhase.COMPILE, timeout_seconds=COMPILE_TIMEOUT_SECONDS)
            attempt += 1
            state.build_attempts.append(result)
            self._save_build_log(result, str(attempt), run_dir)
            if result.success:
                return True
            # If compile timed out and is still making progress, grant one extension.
            if (not result.success and not extended
                    and result.error_category is None
                    and _compile_still_in_progress(result.output)):
                extension = int(COMPILE_TIMEOUT_SECONDS * COMPILE_TIMEOUT_EXTENSION_FACTOR)
                _step(f"  Compile still in progress — extending timeout by {extension // 60}m")
                extended = True
                ext_result = engine.run_phase(BuildPhase.COMPILE, timeout_seconds=extension)
                attempt += 1
                state.build_attempts.append(ext_result)
                self._save_build_log(ext_result, str(attempt), run_dir)
                if ext_result.success:
                    return True
                result = ext_result
            _agent_fix(result, "compile")

        return False

    def _fail_iteration(
        self,
        state: RunState,
        iteration: int,
        prev_findings: list[ScanFinding],
        build_result: BuildResult,
        repo_path: Path | None = None,
        target_findings: list[ScanFinding] | None = None,
    ) -> RunState:
        if repo_path is not None:
            self._rollback_repo(repo_path)
        prev_ids = [f.id for f in prev_findings]
        patch = PatchAttempt(
            iteration=iteration,
            target=PatchTarget.FINDING_REMEDIATION,
            finding_ids=[f.id for f in (target_findings or [])],
            build_result_after=build_result,
            succeeded=False,
            findings_before=prev_ids,
            findings_after=prev_ids,
            delta=0,
        )
        state.iterations.append(IterationSnapshot(
            iteration=iteration,
            findings=prev_findings,
            build_result=build_result,
            patch_attempt=patch,
        ))
        return state

    def _remediation_iteration(
        self,
        state: RunState,
        iteration: int,
        env,
        engine,
        remediation_agent,
        targets: list[ScanFinding],
        repo_path: Path,
        run_dir: Path,
        language: Language,
        trace_path: Path,
    ) -> RunState:
        prev_findings = state.findings
        prev_ids = [f.id for f in prev_findings]
        rep = targets[0]

        self._snapshot_repo(repo_path)
        prompt = self._remediation_prompt(targets, iteration, language, state.probe_results)
        try:
            run_output = _run_agent_with_timeout(remediation_agent, prompt, REMEDIATION_AGENT_TIMEOUT_SECONDS)
        except Exception as exc:
            print(f"  Agent error — rolling back: {exc}")
            exc_result = BuildResult(success=False, phase=BuildPhase.COMPILE, output=str(exc), duration_seconds=0)
            return self._fail_iteration(state, iteration, prev_findings, exc_result, repo_path, targets)
        append_turn(
            trace_path,
            label=(
                f"Iteration {iteration} — [{rep.severity.value.upper()}] {rep.rule_id} "
                f"in {rep.file_path} ({len(targets)} instance(s))"
            ),
            prompt=prompt,
            run_output=run_output,
        )

        # Early exit: if the agent touched no files, the finding is structurally unfixable.
        # Skip compile + rescan entirely and signal the main loop to stop retrying.
        _, early_files = self._capture_diff(repo_path)
        if not early_files:
            no_change_result = BuildResult(
                success=True, phase=BuildPhase.COMPILE,
                output="agent_no_changes", duration_seconds=0,
            )
            patch = PatchAttempt(
                iteration=iteration,
                target=PatchTarget.FINDING_REMEDIATION,
                finding_ids=[f.id for f in targets],
                build_result_after=no_change_result,
                succeeded=False,
                findings_before=prev_ids,
                findings_after=prev_ids,
                delta=0,
                skip_reason="agent_no_changes",
            )
            state.iterations.append(IterationSnapshot(
                iteration=iteration,
                findings=prev_findings,
                build_result=no_change_result,
                patch_attempt=patch,
            ))
            return state

        build_result = engine.run_phase(BuildPhase.COMPILE)
        self._save_build_log(build_result, f"remediation-{iteration}", run_dir)

        # If broken, let the agent repair its own patch before giving up
        if not build_result.success:
            for repair_num in range(1, MAX_BUILD_REPAIR_ATTEMPTS + 1):
                _step(f"  [yellow]Build broken — repair attempt {repair_num}/{MAX_BUILD_REPAIR_ATTEMPTS}[/yellow]")
                repair_prompt = self._patch_repair_prompt(build_result, targets)
                try:
                    repair_output = _run_agent_with_timeout(remediation_agent, repair_prompt, REMEDIATION_AGENT_TIMEOUT_SECONDS)
                except Exception as exc:
                    print(f"  Repair agent error — rolling back: {exc}")
                    return self._fail_iteration(state, iteration, prev_findings, build_result, repo_path, targets)
                append_turn(
                    trace_path,
                    label=f"Iteration {iteration} — build repair {repair_num}/{MAX_BUILD_REPAIR_ATTEMPTS} for {rep.rule_id}",
                    prompt=repair_prompt,
                    run_output=repair_output,
                )
                build_result = engine.run_phase(BuildPhase.COMPILE)
                self._save_build_log(build_result, f"remediation-{iteration}-repair{repair_num}", run_dir)
                if build_result.success:
                    break

        if not build_result.success:
            _step("  [red]Build repair exhausted — rolling back[/red]")
            return self._fail_iteration(state, iteration, prev_findings, build_result, repo_path, targets)

        # Capture what the agent changed before re-scanning
        patch_diff, patch_files = self._capture_diff(repo_path)

        # Re-scan with only the scanner that reported these findings.
        # All targets in a group share the same scanner (same rule_id → same tool).
        build_file = "build.gradle" if language == Language.JAVA_GRADLE else "pom.xml"
        rescan = ScannerOrchestrator([rep.scanner], build_file=build_file, language=language.value)
        fresh = rescan.run(repo_path)
        if rescan.had_timeout or rescan.had_failure:
            _step(f"  [yellow]{rep.scanner.value} failed/timed out on rescan — keeping previous findings[/yellow]")
            fresh = [f for f in prev_findings if f.scanner == rep.scanner]
        # Merge: fresh results from the target scanner + all other scanners unchanged
        other_findings = [f for f in prev_findings if f.scanner != rep.scanner]
        new_findings = other_findings + fresh
        new_ids = [f.id for f in new_findings]
        delta = len(prev_findings) - len(new_findings)
        introduced = any(fid not in prev_ids for fid in new_ids)
        net_negative = introduced and delta <= 0

        if net_negative:
            _step("  [red]Net-negative patch (new findings introduced) — rolling back[/red]")
            self._rollback_repo(repo_path)

        patch = PatchAttempt(
            iteration=iteration,
            target=PatchTarget.FINDING_REMEDIATION,
            finding_ids=[f.id for f in targets],
            files_modified=patch_files,
            diff=patch_diff,
            build_result_after=build_result,
            succeeded=delta > 0 and not net_negative,
            findings_before=prev_ids,
            findings_after=prev_ids if net_negative else new_ids,
            delta=0 if net_negative else delta,
            introduced_new_findings=introduced,
        )
        state.findings = prev_findings if net_negative else new_findings
        state.iterations.append(IterationSnapshot(
            iteration=iteration,
            findings=state.findings,
            build_result=build_result,
            patch_attempt=patch,
            scanner_times_secs={k.value: v for k, v in rescan.scanner_times.items()},
            scanner_had_timeout=rescan.had_timeout,
            scanner_had_failure=rescan.had_failure,
        ))
        return state

    def _build_prompt(self, result: BuildResult, attempt: int) -> str:
        output_tail = "\n".join(result.output.splitlines()[-80:])
        return (
            f"Build attempt {attempt} failed.\n"
            f"Phase: {result.phase.value}\n"
            f"Error category: {result.error_category}\n\n"
            f"Output (last 80 lines):\n{output_tail}\n\n"
            "Please fix the issue and verify by running Maven."
        )

    def _remediation_prompt(self, targets: list[ScanFinding], iteration: int, language: Language, probe_results: list['ProbeResult'] = None) -> str:
        verify_tool = (
            "run_gradle_compile" if language == Language.JAVA_GRADLE else "run_maven_compile"
        )
        rep = targets[0]
        if len(targets) == 1:
            location = (
                f"  File: {rep.file_path}"
                + (f":{rep.line_number}" if rep.line_number else "")
                + f"\n  Issue: {rep.title}"
            )
            count_note = ""
        else:
            instances = "\n".join(
                f"    - Line {t.line_number or '?'}: {t.title}" for t in targets
            )
            location = f"  File: {rep.file_path}\n  Instances:\n{instances}"
            count_note = f" ({len(targets)} instances in the same file — fix all of them)"

        # Include description when it adds information beyond the title (e.g. Trivy has
        # package name + installed version → fixed version in the description field).
        description_note = ""
        if rep.description and rep.description.strip() != rep.title.strip():
            desc = rep.description[:300].rstrip()
            if len(rep.description) > 300:
                desc += "..."
            description_note = f"\n  Description: {desc}"

        probe_info = ""
        if probe_results:
            target_ids = {t.id for t in targets}
            for pr in probe_results:
                if pr.finding_id in target_ids and pr.status.value == "exploitable":
                    probe_info = (
                        f"\n\n[!] EXPLOIT CONFIRMED BY AGENTIC DAST\n"
                        f"An autonomous pentester successfully exploited this vulnerability.\n"
                        f"Endpoint: {pr.endpoint.method} {pr.endpoint.path}\n"
                        f"Payload sent: {pr.request}\n"
                        f"Evidence: {pr.evidence}\n"
                        f"You must patch this to prevent the exploit.\n"
                        f"After you patch, the exact same payload will be re-sent to verify your fix."
                    )
                    break

        return (
            f"Remediation iteration {iteration}. Fix this finding{count_note}:\n\n"
            f"  [{rep.severity.value.upper()}] {rep.rule_id}\n"
            + location
            + description_note
            + probe_info
            + f"\n\nRead the file first, apply the minimal fix to all instances, "
            + f"then optionally verify with {verify_tool}."
        )

    def _patch_repair_prompt(self, result: BuildResult, targets: list[ScanFinding]) -> str:
        errors = "\n".join(
            line for line in result.output.splitlines() if "[ERROR]" in line
        )[:2000]
        return (
            f"Your patch introduced a compilation error while fixing {targets[0].rule_id}. "
            "Fix the compilation error while preserving the security fix.\n\n"
            f"Compilation errors:\n{errors}\n\n"
            "Do NOT revert the security fix — only fix the compilation problem."
        )

    def _count_by_severity(self, findings: list[ScanFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _snapshot_repo(self, repo_path: Path) -> None:
        """Stage all current changes so we can restore to this point if a patch is rejected."""
        subprocess.run(["git", "add", "-A"], cwd=repo_path, capture_output=True)
        result = subprocess.run(
            ["git", "diff", "--cached", "--quiet"], cwd=repo_path, capture_output=True
        )
        if result.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", "asel: pre-patch snapshot", "--no-gpg-sign"],
                cwd=repo_path, capture_output=True,
            )

    def _rollback_repo(self, repo_path: Path) -> None:
        """Discard any uncommitted changes made by the agent."""
        subprocess.run(["git", "checkout", "."], cwd=repo_path, capture_output=True)
        subprocess.run(["git", "clean", "-fd"], cwd=repo_path, capture_output=True)

    def _capture_diff(self, repo_path: Path) -> tuple[str, list[str]]:
        """Return (unified diff, list of modified file paths) for uncommitted agent changes."""
        if not repo_path.exists():
            return "", []
        diff_result = subprocess.run(
            ["git", "diff"], cwd=repo_path, capture_output=True, text=True
        )
        diff = diff_result.stdout or ""
        files_result = subprocess.run(
            ["git", "diff", "--name-only"], cwd=repo_path, capture_output=True, text=True
        )
        files = [f for f in files_result.stdout.splitlines() if f]
        return diff, files

    def _save(self, state: RunState, run_dir: Path) -> None:
        (run_dir / "run-state.json").write_text(state.model_dump_json(indent=2))

    def _save_build_log(self, result: BuildResult, label: str, run_dir: Path) -> None:
        log_dir = run_dir / "build-logs"
        log_dir.mkdir(exist_ok=True)
        (log_dir / f"attempt-{label}.txt").write_text(result.output)
