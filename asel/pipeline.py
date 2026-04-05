# asel/pipeline.py
import logging
import subprocess
import uuid
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
    PatchAttempt, PatchTarget, RunConfig, RunState, RunStatus, ScanFinding,
)
from .reporting import print_summary
from .scanners import ScannerOrchestrator

logger = logging.getLogger(__name__)
_console = Console()

MAX_TRIES_PER_FINDING = 2   # give up on a finding after this many failed attempts
MAX_BUILD_REPAIR_ATTEMPTS = 2  # how many times to ask the agent to fix its own broken patch


def _step(msg: str) -> None:
    """Print a timestamped pipeline step to the console."""
    _console.print(f"[dim]{datetime.now(timezone.utc).strftime('%H:%M:%S')}[/dim]  {msg}")


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

        try:
            # 1. Clone
            _step(f"[bold]Cloning[/bold] {self._config.repo_url}")
            clone_repo(self._config.repo_url, repo_path)
            _step("[green]Clone complete[/green]")

            # 2. Detect language
            try:
                language = detect_language(repo_path)
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

            # 5. Initial scan
            _step("[bold]Running scanners...[/bold]")
            scanner = ScannerOrchestrator(self._config.enabled_scanners)
            findings = scanner.run(repo_path)
            _step(f"[bold]Baseline scan:[/bold] {len(findings)} finding(s)")

            baseline = IterationSnapshot(
                iteration=0,
                findings=findings,
                build_result=state.build_attempts[-1],
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

            # 6. Remediation loop — one finding at a time
            remediation_trace_path = run_dir / "llm-remediation-agent.md"
            init_log(remediation_trace_path, "Remediation Agent", state.run_id, state.repo_url)
            remediation_agent = create_remediation_agent(
                repo_path, self._config.llm_model, self._config.llm_provider, env,
                language=language,
            )

            priority_order = ["critical", "high", "medium", "low", "info"]

            # Cap: scan all findings but only remediate the top N by severity
            in_scope = {
                f.id for f in sorted(findings, key=lambda f: priority_order.index(f.severity.value))
                [: self._config.max_findings_to_remediate]
            }

            # Scale the iteration budget: each in-scope finding gets MAX_TRIES_PER_FINDING attempts
            effective_max = min(
                self._config.max_remediation_iterations,
                len(in_scope) * MAX_TRIES_PER_FINDING,
            )
            _step(
                f"[bold]Remediation loop:[/bold] {len(findings)} finding(s) found, "
                f"remediating top {len(in_scope)}, "
                f"up to {effective_max} iteration(s)"
            )

            skip_ids: set[str] = set()   # findings we've exhausted tries on
            tries: dict[str, int] = {}   # per-finding attempt counter

            for iteration in range(1, effective_max + 1):
                # Timeout check
                elapsed_min = (
                    datetime.now(timezone.utc) - state.started_at
                ).total_seconds() / 60
                if elapsed_min >= self._config.max_runtime_minutes:
                    state.status = RunStatus.TIMEOUT
                    _step("[yellow]Timeout reached.[/yellow]")
                    break

                # Pick the highest-priority in-scope finding we haven't given up on
                candidates = sorted(
                    [f for f in state.findings if f.id in in_scope and f.id not in skip_ids],
                    key=lambda f: priority_order.index(f.severity.value),
                )
                if not candidates:
                    state.status = RunStatus.CONVERGED
                    _step("[green]All actionable findings resolved — converged.[/green]")
                    break

                target = candidates[0]
                tries[target.id] = tries.get(target.id, 0) + 1
                current_try = tries[target.id]

                _step(
                    f"[bold cyan]Iteration {iteration}/{effective_max}[/bold cyan]  "
                    f"[{target.severity.value.upper()}] {target.rule_id} "
                    f"in {target.file_path} "
                    f"(try {current_try}/{MAX_TRIES_PER_FINDING})"
                )

                state = self._remediation_iteration(
                    state, iteration, env, engine, remediation_agent, scanner, target, repo_path, run_dir,
                    trace_path=remediation_trace_path,
                )
                self._save(state, run_dir)

                # Was the target finding resolved?
                current_ids = {f.id for f in state.findings}
                actionable_remaining = len([f for f in state.findings if f.id not in skip_ids])

                if target.id not in current_ids:
                    _step(
                        f"  [green]Fixed:[/green] {target.rule_id} | "
                        f"{actionable_remaining} actionable remaining"
                    )
                    tries.pop(target.id, None)
                else:
                    if current_try >= MAX_TRIES_PER_FINDING:
                        skip_ids.add(target.id)
                        _step(
                            f"  [yellow]Giving up on[/yellow] {target.rule_id} "
                            f"after {current_try} tries | "
                            f"{actionable_remaining - 1} actionable remaining"
                        )
                    else:
                        _step(f"  No progress on {target.rule_id} — will retry")
            else:
                state.status = RunStatus.MAX_ITERATIONS

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
                state.status = RunStatus.BUILD_FAILED
        finally:
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
            run_output = agent.run(prompt)
            append_turn(trace_path, label=f"Build stabilization — attempt {attempt} ({phase_label})", prompt=prompt, run_output=run_output)

        # Step 1: resolve deps (one attempt — if it fails, agent fixes then we move straight to compile)
        if attempt < self._config.max_build_attempts:
            _step(f"  Build attempt {attempt + 1}/{self._config.max_build_attempts} (phase: dependency_resolve)...")
            result = engine.run_phase(BuildPhase.DEPENDENCY_RESOLVE)
            attempt += 1
            state.build_attempts.append(result)
            self._save_build_log(result, str(attempt), run_dir)
            if not result.success:
                _agent_fix(result, "dependency_resolve")

        # Step 2: compile with agent-assisted retries
        while attempt < self._config.max_build_attempts:
            _step(f"  Build attempt {attempt + 1}/{self._config.max_build_attempts} (phase: compile)...")
            result = engine.run_phase(BuildPhase.COMPILE)
            attempt += 1
            state.build_attempts.append(result)
            self._save_build_log(result, str(attempt), run_dir)
            if result.success:
                return True
            _agent_fix(result, "compile")

        return False

    def _fail_iteration(
        self,
        state: RunState,
        iteration: int,
        prev_findings: list[ScanFinding],
        build_result: BuildResult,
        repo_path: Path | None = None,
    ) -> RunState:
        if repo_path is not None:
            self._rollback_repo(repo_path)
        prev_ids = [f.id for f in prev_findings]
        patch = PatchAttempt(
            iteration=iteration,
            target=PatchTarget.FINDING_REMEDIATION,
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
        scanner,
        target: ScanFinding,
        repo_path: Path,
        run_dir: Path,
        trace_path: Path,
    ) -> RunState:
        prev_findings = state.findings
        prev_ids = [f.id for f in prev_findings]

        self._snapshot_repo(repo_path)
        prompt = self._remediation_prompt(target, iteration)
        try:
            run_output = remediation_agent.run(prompt)
        except Exception as exc:
            _step(f"  [red]Agent error — rolling back:[/red] {exc}")
            exc_result = BuildResult(success=False, phase=BuildPhase.COMPILE, output=str(exc), duration_seconds=0)
            return self._fail_iteration(state, iteration, prev_findings, exc_result, repo_path)
        append_turn(
            trace_path,
            label=f"Iteration {iteration} — [{target.severity.value.upper()}] {target.rule_id} in {target.file_path}",
            prompt=prompt,
            run_output=run_output,
        )

        build_result = engine.run_phase(BuildPhase.COMPILE)
        self._save_build_log(build_result, f"remediation-{iteration}", run_dir)

        # If broken, let the agent repair its own patch before giving up
        if not build_result.success:
            for repair_num in range(1, MAX_BUILD_REPAIR_ATTEMPTS + 1):
                _step(f"  [yellow]Build broken — repair attempt {repair_num}/{MAX_BUILD_REPAIR_ATTEMPTS}[/yellow]")
                repair_prompt = self._patch_repair_prompt(build_result, target)
                try:
                    repair_output = remediation_agent.run(repair_prompt)
                except Exception as exc:
                    _step(f"  [red]Repair agent error — rolling back:[/red] {exc}")
                    return self._fail_iteration(state, iteration, prev_findings, build_result, repo_path)
                append_turn(
                    trace_path,
                    label=f"Iteration {iteration} — build repair {repair_num}/{MAX_BUILD_REPAIR_ATTEMPTS} for {target.rule_id}",
                    prompt=repair_prompt,
                    run_output=repair_output,
                )
                build_result = engine.run_phase(BuildPhase.COMPILE)
                self._save_build_log(build_result, f"remediation-{iteration}-repair{repair_num}", run_dir)
                if build_result.success:
                    break

        if not build_result.success:
            _step("  [red]Build repair exhausted — rolling back[/red]")
            return self._fail_iteration(state, iteration, prev_findings, build_result, repo_path)

        # Re-scan
        new_findings = scanner.run(repo_path)
        new_ids = [f.id for f in new_findings]
        delta = len(prev_findings) - len(new_findings)
        introduced = any(fid not in prev_ids for fid in new_ids)
        net_negative = introduced and delta < 0

        if net_negative:
            _step("  [red]Net-negative patch (new findings introduced) — rolling back[/red]")
            self._rollback_repo(repo_path)

        patch = PatchAttempt(
            iteration=iteration,
            target=PatchTarget.FINDING_REMEDIATION,
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

    def _remediation_prompt(self, target: ScanFinding, iteration: int) -> str:
        return (
            f"Remediation iteration {iteration}. Fix this single finding:\n\n"
            f"  [{target.severity.value.upper()}] {target.rule_id}\n"
            f"  File: {target.file_path}"
            + (f":{target.line_number}" if target.line_number else "")
            + f"\n  Issue: {target.title}\n\n"
            "Read the file first, apply the minimal fix, then optionally verify with run_maven_compile."
        )

    def _patch_repair_prompt(self, result: BuildResult, target: ScanFinding) -> str:
        errors = "\n".join(
            line for line in result.output.splitlines() if "[ERROR]" in line
        )[:2000]
        return (
            f"Your patch introduced a compilation error while fixing {target.rule_id}. "
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

    def _save(self, state: RunState, run_dir: Path) -> None:
        (run_dir / "run-state.json").write_text(state.model_dump_json(indent=2))

    def _save_build_log(self, result: BuildResult, label: str, run_dir: Path) -> None:
        log_dir = run_dir / "build-logs"
        log_dir.mkdir(exist_ok=True)
        (log_dir / f"attempt-{label}.txt").write_text(result.output)
