# asel/pipeline.py
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .agents import create_build_agent, create_remediation_agent
from .build import MavenBuildEngine
from .controller import IterationController
from .environment import ExecutionEnvironment
from .ingestor import clone_repo, detect_language
from .models import (
    BuildPhase, BuildResult, IterationSnapshot,
    Language, PatchAttempt, PatchTarget, RunConfig, RunState, RunStatus,
    ScanFinding,
)
from .reporting import print_summary
from .scanners import ScannerOrchestrator

logger = logging.getLogger(__name__)

MAVEN_IMAGE = "maven:3.9-eclipse-temurin-17"


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

        try:
            # 1. Clone
            logger.info("[ASEL] Cloning %s...", self._config.repo_url)
            clone_repo(self._config.repo_url, repo_path)

            # 2. Detect language
            try:
                detect_language(repo_path)
            except ValueError as e:
                logger.error("[ASEL] %s", e)
                state.status = RunStatus.UNSUPPORTED_LANGUAGE
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            # 3. Start container
            env = ExecutionEnvironment(repo_path, MAVEN_IMAGE)
            env.start()

            # 4. Build stabilization loop
            build_agent = create_build_agent(
                env, repo_path, self._config.llm_model, self._config.llm_provider
            )
            build_succeeded = self._stabilize_build(state, env, build_agent, run_dir)
            if not build_succeeded:
                state.status = RunStatus.BUILD_FAILED
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            # 5. Initial scan
            scanner = ScannerOrchestrator(self._config.enabled_scanners)
            findings = scanner.run(repo_path)
            logger.info("[ASEL] Baseline scan: %d findings", len(findings))

            baseline = IterationSnapshot(
                iteration=0,
                findings=findings,
                build_result=state.build_attempts[-1],
            )
            state.iterations.append(baseline)
            state.findings = findings
            self._save(state, run_dir)

            if not findings:
                state.status = RunStatus.CONVERGED
                state.completed_at = datetime.now(timezone.utc)
                self._save(state, run_dir)
                return state

            # 6. Remediation loop
            remediation_agent = create_remediation_agent(
                repo_path, self._config.llm_model, self._config.llm_provider, env
            )
            controller = IterationController(self._config)
            controller.start()
            effective_max = controller.effective_max_iterations(len(findings))

            for iteration in range(1, effective_max + 1):
                state = self._remediation_iteration(
                    state, iteration, env, remediation_agent, scanner, repo_path, run_dir
                )
                should_continue, status = controller.decide(iteration, state.iterations)
                state.status = status
                self._save(state, run_dir)
                if not should_continue:
                    break

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
        self, state: RunState, env: ExecutionEnvironment, build_agent, run_dir: Path
    ) -> bool:
        engine = MavenBuildEngine(env)
        phases = engine.progressive_phases()
        attempt = 0

        for phase in phases:
            if attempt >= self._config.max_build_attempts:
                break
            result = engine.run_phase(phase)
            attempt += 1
            state.build_attempts.append(result)
            self._save_build_log(result, str(attempt), run_dir)

            if result.success:
                logger.info("[ASEL] Build succeeded on attempt %d (%s)", attempt, phase.value)
                return True

            logger.info("[ASEL] Attempt %d failed (%s) — asking BuildAgent...", attempt, result.error_category)
            build_agent.run(self._build_prompt(result, attempt))

        # Remaining attempts: full build after agent fixes
        while attempt < self._config.max_build_attempts:
            result = engine.run_phase(BuildPhase.FULL_BUILD)
            attempt += 1
            state.build_attempts.append(result)
            self._save_build_log(result, str(attempt), run_dir)

            if result.success:
                logger.info("[ASEL] Build succeeded on attempt %d", attempt)
                return True

            logger.info("[ASEL] Attempt %d failed — asking BuildAgent...", attempt)
            build_agent.run(self._build_prompt(result, attempt))

        return False

    def _remediation_iteration(
        self,
        state: RunState,
        iteration: int,
        env,
        remediation_agent,
        scanner,
        repo_path: Path,
        run_dir: Path,
    ) -> RunState:
        prev_findings = state.findings
        prev_ids = [f.id for f in prev_findings]

        logger.info("[ASEL] Remediation iteration %d...", iteration)
        remediation_agent.run(self._remediation_prompt(prev_findings, iteration))

        # Rebuild
        engine = MavenBuildEngine(env)
        build_result = engine.run_phase(BuildPhase.FULL_BUILD)
        self._save_build_log(build_result, f"remediation-{iteration}", run_dir)

        if not build_result.success:
            logger.warning("[ASEL] Patch broke the build — rejecting")
            patch = PatchAttempt(
                iteration=iteration,
                target=PatchTarget.FINDING_REMEDIATION,
                build_result_after=build_result,
                succeeded=False,
                findings_before=prev_ids,
                findings_after=prev_ids,
                delta=0,
            )
            snapshot = IterationSnapshot(
                iteration=iteration,
                findings=prev_findings,
                build_result=build_result,
                patch_attempt=patch,
            )
            state.iterations.append(snapshot)
            return state

        # Re-scan
        new_findings = scanner.run(repo_path)
        new_ids = [f.id for f in new_findings]
        delta = len(prev_findings) - len(new_findings)
        introduced = any(fid not in prev_ids for fid in new_ids)

        logger.info("[ASEL] Iteration %d: delta=%+d, introduced_new=%s", iteration, delta, introduced)

        patch = PatchAttempt(
            iteration=iteration,
            target=PatchTarget.FINDING_REMEDIATION,
            build_result_after=build_result,
            succeeded=delta > 0 and not (introduced and delta < 0),
            findings_before=prev_ids,
            findings_after=new_ids,
            delta=delta,
            introduced_new_findings=introduced,
        )
        state.findings = new_findings
        snapshot = IterationSnapshot(
            iteration=iteration,
            findings=new_findings,
            build_result=build_result,
            patch_attempt=patch,
        )
        state.iterations.append(snapshot)
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

    def _remediation_prompt(self, findings: list[ScanFinding], iteration: int) -> str:
        priority = ["critical", "high", "medium", "low", "info"]
        top = sorted(findings, key=lambda f: priority.index(f.severity.value))[:5]
        lines = [
            f"- [{f.severity.value.upper()}] {f.rule_id} in {f.file_path}:{f.line_number or '?'} — {f.title}"
            for f in top
        ]
        return (
            f"Remediation iteration {iteration}. Top findings to fix:\n"
            + "\n".join(lines)
            + "\n\nFix the highest-priority issue(s). Verify compilation if uncertain."
        )

    def _count_by_severity(self, findings: list[ScanFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _save(self, state: RunState, run_dir: Path) -> None:
        (run_dir / "run-state.json").write_text(state.model_dump_json(indent=2))

    def _save_build_log(self, result: BuildResult, label: str, run_dir: Path) -> None:
        log_dir = run_dir / "build-logs"
        log_dir.mkdir(exist_ok=True)
        (log_dir / f"attempt-{label}.txt").write_text(result.output)
