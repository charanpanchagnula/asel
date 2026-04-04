# asel/controller.py
from datetime import datetime, timezone
from typing import Optional

from .models import RunConfig, RunStatus, IterationSnapshot


class IterationController:
    """Decides when to continue or stop the remediation loop."""

    def __init__(self, config: RunConfig):
        self._config = config
        self._stall_count = 0
        self._start_time: Optional[datetime] = None

    def start(self) -> None:
        """Call this when the run begins to start the clock."""
        self._start_time = datetime.now(timezone.utc)
        self._stall_count = 0

    def effective_max_iterations(self, finding_count: int) -> int:
        """Dynamic max: scales with problem size, capped at hard ceiling."""
        dynamic = max(3, finding_count // self._config.min_findings_per_iteration)
        return min(self._config.max_remediation_iterations, dynamic)

    def decide(
        self, iteration: int, snapshots: list[IterationSnapshot]
    ) -> tuple[bool, RunStatus]:
        """
        Given all snapshots so far, decide whether to continue.
        Returns (should_continue, status).
        """
        if self._start_time is None:
            raise RuntimeError("Call start() before decide()")

        # 1. Timeout check
        elapsed_minutes = (datetime.now(timezone.utc) - self._start_time).total_seconds() / 60
        if elapsed_minutes >= self._config.max_runtime_minutes:
            return False, RunStatus.TIMEOUT

        latest = snapshots[-1]
        baseline_count = len(snapshots[0].findings)

        # 2. Convergence check
        if not latest.findings:
            return False, RunStatus.CONVERGED

        # 3. Stall detection
        if len(snapshots) >= 2:
            prev_count = len(snapshots[-2].findings)
            curr_count = len(latest.findings)
            delta = prev_count - curr_count
            if delta < self._config.min_delta_to_continue:
                self._stall_count += 1
            else:
                self._stall_count = 0

        if self._stall_count >= self._config.stall_threshold:
            return False, RunStatus.STALLED

        # 4. Max iterations check
        if iteration >= self.effective_max_iterations(baseline_count):
            return False, RunStatus.MAX_ITERATIONS

        return True, RunStatus.RUNNING
