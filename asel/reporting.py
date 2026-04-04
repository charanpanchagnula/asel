# asel/reporting.py
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import RunState, RunStatus

console = Console()


def print_summary(state: RunState, run_dir: Path) -> None:
    console.print()
    console.rule("[bold]ASEL Run Summary")

    status_color = {
        RunStatus.CONVERGED: "green",
        RunStatus.BUILD_FAILED: "red",
        RunStatus.UNSUPPORTED_LANGUAGE: "red",
        RunStatus.STALLED: "yellow",
        RunStatus.MAX_ITERATIONS: "yellow",
        RunStatus.TIMEOUT: "yellow",
    }.get(state.status, "white")

    console.print(f"Status:     [{status_color}]{state.status.value.upper()}[/{status_color}]")
    console.print(f"Repo:       {state.repo_url}")
    console.print(f"Run ID:     {state.run_id}")
    console.print(f"Output:     {run_dir}")

    if state.build_attempts:
        last = state.build_attempts[-1]
        outcome = "succeeded" if last.success else "failed"
        console.print(f"Build attempts: {len(state.build_attempts)} ({outcome})")

    if state.final_finding_count:
        table = Table(title="Remaining Findings", show_header=True)
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = state.final_finding_count.get(sev, 0)
            if count:
                color = colors.get(sev, "white")
                table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
        console.print(table)
    else:
        console.print("[green]No findings remaining.[/green]")

    console.print(f"\nFull audit trail: {run_dir / 'run-state.json'}")
