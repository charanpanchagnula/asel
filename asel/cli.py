# asel/cli.py
import logging
from pathlib import Path

import typer
from rich.console import Console

from .models import RunConfig
from .pipeline import PipelineOrchestrator

app = typer.Typer(help="Autonomous Security Execution Lab — build, scan, remediate.")
console = Console()

_run_app = typer.Typer()
app.add_typer(_run_app, name="run")


@_run_app.callback(invoke_without_command=True)
def run(
    ctx: typer.Context,
    repo_url: str = typer.Argument(..., help="Git repository URL to analyze"),
    output_dir: Path = typer.Option(Path("./asel-runs"), help="Directory for run artifacts"),
    max_build_attempts: int = typer.Option(5, help="Max build stabilization attempts"),
    max_remediation_iters: int = typer.Option(10, help="Hard ceiling on remediation iterations"),
    stall_threshold: int = typer.Option(2, help="Stop after N zero-delta iterations"),
    max_runtime_minutes: int = typer.Option(60, help="Wall clock limit for entire run"),
    model: str = typer.Option("deepseek-chat", help="LLM model identifier"),
    provider: str = typer.Option("deepseek", help="LLM provider (deepseek, openai, anthropic)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug logs"),
) -> None:
    """Clone, build, scan, and remediate a Java/Maven repository."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    config = RunConfig(
        repo_url=repo_url,
        output_dir=output_dir,
        max_build_attempts=max_build_attempts,
        max_remediation_iterations=max_remediation_iters,
        stall_threshold=stall_threshold,
        max_runtime_minutes=max_runtime_minutes,
        llm_model=model,
        llm_provider=provider,
    )

    orchestrator = PipelineOrchestrator(config)
    state = orchestrator.run()

    raise typer.Exit(code=0 if state.status.value in ("converged", "max_iterations", "stalled") else 1)
