# asel/cli.py
import logging
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
import typer
from rich.console import Console

load_dotenv()

from .models import RunConfig
from .pipeline import PipelineOrchestrator

app = typer.Typer(help="Autonomous Security Execution Lab — build, scan, remediate.")
console = Console()


@app.command()
def run(
    repo_url: str = typer.Argument(..., help="Git repository URL to analyze"),
    output_dir: Path = typer.Option(Path("./asel-runs"), help="Directory for run artifacts"),
    max_build_attempts: int = typer.Option(5, help="Max build stabilization attempts"),
    max_findings_to_remediate: int = typer.Option(5, help="Only attempt the top-N findings by severity"),
    max_remediation_iters: Optional[int] = typer.Option(None, help="Hard ceiling on remediation iterations (default: findings × 2)"),
    stall_threshold: int = typer.Option(2, help="Stop after N zero-delta iterations"),
    max_runtime_minutes: int = typer.Option(60, help="Wall clock limit for entire run"),
    final_test_timeout: int = typer.Option(5, help="Minutes before killing the final unit test run"),
    model: str = typer.Option("deepseek-chat", help="LLM model identifier"),
    provider: str = typer.Option("deepseek", help="LLM provider (deepseek, openai, anthropic)"),
    exploit_engine: bool = typer.Option(False, "--exploit-engine", help="Enable agentic DAST (adds significant runtime)"),
    exploit_model: Optional[str] = typer.Option(None, help="Model for exploit engine (defaults to --model)"),
    exploit_provider: Optional[str] = typer.Option(None, help="Provider for exploit engine (defaults to --provider)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug logs"),
) -> None:
    """Clone, build, scan, and remediate a Java/Maven repository."""
    if verbose:
        # Only show DEBUG for asel itself — suppress noise from http/docker libs
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
        logging.getLogger("asel").setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
        logging.getLogger("asel").setLevel(logging.INFO)

    config = RunConfig(
        repo_url=repo_url,
        output_dir=output_dir,
        max_build_attempts=max_build_attempts,
        max_findings_to_remediate=max_findings_to_remediate,
        max_remediation_iterations=max_remediation_iters,
        stall_threshold=stall_threshold,
        max_runtime_minutes=max_runtime_minutes,
        final_test_timeout_minutes=final_test_timeout,
        llm_model=model,
        llm_provider=provider,
        enable_exploit_engine=exploit_engine,
        exploit_model=exploit_model or model,
        exploit_provider=exploit_provider or provider,
    )

    orchestrator = PipelineOrchestrator(config)
    state = orchestrator.run()

    raise typer.Exit(code=0 if state.status.value in ("converged", "max_iterations", "stalled") else 1)
