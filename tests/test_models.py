# tests/test_models.py
import json
from datetime import datetime, timezone
from pathlib import Path
from asel.models import (
    RunConfig, BuildResult, BuildPhase, ErrorCategory,
    ScanFinding, ScannerType, Severity, PatchAttempt, PatchTarget,
    IterationSnapshot, RunState, RunStatus, BuildTrack, Language,
)


def test_run_config_defaults():
    cfg = RunConfig(repo_url="https://github.com/x/y", output_dir=Path("/tmp"))
    assert cfg.max_build_attempts == 5
    assert cfg.max_remediation_iterations is None
    assert cfg.stall_threshold == 2
    assert cfg.min_delta_to_continue == 1
    assert cfg.max_runtime_minutes == 60
    assert cfg.llm_model == "deepseek-chat"
    assert cfg.llm_provider == "deepseek"


def test_scan_finding_id_is_stable():
    f = ScanFinding(
        scanner=ScannerType.SEMGREP,
        severity=Severity.HIGH,
        rule_id="python.sql-injection",
        file_path="src/main.py",
        line_number=42,
        title="SQL Injection",
        description="User input in query",
        raw={},
    )
    assert f.id == f.id  # stable
    f2 = ScanFinding(
        scanner=ScannerType.SEMGREP,
        severity=Severity.HIGH,
        rule_id="python.sql-injection",
        file_path="src/main.py",
        line_number=42,
        title="SQL Injection",
        description="User input in query",
        raw={},
    )
    assert f.id == f2.id  # same inputs → same id


def test_run_state_serializes_to_json():
    state = RunState(
        run_id="test-run-1",
        repo_url="https://github.com/x/y",
        started_at=datetime.now(timezone.utc),
        build_track=BuildTrack.FULL,
        build_attempts=[],
        iterations=[],
        findings=[],
        final_finding_count={},
        status=RunStatus.RUNNING,
    )
    data = json.loads(state.model_dump_json())
    assert data["run_id"] == "test-run-1"
    assert data["status"] == "running"
