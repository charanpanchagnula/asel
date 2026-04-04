# tests/test_scanners.py
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from asel.scanners import SemgrepScanner, TrivyScanner, GitleaksScanner, ScannerOrchestrator
from asel.models import ScannerType, Severity


SEMGREP_OUTPUT = json.dumps({
    "results": [{
        "check_id": "python.lang.security.audit.sqli",
        "path": "src/main/java/App.java",
        "start": {"line": 10},
        "extra": {
            "severity": "ERROR",
            "message": "SQL injection risk",
            "metadata": {},
        },
    }]
}).encode()

TRIVY_OUTPUT = json.dumps({
    "Results": [{
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2021-44228",
            "PkgName": "log4j-core",
            "Severity": "CRITICAL",
            "Title": "Log4Shell",
            "Description": "Remote code execution in Log4j",
            "InstalledVersion": "2.14.0",
            "FixedVersion": "2.17.0",
        }]
    }]
}).encode()

GITLEAKS_OUTPUT = json.dumps([{
    "RuleID": "aws-access-token",
    "File": "config/settings.properties",
    "StartLine": 5,
    "Description": "AWS Access Token",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
}]).encode()


def mock_docker_run(output: bytes):
    mock = MagicMock()
    mock.containers.run.return_value = output
    return mock


def test_semgrep_parses_findings(tmp_repo):
    with patch("asel.scanners.docker.from_env", return_value=mock_docker_run(SEMGREP_OUTPUT)):
        findings = SemgrepScanner().run(tmp_repo)
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.SEMGREP
    assert findings[0].rule_id == "python.lang.security.audit.sqli"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "src/main/java/App.java"
    assert findings[0].line_number == 10


def test_trivy_parses_findings(tmp_repo):
    with patch("asel.scanners.docker.from_env", return_value=mock_docker_run(TRIVY_OUTPUT)):
        findings = TrivyScanner().run(tmp_repo)
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.TRIVY
    assert findings[0].rule_id == "CVE-2021-44228"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].title == "Log4Shell"


def test_gitleaks_parses_findings(tmp_repo):
    with patch("asel.scanners.docker.from_env", return_value=mock_docker_run(GITLEAKS_OUTPUT)):
        findings = GitleaksScanner().run(tmp_repo)
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.GITLEAKS
    assert findings[0].rule_id == "aws-access-token"
    assert findings[0].severity == Severity.CRITICAL


def test_scanner_returns_empty_on_error(tmp_repo):
    with patch("asel.scanners.docker.from_env") as mock_docker:
        mock_docker.return_value.containers.run.side_effect = Exception("container failed")
        findings = SemgrepScanner().run(tmp_repo)
    assert findings == []


def test_orchestrator_aggregates_all_scanners(tmp_repo):
    with patch("asel.scanners.docker.from_env") as mock_docker:
        mock_docker.return_value.containers.run.side_effect = [
            SEMGREP_OUTPUT,
            TRIVY_OUTPUT,
            GITLEAKS_OUTPUT,
        ]
        from asel.models import ScannerType
        orchestrator = ScannerOrchestrator(enabled=[ScannerType.SEMGREP, ScannerType.TRIVY, ScannerType.GITLEAKS])
        findings = orchestrator.run(tmp_repo)
    assert len(findings) == 3
