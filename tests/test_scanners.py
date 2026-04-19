# tests/test_scanners.py
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from asel.scanners import SemgrepScanner, TrivyScanner, ScannerOrchestrator
from asel.models import ScanFinding, ScannerType, Severity


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


def mock_docker_run_detached(output: bytes, exit_code: int = 0):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": exit_code}
    container.logs.return_value = output
    mock = MagicMock()
    mock.containers.run.return_value = container
    return mock


@pytest.fixture
def tmp_repo(tmp_path):
    return tmp_path


def test_semgrep_parses_findings(tmp_repo):
    with patch("asel.scanners.docker.from_env", return_value=mock_docker_run_detached(SEMGREP_OUTPUT, exit_code=1)):
        findings = SemgrepScanner().run(tmp_repo)
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.SEMGREP
    assert findings[0].rule_id == "python.lang.security.audit.sqli"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "src/main/java/App.java"
    assert findings[0].line_number == 10


def test_trivy_parses_findings(tmp_repo):
    with patch("asel.scanners.docker.from_env", return_value=mock_docker_run_detached(TRIVY_OUTPUT, exit_code=0)):
        findings = TrivyScanner().run(tmp_repo)
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.TRIVY
    assert findings[0].rule_id == "CVE-2021-44228"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].title == "Log4Shell"


def test_scanner_raises_on_error(tmp_repo):
    with patch("asel.scanners.docker.from_env") as mock_docker:
        mock_docker.return_value.containers.run.side_effect = Exception("container failed")
        with pytest.raises(Exception, match="container failed"):
            SemgrepScanner().run(tmp_repo)


def test_orchestrator_aggregates_all_scanners(tmp_repo):
    semgrep_f = ScanFinding(scanner=ScannerType.SEMGREP, severity=Severity.HIGH, rule_id="r1", file_path="f.java", title="t", description="d")
    trivy_f = ScanFinding(scanner=ScannerType.TRIVY, severity=Severity.CRITICAL, rule_id="CVE-1", file_path="pom.xml", title="t", description="d")

    with patch.object(SemgrepScanner, "run", return_value=[semgrep_f]), \
         patch.object(TrivyScanner, "run", return_value=[trivy_f]):
        orchestrator = ScannerOrchestrator(enabled=[ScannerType.SEMGREP, ScannerType.TRIVY])
        findings = orchestrator.run(tmp_repo)
    assert len(findings) == 2
    assert {f.scanner for f in findings} == {ScannerType.SEMGREP, ScannerType.TRIVY}
