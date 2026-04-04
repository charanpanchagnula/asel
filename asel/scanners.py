# asel/scanners.py
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path

import docker

from .models import ScanFinding, ScannerType, Severity

logger = logging.getLogger(__name__)

_SEMGREP_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.INFO}
_TRIVY_SEV = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}


class BaseScanner(ABC):
    name: ScannerType

    @abstractmethod
    def run(self, repo_path: Path) -> list[ScanFinding]:
        """Run the scanner against the repo. Returns findings; never raises."""
        ...


class SemgrepScanner(BaseScanner):
    name = ScannerType.SEMGREP

    def run(self, repo_path: Path) -> list[ScanFinding]:
        try:
            client = docker.from_env()
            output = client.containers.run(
                "semgrep/semgrep:latest",
                command=["semgrep", "scan", "--config=auto", "--json", "/src"],
                volumes={str(repo_path): {"bind": "/src", "mode": "ro"}},
                remove=True,
                stderr=False,
            )
            data = json.loads(output)
            return [self._parse(r) for r in data.get("results", [])]
        except Exception as e:
            logger.warning("Semgrep scanner failed: %s", e)
            return []

    def _parse(self, r: dict) -> ScanFinding:
        sev_str = r.get("extra", {}).get("severity", "INFO").upper()
        return ScanFinding(
            scanner=ScannerType.SEMGREP,
            severity=_SEMGREP_SEV.get(sev_str, Severity.INFO),
            rule_id=r.get("check_id", "unknown"),
            file_path=r.get("path", ""),
            line_number=r.get("start", {}).get("line"),
            title=r.get("extra", {}).get("message", "")[:120],
            description=r.get("extra", {}).get("message", ""),
            raw=r,
        )


class TrivyScanner(BaseScanner):
    name = ScannerType.TRIVY

    def run(self, repo_path: Path) -> list[ScanFinding]:
        try:
            client = docker.from_env()
            output = client.containers.run(
                "aquasec/trivy:latest",
                command=["fs", "--format", "json", "/workspace"],
                volumes={str(repo_path): {"bind": "/workspace", "mode": "ro"}},
                remove=True,
                stderr=False,
            )
            data = json.loads(output)
            findings = []
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities") or []:
                    findings.append(self._parse(v))
            return findings
        except Exception as e:
            logger.warning("Trivy scanner failed: %s", e)
            return []

    def _parse(self, v: dict) -> ScanFinding:
        return ScanFinding(
            scanner=ScannerType.TRIVY,
            severity=_TRIVY_SEV.get(v.get("Severity", "UNKNOWN"), Severity.INFO),
            rule_id=v.get("VulnerabilityID", "unknown"),
            file_path="pom.xml",
            line_number=None,
            title=v.get("Title", v.get("VulnerabilityID", "")),
            description=(
                f"{v.get('PkgName')} {v.get('InstalledVersion')} → "
                f"{v.get('FixedVersion', 'no fix')}. {v.get('Description', '')}"
            ),
            raw=v,
        )


class GitleaksScanner(BaseScanner):
    name = ScannerType.GITLEAKS

    def run(self, repo_path: Path) -> list[ScanFinding]:
        try:
            client = docker.from_env()
            output = client.containers.run(
                "ghcr.io/gitleaks/gitleaks:latest",
                command=["detect", "--source", "/path", "--report-format", "json",
                         "--report-path", "/dev/stdout", "--no-git"],
                volumes={str(repo_path): {"bind": "/path", "mode": "ro"}},
                remove=True,
                stderr=False,
            )
            data = json.loads(output)
            return [self._parse(r) for r in (data if isinstance(data, list) else [])]
        except Exception as e:
            logger.warning("Gitleaks scanner failed: %s", e)
            return []

    def _parse(self, r: dict) -> ScanFinding:
        return ScanFinding(
            scanner=ScannerType.GITLEAKS,
            severity=Severity.CRITICAL,
            rule_id=r.get("RuleID", "unknown"),
            file_path=r.get("File", ""),
            line_number=r.get("StartLine"),
            title=r.get("Description", "Secret detected"),
            description=f"{r.get('Description', '')} in {r.get('File', '')}",
            raw={k: v for k, v in r.items() if k != "Secret"},  # never log the secret
        )


class ScannerOrchestrator:
    _REGISTRY: dict[ScannerType, type[BaseScanner]] = {
        ScannerType.SEMGREP: SemgrepScanner,
        ScannerType.TRIVY: TrivyScanner,
        ScannerType.GITLEAKS: GitleaksScanner,
    }

    def __init__(self, enabled: list[ScannerType]):
        self._scanners = [self._REGISTRY[s]() for s in enabled if s in self._REGISTRY]

    def run(self, repo_path: Path) -> list[ScanFinding]:
        findings = []
        for scanner in self._scanners:
            logger.info("Running %s...", scanner.name.value)
            results = scanner.run(repo_path)
            logger.info("  %s: %d findings", scanner.name.value, len(results))
            findings.extend(results)
        return findings
