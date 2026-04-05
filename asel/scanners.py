# asel/scanners.py
import json
import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import docker
from rich.console import Console

from .models import ScanFinding, ScannerType, Severity

_console = Console()


def _step(msg: str) -> None:
    _console.print(f"[dim]{datetime.now(timezone.utc).strftime('%H:%M:%S')}[/dim]    {msg}")

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


_SEMGREP_TIMEOUT_SECS = 600  # 10-minute hard cap per scan; normal scans take <6 min


class SemgrepScanner(BaseScanner):
    name = ScannerType.SEMGREP

    def run(self, repo_path: Path) -> list[ScanFinding]:
        client = docker.from_env()
        container = None
        try:
            container = client.containers.run(
                "semgrep/semgrep:latest",
                command=[
                    "semgrep", "scan", "--config=auto", "--json",
                    "--timeout", "30",           # max seconds per rule per file
                    "--timeout-threshold", "3",  # skip file after 3 rule timeouts
                    "/src",
                ],
                volumes={str(repo_path.resolve()): {"bind": "/src", "mode": "ro"}},
                detach=True,
                stderr=False,
            )
            exit_info = container.wait(timeout=_SEMGREP_TIMEOUT_SECS)
            exit_code = exit_info["StatusCode"]
            if exit_code not in (0, 1):  # 1 = findings found (normal)
                raise RuntimeError(f"semgrep exited with code {exit_code}")
            output = container.logs(stdout=True, stderr=False)
            data = json.loads(output)
            return [self._parse(r) for r in data.get("results", [])]
        except Exception as e:
            logger.warning("Semgrep scanner failed: %s", e)
            return []
        finally:
            if container:
                try:
                    container.stop(timeout=5)
                except Exception:
                    pass
                try:
                    container.remove()
                except Exception:
                    pass

    def _parse(self, r: dict) -> ScanFinding:
        sev_str = r.get("extra", {}).get("severity", "INFO").upper()
        # Semgrep reports paths as /src/<path> — strip the mount prefix
        raw_path = r.get("path", "")
        file_path = raw_path.removeprefix("/src/")
        return ScanFinding(
            scanner=ScannerType.SEMGREP,
            severity=_SEMGREP_SEV.get(sev_str, Severity.INFO),
            rule_id=r.get("check_id", "unknown"),
            file_path=file_path,
            line_number=r.get("start", {}).get("line"),
            title=r.get("extra", {}).get("message", "")[:120],
            description=r.get("extra", {}).get("message", ""),
            raw=r,
        )


_TRIVY_TIMEOUT_SECS = 300  # 5-minute hard cap; normal scans take <2 min


class TrivyScanner(BaseScanner):
    name = ScannerType.TRIVY

    def run(self, repo_path: Path) -> list[ScanFinding]:
        client = docker.from_env()
        container = None
        try:
            container = client.containers.run(
                "ghcr.io/aquasecurity/trivy:latest",
                command=["fs", "--format", "json", "/workspace"],
                volumes={str(repo_path.resolve()): {"bind": "/workspace", "mode": "ro"}},
                detach=True,
                stderr=False,
            )
            exit_info = container.wait(timeout=_TRIVY_TIMEOUT_SECS)
            exit_code = exit_info["StatusCode"]
            if exit_code != 0:
                raise RuntimeError(f"trivy exited with code {exit_code}")
            output = container.logs(stdout=True, stderr=False)
            data = json.loads(output)
            findings = []
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities") or []:
                    findings.append(self._parse(v))
            return findings
        except Exception as e:
            logger.warning("Trivy scanner failed: %s", e)
            return []
        finally:
            if container:
                try:
                    container.stop(timeout=5)
                except Exception:
                    pass
                try:
                    container.remove()
                except Exception:
                    pass

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
        client = docker.from_env()
        container = None
        try:
            # Run detached so we can retrieve logs regardless of exit code.
            # Gitleaks exits 0 = no findings, 1 = findings found, >1 = error.
            container = client.containers.run(
                "ghcr.io/gitleaks/gitleaks:latest",
                command=["detect", "--source", "/path", "--report-format", "json",
                         "--report-path", "/dev/stdout", "--no-git"],
                volumes={str(repo_path.resolve()): {"bind": "/path", "mode": "ro"}},
                detach=True,
            )
            exit_info = container.wait()
            exit_code = exit_info["StatusCode"]
            if exit_code > 1:
                raise RuntimeError(f"gitleaks exited with code {exit_code}")
            output = container.logs(stdout=True, stderr=False)
            if not output or not output.strip():
                return []
            data = json.loads(output)
            return [self._parse(r) for r in (data if isinstance(data, list) else [])]
        except Exception as e:
            logger.warning("Gitleaks scanner failed: %s", e)
            return []
        finally:
            if container:
                try:
                    container.remove()
                except Exception:
                    pass

    def _parse(self, r: dict) -> ScanFinding:
        # Gitleaks reports paths as /path/<file> — strip the mount prefix
        raw_path = r.get("File", "")
        file_path = raw_path.removeprefix("/path/")
        return ScanFinding(
            scanner=ScannerType.GITLEAKS,
            severity=Severity.CRITICAL,
            rule_id=r.get("RuleID", "unknown"),
            file_path=file_path,
            line_number=r.get("StartLine"),
            title=r.get("Description", "Secret detected"),
            description=f"{r.get('Description', '')} in {file_path}",
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
        for scanner in self._scanners:
            _step(f"[bold]{scanner.name.value}[/bold] scanning...")

        def _run_one(scanner: BaseScanner) -> list[ScanFinding]:
            results = scanner.run(repo_path)
            _step(f"{scanner.name.value}: [bold]{len(results)}[/bold] finding(s)")
            return results

        with ThreadPoolExecutor() as executor:
            result_lists = list(executor.map(_run_one, self._scanners))

        return [finding for results in result_lists for finding in results]
