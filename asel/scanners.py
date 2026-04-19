# asel/scanners.py
import json
import logging
import threading
import time as _time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import docker
from rich.console import Console

from .models import ScanFinding, ScannerType, Severity


class ScannerTimeoutError(Exception):
    """Raised when a scanner container exceeds its hard time limit.

    The pipeline must treat this as inconclusive — the previous findings
    should be preserved unchanged rather than treating missing results as fixed.
    """
    def __init__(self, scanner_name: str, timeout_secs: int):
        super().__init__(f"{scanner_name} timed out after {timeout_secs}s")
        self.scanner_name = scanner_name

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


_SEMGREP_TIMEOUT_SECS = 600  # 10-minute hard cap per scan

# Map Language values to focused semgrep rule packs — avoids downloading and running
# rules for irrelevant languages (e.g. Python/JS rules against a Java repo).
_SEMGREP_CONFIG: dict[str, str] = {
    "java-maven": "p/java",
    "java-gradle": "p/java",
}
_SEMGREP_CONFIG_DEFAULT = "auto"


class SemgrepScanner(BaseScanner):
    name = ScannerType.SEMGREP

    def __init__(self, language: str | None = None):
        self._config = _SEMGREP_CONFIG.get(language or "", _SEMGREP_CONFIG_DEFAULT)

    def run(self, repo_path: Path) -> list[ScanFinding]:
        client = docker.from_env()
        container = None
        timed_out = threading.Event()

        try:
            container = client.containers.run(
                "semgrep/semgrep:latest",
                command=[
                    "semgrep", "scan", f"--config={self._config}", "--json",
                    "--timeout", "30",           # max seconds per rule per file
                    "--timeout-threshold", "3",  # skip file after 3 rule timeouts
                    "/src",
                ],
                volumes={str(repo_path.resolve()): {"bind": "/src", "mode": "ro"}},
                detach=True,
            )

            def _kill():
                timed_out.set()
                try:
                    container.stop(timeout=2)
                except Exception:
                    pass

            # Keep the timer alive across both container.wait() AND container.logs().
            # Previously the timer was cancelled right after wait(), leaving logs()
            # unprotected — a blocking logs() call on a still-running container
            # could hang indefinitely.
            timer = threading.Timer(_SEMGREP_TIMEOUT_SECS, _kill)
            timer.start()
            try:
                try:
                    exit_info = container.wait(timeout=_SEMGREP_TIMEOUT_SECS + 60)
                except Exception:
                    if timed_out.is_set():
                        raise ScannerTimeoutError("semgrep", _SEMGREP_TIMEOUT_SECS)
                    raise
                if timed_out.is_set():
                    raise ScannerTimeoutError("semgrep", _SEMGREP_TIMEOUT_SECS)
                exit_code = exit_info["StatusCode"]
                if exit_code not in (0, 1):  # 1 = findings found (normal)
                    raise RuntimeError(f"semgrep exited with code {exit_code}")
                output = container.logs(stdout=True, stderr=False)
            finally:
                timer.cancel()

            if timed_out.is_set():
                raise ScannerTimeoutError("semgrep", _SEMGREP_TIMEOUT_SECS)

            data = json.loads(output)
            return [self._parse(r) for r in data.get("results", [])]
        except ScannerTimeoutError:
            raise
        except Exception as e:
            logger.exception("Semgrep scanner failed: %s", e)
            raise
        finally:
            if container:
                try:
                    container.remove(force=True)
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


_TRIVY_TIMEOUT_SECS = 600  # 10-minute hard cap; large repos (WebGoat, wrongsecrets) need 5-8 min


class TrivyScanner(BaseScanner):
    name = ScannerType.TRIVY

    def __init__(self, build_file: str = "pom.xml"):
        self._build_file = build_file

    def run(self, repo_path: Path) -> list[ScanFinding]:
        client = docker.from_env()
        container = None
        timed_out = threading.Event()

        try:
            container = client.containers.run(
                "ghcr.io/aquasecurity/trivy:latest",
                command=["fs", "--format", "json", "--quiet", "/workspace"],
                volumes={
                    str(repo_path.resolve()): {"bind": "/workspace", "mode": "ro"},
                    "asel-trivy-cache": {"bind": "/root/.cache/trivy", "mode": "rw"},
                },
                detach=True,
            )

            def _kill():
                timed_out.set()
                try:
                    container.stop(timeout=2)
                except Exception:
                    pass

            timer = threading.Timer(_TRIVY_TIMEOUT_SECS, _kill)
            timer.start()
            try:
                try:
                    exit_info = container.wait(timeout=_TRIVY_TIMEOUT_SECS + 60)
                except Exception:
                    if timed_out.is_set():
                        raise ScannerTimeoutError("trivy", _TRIVY_TIMEOUT_SECS)
                    raise
            finally:
                timer.cancel()

            if timed_out.is_set():
                raise ScannerTimeoutError("trivy", _TRIVY_TIMEOUT_SECS)

            exit_code = exit_info["StatusCode"]
            if exit_code not in (0, 1):  # 1 = vulnerabilities found (normal)
                raise RuntimeError(f"trivy exited with code {exit_code}")
            output = container.logs(stdout=True, stderr=False)
            data = json.loads(output)
            findings = []
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities") or []:
                    findings.append(self._parse(v))
            return findings
        except ScannerTimeoutError:
            raise
        except Exception as e:
            logger.exception("Trivy scanner failed: %s", e)
            raise
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _parse(self, v: dict) -> ScanFinding:
        return ScanFinding(
            scanner=ScannerType.TRIVY,
            severity=_TRIVY_SEV.get(v.get("Severity", "UNKNOWN"), Severity.INFO),
            rule_id=v.get("VulnerabilityID", "unknown"),
            file_path=self._build_file,
            line_number=None,
            title=v.get("Title", v.get("VulnerabilityID", "")),
            description=(
                f"{v.get('PkgName') or 'unknown'} {v.get('InstalledVersion') or '?'} → "
                f"{v.get('FixedVersion') or 'no fix'}. {v.get('Description', '')}"
            ),
            raw=v,
        )



class ScannerOrchestrator:
    _REGISTRY: dict[ScannerType, type[BaseScanner]] = {
        ScannerType.SEMGREP: SemgrepScanner,
        ScannerType.TRIVY: TrivyScanner,
    }

    def __init__(self, enabled: list[ScannerType], build_file: str = "pom.xml", language: str | None = None):
        scanners = []
        for s in enabled:
            if s not in self._REGISTRY:
                continue
            if s == ScannerType.TRIVY:
                scanners.append(TrivyScanner(build_file=build_file))
            elif s == ScannerType.SEMGREP:
                scanners.append(SemgrepScanner(language=language))
            else:
                scanners.append(self._REGISTRY[s]())
        self._scanners = scanners
        self._timeout_event = threading.Event()
        self._failure_event = threading.Event()
        self._scanner_times: dict[ScannerType, float] = {}

    @property
    def had_timeout(self) -> bool:
        return self._timeout_event.is_set()

    @property
    def had_failure(self) -> bool:
        return self._failure_event.is_set()

    @property
    def scanner_times(self) -> dict[ScannerType, float]:
        """Elapsed seconds per scanner from the most recent run() call."""
        return self._scanner_times

    def run(self, repo_path: Path) -> list[ScanFinding]:
        self._timeout_event.clear()
        self._failure_event.clear()
        self._scanner_times = {}
        times_lock = threading.Lock()

        for scanner in self._scanners:
            _step(f"[bold]{scanner.name.value}[/bold] scanning...")

        def _run_one(scanner: BaseScanner) -> list[ScanFinding]:
            t0 = _time.monotonic()
            for attempt in range(2):
                try:
                    results = scanner.run(repo_path)
                    elapsed = _time.monotonic() - t0
                    with times_lock:
                        self._scanner_times[scanner.name] = elapsed
                    _step(f"{scanner.name.value}: [bold]{len(results)}[/bold] finding(s) ({elapsed:.0f}s)")
                    return results
                except ScannerTimeoutError:
                    _step(f"[yellow]{scanner.name.value}: timed out — partial results only[/yellow]")
                    self._timeout_event.set()
                    return []
                except Exception:
                    if attempt == 0:
                        logger.warning("%s: transient failure, retrying in 10s", scanner.name.value)
                        _time.sleep(10)
                    else:
                        _step(f"[red]{scanner.name.value}: failed — skipping[/red]")
                        self._failure_event.set()
                        return []
            return []  # unreachable

        with ThreadPoolExecutor() as executor:
            result_lists = list(executor.map(_run_one, self._scanners))

        return [finding for results in result_lists for finding in results]
