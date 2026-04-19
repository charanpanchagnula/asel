# asel/environment.py
from pathlib import Path
from typing import Optional
import docker


class ExecutionEnvironment:
    """Wraps a Docker container for running build and scan commands."""

    def __init__(self, repo_path: Path, image: str):
        self.repo_path = repo_path.resolve()  # Docker requires absolute paths for volume mounts
        self.image = image
        self._client = docker.from_env()
        self._container = None

    def start(self) -> None:
        """Start the container with the repo mounted at /workspace."""
        self._container = self._client.containers.run(
            self.image,
            command=["tail", "-f", "/dev/null"],  # keep alive
            volumes={
                str(self.repo_path): {"bind": "/workspace", "mode": "rw"},
                "asel-maven-cache": {"bind": "/root/.m2", "mode": "rw"},
                "asel-gradle-cache": {"bind": "/root/.gradle", "mode": "rw"},
            },
            working_dir="/workspace",
            detach=True,
            mem_limit="2g",
            network_mode="bridge",
        )

    def run(self, command: list[str], timeout_seconds: int | None = None) -> tuple[int, str]:
        """Run a command inside the container. Returns (exit_code, combined output).

        If timeout_seconds is set and the command exceeds it, the exec is killed
        and exit_code 124 is returned (same convention as the Unix `timeout` command).
        """
        if self._container is None:
            raise RuntimeError("Container not started — call start() first")

        if timeout_seconds is not None:
            command = ["timeout", str(timeout_seconds)] + command

        result = self._container.exec_run(
            command,
            workdir="/workspace",
            demux=True,
        )
        stdout = (result.output[0] or b"").decode("utf-8", errors="replace")
        stderr = (result.output[1] or b"").decode("utf-8", errors="replace")
        return result.exit_code, stdout + stderr

    def stop(self) -> None:
        """Stop and remove the container."""
        if self._container:
            self._container.stop()
            self._container.remove()
            self._container = None
