"""Minimal Docker CLI wrapper for real-engine runners (no Python Docker dependency).

Containers are labelled ``rosettalog.verify=1``, publish ports on 127.0.0.1 only, and are always
removed when the context exits.
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

from rosettalog.errors import RosettalogError

LABEL = "rosettalog.verify=1"


class RealEngineError(RosettalogError):
    pass


def docker_available() -> str | None:
    """``None`` if a Docker daemon is reachable, otherwise the reason."""
    if shutil.which("docker") is None:
        return "the docker CLI is not installed"
    proc = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return "no Docker daemon is reachable: " + (proc.stderr.strip() or "docker info failed")
    return None


def docker_arch() -> str:
    proc = subprocess.run(
        ["docker", "info", "--format", "{{.Architecture}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _run(args: Sequence[str], *, timeout: float = 600) -> str:
    proc = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout
    )
    if proc.returncode != 0:
        raise RealEngineError(f"docker {' '.join(args[:2])} failed: {proc.stderr.strip()}")
    return proc.stdout


@dataclass
class Container:
    name: str

    def host_port(self, container_port: int) -> int:
        out = _run(["port", self.name, f"{container_port}/tcp"])
        # e.g. "127.0.0.1:55012"
        return int(out.strip().splitlines()[0].rsplit(":", 1)[1])

    def exec(self, *args: str, user: str | None = None, timeout: float = 600) -> str:
        opts = ["-u", user] if user else []
        return _run(["exec", *opts, self.name, *args], timeout=timeout)

    def copy_in(self, source: str, dest: str) -> None:
        _run(["cp", source, f"{self.name}:{dest}"])

    def healthy(self) -> bool:
        """True once the image's HEALTHCHECK reports healthy; raises if the container stopped."""
        out = _run(
            [
                "inspect",
                "-f",
                "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                self.name,
            ]
        )
        status, _, health = out.strip().partition(" ")
        if status != "running":
            raise RealEngineError(f"container {self.name} is {self.state()}")
        return health == "healthy"

    def state(self) -> str:
        proc = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}",
                self.name,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.stdout.strip() or proc.stderr.strip()

    def logs_tail(self, lines: int = 40) -> str:
        proc = subprocess.run(
            ["docker", "logs", "--tail", str(lines), self.name],
            capture_output=True,
            text=True,
            check=False,
        )
        return (proc.stdout + proc.stderr)[-4000:]


@contextmanager
def container(
    image: str,
    *,
    ports: Sequence[int],
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    memory: str | None = None,
    prefix: str = "rosettalog",
) -> Iterator[Container]:
    name = f"{prefix}-{secrets.token_hex(4)}"
    # No --rm: if the engine exits unexpectedly, its state and logs stay inspectable until the
    # context removes the container in `finally`.
    args = ["run", "-d", "--name", name, "--label", LABEL]
    if platform:
        args += ["--platform", platform]
    if memory:
        args += ["-m", memory]
    for key, value in (env or {}).items():
        args += ["-e", f"{key}={value}"]
    for port in ports:
        args += ["-p", f"127.0.0.1::{port}"]
    _run([*args, image])
    try:
        yield Container(name)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def http_json(
    method: str,
    url: str,
    body: object | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = 120,
) -> object:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:2000]
        raise RealEngineError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc


def wait_until(
    check: Callable[[], bool], *, timeout: float, what: str, interval: float = 2
) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, RealEngineError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(interval)
    raise RealEngineError(f"timed out after {timeout:.0f}s waiting for {what}. {last_error}")
