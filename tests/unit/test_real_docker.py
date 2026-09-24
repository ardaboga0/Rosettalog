"""Docker helper behaviour with subprocess stubbed (no Docker needed)."""

from __future__ import annotations

import subprocess

import pytest

import rosettalog.verify.real.docker as docker
from rosettalog.verify.real.docker import Container, RealEngineError


class Proc:
    def __init__(self, out: str = "", code: int = 0) -> None:
        self.stdout, self.stderr, self.returncode = out, "", code


def test_healthy_parses_status(monkeypatch) -> None:
    monkeypatch.setattr(docker, "_run", lambda args, timeout=600: "running healthy\n")
    assert Container("c").healthy()
    monkeypatch.setattr(docker, "_run", lambda args, timeout=600: "running starting\n")
    assert not Container("c").healthy()


def test_healthy_raises_when_container_stopped(monkeypatch) -> None:
    """Regression: a Splunk container that exited during provisioning must fail fast."""
    monkeypatch.setattr(docker, "_run", lambda args, timeout=600: "exited \n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Proc("exited exit=2 oom=false"))
    with pytest.raises(RealEngineError, match="exit=2"):
        Container("c").healthy()


def test_container_is_always_removed_and_bound_to_loopback(monkeypatch) -> None:
    started: list[list[str]] = []
    removed: list[list[str]] = []
    monkeypatch.setattr(
        docker, "_run", lambda args, timeout=600: started.append(list(args)) or "id"
    )
    monkeypatch.setattr(subprocess, "run", lambda args, **k: removed.append(list(args)) or Proc())
    with pytest.raises(RuntimeError), docker.container("img:1", ports=[9200], env={"A": "b"}):
        raise RuntimeError("boom")
    run_args = started[0]
    assert "--rm" not in run_args
    published = [a for a in run_args if a.endswith("::9200")]
    assert published
    assert published[0].split(":")[0].startswith("127.")  # loopback only
    assert "rosettalog.verify=1" in run_args
    assert removed[-1][:3] == ["docker", "rm", "-f"]
