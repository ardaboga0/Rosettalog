"""Shared fixtures for opt-in real-engine tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack

import pytest

from rosettalog.plugins import RealEngineSession, get_runner
from rosettalog.verify.real.docker import docker_available


@pytest.fixture(scope="session")
def real_session(request: pytest.FixtureRequest) -> Iterator[Callable[[str], RealEngineSession]]:
    selected = [t for t in request.config.getoption("--real-targets").split(",") if t]
    stack = ExitStack()
    sessions: dict[str, RealEngineSession] = {}

    def get(target: str) -> RealEngineSession:
        if selected and target not in selected:
            pytest.skip(f"target {target} not selected (--real-targets)")
        if target not in sessions:
            runner = get_runner(target)
            reason = runner.unavailable_reason()
            if reason is not None:
                if reason == docker_available():
                    # Requested real-engine tests must not silently pass without Docker.
                    pytest.fail(f"real-engine tests requested but {reason}")
                pytest.skip(f"{runner.name}: {reason}")  # e.g. Kusto emulator on ARM
            sessions[target] = stack.enter_context(runner.session())
        return sessions[target]

    with stack:
        yield get
