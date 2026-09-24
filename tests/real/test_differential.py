"""Differential tests: target emulators vs real target engines (opt-in, needs Docker).

Run with ``uv run pytest -m real_engine --real-engine [--real-targets elastic,splunk]``.
Every shipped sample set (Acme, Tessivor, all confirmation cases) goes through the generated
content on the real engine; any disagreement with the emulator fails the test with the sample and
field. A fixed divergence must get a regression test in tests/unit/test_emulator_regressions.py.
"""

from __future__ import annotations

import pytest

from rosettalog.plugins import get_backend
from rosettalog.verify.harness import verify
from rosettalog.verify.samples import load_samples
from tests.conftest import ROOT, parse_lsx, sample_sets

TARGETS = ["elastic", "splunk", "sentinel"]
PAIRS = sample_sets()


@pytest.mark.real_engine
@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize(("samples", "lsx"), PAIRS, ids=lambda p: str(p.relative_to(ROOT)))
def test_emulator_agrees_with_real_engine(target, samples, lsx, real_session) -> None:
    session = real_session(target)
    artifact = parse_lsx(lsx)
    result = get_backend(target).generate(artifact, {})
    if not result.produced_output:
        pytest.skip("backend produced no output for this artifact")
    outcome = verify(artifact, result, load_samples(samples), session)
    assert outcome.real_error is None, outcome.real_error
    divergences = [
        f"{s.name} / {c.field}: emulator={c.target!r} real={c.real!r}"
        for s in outcome.samples
        for c in s.checks
        if c.emulator_diverges
    ]
    assert not divergences, "Emulator diverges from the real engine:\n" + "\n".join(divergences)
