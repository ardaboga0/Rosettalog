"""Harness and CLI behaviour for --engine real, with a fake real-engine session (no Docker)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

import pytest

from rosettalog.backends.elastic import ElasticBackend
from rosettalog.errors import InputError
from rosettalog.pipeline import run
from rosettalog.plugins import BackendResult, NotComparable, RealValue
from rosettalog.report import render_markdown
from rosettalog.verify.emulators.elastic import ElasticEmulator
from rosettalog.verify.harness import verify
from rosettalog.verify.samples import load_samples
from tests.conftest import EXAMPLES, parse_lsx

ACME = EXAMPLES / "acme_firewall"


class FakeSession:
    """Behaves like the emulator, except for one deliberately wrong field."""

    description = "fake engine 1.0 (test)"

    def __init__(self, wrong_field: str | None = None, not_comparable: str | None = None) -> None:
        self.wrong_field = wrong_field
        self.not_comparable = not_comparable

    def extract_batch(
        self, result: BackendResult, logs: Sequence[str], *, now: datetime
    ) -> list[dict[str, RealValue]]:
        em = ElasticEmulator(result)
        rows: list[dict[str, RealValue]] = []
        for log in logs:
            row: dict[str, RealValue] = dict(em.extract(log, now=now))
            if self.wrong_field:
                row[self.wrong_field] = "WRONG"
            if self.not_comparable:
                row[self.not_comparable] = NotComparable("engine clock")
            rows.append(row)
        return rows


def _verify(session: FakeSession):
    artifact = parse_lsx(ACME / "acme_fw.lsx.xml")
    result = ElasticBackend().generate(artifact, {})
    return verify(artifact, result, load_samples(ACME / "samples.yaml"), session)


def test_agreeing_real_engine_passes() -> None:
    v = _verify(FakeSession())
    assert v.passed == v.total == 4
    assert v.real_engine == "fake engine 1.0 (test)"
    assert all(c.has_real for s in v.samples for c in s.checks)
    assert not v.findings()


def test_divergence_is_reported_as_emulator_bug() -> None:
    v = _verify(FakeSession(wrong_field="source.ip"))
    codes = {f.code for f in v.findings()}
    assert {"VERIFY_EMULATOR_DIVERGENCE", "VERIFY_REAL_MISMATCH"} <= codes
    bug = next(f for f in v.findings() if f.code == "VERIFY_EMULATOR_DIVERGENCE")
    assert "Emulator bug" in bug.message
    assert bug.path == "field[SourceIp]"
    assert v.passed < v.total


def test_not_comparable_values_are_notes_not_failures() -> None:
    v = _verify(FakeSession(not_comparable="@timestamp"))
    assert v.passed == v.total
    notes = [f for f in v.findings() if f.code == "VERIFY_REAL_NOT_COMPARABLE"]
    assert notes
    assert notes[0].status.value == "FULL"


def test_real_engine_error_is_reported() -> None:
    class Broken(FakeSession):
        def extract_batch(self, result, logs, *, now):
            raise RuntimeError("engine rejected pipeline")

    v = _verify(Broken())
    assert v.real_error == "engine rejected pipeline"
    assert "VERIFY_REAL_ENGINE_ERROR" in {f.code for f in v.findings()}


def test_report_shows_real_engine_column(monkeypatch) -> None:
    import rosettalog.pipeline as pipeline_mod

    monkeypatch.setattr(pipeline_mod, "_open_sessions", lambda stack, targets, names: {
        "elastic": FakeSession(wrong_field="user.name")
    })  # fmt: skip
    report = run(
        [parse_lsx(ACME / "acme_fw.lsx.xml")],
        ["elastic"],
        samples=load_samples(ACME / "samples.yaml"),
        engine="real",
    )
    md = render_markdown(report)
    assert "**Real engine:** fake engine 1.0 (test)" in md
    assert "diverges from real engine" in md
    assert "| index-time |" in md


def test_engine_real_requires_samples_and_known_runner() -> None:
    artifact = parse_lsx(ACME / "acme_fw.lsx.xml")
    with pytest.raises(InputError, match="needs a samples file"):
        run([artifact], ["elastic"], engine="real")
    with pytest.raises(InputError, match="Unknown engine"):
        run([artifact], ["elastic"], engine="docker")
    with pytest.raises(InputError, match="Unknown runner"):
        run(
            [artifact],
            ["elastic"],
            engine="real",
            runner_names=["nope"],
            samples=load_samples(ACME / "samples.yaml"),
        )
