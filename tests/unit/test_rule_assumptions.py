"""The rule assumption registry, its generated doc tables and its QRadar CE confirmation cases."""

from __future__ import annotations

from datetime import timedelta

import pytest

from rosettalog.frontends.qradar_rules.assumptions import generated_docs, rule_assumptions
from rosettalog.pipeline import assumption_set, load_artifacts
from rosettalog.verify.emulators.source import SourceEmulator
from rosettalog.verify.rule_samples import load_rule_samples
from tests.conftest import NOW, ROOT, parse_lsx

ASET = rule_assumptions()
CASES = ROOT / ASET.confirmation_dir


def test_docs_are_generated_from_the_registry() -> None:
    for path, content in generated_docs(ROOT).items():
        assert path.read_text("utf-8") == content, (
            f"{path} is stale; run uv run python -m rosettalog.frontends.qradar_rules.docs_sync"
        )


def test_every_assumption_has_a_case_and_every_case_an_assumption() -> None:
    dirs = {p.name for p in CASES.iterdir() if p.is_dir()}
    assert {a.case for a in ASET.assumptions} == dirs
    assert len({a.id for a in ASET.assumptions}) == len(ASET.assumptions)
    assert all(a.topic for a in ASET.assumptions)


def test_registry_applies_to_qradar_rules_artifacts() -> None:
    assert assumption_set("qradar-rules") == ASET


@pytest.mark.parametrize("case", sorted(a.case for a in ASET.assumptions))
def test_case_files_agree(case: str) -> None:
    """sample.log (what is sent) parses to exactly the events in samples.yaml, in order, and the
    '# sleep N' pauses match the event times; every rule in rule.ir.json has expected hits."""
    directory = CASES / case
    emulator = SourceEmulator(parse_lsx(CASES / "rl-rules.lsx.xml").parser)  # type: ignore[arg-type]
    samples = load_rule_samples(directory / "samples.yaml")
    parsed, offsets, t = [], [], 0
    for line in (directory / "sample.log").read_text("utf-8").splitlines():
        if line.startswith("# sleep "):
            t += int(line.removeprefix("# sleep "))
            continue
        assert f" rl-rules-{case[:2]} " in line, line
        fields = {k: v for k, v in emulator.extract(line, now=NOW).items() if v is not None}
        parsed.append(fields)
        offsets.append(t)
        t += 1
    assert parsed == [e.fields for e in samples.events]
    if any(e.time is not None for e in samples.events):
        start = samples.event_time(0)
        assert [samples.event_time(i) - start for i in range(len(parsed))] == [
            timedelta(seconds=o - offsets[0]) for o in offsets
        ]
    rules = load_artifacts([directory / "rule.ir.json"])
    assert {a.id for a in rules} == set(samples.expected)
    assert samples.ground_truth_source is not None
    assert samples.ground_truth_source.startswith("assumed")
