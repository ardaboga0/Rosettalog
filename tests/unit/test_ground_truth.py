"""Samples shipped with Rosettalog must be usable as ground truth."""

from __future__ import annotations

import pytest

from rosettalog.verify.emulators.source import SourceEmulator
from rosettalog.verify.samples import Sample, SampleSet, ground_truth_problems, load_samples
from tests.conftest import ROOT, parse_lsx, sample_sets

PAIRS = sample_sets()


def test_repo_has_sample_sets() -> None:
    assert len(PAIRS) >= 2


@pytest.mark.parametrize(("samples", "lsx"), PAIRS, ids=lambda p: str(p.relative_to(ROOT)))
def test_repo_samples_have_complete_ground_truth(samples, lsx) -> None:
    artifact = parse_lsx(lsx)
    assert artifact.parser is not None
    problems = ground_truth_problems(load_samples(samples), artifact.parser.fields())
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(("samples", "lsx"), PAIRS, ids=lambda p: str(p.relative_to(ROOT)))
def test_repo_expectations_match_current_source_semantics(samples, lsx) -> None:
    """If this fails after recording observed QRadar behaviour, an assumption is wrong:
    fix the frontend/emulator (and its finding), not the expected values."""
    artifact = parse_lsx(lsx)
    sample_set = load_samples(samples)
    emulator = SourceEmulator(artifact.parser)
    for index, sample in enumerate(sample_set.samples):
        got = emulator.extract(sample.log, now=sample_set.reference_time)
        diff = {
            k: {"expected": v, "emulated": got.get(k)}
            for k, v in (sample.expected or {}).items()
            if got.get(k) != v
        }
        assert not diff, f"{sample_set.label(index)}: {diff}"


def test_ground_truth_problems() -> None:
    sample_set = SampleSet(
        samples=[
            Sample(log="a"),
            Sample(
                log="b", expected={"UserName": "x", "Bogus": None}, ground_truth_source="assumed"
            ),
        ]
    )
    problems = ground_truth_problems(sample_set, ["UserName", "SourceIp"])
    assert problems == [
        "sample 1: 'expected' is missing or empty",
        "sample 1: 'ground_truth_source' is missing",
        "sample 2: 'expected' does not cover SourceIp",
        "sample 2: 'expected' names unknown field(s) Bogus",
    ]
    assert ground_truth_problems(sample_set) == problems[:2]


def test_confirmation_sample_log_matches_samples_yaml() -> None:
    """The file sent to QRadar and the file used by `rosettalog verify` must stay identical."""
    cases = sorted(p for p in (ROOT / "examples" / "confirmation").iterdir() if p.is_dir())
    assert len(cases) >= 13
    for case in cases:
        sent = (case / "sample.log").read_text(encoding="utf-8").splitlines()
        verified = [s.log for s in load_samples(case / "samples.yaml").samples]
        assert sent == verified, case.name
        assert (case / "extension.xml").is_file(), case.name
