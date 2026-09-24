"""Sample log files used by the verification harness."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from rosettalog.errors import InputError
from rosettalog.verify.rule_samples import RuleSampleSet, is_rule_samples, parse_rule_samples


class Sample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    log: str
    expected: dict[str, str | None] | None = None
    """Optional expected values by canonical field name; ``null`` means "no value"."""
    ground_truth_source: str | None = None
    """Where ``expected`` comes from, e.g. "observed on QRadar CE 7.5", "derived from IBM docs",
    or "assumed". Free text; shown in the report next to every comparison."""


class SampleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    """Used as "now" (e.g. to fill in the year for formats without one)."""
    samples: list[Sample]

    def label(self, index: int) -> str:
        return self.samples[index].name or f"sample {index + 1}"


def ground_truth_problems(sample_set: SampleSet, fields: list[str] | None = None) -> list[str]:
    """Problems that prevent a sample set from serving as ground truth.

    Every sample needs ``expected`` and ``ground_truth_source``. If ``fields`` is given (the
    canonical fields a parser produces), ``expected`` must list each of them (``null`` = no value)
    and must not name fields the parser does not produce.
    """
    problems: list[str] = []
    for index, sample in enumerate(sample_set.samples):
        label = sample_set.label(index)
        if not sample.expected:
            problems.append(f"{label}: 'expected' is missing or empty")
        if not (sample.ground_truth_source or "").strip():
            problems.append(f"{label}: 'ground_truth_source' is missing")
        if fields is not None and sample.expected:
            missing = [f for f in fields if f not in sample.expected]
            unknown = [f for f in sample.expected if f not in fields]
            if missing:
                problems.append(f"{label}: 'expected' does not cover {', '.join(missing)}")
            if unknown:
                problems.append(f"{label}: 'expected' names unknown field(s) {', '.join(unknown)}")
    return problems


def load_sample_file(path: Path) -> SampleSet | RuleSampleSet:
    """Load log samples (for parsers) or rule sample events (for detections, key ``events``)."""
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InputError(f"Invalid samples file {path}: {exc}") from exc
    if is_rule_samples(data):
        return parse_rule_samples(data, path)
    return load_samples(path)


def load_samples(path: Path) -> SampleSet:
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
        sample_set = SampleSet.model_validate(data)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise InputError(f"Invalid samples file {path}: {exc}") from exc
    if sample_set.reference_time.tzinfo is None:
        sample_set = sample_set.model_copy(
            update={"reference_time": sample_set.reference_time.replace(tzinfo=UTC)}
        )
    return sample_set
