"""Sample log files used by the verification harness."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from rosettalog.errors import InputError


class Sample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    log: str
    expected: dict[str, str | None] | None = None
    """Optional expected values by canonical field name; ``null`` means "no value"."""


class SampleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    """Used as "now" (e.g. to fill in the year for formats without one)."""
    samples: list[Sample]

    def label(self, index: int) -> str:
        return self.samples[index].name or f"sample {index + 1}"


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
