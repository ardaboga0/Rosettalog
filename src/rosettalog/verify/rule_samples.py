"""Sample events for verifying detection rules.

A rule sample file holds already-parsed events (canonical field -> value) and, per rule, the
events it is expected to match:

.. code-block:: yaml

    reference_time: 2026-01-05T10:00:00Z
    ground_truth_source: assumed
    events:
      - id: e1
        fields: {SourceIp: 192.0.2.10, UserName: admin}
    expected:
      acme_admin_login: [e1]      # artifact id or rule name -> ids of the matching events
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from rosettalog.errors import InputError


class RuleEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    time: datetime | None = None
    """Event time; defaults to ``reference_time`` plus one second per position."""
    fields: dict[str, str] = Field(default_factory=dict)
    """Canonical field -> value. A field that is absent is "no value" (not an empty string)."""


class RuleSampleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ground_truth_source: str | None = None
    """Where ``expected`` comes from ("observed on QRadar CE x.y", "derived from IBM docs",
    "assumed")."""
    events: list[RuleEvent] = Field(min_length=1)
    expected: dict[str, list[str]] = Field(default_factory=dict)
    reference_data: dict[str, list[str]] = Field(default_factory=dict)
    """Contents of reference sets by name, for rules that test reference data."""

    @model_validator(mode="after")
    def _check(self) -> RuleSampleSet:
        ids = [e.id for e in self.events]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate event ids: {', '.join(dupes)}")
        for rule, hits in self.expected.items():
            unknown = [h for h in hits if h not in ids]
            if unknown:
                raise ValueError(f"expected[{rule}] names unknown event ids: {', '.join(unknown)}")
        return self

    def event_time(self, index: int) -> datetime:
        event = self.events[index]
        if event.time is not None:
            return event.time if event.time.tzinfo else event.time.replace(tzinfo=UTC)
        base = self.reference_time
        if base.tzinfo is None:
            base = base.replace(tzinfo=UTC)
        return base + timedelta(seconds=index)

    def expected_for(self, artifact_id: str, name: str) -> list[str] | None:
        if artifact_id in self.expected:
            return self.expected[artifact_id]
        return self.expected.get(name)


def rule_ground_truth_problems(samples: RuleSampleSet, rules: list[tuple[str, str]]) -> list[str]:
    """Problems preventing ``samples`` from serving as ground truth for ``rules`` (id, name)."""
    problems: list[str] = []
    if not (samples.ground_truth_source or "").strip():
        problems.append("'ground_truth_source' is missing")
    for artifact_id, name in rules:
        if samples.expected_for(artifact_id, name) is None:
            problems.append(f"'expected' has no entry for rule {artifact_id} ({name})")
    return problems


def is_rule_samples(data: object) -> bool:
    return isinstance(data, dict) and "events" in data


def parse_rule_samples(data: object, path: Path) -> RuleSampleSet:
    try:
        return RuleSampleSet.model_validate(data)
    except ValidationError as exc:
        raise InputError(f"Invalid rule samples file {path}: {exc}") from exc


def load_rule_samples(path: Path) -> RuleSampleSet:
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InputError(f"Invalid rule samples file {path}: {exc}") from exc
    return parse_rule_samples(data, path)
