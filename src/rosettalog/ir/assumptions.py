"""Registry of semantic assumptions a frontend makes about its source SIEM.

Each frontend ships one data file (the single source of truth). From it come the
"Unconfirmed global assumptions" section of every report and the generated tables in the docs.
An assumption leaves the report automatically once its ``status`` becomes ``confirmed``.
"""

from __future__ import annotations

from importlib import resources
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from rosettalog.ir.findings import Finding

AssumptionScope = Literal["global", "per-artifact"]
AssumptionStatus = Literal["unconfirmed", "confirmed", "refuted"]


class Assumption(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    case: str
    """Confirmation case directory name, e.g. ``02-single-group-without-eventname``."""
    question: str
    assumption: str
    """What Rosettalog currently does."""
    alternatives: str
    scope: AssumptionScope
    """``per-artifact``: a finding is emitted where the construct occurs (see ``findings``).
    ``global``: applies to every artifact; listed in every report while not confirmed."""
    findings: list[str] = Field(default_factory=list)
    topic: str | None = None
    """Source-independent name backends use to link findings to this assumption."""
    status: AssumptionStatus = "unconfirmed"
    evidence: str | None = None
    """For confirmed or refuted assumptions: what was observed, where and when."""

    @model_validator(mode="before")
    @classmethod
    def _drop_derived(cls, data: Any) -> Any:
        """Accept serialized reports: ``status_label`` is derived, not an input."""
        if isinstance(data, dict) and "status_label" in data:
            data = {k: v for k, v in data.items() if k != "status_label"}
        return data

    evidence_against: str | None = None
    """While unconfirmed: documented evidence that contradicts the current assumption. The
    behaviour stays unchanged until the assumption is observed on the source SIEM."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        """Status as shown in reports and docs, e.g. "unconfirmed, evidence against"."""
        if self.status == "unconfirmed" and self.evidence_against:
            return "unconfirmed, evidence against"
        return self.status


class AssumptionSet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_format: str
    confirmation_dir: str
    """Repository path of the confirmation cases, e.g. ``examples/confirmation``."""
    assumptions: list[Assumption]

    def open_global(self) -> list[Assumption]:
        """Global assumptions that still need attention (unconfirmed or refuted)."""
        return [a for a in self.assumptions if a.scope == "global" and a.status != "confirmed"]


def resolve_dependencies(findings: list[Finding], aset: AssumptionSet | None) -> list[Finding]:
    """Give findings that depend on an assumption the status and text for its current status."""
    by_topic = {a.topic: a for a in aset.assumptions if a.topic} if aset else {}
    out: list[Finding] = []
    for finding in findings:
        dep = finding.depends_on
        if dep is None:
            out.append(finding)
            continue
        assumption = by_topic.get(dep.topic)
        status = assumption.status if assumption else "unconfirmed"
        variant = {"unconfirmed": dep.unconfirmed, "confirmed": dep.confirmed,
                   "refuted": dep.refuted}[status]  # fmt: skip
        suffix = ""
        if assumption is not None:
            suffix = f" [Assumption {assumption.id}: {assumption.status_label}"
            if status == "unconfirmed" and assumption.evidence_against:
                suffix += f" - {assumption.evidence_against}"
            suffix += "]"
        out.append(
            finding.model_copy(
                update={
                    "status": variant.status,
                    "message": variant.message + suffix,
                    "assumption_id": assumption.id if assumption else None,
                }
            )
        )
    return out


def load_assumption_set(package: str, resource: str) -> AssumptionSet:
    text = resources.files(package).joinpath(resource).read_text("utf-8")
    return AssumptionSet.model_validate(yaml.safe_load(text))
