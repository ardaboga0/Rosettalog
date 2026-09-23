"""Registry of semantic assumptions a frontend makes about its source SIEM.

Each frontend ships one data file (the single source of truth). From it come the
"Unconfirmed global assumptions" section of every report and the generated tables in the docs.
An assumption leaves the report automatically once its ``status`` becomes ``confirmed``.
"""

from __future__ import annotations

from importlib import resources
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

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
    status: AssumptionStatus = "unconfirmed"
    evidence: str | None = None
    """For confirmed or refuted assumptions: what was observed, where and when."""


class AssumptionSet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_format: str
    confirmation_dir: str
    """Repository path of the confirmation cases, e.g. ``examples/confirmation``."""
    assumptions: list[Assumption]

    def open_global(self) -> list[Assumption]:
        """Global assumptions that still need attention (unconfirmed or refuted)."""
        return [a for a in self.assumptions if a.scope == "global" and a.status != "confirmed"]


def load_assumption_set(package: str, resource: str) -> AssumptionSet:
    text = resources.files(package).joinpath(resource).read_text("utf-8")
    return AssumptionSet.model_validate(yaml.safe_load(text))
