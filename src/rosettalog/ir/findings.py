"""Translation status and findings.

Every approximation, omission or unsupported construct must surface as a :class:`Finding`.
A finding with status ``FULL`` is an informational note: the element was translated
faithfully, but a reviewer should know something about it.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Status(StrEnum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Status.FULL: 0, Status.PARTIAL: 1, Status.UNSUPPORTED: 2}


class Variant(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Status
    message: str


class AssumptionDependency(BaseModel):
    """Makes a finding's status and text depend on a source-side assumption.

    Backends refer to the assumption by *topic* (e.g. ``value-whitespace``), so they stay
    independent of any source SIEM. The pipeline looks the topic up in the source frontend's
    assumption registry and picks the variant for the assumption's current status.
    """

    model_config = ConfigDict(frozen=True)

    topic: str
    unconfirmed: Variant
    confirmed: Variant
    refuted: Variant


class Finding(BaseModel):
    """A statement about how one element of an artifact was (or was not) translated."""

    model_config = ConfigDict(frozen=True)

    status: Status
    code: str
    """Stable, grep-able identifier, e.g. ``RE2_NO_LOOKAROUND`` (see docs/findings-codes.md)."""
    path: str
    """Element path inside the source artifact. Empty string means the whole artifact."""
    message: str
    suggestion: str | None = None
    target: str | None = None
    """Backend name the finding applies to, or ``None`` if it comes from the source side."""
    line: int | None = None
    """Line in the source file, when known."""
    depends_on: AssumptionDependency | None = None
    """If set, status and message follow the linked assumption (resolved by the pipeline)."""
    assumption_id: str | None = None
    """Registry id of the linked assumption once resolved (e.g. ``A06``)."""


def aggregate_status(findings: Iterable[Finding], *, produced_output: bool) -> Status:
    """Overall status of an artifact for one target.

    * UNSUPPORTED if nothing usable was produced or an artifact-level UNSUPPORTED finding exists.
    * PARTIAL if any element is PARTIAL or UNSUPPORTED (the exact parts are listed as findings).
    * FULL otherwise.
    """
    if not produced_output:
        return Status.UNSUPPORTED
    worst = Status.FULL
    for f in findings:
        if f.status is Status.UNSUPPORTED and f.path == "":
            return Status.UNSUPPORTED
        if f.status.rank > worst.rank:
            worst = Status.PARTIAL
    return worst
