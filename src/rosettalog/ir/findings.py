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
