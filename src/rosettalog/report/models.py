"""Migration report data model (serialized as JSON; rendered as Markdown)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, computed_field

from rosettalog.ir import Finding, Status
from rosettalog.plugins import DeploymentSetting
from rosettalog.verify.harness import VerificationResult

REPORT_SCHEMA_VERSION = "1"


class TargetReport(BaseModel):
    target: str
    status: Status
    findings: list[Finding] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    field_names: dict[str, str] = Field(default_factory=dict)
    settings: list[DeploymentSetting] = Field(default_factory=list)
    verification: VerificationResult | None = None


class ArtifactReport(BaseModel):
    id: str
    name: str
    source_file: str
    source_format: str
    source_findings: list[Finding] = Field(default_factory=list)
    targets: list[TargetReport] = Field(default_factory=list)


class MigrationReport(BaseModel):
    schema_version: str = REPORT_SCHEMA_VERSION
    tool_version: str
    generated_at: datetime
    inputs: list[str]
    targets: list[str]
    artifacts: list[ArtifactReport] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def summary(self) -> dict[str, dict[str, int]]:
        """Target -> status -> number of artifacts."""
        out = {t: {s.value: 0 for s in Status} for t in self.targets}
        for artifact in self.artifacts:
            for tr in artifact.targets:
                out[tr.target][tr.status.value] += 1
        return out

    def worst_status(self) -> Status:
        statuses = [tr.status for a in self.artifacts for tr in a.targets]
        return max(statuses, key=lambda s: s.rank, default=Status.FULL)
