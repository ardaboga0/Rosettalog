"""Migration report (JSON + Markdown)."""

from __future__ import annotations

import json
from typing import Any

from rosettalog.report.markdown import render_markdown
from rosettalog.report.models import ArtifactReport, MigrationReport, TargetReport


def render_json(report: MigrationReport) -> str:
    return report.model_dump_json(indent=2) + "\n"


def json_schema() -> dict[str, Any]:
    return MigrationReport.model_json_schema(mode="serialization")


def json_schema_text() -> str:
    return json.dumps(json_schema(), indent=2) + "\n"


__all__ = [
    "ArtifactReport",
    "MigrationReport",
    "TargetReport",
    "json_schema",
    "json_schema_text",
    "render_json",
    "render_markdown",
]
