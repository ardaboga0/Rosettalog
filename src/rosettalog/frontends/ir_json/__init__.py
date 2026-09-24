"""Frontend for Rosettalog IR serialized as JSON (``*.ir.json``).

Reads what ``rosettalog inspect`` prints (one artifact, or a JSON list of artifacts). It lets
other tools, and tests, hand artifacts to the backends without a source-SIEM frontend. The IR is
validated strictly; the artifacts keep the ``source_format`` they declare, so the declared
source's assumption registry applies to them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from pydantic import TypeAdapter, ValidationError

from rosettalog.ir import Artifact, Finding, Provenance, Status

_ADAPTER = TypeAdapter(list[Artifact])


class IrJsonFrontend:
    name: ClassVar[str] = "rosettalog-ir"
    description: ClassVar[str] = (
        "Rosettalog IR as JSON (*.ir.json), e.g. from 'rosettalog inspect'."
    )

    def accepts(self, path: Path) -> bool:
        return path.name.endswith(".ir.json")

    def parse(self, path: Path) -> list[Artifact]:
        try:
            data = json.loads(path.read_text("utf-8"))
            return _ADAPTER.validate_python(data if isinstance(data, list) else [data])
        except (OSError, ValueError, ValidationError) as exc:
            return [
                Artifact(
                    id=path.name.removesuffix(".ir.json"),
                    name=path.name,
                    source_format="rosettalog-ir",
                    provenance=Provenance(file=str(path)),
                    findings=[
                        Finding(
                            status=Status.UNSUPPORTED,
                            code="IR_INVALID",
                            path="",
                            message=f"Not valid Rosettalog IR: {str(exc)[:2000]}",
                        )
                    ],
                )
            ]
