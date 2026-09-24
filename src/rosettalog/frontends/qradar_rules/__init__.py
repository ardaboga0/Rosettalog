"""IBM QRadar custom rules and building blocks.

The rule-export parser is **not implemented yet**: IBM publishes no schema for the rule XML in
content-management exports, and the encoding of test parameters must be confirmed on QRadar CE
first (see docs/rules-support-matrix.md). Until then this frontend accepts no files; it provides
the rule assumption registry, which applies to detection artifacts with
``source_format: qradar-rules`` (e.g. read from ``*.ir.json``).
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rosettalog.frontends.qradar_rules.assumptions import rule_assumptions
from rosettalog.ir import Artifact
from rosettalog.ir.assumptions import AssumptionSet

SOURCE_FORMAT = "qradar-rules"


class QRadarRulesFrontend:
    name: ClassVar[str] = "qradar-rules"
    description: ClassVar[str] = (
        "IBM QRadar custom rules / building blocks (export parser pending; use *.ir.json)"
    )

    def accepts(self, path: Path) -> bool:
        return False

    def parse(self, path: Path) -> list[Artifact]:
        return []

    def assumptions(self) -> AssumptionSet:
        return rule_assumptions()


__all__ = ["SOURCE_FORMAT", "QRadarRulesFrontend"]
