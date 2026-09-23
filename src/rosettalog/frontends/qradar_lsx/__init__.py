"""IBM QRadar Log Source Extension (LSX) frontend."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rosettalog.frontends.qradar_lsx.parser import LsxParser, is_lsx
from rosettalog.ir import Artifact


class QRadarLsxFrontend:
    name: ClassVar[str] = "qradar-lsx"
    description: ClassVar[str] = "IBM QRadar Log Source Extension XML (regex field extraction)"

    def accepts(self, path: Path) -> bool:
        return path.suffix.lower() == ".xml" and is_lsx(path)

    def parse(self, path: Path) -> list[Artifact]:
        return [LsxParser(path).parse()]


__all__ = ["QRadarLsxFrontend"]
