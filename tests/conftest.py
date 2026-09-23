from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from rosettalog.frontends.qradar_lsx.parser import LsxParser
from rosettalog.ir import Artifact

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "lsx"
EXAMPLES = ROOT / "examples"
NOW = datetime(2026, 6, 1, tzinfo=UTC)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        help="Rewrite golden files in tests/golden from the current output.",
    )


@pytest.fixture
def update_golden(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--update-golden"))


def parse_lsx(path: Path) -> Artifact:
    return LsxParser(path).parse()


LSX_HEADER = '<?xml version="1.0"?>\n<device-extension xmlns="event_parsing/device_extension">\n'


@pytest.fixture
def lsx(tmp_path: Path):
    """Build an LSX file from pattern/match-group snippets and parse it."""

    def build(body: str, name: str = "test.lsx.xml") -> Artifact:
        path = tmp_path / name
        path.write_text(LSX_HEADER + body + "\n</device-extension>\n", encoding="utf-8")
        return parse_lsx(path)

    return build
