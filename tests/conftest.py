from __future__ import annotations

import os
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
    parser.addoption(
        "--real-engine",
        action="store_true",
        help="Run @pytest.mark.real_engine tests against real target engines (needs Docker; "
        "or set ROSETTALOG_REAL_ENGINE=1).",
    )
    parser.addoption(
        "--real-targets",
        default=os.environ.get("ROSETTALOG_REAL_TARGETS", ""),
        help="Comma-separated real-engine targets to test (default: all).",
    )


def real_engine_enabled(config: pytest.Config) -> bool:
    return (
        bool(config.getoption("--real-engine")) or os.environ.get("ROSETTALOG_REAL_ENGINE") == "1"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if real_engine_enabled(config):
        return
    skip = pytest.mark.skip(reason="real-engine test; enable with --real-engine")
    for item in items:
        if "real_engine" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def update_golden(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--update-golden"))


def parse_lsx(path: Path) -> Artifact:
    return LsxParser(path).parse()


def sample_sets() -> list[tuple[Path, Path]]:
    """Every samples file shipped in examples/ or tests/, paired with the LSX it verifies.

    Pairing rule: ``X.samples.yaml`` -> ``X.lsx.xml``; ``samples.yaml`` -> the only ``*.xml``
    in the same directory. A samples file that cannot be paired is an error.
    """
    pairs = []
    for base in (EXAMPLES, ROOT / "tests"):
        for path in sorted(base.rglob("*.yaml")):
            if path.name == "samples.yaml":
                xmls = sorted(path.parent.glob("*.xml"))
                assert len(xmls) == 1, f"{path}: expected exactly one *.xml next to it"
                pairs.append((path, xmls[0]))
            elif path.name.endswith(".samples.yaml"):
                lsx = path.with_name(path.name.removesuffix(".samples.yaml") + ".lsx.xml")
                assert lsx.exists(), f"{path}: missing {lsx.name}"
                pairs.append((path, lsx))
    return pairs


LSX_HEADER = '<?xml version="1.0"?>\n<device-extension xmlns="event_parsing/device_extension">\n'


@pytest.fixture
def lsx(tmp_path: Path):
    """Build an LSX file from pattern/match-group snippets and parse it."""

    def build(body: str, name: str = "test.lsx.xml") -> Artifact:
        path = tmp_path / name
        path.write_text(LSX_HEADER + body + "\n</device-extension>\n", encoding="utf-8")
        return parse_lsx(path)

    return build
