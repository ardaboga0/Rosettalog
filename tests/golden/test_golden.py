"""Golden tests pin the exact generated content. Regenerate with `pytest --update-golden`."""

from __future__ import annotations

from pathlib import Path

import pytest

from rosettalog.pipeline import load_artifacts
from rosettalog.plugins import get_backend
from tests.conftest import EXAMPLES, FIXTURES, parse_lsx

GOLDEN = Path(__file__).parent
CASES = {
    "acme_fw": (EXAMPLES / "acme_firewall" / "acme_fw.lsx.xml", {"splunk": {"sourcetype": "acme:firewall"}}),
    "tessivor_vpn": (FIXTURES / "tessivor_vpn.lsx.xml", {}),
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("target", ["sentinel", "splunk", "elastic"])
def test_golden(case: str, target: str, update_golden: bool) -> None:
    source, options = CASES[case]
    result = get_backend(target).generate(parse_lsx(source), options.get(target, {}))
    assert result.files
    for f in result.files:
        golden = GOLDEN / case / target / f.path
        if update_golden:
            golden.parent.mkdir(parents=True, exist_ok=True)
            golden.write_text(f.content, encoding="utf-8")
        assert golden.exists(), f"missing golden file {golden}; run pytest --update-golden"
        assert f.content == golden.read_text(encoding="utf-8"), f"{golden} differs"


RULES = EXAMPLES / "rules" / "acme_rules.ir.json"


def check_golden(path: Path, content: str, update_golden: bool) -> None:
    if update_golden:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    assert path.exists(), f"missing golden file {path}; run pytest --update-golden"
    assert content == path.read_text(encoding="utf-8"), f"{path} differs"


@pytest.mark.parametrize("queries", [False, True], ids=["sigma", "pysigma"])
def test_golden_sigma(queries: bool, update_golden: bool) -> None:
    """Sigma rules; with the pinned pySigma backends installed, also their converted queries."""
    options = {}
    if queries:
        pytest.importorskip("sigma.backends.splunk")
        options = {"pysigma_targets": "splunk,kusto,lucene,esql"}
    for artifact in load_artifacts([RULES]):
        result = get_backend("sigma").generate(artifact, options)
        for f in result.files:
            if queries != f.path.endswith(".yml"):
                check_golden(GOLDEN / "rules" / "sigma" / f.path, f.content, update_golden)
