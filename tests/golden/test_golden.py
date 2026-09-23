"""Golden tests pin the exact generated content. Regenerate with `pytest --update-golden`."""

from __future__ import annotations

from pathlib import Path

import pytest

from rosettalog.plugins import get_backend
from tests.conftest import EXAMPLES, FIXTURES, parse_lsx

GOLDEN = Path(__file__).parent
CASES = {
    "acme_fw": (EXAMPLES / "acme_firewall" / "acme_fw.lsx.xml", {"splunk": {"sourcetype": "acme:firewall"}}),
    "globex_vpn": (FIXTURES / "globex_vpn.lsx.xml", {}),
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("target", ["sentinel", "splunk"])
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
