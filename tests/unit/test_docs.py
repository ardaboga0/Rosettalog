"""Documentation must stay in sync with the codes the tool can emit."""

from __future__ import annotations

import re

from tests.conftest import ROOT

CODE = re.compile(
    r'"((?:LSX|RE2|REGEX|PCRE|ONIG|DATE|FIELD|KQL|ASIM|SPLUNK|ELASTIC|VERIFY|CANDIDATE|MATCHGROUP|TARGET|NO|EMULATION)_[A-Z0-9_]+)"'
)
NOT_CODES = {
    "ASIM_MANDATORY",
    # Environment variables of the Splunk image, not finding codes:
    "SPLUNK_GENERAL_TERMS",
    "SPLUNK_PASSWORD",
    "SPLUNK_START_ARGS",
}


def test_every_finding_code_is_documented() -> None:
    emitted = set()
    for path in (ROOT / "src").rglob("*.py"):
        emitted |= set(CODE.findall(path.read_text(encoding="utf-8")))
    documented = set(
        re.findall(r"`([A-Z0-9_]+)`", (ROOT / "docs" / "findings-codes.md").read_text())
    )
    missing = sorted(emitted - documented - NOT_CODES)
    assert not missing, f"undocumented finding codes: {missing}"
