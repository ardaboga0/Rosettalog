"""The assumption registry is the single source for reports, docs and confirmation cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rosettalog.cli import app
from rosettalog.frontends.qradar_lsx import assumptions as lsx_mod
from rosettalog.ir.assumptions import AssumptionSet
from tests.conftest import EXAMPLES, FIXTURES, ROOT

ASET = lsx_mod.lsx_assumptions()
GLOBAL_OPEN = [a.id for a in ASET.assumptions if a.scope == "global" and a.status != "confirmed"]


def test_generated_docs_are_up_to_date() -> None:
    for path, expected in lsx_mod.generated_docs(ROOT).items():
        assert path.read_text(encoding="utf-8") == expected, (
            f"{path.relative_to(ROOT)} is stale; run "
            "`uv run python -m rosettalog.frontends.qradar_lsx.docs_sync`"
        )


def test_every_case_has_an_assumption_and_vice_versa() -> None:
    case_dirs = {p.name for p in (ROOT / ASET.confirmation_dir).iterdir() if p.is_dir()}
    referenced = {a.case for a in ASET.assumptions}
    assert case_dirs == referenced
    ids = [a.id for a in ASET.assumptions]
    assert len(ids) == len(set(ids))


def test_per_artifact_assumptions_name_documented_findings() -> None:
    documented = (ROOT / "docs" / "findings-codes.md").read_text(encoding="utf-8")
    for a in ASET.assumptions:
        if a.scope == "per-artifact":
            assert a.findings, a.id
            for code in a.findings:
                assert f"`{code}`" in documented, (a.id, code)
        else:
            assert not a.findings, f"{a.id}: global assumptions are reported, not findings"


def _convert(tmp_path: Path, source: Path) -> dict:
    result = CliRunner().invoke(
        app, ["convert", str(source), "--to", "splunk", "-o", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    return json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))


def test_report_lists_unconfirmed_global_assumptions(tmp_path: Path) -> None:
    report = _convert(tmp_path, EXAMPLES / "acme_firewall" / "acme_fw.lsx.xml")
    listed = [a["id"] for a in report["unconfirmed_global_assumptions"]]
    assert listed == GLOBAL_OPEN
    assert len(listed) == 9
    assert all(a["scope"] == "global" for a in report["unconfirmed_global_assumptions"])
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "## Unconfirmed global assumptions" in md
    for a in ASET.assumptions:
        assert (f"| {a.id} |" in md) == (a.id in GLOBAL_OPEN)


def test_confirmed_assumption_drops_out_and_refuted_stays(tmp_path: Path, monkeypatch) -> None:
    changed = [
        a.model_copy(update={"status": "confirmed", "evidence": "observed"}) if a.id == "A02"
        else a.model_copy(update={"status": "refuted", "evidence": "observed"}) if a.id == "A07"
        else a
        for a in ASET.assumptions
    ]  # fmt: skip
    modified = AssumptionSet(
        source_format=ASET.source_format,
        confirmation_dir=ASET.confirmation_dir,
        assumptions=changed,
    )
    monkeypatch.setattr(lsx_mod, "lsx_assumptions", lambda: modified)
    import rosettalog.frontends.qradar_lsx as fe_pkg

    monkeypatch.setattr(fe_pkg, "lsx_assumptions", lambda: modified)
    report = _convert(tmp_path, FIXTURES / "tessivor_vpn.lsx.xml")
    listed = {a["id"]: a["status"] for a in report["unconfirmed_global_assumptions"]}
    assert "A02" not in listed
    assert listed["A07"] == "refuted"
    assert "REFUTED" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_no_assumptions_without_artifacts_of_that_format(tmp_path: Path) -> None:
    report = _convert(tmp_path, FIXTURES / "not_lsx.xml")
    assert report["unconfirmed_global_assumptions"] == []


def test_registry_rejects_unknown_keys() -> None:
    data = ASET.model_dump()
    data["assumptions"][0]["surprise"] = 1
    with pytest.raises(ValueError, match="surprise"):
        AssumptionSet.model_validate(data)
