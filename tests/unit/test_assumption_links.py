"""Findings linked to assumptions follow the registry status automatically."""

from __future__ import annotations

import pytest

from rosettalog.backends.elastic import ElasticBackend
from rosettalog.backends.sentinel import SentinelBackend
from rosettalog.backends.splunk import SplunkBackend
from rosettalog.frontends.qradar_lsx.assumptions import lsx_assumptions
from rosettalog.ir import Status
from rosettalog.ir.assumptions import AssumptionSet, resolve_dependencies
from rosettalog.pipeline import run
from rosettalog.report import render_markdown
from tests.conftest import EXAMPLES, parse_lsx

CASE06 = EXAMPLES / "confirmation" / "06-trim-whitespace-value" / "extension.xml"
CASE10 = EXAMPLES / "confirmation" / "10-devicetime-two-digit-year" / "extension.xml"


def _with_status(assumption_id: str, status: str) -> AssumptionSet:
    aset = lsx_assumptions()
    return aset.model_copy(
        update={
            "assumptions": [
                a.model_copy(update={"status": status}) if a.id == assumption_id else a
                for a in aset.assumptions
            ]
        }
    )


def _find(findings, code):
    return next(f for f in findings if f.code == code)


@pytest.mark.parametrize(
    ("status", "expected_status", "phrase"),
    [
        ("unconfirmed", Status.PARTIAL, "only matters if QRadar preserves"),
        ("confirmed", Status.PARTIAL, "QRadar preserves it"),
        ("refuted", Status.FULL, "QRadar trims too"),
    ],
)
def test_splunk_trim_finding_follows_a06(status, expected_status, phrase) -> None:
    result = SplunkBackend().generate(parse_lsx(CASE06), {})
    resolved = resolve_dependencies(result.findings, _with_status("A06", status))
    finding = _find(resolved, "SPLUNK_VALUE_TRIMMED")
    assert finding.status is expected_status
    assert phrase in finding.message
    assert finding.message.endswith(f"[Assumption A06: {status}]")
    assert finding.assumption_id == "A06"


@pytest.mark.parametrize(
    ("backend", "window"),
    [
        (SplunkBackend(), "1969-2068"),
        (ElasticBackend(), "2000-2099"),
        (SentinelBackend(), "2000-2099"),
    ],
)
def test_two_digit_year_finding_per_target_linked_to_a11(backend, window) -> None:
    result = backend.generate(parse_lsx(CASE10), {})
    for status in ("confirmed", "refuted"):
        resolved = resolve_dependencies(result.findings, _with_status("A11", status))
        finding = _find(resolved, "DATE_TWO_DIGIT_YEAR_PIVOT")
        assert window in finding.message
        assert finding.message.endswith(f"[Assumption A11: {status}]")
    resolved = resolve_dependencies(result.findings, lsx_assumptions())
    finding = _find(resolved, "DATE_TWO_DIGIT_YEAR_PIVOT")
    assert "[Assumption A11: unconfirmed, evidence against - Joda-Time's default" in finding.message
    assert "1946-2045 in 2026" in finding.message
    confirmed = _find(resolve_dependencies(result.findings, _with_status("A11", "confirmed")),
                      "DATE_TWO_DIGIT_YEAR_PIVOT")  # fmt: skip
    expected = Status.FULL if window == "2000-2099" else Status.PARTIAL
    assert confirmed.status is expected
    unconfirmed = _find(resolve_dependencies(result.findings, lsx_assumptions()),
                        "DATE_TWO_DIGIT_YEAR_PIVOT")  # fmt: skip
    assert "sliding window" in unconfirmed.message


def test_report_resolves_links_from_the_registry() -> None:
    report = run([parse_lsx(CASE06)], ["splunk"])
    target = report.artifacts[0].targets[0]
    finding = _find(target.findings, "SPLUNK_VALUE_TRIMMED")
    assert finding.message.endswith("[Assumption A06: unconfirmed]")
    assert "[Assumption A06: unconfirmed]" in render_markdown(report)


def test_joda_two_digit_year_is_documented_in_a11() -> None:
    a11 = next(a for a in lsx_assumptions().assumptions if a.id == "A11")
    assert a11.topic == "two-digit-year-pivot"
    assert "appendTwoDigitYear" in (a11.evidence_against or "")
    assert a11.status == "unconfirmed"  # semantics frozen until observed on QRadar


def test_evidence_against_is_explicit_everywhere(tmp_path) -> None:
    import json

    from typer.testing import CliRunner

    from rosettalog.cli import app

    a11 = next(a for a in lsx_assumptions().assumptions if a.id == "A11")
    assert a11.status == "unconfirmed"
    assert a11.status_label == "unconfirmed, evidence against"
    assert "1946-2045 in 2026" in (a11.evidence_against or "")
    assert json.loads(a11.model_dump_json())["status_label"] == "unconfirmed, evidence against"
    # Docs tables (generated from the registry):
    from tests.conftest import ROOT

    matrix = (ROOT / "docs" / "lsx-support-matrix.md").read_text(encoding="utf-8")
    assert "**unconfirmed, evidence against**" in matrix
    # Report JSON + Markdown for an artifact with a two-digit year:
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["convert", str(CASE10), "--to", "sentinel", "-o", str(out)])
    assert result.exit_code == 0, result.output
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "[Assumption A11: unconfirmed, evidence against" in md
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    finding = next(
        f
        for f in report["artifacts"][0]["targets"][0]["findings"]
        if f["code"] == "DATE_TWO_DIGIT_YEAR_PIVOT"
    )
    assert finding["assumption_id"] == "A11"
    assert "evidence against" in finding["message"]


def test_global_assumption_with_evidence_against_is_rendered(monkeypatch) -> None:
    import rosettalog.frontends.qradar_lsx as fe_pkg
    from rosettalog.frontends.qradar_lsx import assumptions as lsx_mod

    aset = lsx_assumptions()
    changed = aset.model_copy(
        update={
            "assumptions": [
                a.model_copy(update={"evidence_against": "doc X says otherwise"})
                if a.id == "A02"
                else a
                for a in aset.assumptions
            ]
        }
    )
    monkeypatch.setattr(lsx_mod, "lsx_assumptions", lambda: changed)
    monkeypatch.setattr(fe_pkg, "lsx_assumptions", lambda: changed)
    md = render_markdown(run([parse_lsx(CASE06)], ["splunk"]))
    assert "| A02 | **unconfirmed, evidence against**: doc X says otherwise |" in md


def test_report_json_round_trips_with_status_label(tmp_path) -> None:
    """Regression: serialized status_label must not break reading report.json back."""
    from rosettalog.report import MigrationReport, render_json

    report = run([parse_lsx(CASE06)], ["splunk"])
    again = MigrationReport.model_validate_json(render_json(report))
    assert again.unconfirmed_global_assumptions == report.unconfirmed_global_assumptions


def test_splunk_pivot_finding_states_the_measurement() -> None:
    """Measured on Splunk 10.4.3 (real-engines run 35976943392): 50->2050, 68->2068, 69->1969."""
    result = SplunkBackend().generate(parse_lsx(CASE10), {})
    finding = _find(result.findings, "DATE_TWO_DIGIT_YEAR_PIVOT")
    assert "measured on Splunk 10.4.3" in finding.message
    assert "69 -> 1969" in finding.message
