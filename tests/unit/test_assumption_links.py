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
    for status in ("unconfirmed", "confirmed", "refuted"):
        resolved = resolve_dependencies(result.findings, _with_status("A11", status))
        finding = _find(resolved, "DATE_TWO_DIGIT_YEAR_PIVOT")
        assert window in finding.message
        assert finding.message.endswith(f"[Assumption A11: {status}]")
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
    assert "appendTwoDigitYear" in a11.assumption
    assert a11.status == "unconfirmed"  # semantics frozen until observed on QRadar
