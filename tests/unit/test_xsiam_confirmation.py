"""The XSIAM confirmation pack (examples/confirmation/xsiam) and its registry (unknowns.yaml)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from rosettalog.backends.xsiam import XsiamBackend
from rosettalog.backends.xsiam.unknowns import generated_docs, xsiam_unknowns
from rosettalog.ir import Finding, Status
from rosettalog.ir.assumptions import resolve_dependencies
from rosettalog.pipeline import run
from rosettalog.timefmt.joda import format_timestamp
from rosettalog.verify.emulators.xsiam import XsiamEmulator, parse_rule
from rosettalog.verify.samples import load_samples
from tests.conftest import ROOT, parse_lsx

ACME = ROOT / "examples" / "acme_firewall" / "acme_fw.lsx.xml"
PACK = ROOT / "examples" / "confirmation" / "xsiam"
UNKNOWNS = xsiam_unknowns().assumptions
CASES = sorted(p for p in PACK.iterdir() if p.is_dir())


def test_every_unknown_has_a_case_and_every_case_an_unknown() -> None:
    assert sorted(a.case for a in UNKNOWNS) == [c.name for c in CASES]
    assert xsiam_unknowns().confirmation_dir == "examples/confirmation/xsiam"
    assert [a.id for a in UNKNOWNS] == [f"X{n:02d}" for n in range(1, len(UNKNOWNS) + 1)]


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_case_emulates_to_expected(case: Path) -> None:
    rule = parse_rule((case / "rule.xif").read_text("utf-8"))
    assert rule.header["vendor"] == "rosettalog"
    samples = load_samples(case / "expected.yaml")
    logs = (case / "sample.log").read_text("utf-8").splitlines()
    assert logs == [s.log for s in samples.samples], "sample.log must match expected.yaml"
    now = samples.reference_time
    for sample in samples.samples:
        assert sample.ground_truth_source.startswith("assumed")
        row: dict[str, object] = {"_raw_log": sample.log}
        XsiamEmulator._run(rule, row, now)
        got = {k: None if row.get(k) is None else _text(row[k]) for k in sample.expected}
        assert got == sample.expected, sample.name


def _text(value: object) -> str:
    return format_timestamp(value) if isinstance(value, datetime) else str(value)


def test_generated_docs_are_in_sync() -> None:
    for path, text in generated_docs(ROOT).items():
        assert path.read_text("utf-8") == text, (
            f"{path} is stale; run `uv run python -m rosettalog.backends.xsiam.docs_sync`"
        )


def test_findings_follow_the_unknowns() -> None:
    backend = XsiamBackend()
    result = backend.generate(parse_lsx(ACME), {})
    linked = {f.code: f.depends_on.topic for f in result.findings if f.depends_on}
    assert linked["XSIAM_REGEXCAPTURE_SEMANTICS"] == "xsiam-regexcapture"
    assert linked["XSIAM_XDM_INTEGER_NORMALIZATION"] == "xsiam-to-integer"
    topics = {a.topic for a in backend.assumptions().assumptions}
    assert set(linked.values()) <= topics
    # every per-artifact unknown names the codes that depend on it
    for a in UNKNOWNS:
        if a.scope == "per-artifact":
            assert a.findings
            assert a.topic


def test_integer_normalisation_is_reported() -> None:
    result = XsiamBackend().generate(parse_lsx(ACME), {})
    ports = [f for f in result.findings if f.code == "XSIAM_XDM_INTEGER_NORMALIZATION"]
    assert {f.path for f in ports} == {"field[SourcePort]", "field[DestinationPort]"}
    assert all(f.status is Status.PARTIAL and '"0443" becomes 443' in f.message for f in ports)


def test_resolution_uses_every_registry() -> None:
    confirmed = xsiam_unknowns().model_copy(
        update={
            "assumptions": [
                a.model_copy(update={"status": "confirmed"}) if a.id == "X01" else a
                for a in UNKNOWNS
            ]
        }
    )
    result = XsiamBackend().generate(parse_lsx(ACME), {})
    finding = next(f for f in result.findings if f.code == "XSIAM_REGEXCAPTURE_SEMANTICS")
    [resolved] = resolve_dependencies([finding], [None, confirmed])
    assert resolved.status is Status.FULL
    [unresolved] = resolve_dependencies([finding], [None, xsiam_unknowns()])
    assert unresolved.status is Status.PARTIAL
    assert isinstance(unresolved, Finding)


def test_report_lists_open_global_xsiam_unknowns(tmp_path: Path) -> None:
    report = run([parse_lsx(ACME)], ["xsiam"], out_dir=tmp_path)
    ids = {a.id for a in report.unconfirmed_global_assumptions}
    assert {a.id for a in xsiam_unknowns().open_global()} <= ids
    assert {"X02", "X04"} <= ids
