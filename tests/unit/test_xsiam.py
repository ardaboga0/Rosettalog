"""Cortex XSIAM backend (Parsing Rules), XQL regex dialect and emulator."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from rosettalog.backends.xsiam import XsiamBackend
from rosettalog.backends.xsiam.backend import xql_string, xsiam_field_name
from rosettalog.regex.xql import to_xql, xql_regex_literal
from rosettalog.verify.emulators.source import SourceEmulator
from rosettalog.verify.emulators.xsiam import XsiamEmulationError, XsiamEmulator, lex, parse_rule
from rosettalog.verify.harness import verify
from rosettalog.verify.samples import load_samples
from tests.conftest import ROOT, parse_lsx, sample_sets

NOW = datetime(2026, 6, 1, tzinfo=UTC)

# --- regex dialect ------------------------------------------------------------------------------


def test_groups_are_named_and_wrapped() -> None:
    x = to_xql(r"user=(\w+) src=(?<ip>\d+)")
    assert x.pattern == r"(?P<m>user=(?P<g1>\w+) src=(?P<g2>\d+))"
    assert x.groups == 2


def test_case_insensitive_flag_only_at_start() -> None:
    assert to_xql("abc", case_insensitive=True).pattern == "(?i)(?P<m>abc)"
    x = to_xql("a(?i)b")
    assert [i.code for i in x.issues] == ["XSIAM_REGEX_INLINE_FLAGS"]


@pytest.mark.parametrize(
    ("java", "code"), [(r"(?<=a)b", "RE2_NO_LOOKAROUND"), (r"(a)\1", "RE2_NO_BACKREFERENCE")]
)
def test_re2_limits_apply_and_name_xql(java: str, code: str) -> None:
    x = to_xql(java)
    assert x.pattern is None
    assert x.issues[-1].code == code
    assert "(XQL)" in x.issues[-1].message


def test_string_literals() -> None:
    assert xql_regex_literal(r'a"\d') == r'"a\"\d"'
    assert xql_string('say "hi"') == r'"say \"hi\""'
    for bad in ("ends\\", 'x\\"y', "two\nlines"):
        assert xql_string(bad) is None


@pytest.mark.parametrize(
    ("canonical", "column"),
    [("SourceIp", "source_ip"), ("SourceIpPostNAT", "source_ip_post_nat"), ("NetBIOSName", "net_bios_name"),
     ("DeviceTime", "_time"), ("EventName", "event_name"), ("My Custom-Field", "my_custom_field")],
)  # fmt: skip
def test_field_names(canonical: str, column: str) -> None:
    assert xsiam_field_name(canonical) == column


# --- backend output -----------------------------------------------------------------------------

ACME = ROOT / "examples" / "acme_firewall" / "acme_fw.lsx.xml"


def test_one_statement_with_case_sensitivity_and_cleanup() -> None:
    result = XsiamBackend().generate(parse_lsx(ACME), {"vendor": "acme", "product": "firewall"})
    f, _model = result.files
    text = f.content
    assert f.path == "acme_fw_lsx.xif"
    assert (
        '[INGEST:vendor="acme", product="firewall", target_dataset="acme_firewall_raw", no_hit=keep]'
        in text
    )
    # one statement (rules of a group run independently); the parser rejects a second one
    assert parse_rule(text).stages
    assert text.rstrip().endswith(";")
    assert "config case_sensitive = true" in text
    assert "| fields - _rl_p1" in text
    codes = {x.code for x in result.findings}
    assert {
        "XSIAM_UNVERIFIED_TARGET",
        "XSIAM_INGEST_TIME_DEPENDENCY",
        "XSIAM_REGEXCAPTURE_SEMANTICS",
    } <= codes
    assert result.settings[0].scope == "index-time"
    assert result.field_names["DeviceTime"] == "_time"


def test_match_group_selector_uses_one_statement(lsx) -> None:
    artifact = lsx(
        """
  <pattern id="A" xmlns=""><![CDATA[evt=(A\\w*)]]></pattern>
  <pattern id="B" xmlns=""><![CDATA[evt=(\\w+)]]></pattern>
  <pattern id="U" xmlns=""><![CDATA[user=(\\w+)]]></pattern>
  <match-group order="1" xmlns=""><matcher field="EventName" order="1" pattern-id="A" capture-group="1"/>
    <matcher field="UserName" order="1" pattern-id="U" capture-group="1"/></match-group>
  <match-group order="2" xmlns=""><matcher field="EventName" order="1" pattern-id="B" capture-group="1"/></match-group>
"""
    )
    result = XsiamBackend().generate(artifact, {})
    text = result.files[0].content
    assert "_rl_mg = if(" in text
    em = XsiamEmulator(result)
    event, user = "xdm.event.original_event_type", "xdm.source.user.username"
    assert em.extract("evt=ALPHA user=u1", now=NOW) == {event: "ALPHA", user: "u1"}
    # group 2 wins for BETA; UserName is only defined in group 1, so it gets no value (A01)
    assert em.extract("evt=BETA user=u2", now=NOW) == {event: "BETA", user: None}


# --- timestamps ---------------------------------------------------------------------------------


def time_rule(lsx, fmt: str):
    return lsx(
        f"""
  <pattern id="T" xmlns=""><![CDATA[ts="([^"]+)"]]></pattern>
  <match-group order="1" xmlns="">
    <matcher field="DeviceTime" order="1" pattern-id="T" capture-group="1" ext-data="{fmt}"/>
  </match-group>
"""
    )


@pytest.mark.parametrize(
    ("fmt", "value", "expected"),
    [
        ("MMM dd yyyy HH:mm:ss", "MAR 05 2026 09:07:03", "2026-03-05T09:07:03.000Z"),
        ("MMMM d yyyy h:mm:ss a", "September 5 2026 12:07:03 AM", "2026-09-05T00:07:03.000Z"),
        ("dd/MM/yy hh:mm:ss a Z", "05/03/26 01:02:03 pm +0300", "2026-03-05T10:02:03.000Z"),
        (
            "yyyy-MM-dd'T'HH:mm:ss.SSSZZ",
            "2026-03-05T09:07:03.120-02:00",
            "2026-03-05T11:07:03.120Z",
        ),
        ("MMM d HH:mm:ss", "Mar 5 09:07:03", "2026-03-05T09:07:03.000Z"),  # year from now()
        ("MMM dd yyyy HH:mm:ss", "Foo 05 2026 09:07:03", None),
    ],
)
def test_timestamps_match_the_source_emulator(
    lsx, fmt: str, value: str, expected: str | None
) -> None:
    artifact = time_rule(lsx, fmt)
    log = f'ts="{value}"'
    result = XsiamBackend().generate(artifact, {})
    assert XsiamEmulator(result).extract(log, now=NOW)["_time"] == expected
    assert SourceEmulator(artifact.parser).extract(log, now=NOW)["DeviceTime"] == expected  # type: ignore[arg-type]


def test_date_findings(lsx) -> None:
    codes = {f.code for f in XsiamBackend().generate(time_rule(lsx, "MMM d HH:mm:ss"), {}).findings}
    assert "XSIAM_YEAR_FROM_INGEST_TIME" in codes
    codes = {
        f.code for f in XsiamBackend().generate(time_rule(lsx, "dd/MM/yy HH:mm:ss"), {}).findings
    }
    assert "DATE_TWO_DIGIT_YEAR_PIVOT" in codes


# --- emulator strictness -------------------------------------------------------------------------


def test_emulator_rejects_unknown_constructs() -> None:
    header = '[INGEST:vendor="v", product="p", target_dataset="d", no_hit=keep]\n'
    with pytest.raises(XsiamEmulationError, match="stage 'filter'"):
        parse_rule(header + 'config case_sensitive = true | filter x = "a";')
    with pytest.raises(XsiamEmulationError, match="json_extract"):
        parse_rule(
            header + 'config case_sensitive = true | alter a = json_extract(_raw_log, "$.x");'
        )
    with pytest.raises(XsiamEmulationError, match="one statement"):
        parse_rule(header + "config case_sensitive = true | alter a = 1; alter b = 2;")


def test_string_lexing_keeps_backslashes() -> None:
    [tok] = lex(r'"a\d\"b"')
    assert tok.value == r'a\d"b'


# --- differential: every shipped sample set --------------------------------------------------------


@pytest.mark.parametrize(("samples", "lsx_path"), sample_sets(), ids=lambda p: str(Path(p).name))
def test_differences_from_qradar_are_explained(samples: Path, lsx_path: Path) -> None:
    """Where the XSIAM emulator differs from the QRadar source emulator, a finding must say why
    that field is affected (a dropped candidate, an untranslatable field or pattern)."""
    artifact = parse_lsx(lsx_path)
    result = XsiamBackend().generate(artifact, {})
    if not result.produced_output:
        pytest.skip("no output")
    outcome = verify(artifact, result, load_samples(samples))
    assert outcome.error is None, outcome.error
    explained = {
        f.path.split("field[")[-1].rstrip("]")
        for f in result.findings
        if f.code in ("CANDIDATE_DROPPED", "FIELD_NOT_TRANSLATED")
        or f.status.value == "UNSUPPORTED"
    }
    affected = " ".join(f.message for f in result.findings if f.status.value != "FULL")
    for s in outcome.samples:
        for c in s.checks:
            if not c.matches_source:
                assert c.field in explained or c.field in affected, f"{s.name}/{c.field}"


# --- M5b: Data Model Rules (XDM) ------------------------------------------------------------------

#: Every XDM name Rosettalog may emit, each checked against the published schema pages
#: (https://cortex-docs.paloaltonetworks.com/xsiam-data-model-schema/fields/...). Adding a name
#: to field_map.yaml requires checking the schema and extending this list.
VERIFIED_XDM = {
    "xdm.source.ipv4", "xdm.source.ipv6", "xdm.source.port",
    "xdm.target.ipv4", "xdm.target.ipv6", "xdm.target.port",
    "xdm.source.user.username",
    "xdm.source.host.mac_addresses", "xdm.target.host.mac_addresses",
    "xdm.event.original_event_type",
}  # fmt: skip


def test_xdm_column_only_uses_verified_schema_fields() -> None:
    from rosettalog.ir.fields import field_table

    used = {row["xdm"] for row in field_table().values() if row.get("xdm")}
    assert used <= VERIFIED_XDM


def test_data_model_rule(lsx) -> None:
    artifact = lsx(
        """
  <pattern id="S" xmlns=""><![CDATA[src=(\\S+) spt=(\\d+) mac=(\\S+) host=(\\S+)]]></pattern>
  <match-group order="1" xmlns="">
    <matcher field="SourceIp" order="1" pattern-id="S" capture-group="1"/>
    <matcher field="SourcePort" order="1" pattern-id="S" capture-group="2"/>
    <matcher field="SourceMAC" order="1" pattern-id="S" capture-group="3"/>
    <matcher field="HostName" order="1" pattern-id="S" capture-group="4"/>
  </match-group>
"""
    )
    result = XsiamBackend().generate(artifact, {"vendor": "acme", "product": "fw"})
    _rule, model = result.files
    assert model.path.endswith(".model.xif")
    assert '[MODEL: dataset="acme_fw_raw"]' in model.content
    assert "xdm.source.port = to_integer(source_port)" in model.content
    assert "xdm.source.host.mac_addresses = arraycreate(source_mac)" in model.content
    assert "host_name" not in model.content  # no XDM equivalent: stays raw
    [unmapped] = [f for f in result.findings if f.code == "FIELD_UNMAPPED"]
    assert "kept in the raw dataset as 'host_name'" in unmapped.message
    assert result.field_names == {
        "SourceIp": "xdm.source.ipv4",
        "SourcePort": "xdm.source.port",
        "SourceMAC": "xdm.source.host.mac_addresses",
        "HostName": "host_name",
    }
    values = XsiamEmulator(result).extract("src=192.0.2.1 spt=0443 mac=aa:bb host=h1", now=NOW)
    # to_integer() drops the leading zero: a real difference from QRadar's "0443"
    assert values == {
        "xdm.source.ipv4": "192.0.2.1",
        "xdm.source.port": "443",
        "xdm.source.host.mac_addresses": "aa:bb",
        "host_name": "h1",
    }


def test_model_must_target_the_parsed_dataset() -> None:
    result = XsiamBackend().generate(parse_lsx(ACME), {})
    bad = [
        f.model_copy(update={"content": f.content.replace('dataset="', 'dataset="x')})
        if f.path.endswith(".model.xif")
        else f
        for f in result.files
    ]
    with pytest.raises(XsiamEmulationError, match="parsed dataset"):
        XsiamEmulator(result.model_copy(update={"files": bad}))
