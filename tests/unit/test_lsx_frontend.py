from __future__ import annotations

from rosettalog.frontends.qradar_lsx import QRadarLsxFrontend
from rosettalog.ir import Capture, Coalesce, IfMatch, Lookup, ParseTime, Status, Template
from tests.conftest import FIXTURES, parse_lsx


def codes(artifact) -> dict[str, Status]:
    return {f.code: f.status for f in artifact.findings}


def test_accepts_only_lsx() -> None:
    fe = QRadarLsxFrontend()
    assert fe.accepts(FIXTURES / "globex_vpn.lsx.xml")
    assert not fe.accepts(FIXTURES / "not_lsx.xml")
    # A truncated LSX is still claimed by this frontend, which then reports LSX_INVALID_XML.
    assert fe.accepts(FIXTURES / "broken.xml")
    assert not fe.accepts(FIXTURES / "globex_vpn.samples.yaml")


def test_matcher_order_becomes_coalesce(lsx) -> None:
    a = lsx(
        """
<pattern id="A" xmlns=""><![CDATA[a=(\\w+)]]></pattern>
<pattern id="B" xmlns=""><![CDATA[b=(\\w+)]]></pattern>
<match-group order="1" xmlns="">
  <matcher field="UserName" order="2" pattern-id="B" capture-group="1"/>
  <matcher field="UserName" order="1" pattern-id="A" capture-group="1"/>
</match-group>"""
    )
    (rule,) = a.parser.match_groups[0].rules
    assert rule.expr == Coalesce(
        items=[Capture(pattern_id="A", group=1), Capture(pattern_id="B", group=1)]
    )
    assert codes(a) == {}


def test_substitution_template(lsx) -> None:
    a = lsx(
        """
<pattern id="P" xmlns=""><![CDATA[(\\w+)@(\\w+)]]></pattern>
<match-group order="1" xmlns="">
  <matcher field="UserName" order="1" pattern-id="P" capture-group="\\2/\\1" enable-substitutions="true"/>
</match-group>"""
    )
    (rule,) = a.parser.match_groups[0].rules
    assert rule.expr == Template(pattern_id="P", parts=[2, "/", 1])


def test_default_capture_group_is_whole_match(lsx) -> None:
    a = lsx(
        """
<pattern id="P" xmlns=""><![CDATA[\\d+]]></pattern>
<match-group order="1" xmlns=""><matcher field="SourcePort" order="1" pattern-id="P"/></match-group>"""
    )
    assert a.parser.match_groups[0].rules[0].expr == Capture(pattern_id="P", group=0)


def test_event_mappings(lsx) -> None:
    a = lsx(
        """
<pattern id="E" xmlns=""><![CDATA[evt=(\\w+)]]></pattern>
<pattern id="C" xmlns=""><![CDATA[cat=(\\w+)]]></pattern>
<pattern id="M" xmlns=""><![CDATA[multi=(\\w+)]]></pattern>
<match-group order="1" xmlns="">
  <matcher field="EventName" order="1" pattern-id="E" capture-group="1"/>
  <matcher field="EventCategory" order="1" pattern-id="C" capture-group="1"/>
  <event-match-single event-name="login" device-event-category="Auth" severity="4"/>
  <event-match-multiple pattern-id="M" capture-group-index="1" device-event-category="Multi"/>
</match-group>"""
    )
    rules = {r.field: r.expr for r in a.parser.match_groups[0].rules}
    event_name = Coalesce(
        items=[Capture(pattern_id="E", group=1), Capture(pattern_id="M", group=1)]
    )
    assert rules["EventName"] == event_name
    category = rules["EventCategory"]
    assert isinstance(category, Lookup)
    assert category.table == {"login": "Auth"}
    assert category.default == Coalesce(
        items=[
            Capture(pattern_id="C", group=1),
            IfMatch(pattern_id="M", value={"kind": "literal", "value": "Multi"}),
        ]
    )
    assert rules["EventSeverity"] == Lookup(key=event_name, table={"login": "4"}, default=None)
    assert codes(a)["LSX_EVENT_MATCH_MULTIPLE_ASSUMED"] is Status.PARTIAL


def test_devicetime_with_format(lsx) -> None:
    a = lsx(
        """
<pattern id="T" xmlns=""><![CDATA[t=(\\S+)]]></pattern>
<match-group order="1" xmlns="">
  <matcher field="DeviceTime" order="1" pattern-id="T" capture-group="1" ext-data="yyyy-MM-dd"/>
</match-group>"""
    )
    expr = a.parser.match_groups[0].rules[0].expr
    assert expr == ParseTime(value=Capture(pattern_id="T", group=1), format="yyyy-MM-dd")


def test_multiple_groups_flag_assumption_and_selectors() -> None:
    a = parse_lsx(FIXTURES / "globex_vpn.lsx.xml")
    assert codes(a)["LSX_MATCHGROUP_SELECTION_ASSUMED"] is Status.PARTIAL
    g1, g2 = a.parser.match_groups
    assert g1.selector_pattern_ids == ["LoginEvent"]
    assert g2.selector_pattern_ids == ["Tunnel"]


def test_edge_cases_are_all_reported() -> None:
    a = parse_lsx(FIXTURES / "edge_cases.lsx.xml")
    found = codes(a)
    expected = {
        "LSX_DUPLICATE_PATTERN": Status.UNSUPPORTED,
        "LSX_TRIM_WHITESPACE": Status.PARTIAL,
        "LSX_UNKNOWN_ATTRIBUTE": Status.UNSUPPORTED,
        "LSX_DEVICE_TYPE_OVERRIDE": Status.PARTIAL,
        "LSX_UNKNOWN_PATTERN": Status.UNSUPPORTED,
        "LSX_CAPTURE_GROUP_OUT_OF_RANGE": Status.UNSUPPORTED,
        "LSX_EXT_DATA_IGNORED": Status.PARTIAL,
        "LSX_DEVICETIME_NO_FORMAT": Status.UNSUPPORTED,
        "LSX_UNKNOWN_FIELD": Status.PARTIAL,
        "LSX_INVALID_VALUE": Status.UNSUPPORTED,
        "LSX_MATCHER_TYPE_UNSUPPORTED": Status.UNSUPPORTED,
        "LSX_UNKNOWN_ELEMENT": Status.UNSUPPORTED,
        "LSX_IDENTITY_EVENTS": Status.UNSUPPORTED,
        "LSX_SEVERITY_DEFAULTED": Status.FULL,
    }
    for code, status in expected.items():
        assert found.get(code) is status, code


def test_every_matcher_is_translated_or_reported() -> None:
    """Nothing is dropped silently: each <matcher> becomes IR or yields a finding."""
    from lxml import etree

    for path in FIXTURES.glob("*.lsx.xml"):
        a = parse_lsx(path)
        tree = etree.parse(str(path))
        for m in tree.iter("{*}matcher", "matcher"):
            fld = m.get("field")
            in_ir = a.parser is not None and any(
                r.field == fld for g in a.parser.match_groups for r in g.rules
            )
            reported = any(f"matcher[field={fld}," in f.path for f in a.findings)
            assert in_ir or reported, (path.name, fld)


def test_invalid_inputs() -> None:
    assert codes(parse_lsx(FIXTURES / "broken.xml")) == {"LSX_INVALID_XML": Status.UNSUPPORTED}
    assert codes(parse_lsx(FIXTURES / "not_lsx.xml")) == {"LSX_NOT_AN_LSX": Status.UNSUPPORTED}


def test_external_entities_are_never_resolved() -> None:
    a = parse_lsx(FIXTURES / "xxe.xml")
    assert codes(a)["LSX_PATTERN_MARKUP"] is Status.UNSUPPORTED
    assert a.parser is None or "P" not in a.parser.patterns
    assert "LSX_NOTHING_TO_TRANSLATE" in codes(a)
