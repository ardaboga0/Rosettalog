from __future__ import annotations

import pytest

from rosettalog.backends.sentinel import SentinelBackend
from rosettalog.backends.splunk import SplunkBackend
from rosettalog.ir import Status
from rosettalog.verify.emulators.kql import KqlEmulator
from rosettalog.verify.emulators.splunk import SplunkEmulator
from tests.conftest import EXAMPLES, FIXTURES, NOW, parse_lsx

ACME = EXAMPLES / "acme_firewall" / "acme_fw.lsx.xml"


def codes(result) -> dict[str, Status]:
    return {f.code: f.status for f in result.findings}


def test_sentinel_options_and_asim() -> None:
    a = parse_lsx(ACME)
    r = SentinelBackend().generate(
        a, {"source_table": "AcmeFw_CL", "asim_schema": "NetworkSession"}
    )
    (f,) = r.files
    assert f.path == "vimNetworkSessionAcmeFwLsx.kql"
    assert "AcmeFw_CL\n" in f.content
    assert 'extract(@"action=(\\w+)", 1, RawData)' in f.content
    assert 'EventSchema = "NetworkSession"' in f.content
    assert codes(r)["ASIM_MANDATORY_FIELDS"] is Status.PARTIAL
    assert "KQL_COLUMN_OVERWRITE" not in codes(r)  # custom table: HostName does not clash


def test_sentinel_reports_dropped_parts() -> None:
    r = SentinelBackend().generate(parse_lsx(ACME), {})
    c = codes(r)
    assert c["RE2_NO_LOOKAROUND"] is Status.UNSUPPORTED
    assert c["RE2_NO_BACKREFERENCE"] is Status.UNSUPPORTED
    assert c["CANDIDATE_DROPPED"] is Status.PARTIAL
    assert c["KQL_COLUMN_OVERWRITE"] is Status.PARTIAL
    assert r.field_names["UserName"] == "User"


def test_splunk_direct_and_intermediate_fields() -> None:
    r = SplunkBackend().generate(parse_lsx(ACME), {"sourcetype": "acme:fw"})
    props = next(f.content for f in r.files if f.path == "props.conf")
    transforms = next(f.content for f in r.files if f.path == "transforms.conf")
    assert "[acme:fw]" in props
    assert "FORMAT = src_ip::$1" in transforms
    assert "EVAL-user = coalesce(" in props
    assert 'TIME_PREFIX = ts="' in props
    assert "TIME_FORMAT = %Y-%m-%d %H:%M:%S.%3N" in props
    # Lookup key reuses the directly extracted signature_id instead of a second transform.
    assert 'case(signature_id=="deny"' in props


def test_splunk_single_timestamp_limitation() -> None:
    r = SplunkBackend().generate(parse_lsx(FIXTURES / "globex_vpn.lsx.xml"), {})
    assert codes(r)["SPLUNK_SINGLE_TIMESTAMP"] is Status.PARTIAL


@pytest.mark.parametrize("backend", [SentinelBackend(), SplunkBackend()])
def test_every_field_is_generated_or_reported(backend) -> None:
    """Nothing dropped silently at the backend level."""
    for path in [ACME, *FIXTURES.glob("*.lsx.xml")]:
        a = parse_lsx(path)
        if a.parser is None:
            continue
        r = backend.generate(a, {})
        lost = {f.message.split("'")[1] for f in r.findings if f.code == "FIELD_NOT_TRANSLATED"}
        for field in a.parser.fields():
            assert (
                field in r.field_names
                or field in lost
                or any(f.code == "SPLUNK_TIMESTAMP_UNSUPPORTED" for f in r.findings)
            ), (path.name, backend.name, field)


def test_unparseable_pattern_is_reported_for_every_target() -> None:
    a = parse_lsx(FIXTURES / "edge_cases.lsx.xml")
    for backend in (SentinelBackend(), SplunkBackend()):
        r = backend.generate(a, {})
        assert codes(r)["REGEX_PARSE_ERROR"] is Status.UNSUPPORTED
        assert "UserName" not in r.field_names


@pytest.mark.parametrize(
    ("backend", "emulator"), [(SentinelBackend(), KqlEmulator), (SplunkBackend(), SplunkEmulator)]
)
def test_emulators_read_generated_output(backend, emulator) -> None:
    r = backend.generate(parse_lsx(ACME), {})
    out = emulator(r).extract(
        '<1>Mar 14 09:26:53 fw1 x: ts="2026-03-14 09:26:53.120" action=deny src=10.0.0.1',
        now=NOW,
    )
    ip = r.field_names["SourceIp"]
    assert out[ip] == "10.0.0.1"
    assert out[r.field_names["DeviceTime"]] == "2026-03-14T09:26:53.120Z"
    assert out[r.field_names["EventSeverity"]] == "7"


def test_splunk_separates_index_time_from_search_time() -> None:
    r = SplunkBackend().generate(parse_lsx(ACME), {"sourcetype": "acme:fw"})
    scopes = {s.setting: s.scope for s in r.settings}
    assert scopes["SHOULD_LINEMERGE"] == "index-time"
    assert scopes["TIME_PREFIX"] == "index-time"
    assert scopes["TIME_FORMAT"] == "index-time"
    assert scopes["EVAL-user"] == "search-time"
    assert all(v == "search-time" for k, v in scopes.items() if k.startswith("REPORT-"))
    time_deps = [s for s in r.settings if "_time" in s.fields]
    assert {s.setting for s in time_deps} == {"TIME_PREFIX", "TIME_FORMAT"}
    # Index-time settings come first in props.conf, in their own commented section.
    props = next(f.content for f in r.files if f.path == "props.conf")
    index_section, search_section = props.split("# ---- Search-time extractions")
    assert "TIME_FORMAT" in index_section
    assert "REPORT-" not in index_section
    assert "EVAL-" not in index_section
    assert "TIME_" not in search_section
    c = codes(r)
    assert c["SPLUNK_INDEX_TIME_DEPENDENCY"] is Status.PARTIAL
    assert c["SPLUNK_EVENT_BREAKING_ASSUMED"] is Status.FULL
    dep = next(f for f in r.findings if f.code == "SPLUNK_INDEX_TIME_DEPENDENCY")
    assert "only for events indexed after deployment" in dep.message


def test_sentinel_parser_is_query_time() -> None:
    r = SentinelBackend().generate(parse_lsx(ACME), {})
    assert [s.scope for s in r.settings] == ["query-time"]


def test_multi_group_field_only_in_later_group_respects_earlier_winner() -> None:
    """Regression: found by examples/confirmation/01 - Splunk applied group 2's field even when
    group 1 (earlier, also matching) had been selected."""
    from tests.conftest import EXAMPLES

    case = EXAMPLES / "confirmation" / "01-matchgroup-selection" / "extension.xml"
    log = "<13>Mar 24 10:00:00 rl-confirm-01 rltest: evt=ALPHA user=u1 acct=a1 port=1111"
    for backend, emulator in ((SentinelBackend(), KqlEmulator), (SplunkBackend(), SplunkEmulator)):
        r = backend.generate(parse_lsx(case), {})
        out = emulator(r).extract(log, now=NOW)
        assert out[r.field_names["SourcePort"]] is None, backend.name
        assert out[r.field_names["UserName"]] == "u1", backend.name
