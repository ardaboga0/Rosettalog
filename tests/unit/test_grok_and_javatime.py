from __future__ import annotations

from datetime import UTC, datetime

import pytest

from rosettalog.ir import Status
from rosettalog.regex.grok import to_grok
from rosettalog.regex.onig_emulation import compile_onig, onig_to_python
from rosettalog.timefmt.javatime import compile_java, parse_java, to_java_pattern
from rosettalog.timefmt.joda import compile_format, format_timestamp

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def test_grok_renames_every_group_and_rewires_backrefs() -> None:
    g = to_grok(r"user=(?<u>\w+)@(\w+) \k<u> (x)\3", "rl_p7")
    assert g.pattern == (
        r"(?<rl_p7_m>user=(?<rl_p7_g1>[a-zA-Z0-9_]+)@(?<rl_p7_g2>[a-zA-Z0-9_]+) "
        r"\k<rl_p7_g1> (?<rl_p7_g3>x)\k<rl_p7_g3>)"
    )
    assert g.groups == 3
    assert g.group_field(0) == "rl_p7_m"
    assert g.group_field(2) == "rl_p7_g2"
    m = compile_onig(g.pattern).search("user=bob@corp bob xx")
    assert m.group("rl_p7_g2") == "corp"


def test_grok_case_insensitive_and_unsupported() -> None:
    assert to_grok("abc", "rl_p1", case_insensitive=True).pattern == "(?<rl_p1_m>(?i)abc)"
    bad = to_grok(r"(?<=a+)b", "rl_p1")
    assert bad.pattern is None
    assert bad.issues[0].code == "ONIG_LOOKBEHIND_NOT_FIXED"


def test_onig_to_python_conversions() -> None:
    assert onig_to_python(r"\x{25}\x{1F600}") == r"\x25\U0001F600"
    assert onig_to_python(r"(?<a>x)\k<a>") == r"(?<a>x)(?P=a)"
    assert onig_to_python("(?m)a.b(?i-m:c)") == "(?s)a.b(?i-s:c)"
    assert onig_to_python(r"a\Z") == r"a(?=\n?\Z)"
    assert onig_to_python(r"[0-9[^a-z]]") == r"(?:[0-9]|[^a-z])"
    assert compile_onig("^b$").search("a\nb\nc")  # Ruby: ^/$ are line anchors


@pytest.mark.parametrize(
    ("joda", "java", "codes"),
    [
        ("yyyy-MM-dd HH:mm:ss.SSS", "uuuu-M-d H:m:s.SSS", set()),
        ("MMM dd yyyy HH:mm:ss", "MMM d uuuu H:m:s", {"ELASTIC_DATE_CASE_SENSITIVE"}),
        ("dd/MMM/YYYY:hh:mm:ss a", "d/MMM/uuuu:h:m:s a", {"ELASTIC_DATE_CASE_SENSITIVE"}),
        ("yyyyMMdd'T'HHmm", "uuuuMMdd'T'HHmm", {"ELASTIC_DATE_FIXED_WIDTH"}),
        ("dd/MM/yy HH:mm", "d/M/uu H:m", set()),
        ("yyyy-MM-dd'T'HH:mm:ssZZ", "uuuu-M-d'T'H:m:sxxx", set()),
    ],
)
def test_joda_to_java(joda: str, java: str, codes: set[str]) -> None:
    result = to_java_pattern(compile_format(joda))
    assert result.pattern == java
    assert {i.code for i in result.issues} == codes
    assert all(i.status is Status.PARTIAL for i in result.issues)


@pytest.mark.parametrize(
    ("pattern", "text", "iso"),
    [
        ("uuuu-M-d H:m:s.SSS", "2026-03-14 09:26:53.120", "2026-03-14T09:26:53.120Z"),
        ("MMM d H:m:s", "Mar 24 10:00:00", "2026-03-24T10:00:00.000Z"),  # missing year: now
        ("MMM d H:m:s", "mar 24 10:00:00", None),  # case-sensitive (Elasticsearch 9.5.4)
        ("d/M/uu H:m", "01/02/69 10:00", "2069-02-01T10:00:00.000Z"),
        ("d/MMM/uuuu:h:m:s a", "04/Mar/2026:01:02:03 PM", "2026-03-04T13:02:03.000Z"),
        ("d/MMM/uuuu:h:m:s a", "04/Mar/2026:13:02:03 PM", None),  # STRICT: hour 1..12
        ("uuuu-M-d'T'H:m:sxxx", "2026-03-04T10:00:00+02:00", "2026-03-04T08:00:00.000Z"),
    ],
)
def test_parse_java(pattern: str, text: str, iso: str | None) -> None:
    dt = parse_java(text, compile_java(pattern), now=NOW)
    assert (format_timestamp(dt) if dt else None) == iso
