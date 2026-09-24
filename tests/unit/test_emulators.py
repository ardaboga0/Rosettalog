from __future__ import annotations

from datetime import UTC, datetime

import pytest

from rosettalog.plugins import BackendResult, GeneratedFile
from rosettalog.verify.emulators.kql import KqlEmulationError, KqlEmulator
from rosettalog.verify.emulators.pcre import _HSPACE, pcre_to_python
from rosettalog.verify.emulators.splunk import SplunkEmulationError, SplunkEmulator

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def kql(body: str, fields: dict[str, str]) -> KqlEmulator:
    text = f"let F = (disabled: bool = false) {{\n Syslog\n | where not(disabled)\n{body}\n}};\nF\n"
    result = BackendResult(
        target="sentinel",
        artifact_id="t",
        files=[GeneratedFile(path="F.kql", content=text)],
        field_names=fields,
        options={"message_column": "SyslogMessage"},
    )
    return KqlEmulator(result)


def test_kql_extract_coalesce_and_case() -> None:
    em = kql(
        '| extend _rl_k = extract(@"a=(\\w+)", 1, SyslogMessage)\n'
        '| extend X = coalesce(extract(@"b=(\\w+)", 1, SyslogMessage), "fallback"),'
        ' Y = case(_rl_k == "1", "one", _rl_k == "2", "two", ""),'
        ' Z = iff(SyslogMessage matches regex @"q""uote", strcat("p", "q"), "")\n'
        "| project-away _rl_*",
        {"x": "X", "y": "Y", "z": "Z"},
    )
    assert em.extract('a=2 q"uote', now=NOW) == {"X": "fallback", "Y": "two", "Z": "pq"}
    assert em.extract("b=hi a=9", now=NOW) == {"X": "hi", "Y": None, "Z": None}


def test_kql_datetime_functions() -> None:
    em = kql(
        '| extend T = datetime_add("minute", -(iff("+" == "-", -1, 1) * 90), '
        'make_datetime(2026, 3, 4, 13 % 12 + 12, 5, 6 + toreal(strcat("0.", "25"))))',
        {"t": "T"},
    )
    assert em.extract("", now=NOW) == {"T": "2026-03-04T11:35:06.250Z"}


def test_kql_extract_all_and_indexing() -> None:
    em = kql(
        '| extend P = extract_all(@"(\\d+)-(\\d+)", "12-34 56-78")[1]\n'
        '| extend Q = tostring(P[0]), R = indexof("janfeb", "feb") / 3 + 1',
        {"q": "Q", "r": "R"},
    )
    assert em.extract("", now=NOW) == {"Q": "56", "R": "2"}


def test_kql_rejects_unknown_constructs() -> None:
    with pytest.raises(KqlEmulationError):
        kql("| summarize count()", {}).extract("", now=NOW)
    with pytest.raises(KqlEmulationError):
        kql("| extend X = parse_json(SyslogMessage)", {"x": "X"}).extract("", now=NOW)
    with pytest.raises(KqlEmulationError):
        kql('| extend X = extract(@"(?=a)", 0, SyslogMessage)', {"x": "X"}).extract("a", now=NOW)


def splunk(props: str, transforms: str, fields: dict[str, str]) -> SplunkEmulator:
    result = BackendResult(
        target="splunk",
        artifact_id="t",
        files=[
            GeneratedFile(path="props.conf", content="[st]\nKV_MODE = none\n" + props),
            GeneratedFile(path="transforms.conf", content=transforms),
        ],
        field_names=fields,
        options={"sourcetype": "st"},
    )
    return SplunkEmulator(result)


def test_splunk_report_eval_and_time() -> None:
    em = splunk(
        "TIME_PREFIX = at\\s\nTIME_FORMAT = %d/%b/%Y:%I:%M:%S %p\n"
        "REPORT-x = t1, t2\n"
        'EVAL-user = coalesce(rl_a, rl_b . "!")\n'
        'EVAL-kind = case(match(_raw, "vpn\\\\d"), "vpn", true(), null())\n'
        "EVAL-parallel = user\n",
        "[t1]\nREGEX = a=(\\w+)\nFORMAT = rl_a::$1\n\n[t2]\nREGEX = b=(\\w+):(\\w+)\n"
        "FORMAT = rl_b::$2-$1 port::$2\n",
        {"u": "user", "k": "kind", "p": "port", "t": "_time", "par": "parallel"},
    )
    out = em.extract("vpn1 b=x:y at 04/Mar/2026:01:02:03 PM", now=NOW)
    assert out == {
        "user": "y-x!",
        "kind": "vpn",
        "port": "y",
        "_time": "2026-03-04T13:02:03.000Z",
        "parallel": None,  # EVALs run in parallel: 'user' is not visible to another EVAL
    }


def test_splunk_two_digit_year_pivot() -> None:
    em = splunk("TIME_FORMAT = %y-%m-%d\n", "", {"t": "_time"})
    assert em.extract("70-01-02", now=NOW) == {"_time": "1970-01-02T00:00:00.000Z"}
    assert em.extract("26-01-02", now=NOW) == {"_time": "2026-01-02T00:00:00.000Z"}


def test_splunk_rejects_unknown_settings() -> None:
    with pytest.raises(SplunkEmulationError):
        splunk("MAX_TIMESTAMP_LOOKAHEAD = 30\n", "", {})
    with pytest.raises(SplunkEmulationError):
        splunk('EVAL-x = strftime(_time, "%Y")\n', "", {"x": "x"}).extract("", now=NOW)


@pytest.mark.parametrize(
    ("pcre", "python"),
    [
        (r"\x{E9}\x{1F600}", r"\xE9\U0001F600"),
        (r"(a)\g{1}", r"(a)\g<1>"),
        (r"(?<n>a)\k<n>", r"(?<n>a)(?P=n)"),
        (r"[\h]", "[" + _HSPACE + "]"),
        (r"a\z", r"a\Z"),
        (r"[\\]x", r"[\\]x"),
    ],
)
def test_pcre_conversion(pcre: str, python: str) -> None:
    assert pcre_to_python(pcre) == python


def test_source_emulator_uses_java_ascii_classes() -> None:
    from rosettalog.ir import Capture, FieldRule, MatchGroup, ParserSpec, Pattern
    from rosettalog.verify.emulators.source import SourceEmulator

    spec = ParserSpec(
        patterns={"P": Pattern(id="P", source=r"u=(\w+)", case_insensitive=True)},
        match_groups=[
            MatchGroup(
                order=1,
                rules=[
                    FieldRule(field="UserName", expr=Capture(pattern_id="P", group=1), path="p")
                ],
            )
        ],
    )
    # Java: \w is [a-zA-Z_0-9] unless UNICODE_CHARACTER_CLASS is set, so the match stops at 'é'.
    assert SourceEmulator(spec).extract("U=josé", now=NOW) == {"UserName": "jos"}
