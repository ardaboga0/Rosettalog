from __future__ import annotations

import pytest

from rosettalog.ir import Status
from rosettalog.regex.translate import translate


@pytest.mark.parametrize(
    ("pattern", "target", "status", "code", "expected"),
    [
        (r"src=(\d+)", "re2", Status.FULL, None, r"src=(\d+)"),
        (r"(?<=u=)\w+", "re2", Status.UNSUPPORTED, "RE2_NO_LOOKAROUND", None),
        (r"(?<=u=)\w+", "pcre", Status.FULL, None, r"(?<=u=)\w+"),
        (r"(?<=u=\s*)\w+", "pcre", Status.PARTIAL, "PCRE_VARIABLE_LOOKBEHIND", None),
        (r"(a)\1", "re2", Status.UNSUPPORTED, "RE2_NO_BACKREFERENCE", None),
        (r"(a)\1", "pcre", Status.FULL, None, r"(a)\g{1}"),
        (r"(?<n>a)\k<n>", "pcre", Status.FULL, None, r"(a)\g{1}"),
        (r"(?<n>a)\k<n>", "python", Status.FULL, None, r"(?P<n>a)(?P=n)"),
        (r"a++b", "re2", Status.PARTIAL, "RE2_POSSESSIVE_APPROX", "a+b"),
        (r"a++b", "pcre", Status.FULL, None, "a++b"),
        (r"(?>a|ab)c", "re2", Status.PARTIAL, "RE2_ATOMIC_APPROX", "(?:a|ab)c"),
        (r"x\Z", "re2", Status.PARTIAL, "RE2_END_ANCHOR_APPROX", r"x\z"),
        (r"\Gx", "re2", Status.UNSUPPORTED, "RE2_NO_G_ANCHOR", None),
        (r"\p{Alpha}+", "re2", Status.FULL, None, "[a-zA-Z]+"),
        (r"[\p{Digit}_]", "pcre", Status.FULL, None, "[0-9_]"),
        (r"\p{Lu}", "re2", Status.FULL, None, r"\p{Lu}"),
        (r"\p{javaLowerCase}", "re2", Status.UNSUPPORTED, "REGEX_UNICODE_PROPERTY", None),
        (r"[a-z&&[^b]]", "pcre", Status.UNSUPPORTED, "REGEX_CLASS_SET_OPERATION", None),
        (r"\Qa.b\E", "re2", Status.FULL, None, r"a\.b"),
        (r"\u00e9", "re2", Status.FULL, None, r"\x{E9}"),
        (r"\u00e9", "python", Status.FULL, None, r"\xE9"),
        (r"\h", "pcre", Status.FULL, None, r"\h"),
        (r"(?U)a", "re2", Status.UNSUPPORTED, "REGEX_FLAG_UNSUPPORTED", None),
        (r"(?u)a", "re2", Status.PARTIAL, "REGEX_FLAG_DROPPED", "a"),
        (r"(?i)a", "re2", Status.FULL, None, "(?i)a"),
        (r"a{2000}", "re2", Status.UNSUPPORTED, "RE2_REPEAT_LIMIT", None),
        (r"(unclosed", "pcre", Status.UNSUPPORTED, "REGEX_PARSE_ERROR", None),
        (r"(?<name>x)", "re2", Status.FULL, None, "(?P<name>x)"),
        (r"(?<name>x)", "pcre", Status.FULL, None, "(x)"),  # Splunk: FORMAT needs numbered groups
    ],
)
def test_translation(pattern, target, status, code, expected) -> None:
    result = translate(pattern, target)
    assert result.status is status
    if code:
        assert code in {i.code for i in result.issues}
    else:
        assert not result.issues
    if expected is not None:
        assert result.pattern == expected


def test_case_insensitive_prefix() -> None:
    assert translate("abc", "re2", case_insensitive=True).pattern == "(?i)abc"


def test_group_count_reported() -> None:
    assert translate(r"(a)(?:b)(?<c>c)", "re2").groups == 2


@pytest.mark.parametrize(
    "pattern",
    [
        r"src=(\d{1,3}(?:\.\d{1,3}){3}) dst=(\S+)",
        r"(?i)user=([^\s" "]+)",
        r"^<\d+>\w{3} +\d{1,2} [\d:]{8} (\S+)",
        r"\buser=(?<user>[^\s]+)",
        r"[\t \-]\x41\u00e9",
    ],
)
def test_all_targets_agree_on_simple_patterns(pattern: str) -> None:
    import re2
    import regex

    re2_rx = translate(pattern, "re2").pattern
    py_rx = translate(pattern, "python").pattern
    assert re2_rx is not None
    assert py_rx is not None
    text = "x src=10.0.0.1 dst=h user=Alé <1>Mar 14 09:26:53 host Aé \tAé"
    m1, m2 = re2.search(re2_rx, text), regex.search(py_rx, text)
    assert (m1 is None) == (m2 is None)
    if m1 is not None and m2 is not None:
        assert m1.group(0) == m2.group(0)


@pytest.mark.parametrize(
    ("pattern", "status", "code", "expected"),
    [
        (r"src=(\d+)", Status.FULL, None, r"src=([0-9]+)"),
        (r"\w\s\W", Status.FULL, None, r"[a-zA-Z0-9_][ \t\n\x0B\f\r][^a-zA-Z0-9_]"),
        (r"^a$", Status.FULL, None, r"\Aa\Z"),
        (r"(?m)^a$", Status.PARTIAL, "ONIG_MULTILINE_ANCHORS", "^a$"),
        (r"(?s)a.b", Status.FULL, None, "(?m)a.b"),
        (r"\bx\B", Status.FULL, None, None),
        (r"\h", Status.FULL, None, None),
        (r"a\R", Status.FULL, None, r"a(?>\r\n|[\n-\r\x{85}\x{2028}-\x{2029}])"),
        (r"100%", Status.FULL, None, r"100\x{25}"),
        (r"(?<=a)b", Status.FULL, None, "(?<=a)b"),
        (r"(?<=a|bc)b", Status.FULL, None, "(?<=a|bc)b"),
        (r"(?<=a+)b", Status.UNSUPPORTED, "ONIG_LOOKBEHIND_NOT_FIXED", None),
        (r"(?<=(?:a|bc))b", Status.UNSUPPORTED, "ONIG_LOOKBEHIND_NOT_FIXED", None),
        (r"(a)\1", Status.FULL, None, r"(a)\k<1>"),
        (r"a++(?>b)", Status.FULL, None, "a++(?>b)"),
        (r"[\d\W]", Status.FULL, None, "[0-9[^a-zA-Z0-9_]]"),
        (r"[^\W]", Status.UNSUPPORTED, "REGEX_CLASS_SET_OPERATION", None),
        (r"\Qa.b\E", Status.FULL, None, r"a\.b"),
    ],
)
def test_onig_translation(pattern, status, code, expected) -> None:
    result = translate(pattern, "onig")
    assert result.status is status
    if code:
        assert code in {i.code for i in result.issues}
    if expected is not None:
        assert result.pattern == expected
    if result.pattern is not None:
        assert "\\h" not in result.pattern
        assert "\\d" not in result.pattern
        assert "\\b" not in result.pattern


def test_onig_output_behaves_like_java_on_ascii_input() -> None:
    import regex

    from rosettalog.regex.onig_emulation import compile_onig

    cases = [
        (r"\bsrc=(\d+)\b", "a src=12 b", "12"),
        (r"^<(\d+)>", "<134>x", "134"),
        (r"(\w+)$", "abc def", "def"),
        (r"x(\s+)y", "x \t y", " \t "),
    ]
    for java, text, group in cases:
        onig = translate(java, "onig").pattern
        py = translate(java, "python").pattern
        assert onig is not None
        assert py is not None
        assert compile_onig(onig).search(text).group(1) == regex.search(py, text).group(1) == group
