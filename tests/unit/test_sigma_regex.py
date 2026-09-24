"""The ``sigma`` regex dialect: only the metacharacters the Sigma ``re`` modifier allows."""

from __future__ import annotations

import pytest
import regex as pyregex

from rosettalog.ir import Status
from rosettalog.regex.translate import translate

# The Sigma modifiers appendix allows: . ^ $ * + ? {n,m} [a-z] [^a-z] | ()
ALLOWED_ESCAPES = set("\\^$.|?*+()[]{}-")


def allowed(pattern: str) -> bool:
    """Every backslash escapes a metacharacter, and there is no '(?' construct."""
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\":
            if pattern[i + 1] not in ALLOWED_ESCAPES:
                return False
            i += 2
            continue
        if pattern.startswith("(?", i):
            return False
        i += 1
    return True


@pytest.mark.parametrize(
    ("java", "sigma", "flags"),
    [
        (r"\d+\.\d+", r"[0-9]+\.[0-9]+", ""),
        (r"(?i)^user=(\w+)", r"^user=([a-zA-Z0-9_]+)", "i"),
        (r"a(?:b|c)*?d{3}", r"a(b|c)*d{3,3}", ""),
        (r"\p{Alpha}+", r"[a-zA-Z]+", ""),
        (r"\Aab\Z", r"^ab$", ""),
        (r"(?<n>x)y", r"(x)y", ""),
        (r"(?s)a.b", r"a.b", "s"),
        (r"[\d-]", r"[0-9\-]", ""),
        (r"\D", r"[^0-9]", ""),
    ],
)
def test_translation(java: str, sigma: str, flags: str) -> None:
    tr = translate(java, "sigma")
    assert (tr.pattern, tr.flags) == (sigma, flags)
    assert tr.status is Status.FULL
    assert allowed(tr.pattern)


def test_case_insensitive_test_becomes_i_flag() -> None:
    tr = translate("abc", "sigma", case_insensitive=True)
    assert (tr.pattern, tr.flags) == ("abc", "i")


def test_whitespace_class_uses_literal_characters() -> None:
    tr = translate(r"a\sb", "sigma")
    assert tr.pattern == "a[ \t\n\x0b\x0c\r]b"
    assert allowed(tr.pattern or "")


@pytest.mark.parametrize(
    "java",
    [r"(?<=a)b", r"a(?!b)", r"\bfoo", r"(a)\1", r"a++", r"(?>ab)", r"foo(?i)bar", r"(?i:a)b",
     r"\p{L}", r"\R", r"(?m)\Aab", r"\Gx", r"(?x)a b"],
)  # fmt: skip
def test_outside_subset_is_unsupported(java: str) -> None:
    tr = translate(java, "sigma")
    assert tr.pattern is None
    assert tr.issues[-1].status is Status.UNSUPPORTED


def test_absolute_end_anchor_is_partial() -> None:
    tr = translate(r"x\z", "sigma")
    assert tr.pattern == "x$"
    assert [i.code for i in tr.issues] == ["SIGMA_REGEX_END_ANCHOR"]


@pytest.mark.parametrize(
    ("java", "value", "expected"),
    [
        (r"^auth[-_]fail(ure)?\d*$", "auth_failure2", True),
        (r"^auth[-_]fail(ure)?\d*$", "xauth_fail", False),
        (r"\d{2,3}", "a1234", True),
        (r"a\.b", "axb", False),
    ],
)
def test_same_matches_as_java_emulation(java: str, value: str, expected: bool) -> None:
    sigma = translate(java, "sigma").pattern
    python = translate(java, "python").pattern
    assert sigma is not None
    assert python is not None
    assert bool(pyregex.search(sigma, value)) is expected
    assert bool(pyregex.search(python, value, flags=pyregex.ASCII)) is expected
