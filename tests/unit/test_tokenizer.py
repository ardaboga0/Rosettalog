from __future__ import annotations

import pytest

from rosettalog.regex.tokenizer import (
    GroupKind,
    ItemKind,
    Kind,
    RegexSyntaxError,
    capture_count,
    tokenize,
)


def kinds(pattern: str) -> list[Kind]:
    return [t.kind for t in tokenize(pattern)]


def test_simple_literals_and_groups() -> None:
    toks = tokenize(r"a(b)(?:c)")
    assert [t.kind for t in toks] == [
        Kind.LITERAL,
        Kind.GROUP_OPEN,
        Kind.LITERAL,
        Kind.GROUP_CLOSE,
        Kind.GROUP_OPEN,
        Kind.LITERAL,
        Kind.GROUP_CLOSE,
    ]
    assert toks[1].group is GroupKind.CAPTURE
    assert toks[4].group is GroupKind.NONCAPTURE


@pytest.mark.parametrize(
    ("pattern", "group"),
    [
        ("(?=a)", GroupKind.LOOKAHEAD),
        ("(?!a)", GroupKind.NEG_LOOKAHEAD),
        ("(?<=a)", GroupKind.LOOKBEHIND),
        ("(?<!a)", GroupKind.NEG_LOOKBEHIND),
        ("(?>a)", GroupKind.ATOMIC),
        ("(?<name>a)", GroupKind.NAMED),
        ("(?i:a)", GroupKind.SCOPED_FLAGS),
    ],
)
def test_group_kinds(pattern: str, group: GroupKind) -> None:
    assert tokenize(pattern)[0].group is group


def test_quantifiers() -> None:
    toks = [t for t in tokenize(r"a*b+?c{2,5}+d{3}e{1,}") if t.kind is Kind.QUANT]
    assert [(t.qmin, t.qmax, t.lazy, t.possessive) for t in toks] == [
        (0, None, False, False),
        (1, None, True, False),
        (2, 5, False, True),
        (3, 3, False, False),
        (1, None, False, False),
    ]


def test_quote_expands_to_literals() -> None:
    toks = tokenize(r"\Qa.b\E")
    assert [t.cp for t in toks] == [ord("a"), ord("."), ord("b")]


def test_escapes_to_codepoints() -> None:
    toks = tokenize(r"\t\x41\u00e9\x{1F600}\0101\cA\e")
    assert [t.cp for t in toks] == [9, 0x41, 0xE9, 0x1F600, 0o101, 1, 27]


def test_backreference_number_uses_available_groups() -> None:
    # Java: \11 is backreference 1 followed by literal '1' when only one group exists.
    toks = tokenize(r"(a)\11")
    assert toks[3].kind is Kind.BACKREF
    assert toks[3].ref == 1
    assert toks[4].cp == ord("1")


def test_named_backreference() -> None:
    assert tokenize(r"(?<n>a)\k<n>")[-1].ref == "n"


def test_character_class_items() -> None:
    (tok,) = tokenize(r"[^a-z\d\p{Alpha}_\-]")
    assert tok.negated
    assert [i.kind for i in tok.items] == [
        ItemKind.RANGE,
        ItemKind.ESCAPE_CLASS,
        ItemKind.PROPERTY,
        ItemKind.CHAR,
        ItemKind.CHAR,
    ]


def test_class_set_operations_are_recorded() -> None:
    (tok,) = tokenize(r"[a-z&&[^aeiou]]")
    assert {i.kind for i in tok.items} >= {ItemKind.INTERSECTION, ItemKind.NESTED}


def test_capture_count_includes_named_groups() -> None:
    assert capture_count(tokenize(r"(a)(?:b)(?<c>c)(?=d)")) == 2


@pytest.mark.parametrize(
    "pattern",
    ["(", ")", "[abc", "*a", "a{2,1}", r"\y", r"(?x)a b", "[]a]", "a{", r"\k"],
)
def test_syntax_errors(pattern: str) -> None:
    with pytest.raises(RegexSyntaxError):
        tokenize(pattern)
