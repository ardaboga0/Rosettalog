"""Tokenizer for Java (java.util.regex.Pattern) regular expressions.

The goal is not to build a matcher but to know *exactly* which constructs a pattern uses so
translators can re-emit it for another engine or report precisely why they cannot.
Anything the tokenizer does not understand raises :class:`RegexSyntaxError`; it never guesses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class RegexSyntaxError(ValueError):
    def __init__(self, message: str, pos: int) -> None:
        super().__init__(f"{message} (at offset {pos})")
        self.pos = pos


class Kind(Enum):
    LITERAL = auto()
    CLASS = auto()
    ESCAPE_CLASS = auto()  # \d \D \w \W \s \S
    PROPERTY = auto()  # \p{..} \P{..}
    HSPACE = auto()  # \h \H
    VSPACE = auto()  # \v \V
    LINEBREAK = auto()  # \R
    DOT = auto()
    ANCHOR = auto()  # ^ $ \b \B \A \z \Z \G
    BACKREF = auto()
    GROUP_OPEN = auto()
    GROUP_CLOSE = auto()
    QUANT = auto()
    ALT = auto()
    FLAGS = auto()  # (?i) style, applies to the rest of the enclosing group


class GroupKind(Enum):
    CAPTURE = auto()
    NAMED = auto()
    NONCAPTURE = auto()
    SCOPED_FLAGS = auto()  # (?i:...)
    LOOKAHEAD = auto()
    NEG_LOOKAHEAD = auto()
    LOOKBEHIND = auto()
    NEG_LOOKBEHIND = auto()
    ATOMIC = auto()


class ItemKind(Enum):
    CHAR = auto()
    RANGE = auto()
    ESCAPE_CLASS = auto()
    PROPERTY = auto()
    HSPACE = auto()
    VSPACE = auto()
    NESTED = auto()  # Java union: [a[bc]]
    INTERSECTION = auto()  # Java intersection: [a-z&&[^aeiou]]


@dataclass(frozen=True)
class ClassItem:
    kind: ItemKind
    text: str = ""
    cp: int | None = None
    hi: int | None = None
    hi_text: str = ""
    name: str = ""
    negated: bool = False


@dataclass(frozen=True)
class Token:
    kind: Kind
    text: str
    pos: int
    cp: int | None = None
    name: str = ""
    group: GroupKind | None = None
    flags_on: str = ""
    flags_off: str = ""
    negated: bool = False
    items: tuple[ClassItem, ...] = ()
    qmin: int = 0
    qmax: int | None = None
    lazy: bool = False
    possessive: bool = False
    ref: int | str | None = None
    verbatim: bool = False
    """LITERAL only: ``text`` is a plain char or backslash + ASCII punctuation (valid anywhere)."""


JAVA_FLAGS = set("idmsuxU")
_SIMPLE_ESCAPES = {"t": 9, "n": 10, "r": 13, "f": 12, "a": 7, "e": 27}


@dataclass
class _State:
    s: str
    i: int = 0
    groups: int = 0
    tokens: list[Token] = field(default_factory=list)

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.s[j] if j < len(self.s) else ""


def tokenize(source: str) -> list[Token]:
    st = _State(source)
    depth = 0
    while st.i < len(st.s):
        c = st.s[st.i]
        start = st.i
        if c == "\\":
            st.tokens.extend(_escape(st))
        elif c == "[":
            st.tokens.append(_char_class(st))
        elif c == "(":
            tok = _group_open(st)
            st.tokens.append(tok)
            if tok.kind is Kind.GROUP_OPEN:
                depth += 1
        elif c == ")":
            if depth == 0:
                raise RegexSyntaxError("unmatched ')'", start)
            depth -= 1
            st.i += 1
            st.tokens.append(Token(Kind.GROUP_CLOSE, ")", start))
        elif c == "|":
            st.i += 1
            st.tokens.append(Token(Kind.ALT, "|", start))
        elif c == ".":
            st.i += 1
            st.tokens.append(Token(Kind.DOT, ".", start))
        elif c in "^$":
            st.i += 1
            st.tokens.append(Token(Kind.ANCHOR, c, start, name=c))
        elif c in "*+?" or (c == "{" and _looks_like_quant(st)):
            st.tokens.append(_quantifier(st))
        elif c == "{":
            raise RegexSyntaxError("illegal repetition '{'", start)
        else:
            st.i += 1
            st.tokens.append(
                Token(Kind.LITERAL, c, start, cp=ord(c), verbatim=0x20 <= ord(c) < 0x7F)
            )
    if depth:
        raise RegexSyntaxError("unclosed group", len(st.s))
    return st.tokens


def capture_count(tokens: list[Token]) -> int:
    return sum(
        1
        for t in tokens
        if t.kind is Kind.GROUP_OPEN and t.group in (GroupKind.CAPTURE, GroupKind.NAMED)
    )


def _looks_like_quant(st: _State) -> bool:
    j = st.i + 1
    s = st.s
    k = j
    while k < len(s) and s[k].isdigit():
        k += 1
    if k == j:
        return False
    if k < len(s) and s[k] == "}":
        return True
    if k < len(s) and s[k] == ",":
        k += 1
        while k < len(s) and s[k].isdigit():
            k += 1
        return k < len(s) and s[k] == "}"
    return False


def _quantifier(st: _State) -> Token:
    start = st.i
    prev = st.tokens[-1] if st.tokens else None
    if (
        prev is None
        or prev.kind in (Kind.ALT, Kind.QUANT, Kind.FLAGS)
        or (prev.kind is Kind.GROUP_OPEN)
    ):
        raise RegexSyntaxError("dangling quantifier", start)
    c = st.s[st.i]
    if c == "{":
        end = st.s.index("}", st.i)
        body = st.s[st.i + 1 : end]
        st.i = end + 1
        if "," in body:
            lo_s, hi_s = body.split(",", 1)
            qmin, qmax = int(lo_s), (int(hi_s) if hi_s else None)
        else:
            qmin = qmax = int(body)
        if qmax is not None and qmax < qmin:
            raise RegexSyntaxError("illegal repetition range", start)
    else:
        st.i += 1
        qmin, qmax = {"*": (0, None), "+": (1, None), "?": (0, 1)}[c]
    lazy = possessive = False
    if st.peek() == "?":
        lazy = True
        st.i += 1
    elif st.peek() == "+":
        possessive = True
        st.i += 1
    return Token(
        Kind.QUANT,
        st.s[start : st.i],
        start,
        qmin=qmin,
        qmax=qmax,
        lazy=lazy,
        possessive=possessive,
    )


def _group_open(st: _State) -> Token:
    start = st.i
    s = st.s
    if not s.startswith("(?", st.i):
        st.i += 1
        st.groups += 1
        return Token(Kind.GROUP_OPEN, "(", start, group=GroupKind.CAPTURE)
    st.i += 2
    two = s[st.i : st.i + 2]
    simple = {":": GroupKind.NONCAPTURE, "=": GroupKind.LOOKAHEAD, "!": GroupKind.NEG_LOOKAHEAD}
    simple[">"] = GroupKind.ATOMIC
    if two in ("<=", "<!"):
        st.i += 2
        kind = GroupKind.LOOKBEHIND if two == "<=" else GroupKind.NEG_LOOKBEHIND
        return Token(Kind.GROUP_OPEN, s[start : st.i], start, group=kind)
    c = st.peek()
    if c in simple:
        st.i += 1
        return Token(Kind.GROUP_OPEN, s[start : st.i], start, group=simple[c])
    if c == "<":
        end = s.find(">", st.i)
        name = s[st.i + 1 : end] if end != -1 else ""
        if not name or not name[0].isascii() or not name[0].isalpha() or not name.isalnum():
            raise RegexSyntaxError("invalid group name", start)
        st.i = end + 1
        st.groups += 1
        return Token(Kind.GROUP_OPEN, s[start : st.i], start, group=GroupKind.NAMED, name=name)
    # inline flags: (?on-off) or (?on-off:X)
    j = st.i
    while j < len(s) and s[j] in JAVA_FLAGS | {"-"}:
        j += 1
    spec = s[st.i : j]
    if j >= len(s) or s[j] not in ":)" or spec.count("-") > 1:
        raise RegexSyntaxError("unknown inline group construct", start)
    on, _, off = spec.partition("-")
    if "x" in on:
        raise RegexSyntaxError("comments mode (?x) is not supported", start)
    st.i = j + 1
    if s[j] == ")":
        return Token(Kind.FLAGS, s[start : st.i], start, flags_on=on, flags_off=off)
    return Token(
        Kind.GROUP_OPEN,
        s[start : st.i],
        start,
        group=GroupKind.SCOPED_FLAGS,
        flags_on=on,
        flags_off=off,
    )


def _hex(st: _State, n: int, start: int) -> int:
    digits = st.s[st.i : st.i + n]
    if len(digits) != n or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
        raise RegexSyntaxError("illegal hexadecimal escape", start)
    st.i += n
    return int(digits, 16)


def _codepoint_escape(st: _State, start: int) -> int | None:
    """Parse escapes denoting a single code point. ``st.i`` points after the backslash."""
    c = st.peek()
    if c in _SIMPLE_ESCAPES:
        st.i += 1
        return _SIMPLE_ESCAPES[c]
    if c == "x":
        st.i += 1
        if st.peek() == "{":
            end = st.s.find("}", st.i)
            if end == -1:
                raise RegexSyntaxError("unclosed \\x{", start)
            body = st.s[st.i + 1 : end]
            st.i = end + 1
            try:
                return int(body, 16)
            except ValueError as exc:
                raise RegexSyntaxError("illegal hexadecimal escape", start) from exc
        return _hex(st, 2, start)
    if c == "u":
        st.i += 1
        return _hex(st, 4, start)
    if c == "0":
        st.i += 1
        digits = ""
        while len(digits) < 3 and st.peek() in "01234567" and st.peek():
            if len(digits) == 2 and digits[0] > "3":
                break
            digits += st.peek()
            st.i += 1
        if not digits:
            raise RegexSyntaxError("illegal octal escape", start)
        return int(digits, 8)
    if c == "c":
        st.i += 1
        ch = st.peek()
        if not ch:
            raise RegexSyntaxError("illegal control escape", start)
        st.i += 1
        return ord(ch) ^ 64
    if c and not c.isalnum() and c.isascii():
        st.i += 1
        return ord(c)
    return None


def _property(st: _State, start: int) -> tuple[str, bool]:
    negated = st.peek() == "P"
    st.i += 1
    if st.peek() == "{":
        end = st.s.find("}", st.i)
        if end == -1:
            raise RegexSyntaxError("unclosed property", start)
        name = st.s[st.i + 1 : end]
        st.i = end + 1
    else:
        name = st.peek()
        if not name:
            raise RegexSyntaxError("illegal property", start)
        st.i += 1
    return name, negated


def _escape(st: _State) -> list[Token]:
    start = st.i
    st.i += 1
    c = st.peek()
    if not c:
        raise RegexSyntaxError("trailing backslash", start)
    if c == "Q":
        end = st.s.find("\\E", st.i + 1)
        body = st.s[st.i + 1 :] if end == -1 else st.s[st.i + 1 : end]
        st.i = len(st.s) if end == -1 else end + 2
        return [Token(Kind.LITERAL, ch, start, cp=ord(ch)) for ch in body]
    if c in "123456789":
        num = c
        st.i += 1
        while st.peek().isdigit() and int(num + st.peek()) <= st.groups:
            num += st.peek()
            st.i += 1
        return [Token(Kind.BACKREF, st.s[start : st.i], start, ref=int(num))]
    if c == "k":
        st.i += 1
        if st.peek() != "<":
            raise RegexSyntaxError("\\k is not followed by '<'", start)
        end = st.s.find(">", st.i)
        if end == -1:
            raise RegexSyntaxError("unclosed \\k<name>", start)
        name = st.s[st.i + 1 : end]
        st.i = end + 1
        return [Token(Kind.BACKREF, st.s[start : st.i], start, ref=name)]
    if c in "dDwWsS":
        st.i += 1
        return [Token(Kind.ESCAPE_CLASS, "\\" + c, start, name=c)]
    if c in "pP":
        name, negated = _property(st, start)
        return [Token(Kind.PROPERTY, st.s[start : st.i], start, name=name, negated=negated)]
    if c in "hH":
        st.i += 1
        return [Token(Kind.HSPACE, "\\" + c, start, negated=c == "H")]
    if c in "vV":
        st.i += 1
        return [Token(Kind.VSPACE, "\\" + c, start, negated=c == "V")]
    if c == "R":
        st.i += 1
        return [Token(Kind.LINEBREAK, "\\R", start)]
    if c in "bBAzZG":
        st.i += 1
        return [Token(Kind.ANCHOR, "\\" + c, start, name="\\" + c)]
    cp = _codepoint_escape(st, start)
    if cp is None:
        raise RegexSyntaxError(f"unsupported escape '\\{c}'", start)
    text = st.s[start : st.i]
    verbatim = len(text) == 2 and not text[1].isalnum() and text[1].isascii()
    return [Token(Kind.LITERAL, text, start, cp=cp, verbatim=verbatim)]


def _class_char(st: _State, start: int) -> ClassItem:
    """One class member that denotes a single code point (for ranges) or an escape item."""
    c = st.s[st.i]
    if c != "\\":
        st.i += 1
        return ClassItem(ItemKind.CHAR, text=c, cp=ord(c))
    esc_start = st.i
    st.i += 1
    e = st.peek()
    if not e:
        raise RegexSyntaxError("trailing backslash in class", start)
    if e in "dDwWsS":
        st.i += 1
        return ClassItem(ItemKind.ESCAPE_CLASS, text="\\" + e, name=e)
    if e in "pP":
        name, negated = _property(st, esc_start)
        return ClassItem(ItemKind.PROPERTY, text=st.s[esc_start : st.i], name=name, negated=negated)
    if e in "hH":
        st.i += 1
        return ClassItem(ItemKind.HSPACE, text="\\" + e, negated=e == "H")
    if e in "vV":
        st.i += 1
        return ClassItem(ItemKind.VSPACE, text="\\" + e, negated=e == "V")
    cp = _codepoint_escape(st, esc_start)
    if cp is None:
        raise RegexSyntaxError(f"unsupported escape '\\{e}' in class", esc_start)
    return ClassItem(ItemKind.CHAR, text=st.s[esc_start : st.i], cp=cp)


def _char_class(st: _State) -> Token:
    start = st.i
    st.i += 1
    negated = False
    if st.peek() == "^":
        negated = True
        st.i += 1
    if st.peek() == "]":
        raise RegexSyntaxError("empty or ambiguous character class '[]'", start)
    items: list[ClassItem] = []
    while True:
        if st.i >= len(st.s):
            raise RegexSyntaxError("unclosed character class", start)
        c = st.s[st.i]
        if c == "]":
            st.i += 1
            break
        if c == "[":
            nested = _char_class(st)
            items.append(ClassItem(ItemKind.NESTED, text=nested.text))
            continue
        if st.s.startswith("&&", st.i):
            st.i += 2
            items.append(ClassItem(ItemKind.INTERSECTION, text="&&"))
            continue
        if st.s.startswith("\\Q", st.i):
            end = st.s.find("\\E", st.i + 2)
            if end == -1:
                raise RegexSyntaxError("unclosed \\Q in class", st.i)
            items.extend(
                ClassItem(ItemKind.CHAR, text=ch, cp=ord(ch)) for ch in st.s[st.i + 2 : end]
            )
            st.i = end + 2
            continue
        item = _class_char(st, start)
        if (
            item.kind is ItemKind.CHAR
            and st.peek() == "-"
            and st.peek(1) not in ("]", "")
            and st.peek(1) != "["
        ):
            st.i += 1
            hi = _class_char(st, start)
            if hi.kind is not ItemKind.CHAR or hi.cp is None or item.cp is None:
                raise RegexSyntaxError("illegal character range", start)
            if hi.cp < item.cp:
                raise RegexSyntaxError("illegal character range", start)
            items.append(
                ClassItem(ItemKind.RANGE, text=item.text, cp=item.cp, hi=hi.cp, hi_text=hi.text)
            )
            continue
        items.append(item)
    return Token(Kind.CLASS, st.s[start : st.i], start, negated=negated, items=tuple(items))


__all__ = [
    "ClassItem",
    "GroupKind",
    "ItemKind",
    "Kind",
    "RegexSyntaxError",
    "Token",
    "capture_count",
    "tokenize",
]
