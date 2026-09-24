r"""Translate Java regular expressions to other engines, reporting every semantic difference.

Targets:

* ``re2``    - Google RE2, used by Kusto (Microsoft Sentinel KQL).
* ``pcre``   - PCRE, used by Splunk ``REGEX``/``EXTRACT``/``match()``.
* ``python`` - the third-party ``regex`` module; used only to *emulate* the Java source locally.
* ``onig``   - Oniguruma as embedded by Elasticsearch grok: Joni with ``Syntax.RUBY``
  (https://github.com/elastic/elasticsearch/blob/main/libs/grok/src/main/java/org/elasticsearch/grok/Grok.java,
  https://github.com/jruby/joni/blob/master/src/org/joni/Syntax.java). Ruby syntax differs from
  Java: ``\h`` is a hex digit, ``^``/``$`` are line anchors, ``(?m)`` means dot-all and there is
  no ``\Q..\E`` (https://github.com/kkos/oniguruma/blob/master/doc/RE). The translator
  therefore emits only constructs whose meaning is the same in both: explicit ASCII classes for
  ``\d \w \s``, lookaround-based ``\b``, ``\A``/``\Z`` anchors and explicit whitespace sets.

A translation returns the new pattern (or ``None`` if impossible) and a list of issues. An issue
with status PARTIAL means the pattern was emitted but may not behave identically; UNSUPPORTED
means no pattern was emitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Literal

import regex as pyregex

from rosettalog.ir.findings import Status
from rosettalog.regex.tokenizer import (
    ClassItem,
    GroupKind,
    ItemKind,
    Kind,
    RegexSyntaxError,
    Token,
    capture_count,
    tokenize,
)

Target = Literal["re2", "pcre", "python", "onig"]

META = set("\\^$.|?*+()[]{}")
CLASS_SPECIAL = set("\\]^-[&")
RE2_MAX_REPEAT = 1000

# Java's predefined classes are ASCII-only by default; Oniguruma's may not be. Spell them out.
_ASCII_CLASS = {"d": "0-9", "w": "a-zA-Z0-9_", "s": " \\t\\n\\x0B\\f\\r"}
_WORD = "[a-zA-Z0-9_]"
_ONIG_BOUNDARY = f"(?:(?<={_WORD})(?!{_WORD})|(?<!{_WORD})(?={_WORD}))"
_ONIG_NON_BOUNDARY = f"(?:(?<={_WORD})(?={_WORD})|(?<!{_WORD})(?!{_WORD}))"

# Java POSIX character classes are US-ASCII only by default. Expanded as class members.
POSIX = {
    "Lower": r"a-z",
    "Upper": r"A-Z",
    "ASCII": r"\x00-\x7F",
    "Alpha": r"a-zA-Z",
    "Digit": r"0-9",
    "Alnum": r"a-zA-Z0-9",
    "Punct": r"!-/:-@\[-`{-~",
    "Graph": r"!-~",
    "Print": r"\x20-\x7E",
    "Blank": r" \t",
    "Cntrl": r"\x00-\x1F\x7F",
    "XDigit": r"0-9a-fA-F",
    "Space": r" \t\n\x0B\f\r",
}
GENERAL_CATEGORIES = {
    "L", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No",
    "P", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "S", "Sm", "Sc", "Sk", "So",
    "Z", "Zs", "Zl", "Zp", "C", "Cc", "Cf", "Co", "Cn",
}  # fmt: skip
_HSPACE_CPS = [(0x09, 0x09), (0x20, 0x20), (0xA0, 0xA0), (0x1680, 0x1680), (0x180E, 0x180E),
               (0x2000, 0x200A), (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000)]  # fmt: skip
_VSPACE_CPS = [(0x0A, 0x0D), (0x85, 0x85), (0x2028, 0x2029)]


@dataclass(frozen=True)
class RegexIssue:
    status: Status
    code: str
    message: str


@dataclass(frozen=True)
class RegexTranslation:
    target: Target
    pattern: str | None
    issues: tuple[RegexIssue, ...] = ()
    groups: int = 0

    @property
    def status(self) -> Status:
        if self.pattern is None:
            return Status.UNSUPPORTED
        return (
            Status.PARTIAL
            if any(i.status is not Status.FULL for i in self.issues)
            else (Status.FULL)
        )


class _Unsupported(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class _Ctx:
    target: Target
    issues: list[RegexIssue] = field(default_factory=list)
    group_numbers: dict[str, int] = field(default_factory=dict)
    """pcre only: Java group name -> number (names are dropped for Splunk, see _group_open)."""
    multiline: bool = False
    """onig only: the pattern turns on Java's MULTILINE flag somewhere."""

    def partial(self, code: str, message: str) -> None:
        issue = RegexIssue(Status.PARTIAL, code, message)
        if issue not in self.issues:
            self.issues.append(issue)

    def unsupported(self, code: str, message: str) -> _Unsupported:
        return _Unsupported(code, message)


# --- code point formatting -----------------------------------------------------------------


def _fmt_cp(cp: int, target: Target, *, in_class: bool = False) -> str:
    ch = chr(cp)
    if target == "onig" and cp == 0x25:
        return "\\x{25}"  # never let grok see '%{' (its pattern-reference syntax)
    special = CLASS_SPECIAL if in_class else META
    if 0x20 <= cp < 0x7F:
        if ch in special:
            return "\\" + ch
        return ch
    named = {9: r"\t", 10: r"\n", 13: r"\r", 12: r"\f"}
    if cp in named:
        return named[cp]
    if target == "python":
        if cp <= 0xFF:
            return f"\\x{cp:02X}"
        if cp <= 0xFFFF:
            return f"\\u{cp:04X}"
        return f"\\U{cp:08X}"
    return f"\\x{{{cp:X}}}"


def _ranges(pairs: list[tuple[int, int]], target: Target) -> str:
    out = []
    for lo, hi in pairs:
        out.append(_fmt_cp(lo, target, in_class=True))
        if hi != lo:
            out.append("-" + _fmt_cp(hi, target, in_class=True))
    return "".join(out)


# --- translation ---------------------------------------------------------------------------


def _property_members(name: str, ctx: _Ctx) -> tuple[str, bool]:
    """Return (text, is_class_members). ``is_class_members`` means it must be wrapped in [...]."""
    base = name[2:] if name.startswith("Is") and len(name) > 2 else name
    if name in POSIX:
        return POSIX[name], True
    if base in GENERAL_CATEGORIES:
        return base, False
    if name.startswith(("In", "java")) or "=" in name:
        raise ctx.unsupported(
            "REGEX_UNICODE_PROPERTY",
            f"Java-specific character property '\\p{{{name}}}' has no equivalent in {ctx.target}.",
        )
    # Treat as a Unicode script name (e.g. IsLatin -> Latin); validated by compiling later.
    ctx.partial(
        "REGEX_UNICODE_SCRIPT",
        f"'\\p{{{name}}}' assumed to be the Unicode script '{base}'; "
        "verify the target supports it.",
    )
    return base, False


def _class_item(item: ClassItem, ctx: _Ctx) -> str:
    t = ctx.target
    match item.kind:
        case ItemKind.CHAR:
            assert item.cp is not None
            plain = len(item.text) == 1 and 0x20 <= item.cp < 0x7F
            if plain and item.text not in CLASS_SPECIAL and not (t == "onig" and item.cp == 0x25):
                return item.text
            return _fmt_cp(item.cp, t, in_class=True)
        case ItemKind.RANGE:
            assert item.cp is not None
            assert item.hi is not None
            return _fmt_cp(item.cp, t, in_class=True) + "-" + _fmt_cp(item.hi, t, in_class=True)
        case ItemKind.ESCAPE_CLASS:
            if t == "onig":
                ascii_members = _ASCII_CLASS[item.name.lower()]
                return f"[^{ascii_members}]" if item.name.isupper() else ascii_members
            return "\\" + item.name
        case ItemKind.PROPERTY:
            text, members = _property_members(item.name, ctx)
            if members:
                if item.negated:
                    raise ctx.unsupported(
                        "REGEX_CLASS_SET_OPERATION",
                        f"Negated POSIX property '{item.text}' inside a character class.",
                    )
                return text
            return ("\\P" if item.negated else "\\p") + "{" + text + "}"
        case ItemKind.HSPACE | ItemKind.VSPACE:
            if t == "pcre":
                return item.text
            if item.negated:
                raise ctx.unsupported(
                    "REGEX_CLASS_SET_OPERATION",
                    f"Negated '{item.text}' inside a character class cannot be expressed in {t}.",
                )
            return _ranges(_HSPACE_CPS if item.kind is ItemKind.HSPACE else _VSPACE_CPS, t)
        case ItemKind.NESTED | ItemKind.INTERSECTION:
            raise ctx.unsupported(
                "REGEX_CLASS_SET_OPERATION",
                "Java character class union/intersection (nested '[...]' or '&&') is not "
                f"supported by {t}.",
            )
    raise AssertionError(item.kind)  # pragma: no cover


def _flags(on: str, off: str, ctx: _Ctx) -> tuple[str, str]:
    keep_on: list[str] = []
    keep_off: list[str] = []
    for flag, bucket in [(f, keep_on) for f in on] + [(f, keep_off) for f in off]:
        if ctx.target == "onig" and flag in "sm":
            # Ruby syntax: (?m) is dot-all (Java's s); Java's m is handled via raw ^/$ anchors.
            if flag == "s":
                bucket.append("m")
        elif flag in "ims":
            bucket.append(flag)
        elif flag == "U":
            raise ctx.unsupported(
                "REGEX_FLAG_UNSUPPORTED",
                "Java flag 'U' (UNICODE_CHARACTER_CLASS) has no equivalent "
                f"(in {ctx.target} 'U' means something else).",
            )
        elif flag in "ud" and (ctx.target != "python" or flag == "d"):
            desc = "UNICODE_CASE" if flag == "u" else "UNIX_LINES"
            ctx.partial(
                "REGEX_FLAG_DROPPED",
                f"Java flag '{flag}' ({desc}) was dropped; case-folding or line-terminator "
                "behaviour may differ for non-ASCII input.",
            )
    return "".join(keep_on), "".join(keep_off)


def _flag_text(on: str, off: str) -> str:
    return on + ("-" + off if off else "")


def _lookbehind_variable(tokens: list[Token], start: int) -> bool:
    depth = 0
    for tok in tokens[start + 1 :]:
        if tok.kind is Kind.GROUP_OPEN:
            depth += 1
        elif tok.kind is Kind.GROUP_CLOSE:
            if depth == 0:
                return False
            depth -= 1
        elif tok.kind is Kind.QUANT and tok.qmax != tok.qmin:
            return True
    return False


def _emit(tokens: list[Token], ctx: _Ctx) -> str:
    t = ctx.target
    out: list[str] = []
    for idx, tok in enumerate(tokens):
        match tok.kind:
            case Kind.LITERAL:
                assert tok.cp is not None
                verbatim = tok.verbatim and not (t == "onig" and tok.cp == 0x25)
                out.append(tok.text if verbatim else _fmt_cp(tok.cp, t))
            case Kind.CLASS:
                if (
                    t == "onig"
                    and tok.negated
                    and any(i.kind is ItemKind.ESCAPE_CLASS and i.name.isupper() for i in tok.items)
                ):
                    raise ctx.unsupported(
                        "REGEX_CLASS_SET_OPERATION",
                        f"'{tok.text}' negates a negated class escape; expressing it for "
                        "Oniguruma would need class intersection.",
                    )
                body = "".join(_class_item(item, ctx) for item in tok.items)
                out.append("[" + ("^" if tok.negated else "") + body + "]")
            case Kind.ESCAPE_CLASS:
                if t == "onig":
                    ascii_members = _ASCII_CLASS[tok.name.lower()]
                    out.append(("[^" if tok.name.isupper() else "[") + ascii_members + "]")
                else:
                    out.append(tok.text)
            case Kind.PROPERTY:
                text, members = _property_members(tok.name, ctx)
                if members:
                    out.append("[" + ("^" if tok.negated else "") + text + "]")
                else:
                    out.append(("\\P" if tok.negated else "\\p") + "{" + text + "}")
            case Kind.HSPACE | Kind.VSPACE:
                if t == "pcre":
                    out.append(tok.text)
                else:
                    cps = _HSPACE_CPS if tok.kind is Kind.HSPACE else _VSPACE_CPS
                    out.append("[" + ("^" if tok.negated else "") + _ranges(cps, t) + "]")
            case Kind.LINEBREAK:
                alt = r"\r\n|[" + _ranges([(0x0A, 0x0D), (0x85, 0x85), (0x2028, 0x2029)], t) + "]"
                if t == "pcre":
                    out.append(r"\R")
                elif t in ("python", "onig"):
                    out.append("(?>" + alt + ")")
                else:
                    ctx.partial(
                        "RE2_LINEBREAK_APPROX",
                        "'\\R' is atomic in Java; RE2 emulation is non-atomic and may match "
                        "differently when '\\r\\n' is followed by pattern parts that need '\\n'.",
                    )
                    out.append("(?:" + alt + ")")
            case Kind.DOT | Kind.ALT | Kind.GROUP_CLOSE:
                out.append(tok.text)
            case Kind.ANCHOR:
                out.append(_anchor(tok.name, ctx))
            case Kind.BACKREF:
                if t == "re2":
                    raise ctx.unsupported(
                        "RE2_NO_BACKREFERENCE",
                        f"Backreference '{tok.text}' is not supported by RE2 (KQL).",
                    )
                if t == "onig":
                    out.append(f"\\k<{tok.ref}>")
                elif isinstance(tok.ref, str) and t == "pcre":
                    out.append(f"\\g{{{ctx.group_numbers[tok.ref]}}}")
                elif isinstance(tok.ref, str):
                    out.append(f"(?P={tok.ref})")
                else:
                    out.append(f"\\g{{{tok.ref}}}" if t == "pcre" else f"\\g<{tok.ref}>")
            case Kind.GROUP_OPEN:
                out.append(_group_open(tok, tokens, idx, ctx))
            case Kind.FLAGS:
                on, off = _flags(tok.flags_on, tok.flags_off, ctx)
                if on or off:
                    out.append(f"(?{_flag_text(on, off)})")
            case Kind.QUANT:
                out.append(_quant(tok, ctx))
    return "".join(out)


def _anchor(name: str, ctx: _Ctx) -> str:
    t = ctx.target
    if t == "onig":
        return _onig_anchor(name, ctx)
    if name in ("^", "$", "\\b", "\\B", "\\A"):
        return name
    if name == "\\z":
        return "\\Z" if t == "python" else "\\z"
    if name == "\\Z":
        if t == "pcre":
            return "\\Z"
        if t == "python":
            return r"(?=(?:\r\n|[\n\r\x85\u2028\u2029])?\Z)"
        ctx.partial(
            "RE2_END_ANCHOR_APPROX",
            "Java '\\Z' (end of input but for a final line terminator) was translated to '\\z' "
            "(absolute end); events ending in a line break may no longer match.",
        )
        return "\\z"
    if name == "\\G":
        if t == "re2":
            raise ctx.unsupported("RE2_NO_G_ANCHOR", "'\\G' is not supported by RE2 (KQL).")
        return "\\G"
    raise AssertionError(name)  # pragma: no cover


def _onig_anchor(name: str, ctx: _Ctx) -> str:
    """Anchors for Oniguruma/Ruby syntax, where ^ and $ always match at line boundaries."""
    if name in ("^", "$"):
        if ctx.multiline:
            ctx.partial(
                "ONIG_MULTILINE_ANCHORS",
                "The pattern uses Java's MULTILINE flag; '^'/'$' are emitted as Ruby line "
                "anchors for the whole pattern, which may differ where the flag is scoped.",
            )
            return name
        return "\\A" if name == "^" else "\\Z"
    if name == "\\b":
        return _ONIG_BOUNDARY
    if name == "\\B":
        return _ONIG_NON_BOUNDARY
    return name  # \A \z \Z \G have the same meaning in Oniguruma


def _onig_lookbehind_fixed(tokens: list[Token], start: int) -> bool:
    """Oniguruma requires fixed-width lookbehind (only top-level alternatives may differ)."""
    depth = 0
    for tok in tokens[start + 1 :]:
        if tok.kind is Kind.GROUP_OPEN:
            depth += 1
        elif tok.kind is Kind.GROUP_CLOSE:
            if depth == 0:
                return True
            depth -= 1
        elif _variable_width(tok, depth):
            return False
    return True


def _variable_width(tok: Token, depth: int) -> bool:
    """Token that can make a lookbehind variable-width (nested alternation counts)."""
    if tok.kind is Kind.QUANT:
        return tok.qmax != tok.qmin
    return tok.kind in (Kind.BACKREF, Kind.LINEBREAK) or (tok.kind is Kind.ALT and depth > 0)


def _group_open(tok: Token, tokens: list[Token], idx: int, ctx: _Ctx) -> str:
    t = ctx.target
    g = tok.group
    if g is GroupKind.CAPTURE:
        return "("
    if g is GroupKind.NAMED:
        if t == "pcre":
            # Splunk turns named groups in a transform's REGEX into fields and then does not
            # apply FORMAT $N (found with Splunk 10.4.3), so named groups become plain groups.
            return "("
        return f"(?<{tok.name}>" if t == "onig" else f"(?P<{tok.name}>"
    if g is GroupKind.NONCAPTURE:
        return "(?:"
    if g is GroupKind.SCOPED_FLAGS:
        on, off = _flags(tok.flags_on, tok.flags_off, ctx)
        return f"(?{_flag_text(on, off)}:" if (on or off) else "(?:"
    if g is GroupKind.ATOMIC:
        if t == "re2":
            ctx.partial(
                "RE2_ATOMIC_APPROX",
                "Atomic group '(?>...)' translated to a plain group; RE2 may match some inputs "
                "that Java rejects.",
            )
            return "(?:"
        return "(?>"
    # lookaround
    if t == "re2":
        raise ctx.unsupported(
            "RE2_NO_LOOKAROUND",
            f"Lookaround '{tok.text}...)' is not supported by RE2 (KQL).",
        )
    lookbehind = g in (GroupKind.LOOKBEHIND, GroupKind.NEG_LOOKBEHIND)
    if t == "onig" and lookbehind and not _onig_lookbehind_fixed(tokens, idx):
        raise ctx.unsupported(
            "ONIG_LOOKBEHIND_NOT_FIXED",
            "Lookbehind is not fixed-width. Oniguruma (grok) rejects such patterns, and an "
            "invalid grok pattern would make the whole ingest pipeline unusable.",
        )
    if t == "pcre" and lookbehind and _lookbehind_variable(tokens, idx):
        ctx.partial(
            "PCRE_VARIABLE_LOOKBEHIND",
            "Lookbehind contains a variable-length quantifier; Java allows bounded "
            "variable-length lookbehind but many PCRE versions reject it.",
        )
    return tok.text


def _quant(tok: Token, ctx: _Ctx) -> str:
    if tok.qmax == tok.qmin:
        base = {0: "{0}", 1: "{1}"}.get(tok.qmin, f"{{{tok.qmin}}}")
    elif (tok.qmin, tok.qmax) == (0, None):
        base = "*"
    elif (tok.qmin, tok.qmax) == (1, None):
        base = "+"
    elif (tok.qmin, tok.qmax) == (0, 1):
        base = "?"
    elif tok.qmax is None:
        base = f"{{{tok.qmin},}}"
    else:
        base = f"{{{tok.qmin},{tok.qmax}}}"
    if ctx.target == "re2" and max(tok.qmin, tok.qmax or 0) > RE2_MAX_REPEAT:
        raise ctx.unsupported(
            "RE2_REPEAT_LIMIT", f"Repetition '{tok.text}' exceeds RE2's limit of {RE2_MAX_REPEAT}."
        )
    if tok.lazy:
        return base + "?"
    if tok.possessive:
        if ctx.target == "re2":
            ctx.partial(
                "RE2_POSSESSIVE_APPROX",
                f"Possessive quantifier '{tok.text}' translated to greedy; RE2 may match some "
                "inputs that Java rejects.",
            )
            return base
        return base + "+"
    return base


# --- public API ----------------------------------------------------------------------------


def _validate(pattern: str, target: Target) -> str | None:
    """Compile ``pattern`` with the real engine where one is available. Returns an error text."""
    try:
        if target == "re2":
            import re2

            opts = re2.Options()
            opts.log_errors = False
            re2.compile(pattern, opts)
        elif target == "python":
            pyregex.compile(pattern)
    except Exception as exc:  # engine-specific error types
        return str(exc)
    return None


def _uses_multiline(tokens: list[Token]) -> bool:
    return any(
        "m" in t.flags_on
        for t in tokens
        if t.kind is Kind.FLAGS or (t.kind is Kind.GROUP_OPEN and t.group is GroupKind.SCOPED_FLAGS)
    )


def translate_tokens(tokens: list[Token], target: Target) -> RegexTranslation:
    """Translate an already tokenized pattern (or a slice of one) without validation."""
    ctx = _Ctx(target, multiline=target == "onig" and _uses_multiline(tokens))
    number = 0
    for tok in tokens:
        if tok.kind is Kind.GROUP_OPEN and tok.group in (GroupKind.CAPTURE, GroupKind.NAMED):
            number += 1
            if tok.group is GroupKind.NAMED:
                ctx.group_numbers[tok.name] = number
    try:
        text = _emit(tokens, ctx)
    except _Unsupported as exc:
        return RegexTranslation(
            target, None, (*ctx.issues, RegexIssue(Status.UNSUPPORTED, exc.code, exc.message))
        )
    return RegexTranslation(target, text, tuple(ctx.issues))


@lru_cache(maxsize=4096)
def translate(source: str, target: Target, *, case_insensitive: bool = False) -> RegexTranslation:
    """Translate a Java regex to ``target``."""
    try:
        tokens = tokenize(source)
    except RegexSyntaxError as exc:
        issue = RegexIssue(
            Status.UNSUPPORTED,
            "REGEX_PARSE_ERROR",
            f"Could not parse the Java regex: {exc}. Nothing was translated.",
        )
        return RegexTranslation(target, None, (issue,))
    result = translate_tokens(tokens, target)
    if result.pattern is None:
        return result
    pattern = ("(?i)" if case_insensitive else "") + result.pattern
    error = _validate(pattern, target)
    if error is not None:
        code = {"re2": "RE2_COMPILE_ERROR", "python": "EMULATION_COMPILE_ERROR"}.get(
            target, "REGEX_COMPILE_ERROR"
        )
        issue = RegexIssue(
            Status.UNSUPPORTED,
            code,
            f"Translated pattern does not compile for {target}: {error}",
        )
        return RegexTranslation(target, None, (*result.issues, issue))
    groups = capture_count(tokens)
    return RegexTranslation(target, pattern, result.issues, groups)
