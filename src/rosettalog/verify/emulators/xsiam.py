"""Local emulator for the XSIAM Parsing Rule subset emitted by the ``xsiam`` backend.

It parses the *generated text* and evaluates it for one raw log, using Google RE2 like XQL does.
Anything outside the subset raises :class:`XsiamEmulationError`; nothing is silently skipped.

**This is not XSIAM.** It encodes Rosettalog's reading of Palo Alto's documentation, plus two
undocumented behaviours evidenced by Palo Alto's shipped Parsing Rules (``demisto/content``):

* ``regexcapture`` returns an empty object when the pattern does not match (``obj -> name`` is
  then null), and a group that did not participate reads as null;
* in string literals, backslashes pass through unchanged and ``\\"`` is a double quote.

Other semantics: ``x = null`` / ``x != null`` test for null, other comparisons involving null
are false, ``concat`` with a null argument returns
null (as in SQL), ``config case_sensitive = true`` makes ``=`` exact (otherwise case-insensitive),
``current_time()`` is the reference time of the samples (the ingestion time).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, ClassVar

import re2

from rosettalog.plugins import BackendResult
from rosettalog.timefmt.joda import format_timestamp

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+|//[^\n]*)
  | (?P<header>^\[(?:INGEST|MODEL):[^\]\n]*\])
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<number>\d+)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
  | (?P<op>->|!=|[=(),|;-])
    """,
    re.VERBOSE | re.MULTILINE,
)
_FUNCS = {
    "regexcapture", "if", "coalesce", "concat", "lowercase", "to_integer", "add", "mod",
    "format_string", "format_timestamp", "current_time", "parse_timestamp", "arraycreate",
}  # fmt: skip


class XsiamEmulationError(Exception):
    pass


@dataclass(frozen=True)
class Tok:
    kind: str
    value: str


def _string(raw: str) -> str:
    """An XQL string literal: only ``\\"`` is an escape; other backslashes are kept."""
    return raw[1:-1].replace('\\"', '"')


def lex(text: str) -> list[Tok]:
    out: list[Tok] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise XsiamEmulationError(f"unexpected character {text[pos]!r} at offset {pos}")
        pos = m.end()
        kind = m.lastgroup
        assert kind is not None
        if kind == "ws":
            continue
        value = m.group()
        out.append(Tok(kind, _string(value) if kind == "string" else value))
    return out


Node = tuple[Any, ...]


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self) -> Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, kind: str | None = None, value: str | None = None) -> Tok:
        tok = self.peek()
        if tok is None or (kind and tok.kind != kind) or (value and tok.value != value):
            raise XsiamEmulationError(f"expected {value or kind}, got {tok}")
        self.i += 1
        return tok

    def at(self, value: str) -> bool:
        tok = self.peek()
        return tok is not None and tok.value == value and tok.kind in ("op", "ident")

    def expr(self) -> Node:
        node = self.conj()
        while self.at("or"):
            self.take()
            node = ("or", node, self.conj())
        return node

    def conj(self) -> Node:
        node = self.cmp()
        while self.at("and"):
            self.take()
            node = ("and", node, self.cmp())
        return node

    def cmp(self) -> Node:
        node = self.arrow()
        if self.at("=") or self.at("!="):
            op = self.take().value
            node = (op, node, self.arrow())
        return node

    def arrow(self) -> Node:
        node = self.primary()
        while self.at("->"):
            self.take()
            node = ("->", node, self.take("ident").value)
        return node

    def primary(self) -> Node:
        tok = self.take()
        if tok.kind == "string":
            return ("lit", tok.value)
        if tok.kind == "number":
            return ("lit", int(tok.value))
        if tok.kind == "ident":
            if tok.value == "null":
                return ("lit", None)
            if self.at("("):
                if tok.value not in _FUNCS:
                    raise XsiamEmulationError(f"function {tok.value}() is not emulated")
                self.take("op", "(")
                args: list[Node] = []
                if not self.at(")"):
                    args.append(self.expr())
                    while self.at(","):
                        self.take()
                        args.append(self.expr())
                self.take("op", ")")
                return ("call", tok.value, args)
            return ("col", tok.value)
        raise XsiamEmulationError(f"unexpected token {tok}")


@dataclass
class ParsingRule:
    header: dict[str, str]
    case_sensitive: bool
    stages: list[tuple[str, Any]]
    """("alter", [(column, node)]) or ("fields-", [column])."""


def parse_rule(text: str, section: str = "INGEST") -> ParsingRule:
    toks = lex(text)
    if not toks or toks[0].kind != "header" or not toks[0].value.startswith(f"[{section}:"):
        raise XsiamEmulationError(f"expected a [{section}:...] header")
    body = toks[0].value[len(section) + 2 : -1]
    header = dict(re.findall(r'(\w+)\s*=\s*"?([^",\]]*)"?', body))
    p = _Parser(toks[1:])
    case_sensitive = False
    stages: list[tuple[str, Any]] = []
    first = True
    while True:
        if not first:
            if p.at(";"):
                p.take()
                break
            p.take("op", "|")
        first = False
        word = p.take("ident").value
        if word == "config":
            p.take("ident", "case_sensitive")
            p.take("op", "=")
            value = p.take("ident").value
            if value not in ("true", "false"):
                raise XsiamEmulationError(f"case_sensitive = {value}")
            case_sensitive = value == "true"
        elif word == "alter":
            assigns = []
            while True:
                name = p.take("ident").value
                p.take("op", "=")
                assigns.append((name, p.expr()))
                if not p.at(","):
                    break
                p.take()
            stages.append(("alter", assigns))
        elif word == "fields":
            p.take("op", "-")
            names = [p.take("ident").value]
            while p.at(","):
                p.take()
                names.append(p.take("ident").value)
            stages.append(("fields-", names))
        else:
            raise XsiamEmulationError(f"stage {word!r} is not emulated")
    if p.peek() is not None:
        raise XsiamEmulationError("only one statement is emulated")
    return ParsingRule(header, case_sensitive, stages)


def _zone(text: str) -> timezone:
    m = re.fullmatch(r"([+-])(\d{2}):(\d{2})", text)
    if not m:
        raise XsiamEmulationError(f"time zone {text!r} is not emulated")
    minutes = int(m.group(2)) * 60 + int(m.group(3))
    return timezone(timedelta(minutes=minutes if m.group(1) == "+" else -minutes))


def _parse_timestamp(fmt: str, text: str, zone: str | None) -> datetime | None:
    if fmt == "%Y-%m-%d %H:%M:%S":
        m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", text)
        frac = ""
    elif fmt == "%Y-%m-%d %H:%M:%E*S":
        m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", text)
        frac = (m.group(7) or "") if m else ""
    else:
        raise XsiamEmulationError(f"parse_timestamp format {fmt!r} is not emulated")
    if m is None:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=_zone(zone) if zone else UTC)
    except ValueError:
        return None  # e.g. day 31 in a 30-day month; XSIAM's behaviour is not documented
    if frac:
        dt += timedelta(microseconds=int((frac + "000000")[:6]))
    return dt.astimezone(UTC)


class _Eval:
    def __init__(self, row: dict[str, Any], case_sensitive: bool, now: datetime) -> None:
        self.row = row
        self.case_sensitive = case_sensitive
        self.now = now

    def eq(self, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return False
        if isinstance(a, str) and isinstance(b, str) and not self.case_sensitive:
            return a.lower() == b.lower()
        return bool(a == b)

    def __call__(self, node: Node) -> Any:
        kind = node[0]
        if kind == "lit":
            return node[1]
        if kind == "col":
            if node[1] not in self.row:
                raise XsiamEmulationError(f"unknown column {node[1]}")
            return self.row[node[1]]
        if kind == "->":
            obj = self(node[1])
            return None if obj is None else obj.get(node[2])
        if kind in ("=", "!="):
            if node[2] == ("lit", None):  # "x = null" / "x != null" test for null
                return (self(node[1]) is None) == (kind == "=")
            a, b = self(node[1]), self(node[2])
            if a is None or b is None:
                return False  # other comparisons with null are not true
            return self.eq(a, b) == (kind == "=")
        if kind == "and":
            return bool(self(node[1])) and bool(self(node[2]))
        if kind == "or":
            return bool(self(node[1])) or bool(self(node[2]))
        if kind == "call":
            return self.call(node[1], node[2])
        raise AssertionError(node)  # pragma: no cover

    def call(self, name: str, args: list[Node]) -> Any:
        if name == "if":
            for i in range(0, len(args) - 1, 2):
                if self(args[i]):
                    return self(args[i + 1])
            return self(args[-1]) if len(args) % 2 else None
        if name == "coalesce":
            for a in args:
                v = self(a)
                if v is not None:
                    return v
            return None
        values = [self(a) for a in args]
        if name == "regexcapture":
            text, pattern = values
            if text is None:
                return None
            m = re2.search(pattern, str(text))
            return {} if m is None else dict(m.groupdict())
        if name == "concat":
            return None if any(v is None for v in values) else "".join(str(v) for v in values)
        if name == "lowercase":
            return None if values[0] is None else str(values[0]).lower()
        if name == "arraycreate":
            return None if any(v is None for v in values) else list(values)
        if name == "to_integer":
            return None if values[0] is None else int(values[0])
        if name == "add":
            return None if None in values else values[0] + values[1]
        if name == "mod":
            return None if None in values else values[0] % values[1]
        if name == "current_time":
            return self.now
        if name == "format_timestamp":
            fmt, ts = values
            if fmt != "%Y":
                raise XsiamEmulationError(f"format_timestamp format {fmt!r} is not emulated")
            return f"{ts.year:04d}"
        if name == "format_string":
            fmt, *rest = values
            if any(v is None for v in rest):
                return None
            return str(fmt % tuple(rest))
        if name == "parse_timestamp":
            fmt, text, *zone = values
            if text is None:
                return None
            return _parse_timestamp(fmt, text, zone[0] if zone else None)
        raise XsiamEmulationError(f"function {name}() is not emulated")  # pragma: no cover


class XsiamEmulator:
    target: ClassVar[str] = "xsiam"
    engine_note: ClassVar[str] = (
        "XSIAM emulation: Rosettalog's interpreter of the documented XQL subset it emits, with "
        "RE2 regexes. Not verified against a tenant (no local XSIAM engine exists)."
    )

    def __init__(self, result: BackendResult) -> None:
        text = next((f.content for f in result.files if f.path.endswith(".xif")), None)
        if text is None:
            raise XsiamEmulationError("no parsing rule in the backend output")
        self.rule = parse_rule(text)
        model = next((f.content for f in result.files if f.path.endswith(".model.xif")), None)
        self.model = parse_rule(model, "MODEL") if model is not None else None
        if self.model and self.model.header.get("dataset") != self.rule.header.get(
            "target_dataset"
        ):
            raise XsiamEmulationError("the Data Model Rule does not model the parsed dataset")
        self.field_names = result.field_names

    @staticmethod
    def _run(rule: ParsingRule, row: dict[str, Any], now: datetime) -> None:
        ev = _Eval(row, rule.case_sensitive, now)
        for kind, payload in rule.stages:
            if kind == "alter":
                computed = {name: ev(node) for name, node in payload}
                row.update(computed)
            else:
                for name in payload:
                    row.pop(name, None)

    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]:
        """Parsed raw-dataset row, then (if present) the Data Model Rule's XDM fields.

        An XDM array (MAC addresses) is reported as its elements joined with ",".
        """
        row: dict[str, Any] = {"_raw_log": log}
        self._run(self.rule, row, now)
        if self.model is not None:
            self._run(self.model, row, now)
        out: dict[str, str | None] = {}
        for name in self.field_names.values():
            value = row.get(name)
            if isinstance(value, datetime):
                out[name] = format_timestamp(value)
            elif isinstance(value, list):
                out[name] = ",".join(str(v) for v in value)
            else:
                out[name] = None if value is None else str(value)
        return out
