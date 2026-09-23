"""Local emulator for the KQL subset emitted by the Sentinel backend.

It parses the *generated text* (not the backend's intent) and executes it row by row, using
Google RE2 for regular expressions exactly like Kusto does. Any construct outside the supported
subset raises :class:`KqlEmulationError` - it never silently skips.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import re2

from rosettalog.plugins import BackendResult
from rosettalog.timefmt.joda import format_timestamp

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+|//[^\n]*)
  | (?P<verbatim>@"(?:[^"]|"")*")
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<number>\d+\.\d+|\d+)
  | (?P<ident>project-away|[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|!=|[-+*/%()\[\],|=;{}:])
    """,
    re.VERBOSE,
)


class KqlEmulationError(Exception):
    pass


@dataclass(frozen=True)
class Tok:
    kind: str
    value: str


def lex(text: str) -> list[Tok]:
    out: list[Tok] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise KqlEmulationError(f"unexpected character {text[pos]!r} at offset {pos}")
        pos = m.end()
        kind = m.lastgroup
        assert kind is not None
        if kind == "ws":
            continue
        value = m.group()
        if kind == "verbatim":
            value = value[2:-1].replace('""', '"')
            kind = "string"
        elif kind == "string":
            value = json.loads(value)
        out.append(Tok(kind, value))
    return out


# --- AST ------------------------------------------------------------------------------------

Node = tuple[Any, ...]


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self, k: int = 0) -> Tok | None:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def next(self) -> Tok:
        tok = self.peek()
        if tok is None:
            raise KqlEmulationError("unexpected end of query")
        self.i += 1
        return tok

    def expect(self, value: str) -> Tok:
        tok = self.next()
        if tok.value != value:
            raise KqlEmulationError(f"expected {value!r}, got {tok.value!r}")
        return tok

    def accept(self, value: str) -> bool:
        tok = self.peek()
        if tok is not None and tok.value == value and tok.kind in ("op", "ident"):
            self.i += 1
            return True
        return False

    # program
    def program(self) -> tuple[str, list[Node]]:
        self.expect("let")
        name = self.next().value
        self.expect("=")
        self.expect("(")
        depth = 1
        while depth:
            tok = self.next()
            depth += {"(": 1, ")": -1}.get(tok.value, 0) if tok.kind == "op" else 0
        self.expect("{")
        table = self.next().value
        ops: list[Node] = [("table", table)]
        while self.accept("|"):
            ops.append(self.operator())
        self.expect("}")
        self.expect(";")
        if self.next().value != name or self.peek() is not None:
            raise KqlEmulationError("expected the program to end by invoking the function")
        return name, ops

    def operator(self) -> Node:
        tok = self.next()
        if tok.value == "where":
            return ("where", self.expr())
        if tok.value == "extend":
            assigns = [self.assign()]
            while self.accept(","):
                assigns.append(self.assign())
            return ("extend", assigns)
        if tok.value == "project-away":
            names = [self.column_pattern()]
            while self.accept(","):
                names.append(self.column_pattern())
            return ("project-away", names)
        raise KqlEmulationError(f"unsupported operator {tok.value!r}")

    def column_pattern(self) -> str:
        name = self.next().value
        if self.accept("*"):
            name += "*"
        return name

    def assign(self) -> tuple[str, Node]:
        name = self.next()
        if name.kind != "ident":
            raise KqlEmulationError(f"expected column name, got {name.value!r}")
        self.expect("=")
        return name.value, self.expr()

    # expressions
    def expr(self) -> Node:
        node = self.and_()
        while self.accept("or"):
            node = ("or", node, self.and_())
        return node

    def and_(self) -> Node:
        node = self.cmp()
        while self.accept("and"):
            node = ("and", node, self.cmp())
        return node

    def cmp(self) -> Node:
        node = self.add()
        tok = self.peek()
        if tok and tok.value in ("==", "!="):
            self.i += 1
            return (tok.value, node, self.add())
        if tok and tok.value == "matches":
            self.i += 1
            self.expect("regex")
            return ("matches", node, self.add())
        return node

    def add(self) -> Node:
        node = self.mul()
        while (tok := self.peek()) and tok.kind == "op" and tok.value in "+-":
            self.i += 1
            node = (tok.value, node, self.mul())
        return node

    def mul(self) -> Node:
        node = self.unary()
        while (tok := self.peek()) and tok.kind == "op" and tok.value in ("*", "/", "%"):
            self.i += 1
            node = (tok.value, node, self.unary())
        return node

    def unary(self) -> Node:
        if self.accept("-"):
            return ("neg", self.unary())
        node = self.primary()
        while self.accept("["):
            node = ("index", node, self.expr())
            self.expect("]")
        return node

    def primary(self) -> Node:
        tok = self.next()
        if tok.kind == "string":
            return ("lit", tok.value)
        if tok.kind == "number":
            return ("lit", float(tok.value) if "." in tok.value else int(tok.value))
        if tok.value == "(":
            node = self.expr()
            self.expect(")")
            return node
        if tok.kind == "ident":
            if tok.value in ("true", "false"):
                return ("lit", tok.value == "true")
            if self.accept("("):
                if tok.value == "datetime":
                    self.expect("null")
                    self.expect(")")
                    return ("lit", None)
                args: list[Node] = []
                if not self.accept(")"):
                    args.append(self.expr())
                    while self.accept(","):
                        args.append(self.expr())
                    self.expect(")")
                return ("call", tok.value, args)
            return ("col", tok.value)
        raise KqlEmulationError(f"unexpected token {tok.value!r}")


# --- evaluation -----------------------------------------------------------------------------

_RE2_CACHE: dict[str, Any] = {}


def _re2(pattern: str) -> Any:
    if pattern not in _RE2_CACHE:
        opts = re2.Options()
        opts.log_errors = False
        try:
            _RE2_CACHE[pattern] = re2.compile(pattern, opts)
        except Exception as exc:
            raise KqlEmulationError(f"regex does not compile in RE2: {pattern!r}: {exc}") from exc
    return _RE2_CACHE[pattern]


def _s(value: Any) -> str:
    return "" if value is None else str(value)


def _toint(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    text = str(value).strip()
    return int(text) if re.fullmatch(r"[+-]?\d+", text) else None


def _toreal(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value))
    except ValueError:
        return None


def _empty(value: Any) -> bool:
    return value is None or value == ""


def _make_datetime(args: list[Any]) -> datetime | None:
    if any(a is None for a in args):
        return None
    y, mo, d, h, mi = (int(a) for a in args[:5])
    sec = float(args[5])
    try:
        base = datetime(y, mo, d, h, mi, tzinfo=UTC)
    except ValueError:
        return None
    return base + timedelta(seconds=sec)


class _Evaluator:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def ev(self, node: Node, row: dict[str, Any]) -> Any:
        op = node[0]
        if op == "lit":
            return node[1]
        if op == "col":
            if node[1] not in row:
                raise KqlEmulationError(f"unknown column {node[1]!r}")
            return row[node[1]]
        if op == "call":
            return self.call(node[1], node[2], row)
        if op == "index":
            base, idx = self.ev(node[1], row), self.ev(node[2], row)
            if (
                not isinstance(base, list)
                or not isinstance(idx, int)
                or not -len(base) <= idx < len(base)
            ):
                return None
            return base[idx]
        if op == "neg":
            v = self.ev(node[1], row)
            return None if v is None else -v
        if op in ("and", "or"):
            left = bool(self.ev(node[1], row))
            if op == "and":
                return left and bool(self.ev(node[2], row))
            return left or bool(self.ev(node[2], row))
        if op == "matches":
            text = _s(self.ev(node[1], row))
            return _re2(_s(self.ev(node[2], row))).search(text) is not None
        a, b = self.ev(node[1], row), self.ev(node[2], row)
        if op in ("==", "!="):
            if isinstance(a, str) or isinstance(b, str):
                a, b = _s(a), _s(b)
            return (a == b) if op == "==" else (a != b)
        if a is None or b is None:
            return None
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            if b == 0:
                return None
            if isinstance(a, int) and isinstance(b, int):
                return int(a / b)
            return a / b
        if op == "%":
            return (
                None
                if b == 0
                else math.fmod(a, b)
                if isinstance(a, float)
                else int(math.fmod(a, b))
            )
        raise KqlEmulationError(f"unsupported operator {op!r}")

    def call(self, name: str, args: list[Node], row: dict[str, Any]) -> Any:
        if name == "iff":
            cond = self.ev(args[0], row)
            return self.ev(args[1] if cond else args[2], row)
        if name == "case":
            for i in range(0, len(args) - 1, 2):
                if self.ev(args[i], row):
                    return self.ev(args[i + 1], row)
            return self.ev(args[-1], row)
        if name == "coalesce":
            for arg in args:
                v = self.ev(arg, row)
                if not _empty(v):
                    return v
            return None
        vals = [self.ev(a, row) for a in args]
        if name == "not":
            return not vals[0]
        if name == "extract":
            m = _re2(_s(vals[0])).search(_s(vals[2]))
            if m is None:
                return ""
            return m.group(int(vals[1])) or ""
        if name == "extract_all":
            rx = _re2(_s(vals[0]))
            text = _s(vals[1])
            matches = list(rx.finditer(text)) if text else []
            if not matches:
                return None
            if rx.groups <= 1:
                return [m.group(rx.groups) or "" for m in matches]
            return [[g or "" for g in m.groups()] for m in matches]
        if name == "strcat":
            return "".join(_s(v) for v in vals)
        if name == "tostring":
            v = vals[0]
            return "" if v is None else v if isinstance(v, str) else json.dumps(v)
        if name == "toint":
            return _toint(vals[0])
        if name == "toreal":
            return _toreal(vals[0])
        if name == "tolower":
            return _s(vals[0]).lower()
        if name == "substring":
            text = _s(vals[0])
            start = int(vals[1])
            return text[start : start + int(vals[2])] if len(vals) > 2 else text[start:]
        if name == "indexof":
            return _s(vals[0]).find(_s(vals[1]))
        if name == "isnotempty":
            return not _empty(vals[0])
        if name == "make_datetime":
            return _make_datetime(vals)
        if name == "datetime_add":
            part, amount, dt = vals
            if dt is None or amount is None:
                return None
            units = {"minute": "minutes", "hour": "hours", "second": "seconds", "day": "days"}
            return dt + timedelta(**{units[part]: amount})
        if name == "now":
            return self.now
        if name == "getyear":
            return None if vals[0] is None else vals[0].year
        raise KqlEmulationError(f"unsupported function {name!r}")


class KqlEmulator:
    target: ClassVar[str] = "sentinel"
    engine_note: ClassVar[str] = (
        "Generated KQL is parsed and executed locally with Google RE2 (Kusto's regex engine); "
        "only the operator/function subset the backend emits is supported."
    )

    def __init__(self, result: BackendResult) -> None:
        self.result = result
        kql = next((f.content for f in result.files if f.path.endswith(".kql")), None)
        if kql is None:
            raise KqlEmulationError("no .kql file in backend output")
        _, self.ops = _Parser(lex(kql)).program()
        self.message_column = result.options.get("message_column", "SyslogMessage")

    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]:
        ev = _Evaluator(now)
        row: dict[str, Any] = {self.message_column: log, "disabled": False}
        for op in self.ops:
            kind = op[0]
            if kind == "where" and not ev.ev(op[1], row):
                return dict.fromkeys(self.result.field_names.values())
            if kind == "extend":
                for name, node in op[1]:
                    row[name] = ev.ev(node, row)
            if kind == "project-away":
                for pattern in op[1]:
                    prefix = pattern.rstrip("*")
                    for col in [
                        c
                        for c in row
                        if c == pattern or (pattern.endswith("*") and c.startswith(prefix))
                    ]:
                        del row[col]
        out: dict[str, str | None] = {}
        for name in self.result.field_names.values():
            v = row.get(name)
            if isinstance(v, datetime):
                out[name] = format_timestamp(v)
            elif _empty(v):
                out[name] = None
            else:
                out[name] = str(v)
        return out
