"""Local emulator for the props.conf / transforms.conf subset emitted by the Splunk backend.

Reads the generated .conf files and applies them to a raw event like Splunk's search-time
pipeline would: REPORT transforms (in order) -> EVAL (all evaluated in parallel against the
pre-EVAL fields) -> plus TIME_PREFIX/TIME_FORMAT for ``_time``. Regexes run as PCRE via the
``regex`` module. Unknown settings or eval functions raise :class:`SplunkEmulationError`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from rosettalog.plugins import BackendResult
from rosettalog.timefmt.joda import Comp, build_datetime, format_timestamp
from rosettalog.verify.emulators.pcre import compile_pcre

SUPPORTED_PROPS = {"SHOULD_LINEMERGE", "TIME_PREFIX", "TIME_FORMAT"}


class SplunkEmulationError(Exception):
    pass


def parse_conf(text: str) -> dict[str, dict[str, str]]:
    stanzas: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = stanzas.setdefault(line[1:-1], {})
            continue
        if current is None or "=" not in line:
            raise SplunkEmulationError(f"unexpected line in .conf: {raw!r}")
        key, _, value = line.partition("=")
        current[key.strip()] = value.strip()
    return stanzas


# --- eval language subset -------------------------------------------------------------------

_EVAL_TOKEN = re.compile(
    r"""(?P<ws>\s+)|(?P<string>"(?:[^"\\]|\\.)*")|(?P<number>\d+)
    |(?P<ident>[A-Za-z_][A-Za-z0-9_]*)|(?P<op>==|!=|[(),.])""",
    re.VERBOSE,
)


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text[1:-1])


def _lex_eval(text: str) -> list[tuple[str, str]]:
    out = []
    pos = 0
    while pos < len(text):
        m = _EVAL_TOKEN.match(text, pos)
        if not m:
            raise SplunkEmulationError(
                f"cannot parse eval expression near {text[pos : pos + 20]!r}"
            )
        pos = m.end()
        if m.lastgroup != "ws":
            assert m.lastgroup is not None
            out.append((m.lastgroup, m.group()))
    return out


class _EvalParser:
    def __init__(self, text: str) -> None:
        self.toks = _lex_eval(text)
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise SplunkEmulationError("unexpected end of eval expression")
        self.i += 1
        return tok

    def accept(self, value: str) -> bool:
        tok = self.peek()
        if tok is not None and tok[1] == value:
            self.i += 1
            return True
        return False

    def parse(self) -> tuple[Any, ...]:
        node = self.or_()
        if self.peek() is not None:
            raise SplunkEmulationError(f"trailing tokens in eval: {self.toks[self.i :]}")
        return node

    def or_(self) -> tuple[Any, ...]:
        node = self.and_()
        while self.accept("OR"):
            node = ("or", node, self.and_())
        return node

    def and_(self) -> tuple[Any, ...]:
        node = self.cmp()
        while self.accept("AND"):
            node = ("and", node, self.cmp())
        return node

    def cmp(self) -> tuple[Any, ...]:
        node = self.concat()
        tok = self.peek()
        if tok and tok[1] in ("==", "!="):
            self.i += 1
            return (tok[1], node, self.concat())
        return node

    def concat(self) -> tuple[Any, ...]:
        node = self.primary()
        while self.accept("."):
            node = ("concat", node, self.primary())
        return node

    def primary(self) -> tuple[Any, ...]:
        kind, value = self.next()
        if kind == "string":
            return ("lit", _unescape(value))
        if kind == "number":
            return ("lit", value)
        if value == "(":
            node = self.or_()
            if not self.accept(")"):
                raise SplunkEmulationError("expected ')'")
            return node
        if kind == "ident":
            if self.accept("("):
                args = []
                if not self.accept(")"):
                    args.append(self.or_())
                    while self.accept(","):
                        args.append(self.or_())
                    if not self.accept(")"):
                        raise SplunkEmulationError("expected ')' after arguments")
                return ("call", value, args)
            return ("field", value)
        raise SplunkEmulationError(f"unexpected token {value!r}")


def _eval(node: tuple[Any, ...], fields: dict[str, str]) -> Any:
    op = node[0]
    if op == "lit":
        return node[1]
    if op == "field":
        return fields.get(node[1])
    if op == "concat":
        a, b = _eval(node[1], fields), _eval(node[2], fields)
        return None if a is None or b is None else f"{a}{b}"
    if op in ("and", "or"):
        a = bool(_eval(node[1], fields))
        return (
            (a and bool(_eval(node[2], fields)))
            if op == "and"
            else (a or bool(_eval(node[2], fields)))
        )
    if op in ("==", "!="):
        a, b = _eval(node[1], fields), _eval(node[2], fields)
        if a is None or b is None:
            return False
        return (a == b) if op == "==" else (a != b)
    name, args = node[1], node[2]
    if name == "true":
        return True
    if name == "false":
        return False
    if name == "null":
        return None
    if name == "if":
        return _eval(args[1] if _eval(args[0], fields) else args[2], fields)
    if name == "case":
        for i in range(0, len(args) - 1, 2):
            if _eval(args[i], fields):
                return _eval(args[i + 1], fields)
        return None
    if name == "coalesce":
        for arg in args:
            v = _eval(arg, fields)
            if v is not None:
                return v
        return None
    vals = [_eval(a, fields) for a in args]
    if name == "match":
        return vals[0] is not None and compile_pcre(vals[1]).search(vals[0]) is not None
    if name == "isnotnull":
        return vals[0] is not None
    if name == "isnull":
        return vals[0] is None
    raise SplunkEmulationError(f"unsupported eval function {name!r}")


# --- timestamps -----------------------------------------------------------------------------

_STRPTIME = {
    "Y": (r"(\d{4})", Comp.YEAR4),
    "y": (r"(\d{2})", Comp.YEAR2),
    "m": (r"(\d{1,2})", Comp.MONTH_NUM),
    "b": (r"([A-Za-z]{3})", Comp.MONTH_TEXT),
    "h": (r"([A-Za-z]{3})", Comp.MONTH_TEXT),
    "B": (r"([A-Za-z]+)", Comp.MONTH_TEXT),
    "d": (r"(\d{1,2})", Comp.DAY),
    "e": (r"\s?(\d{1,2})", Comp.DAY),
    "H": (r"(\d{1,2})", Comp.HOUR24),
    "I": (r"(\d{1,2})", Comp.HOUR12),
    "M": (r"(\d{1,2})", Comp.MINUTE),
    "S": (r"(\d{1,2})", Comp.SECOND),
    "p": (r"([AaPp][Mm])", Comp.AMPM),
    "a": (r"[A-Za-z]{3}", None),
    "A": (r"[A-Za-z]+", None),
}


def strptime_regex(fmt: str) -> tuple[str, list[Comp]]:
    rx: list[str] = []
    comps: list[Comp] = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c != "%":
            rx.append(re.escape(c))
            i += 1
            continue
        spec = fmt[i + 1 : i + 3]
        if spec[:1].isdigit() and spec[1:] == "N":
            rx.append(rf"(\d{{{spec[0]}}})")
            comps.append(Comp.FRACTION)
            i += 3
            continue
        if fmt.startswith("%:z", i):
            rx.append(r"([+-])(\d{2}):(\d{2})")
            comps += [Comp.TZ_SIGN, Comp.TZ_HOURS, Comp.TZ_MINUTES]
            i += 3
            continue
        letter = fmt[i + 1 : i + 2]
        if letter == "%":
            rx.append("%")
        elif letter == "N":
            rx.append(r"(\d{3})")
            comps.append(Comp.FRACTION)
        elif letter == "z":
            rx.append(r"([+-])(\d{2})(\d{2})")
            comps += [Comp.TZ_SIGN, Comp.TZ_HOURS, Comp.TZ_MINUTES]
        elif letter in _STRPTIME:
            pattern, comp = _STRPTIME[letter]
            rx.append(pattern)
            if comp is not None:
                comps.append(comp)
        else:
            raise SplunkEmulationError(f"TIME_FORMAT directive %{letter} is not emulated")
        i += 2
    return "".join(rx), comps


@dataclass
class _Timestamp:
    prefix: Any
    fmt: Any
    comps: list[Comp]

    def extract(self, raw: str, now: datetime) -> str | None:
        start = 0
        if self.prefix is not None:
            m = self.prefix.search(raw)
            if m is None:
                return None
            start = m.end()
            found = self.fmt.match(raw, start)
        else:
            found = self.fmt.search(raw)
        if found is None:
            return None
        values = dict(zip(self.comps, found.groups(), strict=True))
        if Comp.YEAR2 in values:  # Splunk's %y pivot: 69-99 -> 19xx, 00-68 -> 20xx
            yy = int(values.pop(Comp.YEAR2))
            values[Comp.YEAR4] = str(1900 + yy if yy >= 69 else 2000 + yy)
        dt = build_datetime(values, now=now)
        return format_timestamp(dt) if dt else None


class SplunkEmulator:
    target: ClassVar[str] = "splunk"
    engine_note: ClassVar[str] = (
        "Generated props/transforms are parsed and applied locally (REPORT -> parallel EVAL -> "
        "timestamp); PCRE is approximated with the Python 'regex' module."
    )

    def __init__(self, result: BackendResult) -> None:
        self.result = result
        files = {f.path: f.content for f in result.files}
        props = parse_conf(files.get("props.conf", ""))
        transforms = parse_conf(files.get("transforms.conf", ""))
        sourcetype = result.options.get("sourcetype")
        if sourcetype not in props:
            raise SplunkEmulationError(f"stanza [{sourcetype}] not found in props.conf")
        stanza = props[sourcetype]
        self.reports: list[tuple[Any, list[tuple[str, str]]]] = []
        self.evals: list[tuple[str, tuple[Any, ...]]] = []
        for key, value in stanza.items():
            if key.startswith("REPORT-"):
                for name in (n.strip() for n in value.split(",")):
                    t = transforms.get(name)
                    if t is None or set(t) - {"REGEX", "FORMAT"}:
                        raise SplunkEmulationError(f"transform [{name}] missing or unsupported")
                    pairs = [tuple(p.split("::", 1)) for p in t["FORMAT"].split()]
                    self.reports.append((compile_pcre(t["REGEX"]), pairs))  # type: ignore[arg-type]
            elif key.startswith("EVAL-"):
                self.evals.append((key[5:], _EvalParser(value).parse()))
            elif key not in SUPPORTED_PROPS:
                raise SplunkEmulationError(f"props setting {key} is not emulated")
        self.timestamp: _Timestamp | None = None
        if "TIME_FORMAT" in stanza:
            rx, comps = strptime_regex(stanza["TIME_FORMAT"])
            prefix = stanza.get("TIME_PREFIX")
            self.timestamp = _Timestamp(
                compile_pcre(prefix) if prefix else None, compile_pcre(rx), comps
            )

    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]:
        fields: dict[str, str] = {"_raw": log}
        for rx, pairs in self.reports:
            m = rx.search(log)
            if m is None:
                continue
            groups = [m.group(0), *m.groups()]
            for name, template in pairs:
                value = re.sub(r"\$(\d+)", lambda g: groups[int(g.group(1))] or "", template)  # noqa: B023
                if value:
                    fields[name] = value
        computed = {name: _eval(node, fields) for name, node in self.evals}
        fields.update({k: v for k, v in computed.items() if v is not None})
        for k, v in computed.items():
            if v is None:
                fields.pop(k, None)
        if self.timestamp is not None:
            ts = self.timestamp.extract(log, now)
            if ts is not None:
                fields["_time"] = ts
        return {name: fields.get(name) for name in self.result.field_names.values()}
