"""Local emulator for the ingest pipelines emitted by the Elastic backend.

It parses the generated JSON and executes the processors in order, mirroring the documented
behaviour of ``grok`` (first matching pattern wins, named captures only), ``set``
(``override``, ``ignore_empty_value``, ``{{{field}}}`` templates), ``date`` (java.time, see
:mod:`rosettalog.timefmt.javatime`) and ``remove``. Conditions are a strict subset of Painless.
Anything else - processor, option, condition or template syntax - raises
:class:`ElasticEmulationError`.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, ClassVar

from rosettalog.plugins import BackendResult
from rosettalog.regex.onig_emulation import compile_onig
from rosettalog.timefmt.javatime import compile_java, parse_java
from rosettalog.timefmt.joda import format_timestamp

ALLOWED = {
    "grok": {"field", "patterns", "ignore_failure", "if", "tag", "description"},
    "set": {"field", "value", "override", "ignore_empty_value", "if", "tag", "description"},
    # "locale" is deliberately not emulated: Elasticsearch rejects some documented values (e.g.
    # "ENGLISH"), so the backend never sets it and the emulator refuses it.
    "date": {
        "field",
        "target_field",
        "formats",
        "timezone",
        "ignore_failure",
        "if",
        "tag",
        "description",
    },
    "remove": {"field", "ignore_missing", "tag", "description"},
}
_MUSTACHE = re.compile(r"\{\{\{([A-Za-z0-9_.@]+)\}\}\}")
_COND_TOKEN = re.compile(
    r"\s*(?:(?P<ctx>ctx\.[A-Za-z_][A-Za-z0-9_]*)|(?P<null>null\b)|(?P<int>-?\d+)"
    r"|(?P<str>'(?:[^'\\]|\\.)*')|(?P<op>==|!=|&&|\|\||!|\(|\)))"
)


class ElasticEmulationError(Exception):
    pass


# --- Painless condition subset ----------------------------------------------------------------


class _Cond:
    def __init__(self, text: str) -> None:
        self.toks: list[tuple[str, str]] = []
        pos = 0
        while pos < len(text):
            if text[pos:].strip() == "":
                break
            m = _COND_TOKEN.match(text, pos)
            if not m or m.end() == pos:
                raise ElasticEmulationError(f"unsupported Painless condition: {text!r}")
            kind = m.lastgroup
            assert kind is not None
            self.toks.append((kind, m.group(kind)))
            pos = m.end()
        self.i = 0

    def _peek(self) -> str | None:
        return self.toks[self.i][1] if self.i < len(self.toks) else None

    def _take(self) -> tuple[str, str]:
        if self.i >= len(self.toks):
            raise ElasticEmulationError("truncated Painless condition")
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def evaluate(self, doc: dict[str, Any]) -> bool:
        self.i = 0
        value = self._or(doc)
        if self.i != len(self.toks):
            raise ElasticEmulationError("trailing tokens in Painless condition")
        return bool(value)

    def _or(self, doc: dict[str, Any]) -> bool:
        value = self._and(doc)
        while self._peek() == "||":
            self._take()
            right = self._and(doc)
            value = value or right
        return value

    def _and(self, doc: dict[str, Any]) -> bool:
        value = self._not(doc)
        while self._peek() == "&&":
            self._take()
            right = self._not(doc)
            value = value and right
        return value

    def _not(self, doc: dict[str, Any]) -> bool:
        if self._peek() == "!":
            self._take()
            return not self._not(doc)
        if self._peek() == "(":
            self._take()
            value = self._or(doc)
            if self._take()[1] != ")":
                raise ElasticEmulationError("expected ')' in Painless condition")
            return value
        left = self._operand(doc)
        op = self._take()[1]
        if op not in ("==", "!="):
            raise ElasticEmulationError(f"unsupported Painless operator {op!r}")
        right = self._operand(doc)
        return bool(left == right) if op == "==" else bool(left != right)

    def _operand(self, doc: dict[str, Any]) -> Any:
        kind, text = self._take()
        if kind == "ctx":
            return doc.get(text[4:])
        if kind == "null":
            return None
        if kind == "int":
            return int(text)
        if kind == "str":
            return re.sub(r"\\(.)", r"\1", text[1:-1])
        raise ElasticEmulationError(f"unexpected token {text!r} in Painless condition")


# --- processors -------------------------------------------------------------------------------


def _render(template: str, doc: dict[str, Any]) -> str:
    if "{{" in _MUSTACHE.sub("", template) or "}}" in _MUSTACHE.sub("", template):
        raise ElasticEmulationError(f"unsupported mustache template {template!r}")
    return _MUSTACHE.sub(lambda m: "" if doc.get(m.group(1)) is None else str(doc[m.group(1)]),
                         template)  # fmt: skip


class ElasticEmulator:
    target: ClassVar[str] = "elastic"
    engine_note: ClassVar[str] = (
        "Generated ingest pipeline JSON is executed locally (grok, set, date, remove); grok's "
        "Oniguruma patterns are approximated with the Python 'regex' module in ASCII mode."
    )

    def __init__(self, result: BackendResult) -> None:
        self.result = result
        text = next((f.content for f in result.files if f.path.endswith(".json")), None)
        if text is None:
            raise ElasticEmulationError("no pipeline JSON in backend output")
        pipeline = json.loads(text)
        if set(pipeline) - {"description", "processors"}:
            raise ElasticEmulationError(f"unsupported pipeline keys: {sorted(pipeline)}")
        self.steps: list[tuple[str, dict[str, Any], _Cond | None]] = []
        for proc in pipeline["processors"]:
            if len(proc) != 1:
                raise ElasticEmulationError(f"malformed processor {proc!r}")
            ((kind, body),) = proc.items()
            if kind not in ALLOWED:
                raise ElasticEmulationError(f"processor {kind!r} is not emulated")
            unknown = set(body) - ALLOWED[kind]
            if unknown:
                raise ElasticEmulationError(f"{kind} option(s) {sorted(unknown)} not emulated")
            if kind == "date" and body.get("timezone", "UTC") != "UTC":
                raise ElasticEmulationError("only timezone UTC is emulated")
            if kind == "grok":
                body = {**body, "_compiled": [compile_onig(p) for p in body["patterns"]]}
            if kind == "date":
                body = {**body, "_formats": [compile_java(f) for f in body["formats"]]}
            cond = _Cond(body["if"]) if "if" in body else None
            self.steps.append((kind, body, cond))

    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]:
        source_field = self.result.options.get("source_field", "message")
        doc: dict[str, Any] = {source_field: log}
        for kind, body, cond in self.steps:
            if cond is not None and not cond.evaluate(doc):
                continue
            if kind == "grok":
                self._grok(body, doc)
            elif kind == "set":
                self._set(body, doc)
            elif kind == "date":
                self._date(body, doc, now)
            else:
                fields = body["field"] if isinstance(body["field"], list) else [body["field"]]
                for name in fields:
                    if name not in doc and not body.get("ignore_missing", False):
                        raise ElasticEmulationError(f"remove: field {name!r} missing")
                    doc.pop(name, None)
        out: dict[str, str | None] = {}
        for name in self.result.field_names.values():
            value = doc.get(name)
            out[name] = None if value in (None, "") else str(value)
        return out

    @staticmethod
    def _grok(body: dict[str, Any], doc: dict[str, Any]) -> None:
        value = doc.get(body["field"])
        if isinstance(value, str):
            for rx in body["_compiled"]:
                m = rx.search(value)
                if m is not None:
                    doc.update({k: v for k, v in m.groupdict().items() if v is not None})
                    return
        if not body.get("ignore_failure", False):
            raise ElasticEmulationError("grok: no pattern matched and ignore_failure is false")

    @staticmethod
    def _set(body: dict[str, Any], doc: dict[str, Any]) -> None:
        value = body["value"]
        rendered = _render(value, doc) if isinstance(value, str) else value
        if body.get("ignore_empty_value", False) and rendered in (None, ""):
            return
        field = body["field"]
        if not body.get("override", True) and doc.get(field) is not None:
            return
        doc[field] = rendered

    @staticmethod
    def _date(body: dict[str, Any], doc: dict[str, Any], now: datetime) -> None:
        text = doc.get(body["field"])
        for fmt in body["_formats"]:
            dt = parse_java(text, fmt, now=now) if isinstance(text, str) else None
            if dt is not None:
                doc[body.get("target_field", "@timestamp")] = format_timestamp(dt)
                return
        if not body.get("ignore_failure", False):
            raise ElasticEmulationError(f"date: could not parse {text!r}")
