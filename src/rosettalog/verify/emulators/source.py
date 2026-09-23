"""Reference evaluator for the IR, using the *source* regex dialect (Java for QRadar LSX).

This stands in for "what QRadar would extract". It evaluates the IR directly, so it reflects
the parser's semantics as the frontend understood them; the regexes are executed with Java
semantics approximated by the ``regex`` module (see docs/verification.md for known gaps).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import regex as pyregex

from rosettalog.ir import (
    Capture,
    Coalesce,
    Expr,
    IfMatch,
    Literal_,
    Lookup,
    MatchGroup,
    ParserSpec,
    ParseTime,
    Template,
)
from rosettalog.regex.translate import translate
from rosettalog.timefmt.joda import compile_format, format_timestamp, parse

REGEX_TIMEOUT_S = 2.0


@dataclass
class SourceEmulator:
    spec: ParserSpec
    compiled: dict[str, Any] = field(init=False)
    unavailable: dict[str, str] = field(init=False)
    """Pattern id -> reason, for patterns that cannot be emulated locally."""

    def __post_init__(self) -> None:
        self.compiled = {}
        self.unavailable = {}
        for pid, pattern in self.spec.patterns.items():
            tr = translate(pattern.source, "python", case_insensitive=pattern.case_insensitive)
            if tr.pattern is None:
                self.unavailable[pid] = "; ".join(i.message for i in tr.issues)
            else:
                # Java's \w \d \s \b and (?i) are ASCII-only by default; so is ASCII mode here.
                self.compiled[pid] = pyregex.compile(tr.pattern, pyregex.ASCII)

    def _search(self, pid: str, log: str) -> Any:
        rx = self.compiled.get(pid)
        if rx is None:
            return None
        try:
            return rx.search(log, timeout=REGEX_TIMEOUT_S)
        except TimeoutError:
            return None

    def _eval(self, e: Expr, log: str, now: datetime) -> str | None:
        match e:
            case Capture(pattern_id=pid, group=g):
                m = self._search(pid, log)
                return (m.group(g) or None) if m else None
            case Template(pattern_id=pid, parts=parts):
                m = self._search(pid, log)
                if not m:
                    return None
                return "".join(p if isinstance(p, str) else (m.group(p) or "") for p in parts)
            case Literal_(value=v):
                return v
            case IfMatch(pattern_id=pid, value=v):
                return self._eval(v, log, now) if self._search(pid, log) else None
            case Coalesce(items=items):
                for item in items:
                    value = self._eval(item, log, now)
                    if value:
                        return value
                return None
            case Lookup(key=k, table=table, default=d):
                key = self._eval(k, log, now)
                if key is not None and key in table:
                    return table[key]
                return self._eval(d, log, now) if d is not None else None
            case ParseTime(value=v, format=fmt_text):
                text = self._eval(v, log, now)
                fmt = compile_format(fmt_text)
                if text is None or not fmt.usable:
                    return None
                dt = parse(text, fmt, now=now)
                return format_timestamp(dt) if dt else None
        raise AssertionError(e)  # pragma: no cover

    def select_group(self, log: str) -> MatchGroup | None:
        groups = self.spec.match_groups
        if len(groups) == 1:
            return groups[0]
        for group in groups:
            if any(self._search(pid, log) for pid in group.selector_pattern_ids):
                return group
        return None

    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]:
        """Canonical field -> value (``None`` when the field gets no value)."""
        out: dict[str, str | None] = dict.fromkeys(self.spec.fields())
        group = self.select_group(log)
        if group is None:
            return out
        for rule in group.rules:
            out[rule.field] = self._eval(rule.expr, log, now)
        return out
