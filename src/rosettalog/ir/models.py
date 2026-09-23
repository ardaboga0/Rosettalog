"""Vendor-neutral intermediate representation (IR).

Frontends build these models from source-SIEM artifacts; backends consume them. Nothing in
this module may refer to a specific source or target SIEM beyond descriptive metadata.

A parser artifact is modelled as a small, side-effect-free *extraction program*: an ordered list
of match groups, each holding field rules whose values are :data:`Expr` trees evaluated against
the raw event text.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from rosettalog.ir.findings import Finding


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Provenance(_Frozen):
    file: str
    line: int | None = None


class Pattern(_Frozen):
    id: str
    source: str
    """Regex text exactly as written in the source artifact."""
    dialect: Literal["java"] = "java"
    case_insensitive: bool = False
    provenance: Provenance | None = None


# --- expressions ---------------------------------------------------------------------------


class Capture(_Frozen):
    """Value of capture group ``group`` of the first match of a pattern (0 = whole match)."""

    kind: Literal["capture"] = "capture"
    pattern_id: str
    group: int


class Template(_Frozen):
    """String built from literal text and capture groups of one match of a pattern."""

    kind: Literal["template"] = "template"
    pattern_id: str
    parts: list[str | int]
    """Literal strings and group numbers, e.g. ``[1, ":", 2]``."""


class Literal_(_Frozen):
    kind: Literal["literal"] = "literal"
    value: str


class IfMatch(_Frozen):
    """``value`` if the pattern matches the event, else no value."""

    kind: Literal["if_match"] = "if_match"
    pattern_id: str
    value: Expr


class Coalesce(_Frozen):
    """First item that yields a non-empty value (ordered fallback)."""

    kind: Literal["coalesce"] = "coalesce"
    items: list[Expr]


class Lookup(_Frozen):
    """Map the value of ``key`` through ``table``; use ``default`` when the key is not in it."""

    kind: Literal["lookup"] = "lookup"
    key: Expr
    table: dict[str, str]
    default: Expr | None = None


class ParseTime(_Frozen):
    """Parse ``value`` as a timestamp using a Joda-Time style format string."""

    kind: Literal["parse_time"] = "parse_time"
    value: Expr
    format: str


Expr = Annotated[
    Capture | Template | Literal_ | IfMatch | Coalesce | Lookup | ParseTime,
    Field(discriminator="kind"),
]


# --- parser program ------------------------------------------------------------------------


class FieldRule(_Frozen):
    field: str
    """Canonical (source-neutral) field name, see :mod:`rosettalog.ir.fields`."""
    expr: Expr
    path: str
    """Element path used in findings and reports."""
    line: int | None = None


class MatchGroup(_Frozen):
    order: int
    description: str = ""
    selector_pattern_ids: list[str] = Field(default_factory=list)
    """Patterns deciding whether this group applies when several groups exist."""
    rules: list[FieldRule] = Field(default_factory=list)
    path: str = ""
    line: int | None = None


class ParserSpec(_Frozen):
    patterns: dict[str, Pattern]
    match_groups: list[MatchGroup]
    """Sorted by ``order``. With several groups, the first group whose selector matches wins."""

    def fields(self) -> list[str]:
        seen: dict[str, None] = {}
        for group in self.match_groups:
            for rule in group.rules:
                seen.setdefault(rule.field, None)
        return list(seen)


class Artifact(_Frozen):
    id: str
    """Stable slug, unique within one run; used for output file names."""
    name: str
    kind: Literal["parser"] = "parser"
    source_format: str
    provenance: Provenance
    parser: ParserSpec | None = None
    findings: list[Finding] = Field(default_factory=list)


IfMatch.model_rebuild()
Coalesce.model_rebuild()
Lookup.model_rebuild()
ParseTime.model_rebuild()


def pattern_ids(expr: Expr) -> list[str]:
    """All pattern ids referenced by an expression, in evaluation order, without duplicates."""
    out: dict[str, None] = {}

    def walk(e: Expr) -> None:
        match e:
            case Capture(pattern_id=pid) | Template(pattern_id=pid):
                out.setdefault(pid, None)
            case IfMatch(pattern_id=pid, value=v):
                out.setdefault(pid, None)
                walk(v)
            case Coalesce(items=items):
                for item in items:
                    walk(item)
            case Lookup(key=k, default=d):
                walk(k)
                if d is not None:
                    walk(d)
            case ParseTime(value=v):
                walk(v)
            case Literal_():
                pass

    walk(expr)
    return list(out)
