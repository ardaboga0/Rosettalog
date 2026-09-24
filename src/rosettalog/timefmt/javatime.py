"""java.time patterns as used by the Elasticsearch ingest ``date`` processor.

Elasticsearch builds custom patterns with
``new DateTimeFormatterBuilder().appendPattern(p).toFormatter(Locale.ROOT)
.withResolverStyle(ResolverStyle.STRICT)`` and the processor's locale (ENGLISH by default); no
case-insensitive parsing is enabled. A missing year becomes the current UTC year
(https://github.com/elastic/elasticsearch/blob/main/server/src/main/java/org/elasticsearch/common/time/DateFormatters.java,
https://github.com/elastic/elasticsearch/blob/main/modules/ingest-common/src/main/java/org/elasticsearch/ingest/common/DateFormat.java,
https://www.elastic.co/docs/reference/enrich-processor/date-processor).

This module converts QRadar's Joda-Time ``ext-data`` formats (:mod:`rosettalog.timefmt.joda`)
into such patterns, and parses dates the way that formatter does, for the local emulator.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import regex as pyregex

from rosettalog.ir.findings import Status
from rosettalog.timefmt.joda import Comp, DateFormat, DateIssue, DateToken, build_datetime

MONTHS_SHORT = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTHS_FULL = ["January", "February", "March", "April", "May", "June", "July", "August",
               "September", "October", "November", "December"]  # fmt: skip
DAYS_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
DAYS_FULL = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
_NUMERIC = {"y", "Y", "d", "H", "h", "m", "s", "S"}
_TEXT = {"E", "a"}
_RESERVED = set("'[]{}#")


def _is_numeric(tok: DateToken) -> bool:
    return tok.letter in _NUMERIC or (tok.letter == "M" and tok.count <= 2)


def _quote(text: str) -> str:
    if not text:
        return ""
    if any(ch.isalpha() or ch in _RESERVED for ch in text):
        return "'" + text.replace("'", "''") + "'"
    return text


@dataclass(frozen=True)
class JavaPattern:
    pattern: str
    issues: tuple[DateIssue, ...]


def to_java_pattern(fmt: DateFormat) -> JavaPattern:
    """Translate a (usable) Joda format into an Elasticsearch java.time pattern."""
    toks = fmt.tokens
    out: list[str] = []
    issues: list[DateIssue] = []
    fixed_width = text_fields = False
    for i, tok in enumerate(toks):
        if not tok.letter:
            out.append(_quote(tok.literal))
            continue
        prev_num = i > 0 and _is_numeric(toks[i - 1])
        next_num = i + 1 < len(toks) and _is_numeric(toks[i + 1])
        adjacent = _is_numeric(tok) and (prev_num or next_num)
        fixed_width = fixed_width or adjacent
        L, n = tok.letter, tok.count
        if L in ("y", "Y"):
            # 'u' (proleptic year): with STRICT resolution 'y' (year-of-era) needs an era.
            out.append("uu" if n == 2 else "uuuu")
        elif L == "M" and n >= 3:
            text_fields = True
            out.append("MMMM" if n >= 4 else "MMM")
        elif L == "S":
            out.append("S" * n)
        elif L in ("M", "d", "H", "h", "m", "s"):
            # Joda parses a variable number of digits; java.time does so for one letter.
            out.append(L * max(n, 2) if adjacent else L)
        elif L == "a":
            text_fields = True
            out.append("a")
        elif L == "E":
            text_fields = True
            out.append("EEEE" if n >= 4 else "EEE")
        elif L == "Z":
            out.append("xxx" if n == 2 else "xx")
        else:  # already reported as unsupported by the Joda compiler
            out.append(L * n)
    if text_fields:
        issues.append(
            DateIssue(
                Status.PARTIAL,
                "ELASTIC_DATE_CASE_SENSITIVE",
                "Elasticsearch parses month/day names and AM/PM case-sensitively (English), "
                "while Joda (QRadar) is assumed case-insensitive (A10): e.g. 'mar' fails in "
                "Elasticsearch.",
            )
        )
    if fixed_width:
        issues.append(
            DateIssue(
                Status.PARTIAL,
                "ELASTIC_DATE_FIXED_WIDTH",
                "Adjacent numeric fields without a separator must be fixed-width in java.time; "
                "values Joda would accept with fewer digits fail to parse.",
            )
        )
    return JavaPattern("".join(out), tuple(issues))


# --- parsing (emulation) --------------------------------------------------------------------


@dataclass(frozen=True)
class JavaFormat:
    regex: str
    components: tuple[Comp | None, ...]


def _lex(pattern: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "'":
            j = i + 1
            text = ""
            while j < len(pattern):
                if pattern[j] == "'":
                    if pattern.startswith("''", j):
                        text += "'"
                        j += 2
                        continue
                    break
                text += pattern[j]
                j += 1
            out.append(("", 0, text or "'"))
            i = j + 1
        elif c.isascii() and c.isalpha():
            j = i
            while j < len(pattern) and pattern[j] == c:
                j += 1
            out.append((c, j - i, ""))
            i = j
        else:
            out.append(("", 0, c))
            i += 1
    return out


def compile_java(pattern: str) -> JavaFormat:
    """Regex for the subset of java.time pattern letters Rosettalog emits."""
    rx: list[str] = []
    comps: list[Comp | None] = []

    def cap(expr: str, comp: Comp) -> None:
        rx.append(f"({expr})")
        comps.append(comp)

    for letter, n, literal in _lex(pattern):
        if not letter:
            rx.append(pyregex.escape(literal))
        elif letter == "u":
            cap(r"\d{2}" if n == 2 else r"\d{4}", Comp.YEAR2 if n == 2 else Comp.YEAR4)
        elif letter == "M" and n >= 3:
            names = MONTHS_FULL if n >= 4 else MONTHS_SHORT
            cap("|".join(names), Comp.MONTH_TEXT)
        elif letter in "MdHhms":
            comp = {"M": Comp.MONTH_NUM, "d": Comp.DAY, "H": Comp.HOUR24, "h": Comp.HOUR12,
                    "m": Comp.MINUTE, "s": Comp.SECOND}[letter]  # fmt: skip
            cap(r"\d{1,19}" if n == 1 else rf"\d{{{n}}}", comp)
        elif letter == "S":
            cap(rf"\d{{{n}}}", Comp.FRACTION)
        elif letter == "a":
            cap("AM|PM", Comp.AMPM)
        elif letter == "E":
            rx.append("(?:" + "|".join(DAYS_FULL if n >= 4 else DAYS_SHORT) + ")")
        elif letter == "x" and n in (2, 3):
            sep = ":" if n == 3 else ""
            rx.append(rf"([+-])(\d{{2}}){sep}(\d{{2}})")
            comps.extend([Comp.TZ_SIGN, Comp.TZ_HOURS, Comp.TZ_MINUTES])
        else:
            raise ValueError(f"java.time pattern letter {letter * n!r} is not emulated")
    return JavaFormat("^" + "".join(rx) + "$", tuple(comps))


def parse_java(text: str, fmt: JavaFormat, *, now: datetime) -> datetime | None:
    """Parse like Elasticsearch's STRICT formatter (case-sensitive, missing year = now.year)."""
    m = pyregex.match(fmt.regex, text)
    if m is None:
        return None
    values = {c: v for c, v in zip(fmt.components, m.groups(), strict=True) if c is not None}
    if Comp.HOUR12 in values and not 1 <= int(values[Comp.HOUR12]) <= 12:
        return None  # clock-hour-of-am-pm is 1..12 under STRICT resolution
    return build_datetime(values, now=now)
