"""Joda-Time date format patterns (used by QRadar LSX ``ext-data`` for DeviceTime).

The format is parsed once into :class:`DateToken` objects. From those we derive

* a regex with one capture group per value-bearing component (portable between RE2, PCRE and
  Python ``regex``), used by the KQL backend and by all emulators;
* a Splunk ``TIME_FORMAT`` (strptime) string;
* a reference parser (:func:`parse`) that approximates Joda's parsing for the source emulator.

Components we cannot reproduce faithfully are reported as issues, never silently ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import regex as pyregex

from rosettalog.ir.findings import Status


class Comp(StrEnum):
    YEAR4 = "year4"
    YEAR2 = "year2"
    MONTH_NUM = "month_num"
    MONTH_TEXT = "month_text"
    DAY = "day"
    HOUR24 = "hour24"
    HOUR12 = "hour12"
    MINUTE = "minute"
    SECOND = "second"
    FRACTION = "fraction"
    AMPM = "ampm"
    TZ_SIGN = "tz_sign"
    TZ_HOURS = "tz_hours"
    TZ_MINUTES = "tz_minutes"


@dataclass(frozen=True)
class DateIssue:
    status: Status
    code: str
    message: str


@dataclass(frozen=True)
class DateToken:
    letter: str  # "" for literal text
    count: int = 0
    literal: str = ""


@dataclass(frozen=True)
class DateFormat:
    source: str
    tokens: tuple[DateToken, ...]
    regex: str
    """Anchored regex; capture groups correspond to :attr:`components` in order."""
    components: tuple[Comp, ...]
    strptime: str | None
    issues: tuple[DateIssue, ...] = field(default=())

    @property
    def has_year(self) -> bool:
        return Comp.YEAR4 in self.components or Comp.YEAR2 in self.components

    @property
    def fraction_digits(self) -> int:
        for tok in self.tokens:
            if tok.letter == "S":
                return tok.count
        return 0

    @property
    def usable(self) -> bool:
        return not any(i.status is Status.UNSUPPORTED for i in self.issues)


MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
_UNSUPPORTED_LETTERS = {
    "G": "era",
    "C": "century of era",
    "x": "week-year",
    "w": "week of week-year",
    "e": "day of week (number)",
    "D": "day of year",
    "k": "clock hour of day (1-24)",
    "K": "hour of half-day (0-11)",
    "z": "time zone name",
}


def _lex(fmt: str) -> list[DateToken]:
    tokens: list[DateToken] = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == "'":
            j = i + 1
            text = ""
            while j < len(fmt):
                if fmt[j] == "'":
                    if j + 1 < len(fmt) and fmt[j + 1] == "'":
                        text += "'"
                        j += 2
                        continue
                    break
                text += fmt[j]
                j += 1
            tokens.append(DateToken("", literal=text if j > i + 1 else "'"))
            i = j + 1
            continue
        if c.isascii() and c.isalpha():
            j = i
            while j < len(fmt) and fmt[j] == c:
                j += 1
            tokens.append(DateToken(c, j - i))
            i = j
            continue
        tokens.append(DateToken("", literal=c))
        i += 1
    return tokens


_REGEX_META = set("\\^$.|?*+()[]{}")


def _esc(text: str) -> str:
    return "".join("\\" + ch if ch in _REGEX_META else ch for ch in text)


def compile_format(fmt: str) -> DateFormat:
    tokens = _lex(fmt)
    rx: list[str] = []
    comps: list[Comp] = []
    strp: list[str] = []
    issues: list[DateIssue] = []

    def cap(pattern: str, comp: Comp, spec: str) -> None:
        rx.append(f"({pattern})")
        comps.append(comp)
        strp.append(spec)

    for tok in tokens:
        L, n = tok.letter, tok.count
        if not L:
            rx.append(_esc(tok.literal))
            strp.append(tok.literal.replace("%", "%%"))
        elif L in ("y", "Y"):
            if n == 2:
                # Century handling differs per engine; each backend reports it
                # (DATE_TWO_DIGIT_YEAR_PIVOT, linked to the QRadar pivot assumption).
                cap(r"\d{2}", Comp.YEAR2, "%y")
            else:
                cap(r"\d{4}", Comp.YEAR4, "%Y")
        elif L == "M":
            if n >= 4:
                cap(r"[A-Za-z]+", Comp.MONTH_TEXT, "%B")
            elif n == 3:
                cap(r"[A-Za-z]{3}", Comp.MONTH_TEXT, "%b")
            else:
                cap(r"\d{1,2}", Comp.MONTH_NUM, "%m")
        elif L == "d":
            cap(r"\d{1,2}", Comp.DAY, "%d")
        elif L == "H":
            cap(r"\d{1,2}", Comp.HOUR24, "%H")
        elif L == "h":
            cap(r"\d{1,2}", Comp.HOUR12, "%I")
        elif L == "m":
            cap(r"\d{1,2}", Comp.MINUTE, "%M")
        elif L == "s":
            cap(r"\d{1,2}", Comp.SECOND, "%S")
        elif L == "S":
            cap(rf"\d{{{n}}}", Comp.FRACTION, f"%{n}N")
        elif L == "a":
            cap(r"[AaPp][Mm]", Comp.AMPM, "%p")
        elif L == "E":
            rx.append(r"[A-Za-z]+" if n >= 4 else r"[A-Za-z]{3}")
            strp.append("%A" if n >= 4 else "%a")
        elif L == "Z" and n <= 2:
            sep = ":" if n == 2 else ""
            rx.append(rf"([+-])(\d{{2}}){sep}(\d{{2}})")
            comps.extend([Comp.TZ_SIGN, Comp.TZ_HOURS, Comp.TZ_MINUTES])
            strp.append("%:z" if n == 2 else "%z")
            if n == 2:
                issues.append(
                    DateIssue(
                        Status.PARTIAL,
                        "DATE_TZ_COLON_OFFSET",
                        "Offset with colon (ZZ) maps to Splunk '%:z'; confirm your Splunk "
                        "version supports it.",
                    )
                )
        else:
            what = _UNSUPPORTED_LETTERS.get(L, "unknown pattern letter")
            if L == "Z":
                what = "time zone id (ZZZ)"
            issues.append(
                DateIssue(
                    Status.UNSUPPORTED,
                    "DATE_UNSUPPORTED_TOKEN",
                    f"Joda format token '{L * n}' ({what}) is not supported.",
                )
            )

    if Comp.HOUR12 in comps and Comp.AMPM not in comps:
        issues.append(
            DateIssue(
                Status.PARTIAL,
                "DATE_12H_WITHOUT_AMPM",
                "12-hour clock ('h') without AM/PM marker ('a'): hours are taken as-is (AM).",
            )
        )
    if (Comp.MONTH_NUM not in comps and Comp.MONTH_TEXT not in comps) or Comp.DAY not in comps:
        issues.append(
            DateIssue(
                Status.UNSUPPORTED,
                "DATE_INCOMPLETE",
                "Format has no month or day; a full timestamp cannot be built.",
            )
        )
    if Comp.YEAR4 not in comps and Comp.YEAR2 not in comps:
        issues.append(
            DateIssue(
                Status.PARTIAL,
                "DATE_NO_YEAR",
                "Format has no year; generated content assumes the current year (QRadar and "
                "the target may disagree around New Year).",
            )
        )
    if Comp.TZ_SIGN not in comps:
        issues.append(
            DateIssue(
                Status.FULL,
                "DATE_NO_TIMEZONE",
                "Format has no UTC offset; timestamps are interpreted as UTC. Adjust if the "
                "device logs local time.",
            )
        )
    return DateFormat(
        source=fmt,
        tokens=tuple(tokens),
        regex="^" + "".join(rx) + "$",
        components=tuple(comps),
        strptime="".join(strp),
        issues=tuple(issues),
    )


# --- evaluation shared by emulators ---------------------------------------------------------


def month_from_text(text: str) -> int | None:
    key = text[:3].lower()
    return MONTHS.index(key) + 1 if key in MONTHS else None


def build_datetime(values: dict[Comp, str], *, now: datetime) -> datetime | None:
    """Assemble a UTC datetime from component strings; ``None`` if invalid."""
    try:
        if Comp.YEAR4 in values:
            year = int(values[Comp.YEAR4])
        elif Comp.YEAR2 in values:
            year = 2000 + int(values[Comp.YEAR2])
        else:
            year = now.year
        if Comp.MONTH_TEXT in values:
            month = month_from_text(values[Comp.MONTH_TEXT])
            if month is None:
                return None
        else:
            month = int(values[Comp.MONTH_NUM])
        day = int(values[Comp.DAY])
        if Comp.HOUR12 in values:
            hour = int(values[Comp.HOUR12]) % 12
            if values.get(Comp.AMPM, "am").lower() == "pm":
                hour += 12
        else:
            hour = int(values.get(Comp.HOUR24, "0"))
        minute = int(values.get(Comp.MINUTE, "0"))
        second = int(values.get(Comp.SECOND, "0"))
        frac = values.get(Comp.FRACTION, "")
        micro = int((frac + "000000")[:6]) if frac else 0
        dt = datetime(year, month, day, hour, minute, second, micro, tzinfo=UTC)
        if Comp.TZ_SIGN in values:
            offset = timedelta(
                hours=int(values[Comp.TZ_HOURS]), minutes=int(values[Comp.TZ_MINUTES])
            )
            dt = dt - offset if values[Comp.TZ_SIGN] == "+" else dt + offset
    except (KeyError, ValueError):
        return None
    return dt


def parse(text: str, fmt: DateFormat, *, now: datetime) -> datetime | None:
    """Reference parse approximating Joda ``DateTimeFormatter.parseDateTime`` (month/day names
    are matched case-insensitively; numeric fields accept 1-2 digits)."""
    m = pyregex.match(fmt.regex, text, flags=pyregex.IGNORECASE)
    if m is None:
        return None
    return build_datetime(dict(zip(fmt.components, m.groups(), strict=True)), now=now)


def format_timestamp(dt: datetime) -> str:
    """Canonical text form used when comparing timestamps across engines."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
