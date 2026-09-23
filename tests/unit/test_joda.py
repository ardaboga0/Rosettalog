from __future__ import annotations

from datetime import UTC, datetime

import pytest

from rosettalog.ir import Status
from rosettalog.timefmt.joda import compile_format, format_timestamp, parse

NOW = datetime(2026, 6, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("fmt", "text", "iso", "strptime"),
    [
        ("yyyy-MM-dd HH:mm:ss", "2026-03-04 05:06:07", "2026-03-04T05:06:07.000Z",
         "%Y-%m-%d %H:%M:%S"),
        ("MMM dd yyyy HH:mm:ss", "mar 04 2026 05:06:07", "2026-03-04T05:06:07.000Z",
         "%b %d %Y %H:%M:%S"),
        ("dd/MMM/YYYY:hh:mm:ss a", "04/Mar/2026:01:02:03 PM", "2026-03-04T13:02:03.000Z",
         "%d/%b/%Y:%I:%M:%S %p"),
        ("dd/MMM/YYYY:hh:mm:ss a", "04/Mar/2026:12:02:03 AM", "2026-03-04T00:02:03.000Z",
         "%d/%b/%Y:%I:%M:%S %p"),
        ("yyyy-MM-dd'T'HH:mm:ss.SSSZ", "2026-03-04T10:00:00.250+0200", "2026-03-04T08:00:00.250Z",
         "%Y-%m-%dT%H:%M:%S.%3N%z"),
        ("MMM d HH:mm:ss", "Mar 4 10:00:00", "2026-03-04T10:00:00.000Z", "%b %d %H:%M:%S"),
        ("EEE MMMM dd yy", "Wed March 04 26", "2026-03-04T00:00:00.000Z", "%a %B %d %y"),
    ],
)  # fmt: skip
def test_parse_and_strptime(fmt: str, text: str, iso: str, strptime: str) -> None:
    compiled = compile_format(fmt)
    dt = parse(text, compiled, now=NOW)
    assert dt is not None
    assert format_timestamp(dt) == iso
    assert compiled.strptime == strptime


def test_syslog_space_padded_day_does_not_match_single_space_format() -> None:
    # Assumption (confirmation case 09): Joda literals are exact, so "Mar  4" fails "MMM d".
    assert parse("Mar  4 10:00:00", compile_format("MMM d HH:mm:ss"), now=NOW) is None


@pytest.mark.parametrize(
    ("fmt", "code", "status"),
    [
        ("MMM d HH:mm:ss", "DATE_NO_YEAR", Status.PARTIAL),
        ("yy-MM-dd", "DATE_TWO_DIGIT_YEAR", Status.PARTIAL),
        ("yyyy-MM-dd zzz", "DATE_UNSUPPORTED_TOKEN", Status.UNSUPPORTED),
        ("yyyy-DDD", "DATE_UNSUPPORTED_TOKEN", Status.UNSUPPORTED),
        ("HH:mm:ss", "DATE_INCOMPLETE", Status.UNSUPPORTED),
        ("yyyy-MM-dd hh:mm", "DATE_12H_WITHOUT_AMPM", Status.PARTIAL),
        ("yyyy-MM-dd", "DATE_NO_TIMEZONE", Status.FULL),
    ],
)
def test_issues(fmt: str, code: str, status: Status) -> None:
    issues = {i.code: i.status for i in compile_format(fmt).issues}
    assert issues.get(code) is status


def test_quoted_literals() -> None:
    compiled = compile_format("yyyy-MM-dd'T'HH 'o''clock'")
    assert compiled.strptime == "%Y-%m-%dT%H o'clock"
    assert parse("2026-01-02T03 o'clock", compiled, now=NOW) is not None


def test_invalid_date_values_yield_none() -> None:
    assert parse("2026-02-31 00:00:00", compile_format("yyyy-MM-dd HH:mm:ss"), now=NOW) is None
