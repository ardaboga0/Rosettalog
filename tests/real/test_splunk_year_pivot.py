"""Measures Splunk's two-digit year (%y) pivot, which Splunk does not document.

The emulator and the DATE_TWO_DIGIT_YEAR_PIVOT finding assume the standard strptime pivot
(69-99 -> 19xx, 00-68 -> 20xx). This checks it with Splunk's own strptime() (search time). It
runs in the real-engines workflow.
"""

from __future__ import annotations

import json

import pytest


@pytest.mark.real_engine
def test_splunk_percent_y_uses_the_strptime_pivot(real_session) -> None:
    session = real_session("splunk")
    search = (
        '| makeresults | eval y50=strftime(strptime("01/02/50 10:00", "%d/%m/%y %H:%M"), "%Y"), '
        'y68=strftime(strptime("01/02/68 10:00", "%d/%m/%y %H:%M"), "%Y"), '
        'y69=strftime(strptime("01/02/69 10:00", "%d/%m/%y %H:%M"), "%Y") '
        "| table y50 y68 y69"
    )
    out = session.rest("POST", "/services/search/jobs/export", {"search": search})
    rows = [json.loads(line)["result"] for line in out.splitlines() if '"result"' in line]
    assert rows, out[:500]
    assert rows[0] == {"y50": "2050", "y68": "2068", "y69": "1969"}
