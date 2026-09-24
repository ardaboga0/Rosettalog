"""Time-window semantics shared by the rule evaluators: which groups a stateful rule alerts on.

Both the IR evaluator (the QRadar rule, under the rule assumptions R04-R08) and the Sigma
emulator (Sigma correlation rules v2.1.0) use these definitions:

* **Window (R04; Sigma: "should not be restricted to boundaries")**: sliding. A set of events
  fits the window when the last one is at most ``window_s`` seconds after the first one.
* **Grouping (R05; Sigma ``group-by``)**: per combination of the group fields' values. An event
  that lacks a group field belongs to no group.
* **Sequences (R07/R08; Sigma ``temporal_ordered``)**: the steps must occur in order, other
  events may occur in between, and the window runs from the first to the last step.
  ``temporal`` (unordered) only needs one event per step inside the window.

A group key is ``field=value`` pairs joined by ``,`` in group-field order, or ``(all)``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

ALL = "(all)"


@dataclass(frozen=True)
class TimedEvent:
    time: datetime
    fields: Mapping[str, object]


def group_key(fields: Mapping[str, object], group_by: Sequence[str]) -> str | None:
    if not group_by:
        return ALL
    values = [fields.get(f) for f in group_by]
    if any(v is None for v in values):
        return None
    return ",".join(f"{f}={v}" for f, v in zip(group_by, values, strict=True))


def _groups(events: Sequence[TimedEvent], group_by: Sequence[str]) -> dict[str, list[TimedEvent]]:
    out: dict[str, list[TimedEvent]] = {}
    for event in sorted(events, key=lambda e: e.time):
        key = group_key(event.fields, group_by)
        if key is not None:
            out.setdefault(key, []).append(event)
    return out


def count_groups(
    events: Sequence[TimedEvent],
    *,
    count: int,
    window_s: int,
    group_by: Sequence[str],
    distinct_field: str | None = None,
) -> set[str]:
    """Groups with at least ``count`` events (or distinct ``distinct_field`` values) in a window."""
    alerting: set[str] = set()
    for key, group in _groups(events, group_by).items():
        for i, first in enumerate(group):
            inside = [e for e in group[i:] if (e.time - first.time).total_seconds() <= window_s]
            if distinct_field is None:
                n = len(inside)
            else:
                n = len({e.fields.get(distinct_field) for e in inside} - {None})
            if n >= count:
                alerting.add(key)
                break
    return alerting


def sequence_groups(
    events: Sequence[TimedEvent],
    steps: Sequence[Callable[[Mapping[str, object]], bool]],
    *,
    ordered: bool,
    window_s: int,
    group_by: Sequence[str],
) -> set[str]:
    """Groups in which every step matches an event inside one window (in order if ``ordered``)."""
    alerting: set[str] = set()
    for key, group in _groups(events, group_by).items():
        matches = [[step(e.fields) for step in steps] for e in group]
        for i, first in enumerate(group):
            inside = [
                j for j in range(i, len(group))
                if (group[j].time - first.time).total_seconds() <= window_s
            ]  # fmt: skip
            if ordered:
                # earliest-completion greedy from event i (which must match step 1)
                if not matches[i][0]:
                    continue
                pos, ok = i, True
                for s in range(1, len(steps)):
                    nxt = next((j for j in inside if j > pos and matches[j][s]), None)
                    if nxt is None:
                        ok = False
                        break
                    pos = nxt
                if ok:
                    alerting.add(key)
                    break
            elif all(any(matches[j][s] for j in inside) for s in range(len(steps))):
                alerting.add(key)
                break
    return alerting
