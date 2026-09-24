"""Evaluate an IR detection condition against parsed events: the *source* rule's semantics.

This is the reference the generated Sigma rule and the pySigma queries are compared with. Where
QRadar's behaviour is not documented, the evaluator follows the rule assumption registry
(``frontends/qradar_rules/assumptions.yaml``):

* A field test on a property the event does not have is false (so its negation is true).
* ``regex`` uses Java regex *find* semantics: the pattern may match anywhere in the value.
* ``equals``/``contains`` compare case-sensitively unless the test says otherwise.
* Counters and sequences follow :mod:`rosettalog.verify.emulators.windows` (R04-R08).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

import regex as pyregex

from rosettalog.ir import (
    And,
    Cond,
    Counter,
    DetectionSpec,
    FieldTest,
    LogSourceTest,
    Not,
    Opaque,
    Or,
    QidTest,
    ReferenceTest,
    RuleRef,
)
from rosettalog.ir import Sequence as SequenceTest
from rosettalog.regex.translate import translate
from rosettalog.verify.emulators.windows import TimedEvent, count_groups, sequence_groups

#: Canonical pseudo-fields holding the log source (type) and QID of a sample event.
LOG_SOURCE_FIELDS = {"log_source": "LogSource", "log_source_type": "LogSourceType"}
QID = "QID"


_Predicate = Callable[[Mapping[str, object]], bool]


class NotEvaluable(Exception):
    """The condition contains a test the evaluator cannot decide (reported, never guessed)."""


class RuleEvaluator:
    def __init__(
        self,
        cond: Cond,
        *,
        reference_data: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.cond = cond
        self.reference_data = reference_data or {}

    def matches(self, event: Mapping[str, str]) -> bool:
        return self._eval(self.cond, event)

    def _matches_cond(self, cond: Cond) -> _Predicate:
        return lambda fields: self._eval(cond, fields)  # type: ignore[arg-type]

    def alerting_groups(self, spec: DetectionSpec, events: Sequence[TimedEvent]) -> set[str]:
        """Group keys a counter/sequence rule alerts on (see the windows module)."""
        matching = [e for e in events if self._eval(self.cond, e.fields)]  # type: ignore[arg-type]
        match spec.stateful:
            case Counter() as c:
                return count_groups(
                    matching,
                    count=c.count,
                    window_s=c.window_s,
                    group_by=c.group_by,
                    distinct_field=c.distinct_field,
                )
            case SequenceTest() as s:
                steps = [self._matches_cond(step) for step in s.steps]
                return sequence_groups(
                    matching, steps, ordered=s.ordered, window_s=s.window_s, group_by=s.group_by
                )
        raise ValueError("not a stateful rule")

    def _eval(self, cond: Cond, event: Mapping[str, str]) -> bool:
        match cond:
            case And(items=items):
                return all(self._eval(i, event) for i in items)
            case Or(items=items):
                return any(self._eval(i, event) for i in items)
            case Not(item=item):
                return not self._eval(item, event)
            case FieldTest():
                return _field_test(cond, event.get(cond.field))
            case LogSourceTest():
                return event.get(LOG_SOURCE_FIELDS[cond.by]) in cond.values
            case QidTest():
                return event.get(QID) in cond.values
            case ReferenceTest(collection=name, fields=fields):
                if name not in self.reference_data:
                    raise NotEvaluable(f"no reference data '{name}' in the samples")
                members = set(self.reference_data[name])
                return any(event.get(f) in members for f in fields)
            case RuleRef():
                raise NotEvaluable("rule references are not evaluated")
            case Opaque(test=test):
                raise NotEvaluable(f"source test '{test}' is not modelled")
        raise AssertionError(cond)  # pragma: no cover


def _field_test(test: FieldTest, value: str | None) -> bool:
    if value is None:
        return False
    if test.op == "regex":
        for pattern in test.values:
            tr = translate(pattern, "python", case_insensitive=not test.case_sensitive)
            if tr.pattern is None:
                raise NotEvaluable(f"regex '{pattern}' cannot be emulated")
            if pyregex.search(tr.pattern, value, flags=pyregex.ASCII, timeout=2) is not None:
                return True
        return False
    folded = value if test.case_sensitive else value.casefold()
    for v in test.values:
        needle = v if test.case_sensitive else v.casefold()
        if (test.op == "equals" and folded == needle) or (
            test.op == "contains" and needle in folded
        ):
            return True
    return False
