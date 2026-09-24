"""Counters and sequences: window semantics, Sigma correlation output, emulator, findings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import yaml

from rosettalog.backends.sigma import SigmaBackend
from rosettalog.backends.sigma.backend import timespan
from rosettalog.ir import Artifact, Counter, DetectionSpec, FieldTest, Provenance, Sequence, Status
from rosettalog.verify.emulators.sigma import SigmaEmulator, parse_timespan
from rosettalog.verify.emulators.windows import TimedEvent, count_groups, sequence_groups

T0 = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)


def ev(seconds: int, **fields: object) -> TimedEvent:
    return TimedEvent(T0 + timedelta(seconds=seconds), fields)


def is_(value: str):
    return lambda f: f.get("u") == value


# --- window semantics -------------------------------------------------------------------------


def test_counter_is_sliding_and_grouped() -> None:
    events = [ev(210, ip="a"), ev(270, ip="a"), ev(330, ip="a"), ev(0, ip="b"), ev(301, ip="b")]
    # a: 3 events within 120 s across the 10:05 boundary; b: only 2
    assert count_groups(events, count=3, window_s=300, group_by=["ip"]) == {"ip=a"}
    assert count_groups(events, count=2, window_s=300, group_by=["ip"]) == {"ip=a"}
    assert count_groups(events, count=2, window_s=301, group_by=["ip"]) == {"ip=a", "ip=b"}


def test_counter_distinct_values_and_missing_group_field() -> None:
    events = [ev(0, ip="a", p=22), ev(1, ip="a", p=22), ev(2, ip="a", p=23), ev(3, p=24)]
    assert count_groups(events, count=2, window_s=60, group_by=["ip"], distinct_field="p") == {
        "ip=a"
    }
    assert count_groups(events, count=3, window_s=60, group_by=["ip"], distinct_field="p") == set()
    assert count_groups(events, count=4, window_s=60, group_by=[]) == {"(all)"}


def test_ordered_sequence_allows_gaps_and_needs_order_and_window() -> None:
    events = [
        ev(0, g="1", u="a"), ev(5, g="1", u="x"), ev(10, g="1", u="b"),  # gap allowed
        ev(0, g="2", u="b"), ev(10, g="2", u="a"),  # wrong order
        ev(0, g="3", u="a"), ev(100, g="3", u="b"),  # outside window
        ev(0, g="4", u="a"), ev(50, g="4", u="a"), ev(100, g="4", u="b"),  # a later start fits
    ]  # fmt: skip
    steps = [is_("a"), is_("b")]
    got = sequence_groups(events, steps, ordered=True, window_s=60, group_by=["g"])
    assert got == {"g=1", "g=4"}
    unordered = sequence_groups(events, steps, ordered=False, window_s=60, group_by=["g"])
    assert unordered == {"g=1", "g=2", "g=4"}


def test_window_from_first_to_last_step() -> None:
    events = [ev(0, u="a"), ev(40, u="b"), ev(80, u="c")]
    steps = [is_("a"), is_("b"), is_("c")]
    assert sequence_groups(events, steps, ordered=True, window_s=60, group_by=[]) == set()
    assert sequence_groups(events, steps, ordered=True, window_s=80, group_by=[]) == {"(all)"}


@pytest.mark.parametrize(
    ("seconds", "text"), [(300, "5m"), (90, "90s"), (3600, "1h"), (86400, "1d")]
)
def test_timespan_round_trip(seconds: int, text: str) -> None:
    assert timespan(seconds) == text
    assert parse_timespan(text) == seconds


# --- Sigma output -----------------------------------------------------------------------------


def artifact(stateful: Counter | Sequence) -> Artifact:
    cond = FieldTest(field="EventName", op="equals", values=["x"], case_sensitive=False)
    spec = DetectionSpec(rule_id="1", name="R", severity=5, condition=cond, stateful=stateful)
    return Artifact(
        id="r", name="R", kind="detection", source_format="qradar-rules",
        provenance=Provenance(file="x"), detection=spec,
    )  # fmt: skip


def generate(stateful: Counter | Sequence, options: dict[str, str] | None = None):
    result = SigmaBackend().generate(artifact(stateful), options or {})
    docs = list(yaml.safe_load_all(result.files[0].content))
    return result, docs


def test_event_count_correlation() -> None:
    result, docs = generate(Counter(count=3, window_s=300, group_by=["SourceIp", "UserName"]))
    base, corr = docs
    assert base["name"] == "r_events"
    assert base["detection"]["condition"] == "sel_1"
    assert "level" not in base
    assert corr["name"] == "r"
    assert "detection" not in corr
    assert "logsource" not in corr
    assert corr["correlation"] == {
        "type": "event_count",
        "rules": ["r_events"],
        "group-by": ["src_ip", "username"],
        "timespan": "5m",
        "condition": {"gte": 3},
    }
    assert corr["level"] == "medium"
    codes = {f.code: f for f in result.findings}
    assert codes["SIGMA_COUNTER_WINDOW"].depends_on.topic == "rule-counter-window"  # type: ignore[union-attr]
    assert codes["SIGMA_COUNTER_GROUPING"].depends_on.topic == "rule-counter-grouping"  # type: ignore[union-attr]


def test_value_count_correlation_without_group_by() -> None:
    result, docs = generate(Counter(count=2, window_s=60, distinct_field="DestinationPort"))
    corr = docs[-1]["correlation"]
    assert corr["type"] == "value_count"
    assert "group-by" not in corr
    assert corr["condition"] == {"gte": 2, "field": "dst_port"}
    assert "SIGMA_COUNTER_GROUPING" not in {f.code for f in result.findings}


def test_sequence_correlation() -> None:
    steps = [
        FieldTest(field="UserName", op="equals", values=[v], case_sensitive=False) for v in "ab"
    ]
    result, docs = generate(
        Sequence(steps=steps, ordered=True, window_s=120, group_by=["SourceIp"])
    )
    assert [d["name"] for d in docs] == ["r_step1", "r_step2", "r"]
    assert docs[0]["detection"] == {
        "sel_1": {"EventName": "x"},
        "sel_2": {"username": "a"},
        "condition": "sel_1 and sel_2",
    }
    corr = docs[2]["correlation"]
    assert corr["type"] == "temporal_ordered"
    assert corr["rules"] == ["r_step1", "r_step2"]
    assert "condition" not in corr
    codes = {f.code for f in result.findings}
    assert {"SIGMA_SEQUENCE_GAPS", "SIGMA_SEQUENCE_WINDOW"} <= codes
    _, unordered = generate(Sequence(steps=steps, ordered=False, window_s=120))
    assert unordered[-1]["correlation"]["type"] == "temporal"


def test_correlations_pass_pysigma_validation() -> None:
    pytest.importorskip("sigma")
    steps = [
        FieldTest(field="UserName", op="equals", values=[v], case_sensitive=False) for v in "ab"
    ]
    for st in (
        Counter(count=3, window_s=300, group_by=["SourceIp"]),
        Counter(count=2, window_s=60, group_by=["SourceIp"], distinct_field="DestinationPort"),
        Sequence(steps=steps, window_s=60, group_by=["SourceIp"]),
    ):
        result, _ = generate(st)
        bad = [
            f
            for f in result.findings
            if f.code == "SIGMA_VALIDATION_ISSUE" and f.status is not Status.FULL
        ]
        assert bad == []


def test_fixed_window_backends_are_reported() -> None:
    pytest.importorskip("sigma.backends.splunk")
    result, _ = generate(
        Counter(count=3, window_s=300, group_by=["SourceIp"]),
        {"pysigma_targets": "splunk,kusto,esql,eql"},
    )
    fixed = [f.message for f in result.findings if f.code == "PYSIGMA_CORRELATION_FIXED_WINDOW"]
    assert len(fixed) == 2
    assert "pysigma-backend-splunk" in fixed[0]
    gaps = [f.message for f in result.findings if f.code == "PYSIGMA_BACKEND_GAP"]
    assert gaps == [
        "pysigma-backend-kusto 1.0.1 could not convert the rule: Backend does not support "
        "correlation rules."
    ]
    assert [q.group_by for q in result.queries] == [["src_ip"]] * 3


def test_sigma_emulator_evaluates_correlation() -> None:
    result, _ = generate(Counter(count=2, window_s=60, group_by=["SourceIp"]))
    emulator = SigmaEmulator(result)
    events = [
        ev(0, EventName="x", src_ip="a"),
        ev(30, EventName="X", src_ip="a"),
        ev(0, EventName="x", src_ip="b"),
    ]
    assert emulator.alerting_groups(events) == {"src_ip=a"}
    with pytest.raises(Exception, match="groups, not single events"):
        emulator.matches({"EventName": "x"})


def test_refused_conversion_does_not_make_the_sigma_rule_unsupported() -> None:
    """Regression: a pySigma backend refusing temporal_ordered made the whole Sigma target
    UNSUPPORTED. The Sigma rule is fine; only that conversion is missing (element-level)."""
    pytest.importorskip("sigma.backends.splunk")
    from rosettalog.pipeline import run

    steps = [
        FieldTest(field="UserName", op="equals", values=[v], case_sensitive=False) for v in "ab"
    ]
    report = run(
        [artifact(Sequence(steps=steps, window_s=60))],
        ["sigma"],
        options={"sigma": {"pysigma_targets": "splunk"}},
    )
    [tr] = report.artifacts[0].targets
    gap = next(f for f in tr.findings if f.code == "PYSIGMA_BACKEND_GAP")
    assert gap.path == "pysigma[splunk]"
    assert tr.status is Status.PARTIAL
