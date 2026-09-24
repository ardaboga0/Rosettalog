"""Building blocks and reference data: resolution, inlining, correlation references, findings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import yaml

from rosettalog.backends.sigma import SigmaBackend
from rosettalog.ir import (
    And,
    Artifact,
    Cond,
    Counter,
    DetectionSpec,
    FieldTest,
    Not,
    Provenance,
    ReferenceTest,
    RuleRef,
    Sequence,
    Status,
)
from rosettalog.ir.references import resolve_references
from rosettalog.verify.emulators.rules import RuleEvaluator
from rosettalog.verify.emulators.sigma import SigmaEmulator
from rosettalog.verify.emulators.windows import TimedEvent


def eq(field: str, value: str) -> FieldTest:
    return FieldTest(field=field, op="equals", values=[value], case_sensitive=False)


def rule(
    aid: str,
    cond: Cond | None,
    *,
    rule_id: str | None = None,
    uuid: str | None = None,
    bb: bool = False,
    stateful: Counter | Sequence | None = None,
) -> Artifact:
    spec = DetectionSpec(
        rule_id=rule_id or aid, uuid=uuid, name=f"Name {aid}", building_block=bb,
        condition=cond, stateful=stateful,
    )  # fmt: skip
    return Artifact(
        id=aid, name=f"Name {aid}", kind="detection", source_format="qradar-rules",
        provenance=Provenance(file="x"), detection=spec,
    )  # fmt: skip


def codes(artifact: Artifact) -> list[str]:
    return [f.code for f in artifact.findings]


def by_id(artifacts: list[Artifact]) -> dict[str, Artifact]:
    return {a.id: a for a in artifacts}


# --- resolution -------------------------------------------------------------------------------


def test_resolution_by_rule_id_uuid_and_name() -> None:
    arts = resolve_references(
        [
            rule("bb1", eq("UserName", "a"), rule_id="100", bb=True),
            rule("bb2", eq("UserName", "b"), uuid="u-2", bb=True),
            rule("bb3", eq("UserName", "c"), bb=True),
            rule("r", RuleRef(rules=["100", "u-2", "Name bb3"])),
        ]
    )
    ref = by_id(arts)["r"].detection.condition  # type: ignore[union-attr]
    assert isinstance(ref, RuleRef)
    assert [t.artifact_id for t in ref.resolved or []] == ["bb1", "bb2", "bb3"]
    assert codes(by_id(arts)["r"]) == []


def test_missing_and_ambiguous_references() -> None:
    arts = by_id(
        resolve_references(
            [
                rule("x1", eq("UserName", "a"), rule_id="dup"),
                rule("x2", eq("UserName", "b"), rule_id="dup"),
                rule("missing", RuleRef(rules=["nope"], path="test[1]")),
                rule("ambiguous", RuleRef(rules=["dup"])),
            ]
        )
    )
    assert codes(arts["missing"]) == ["RULE_REF_MISSING"]
    assert codes(arts["ambiguous"]) == ["RULE_REF_AMBIGUOUS"]
    assert arts["missing"].detection.condition.resolved is None  # type: ignore[union-attr]


def test_cycle_is_reported_on_every_member_and_dependants() -> None:
    arts = by_id(
        resolve_references(
            [
                rule("a", And(items=[eq("EventName", "x"), RuleRef(rules=["b"])]), bb=True),
                rule("b", And(items=[eq("UserName", "y"), RuleRef(rules=["a"])]), bb=True),
                rule("user", RuleRef(rules=["a"])),
            ]
        )
    )
    assert codes(arts["a"]) == ["RULE_REF_CYCLE"]
    assert codes(arts["b"]) == ["RULE_REF_CYCLE"]
    assert codes(arts["user"]) == ["RULE_REF_NESTED"]
    assert "a -> b -> a" in arts["a"].findings[0].message
    assert arts["a"].findings[0].status is Status.UNSUPPORTED


def test_evaluator_uses_resolved_references() -> None:
    arts = by_id(
        resolve_references(
            [
                rule("bb1", eq("UserName", "a"), bb=True),
                rule("bb2", eq("DestinationPort", "443"), bb=True),
                rule("any", RuleRef(rules=["bb1", "bb2"], mode="any")),
                rule("all", RuleRef(rules=["bb1", "bb2"], mode="all")),
            ]
        )
    )
    event = {"UserName": "a", "DestinationPort": "22"}
    assert RuleEvaluator(arts["any"].detection.condition).matches(event)  # type: ignore[union-attr]
    assert not RuleEvaluator(arts["all"].detection.condition).matches(event)  # type: ignore[union-attr]


# --- Sigma: inlining --------------------------------------------------------------------------


def sigma(arts: list[Artifact], aid: str, options: dict[str, str] | None = None):
    artifact = by_id(resolve_references(arts))[aid]
    return SigmaBackend().generate(artifact, options or {})


def docs(result) -> list[dict]:
    return list(yaml.safe_load_all(result.files[0].content))


def test_single_event_rule_inlines_building_blocks() -> None:
    arts = [
        rule("bb1", eq("UserName", "a"), bb=True),
        rule("bb2", eq("DestinationPort", "443"), bb=True),
        rule("r", And(items=[eq("EventName", "x"), RuleRef(rules=["bb1", "bb2"], mode="any")])),
    ]
    result = sigma(arts, "r")
    [doc] = docs(result)
    assert doc["detection"]["condition"] == "sel_1 and (sel_2 or sel_3)"
    assert doc["detection"]["sel_2"] == {"username": "a"}
    assert "SIGMA_BB_INLINED" in {f.code for f in result.findings}
    assert not result.broadened


def test_negated_building_block_is_inlined_under_not() -> None:
    arts = [
        rule("bb1", eq("UserName", "a"), bb=True),
        rule("r", And(items=[eq("EventName", "x"), Not(item=RuleRef(rules=["bb1"]))])),
    ]
    [doc] = docs(sigma(arts, "r"))
    assert doc["detection"]["condition"] == "sel_1 and not sel_2"


def test_unresolved_reference_is_dropped_broader() -> None:
    result = sigma([rule("r", And(items=[eq("EventName", "x"), RuleRef(rules=["nope"])]))], "r")
    assert "SIGMA_TEST_DROPPED" in {f.code for f in result.findings}
    assert result.broadened


def test_reference_to_a_counter_rule_is_dropped() -> None:
    arts = [
        rule("cnt", eq("UserName", "a"), stateful=Counter(count=2, window_s=60)),
        rule("r", And(items=[eq("EventName", "x"), RuleRef(rules=["cnt"])])),
    ]
    result = sigma(arts, "r")
    dropped = [f.message for f in result.findings if f.code == "SIGMA_TEST_DROPPED"]
    assert "counter/sequence rule" in dropped[0]


def test_reference_data_names_the_collection_and_mechanisms() -> None:
    result = sigma(
        [
            rule(
                "r",
                And(
                    items=[
                        eq("EventName", "x"),
                        ReferenceTest(
                            collection="Blocked", collection_type="set", fields=["SourceIp"]
                        ),
                    ]
                ),
            )
        ],
        "r",
    )
    [finding] = [f for f in result.findings if f.code == "SIGMA_REFERENCE_DATA"]
    assert "'Blocked'" in finding.message
    assert "SourceIp" in finding.message
    assert finding.suggestion is not None
    for mechanism in ("watchlist", "lookup", "enrich policy"):
        assert mechanism in finding.suggestion


# --- Sigma: correlations referencing building blocks ------------------------------------------


T0 = datetime(2026, 1, 6, 9, tzinfo=UTC)


def test_counter_references_building_block_by_name() -> None:
    arts = [
        rule("bb_admin", eq("UserName", "admin"), bb=True),
        rule(
            "cnt",
            RuleRef(rules=["bb_admin"]),
            stateful=Counter(count=2, window_s=60, group_by=["SourceIp"]),
        ),
    ]
    result = sigma(arts, "cnt")
    [corr] = docs(result)  # no own base rule: the building block's rule is referenced
    assert corr["correlation"]["rules"] == ["bb_admin"]
    assert [f.path for f in result.context_files] == ["bb_admin.yml"]
    assert "SIGMA_BB_REFERENCED" in {f.code for f in result.findings}
    # Regression: the referenced rule's field names are part of the output's field names, so
    # that sample events are renamed for it (the emulator found no group without this).
    assert result.field_names["UserName"] == "username"
    events = [
        TimedEvent(T0, {"username": "admin", "src_ip": "a"}),
        TimedEvent(T0 + timedelta(seconds=30), {"username": "admin", "src_ip": "a"}),
    ]
    assert SigmaEmulator(result).alerting_groups(events) == {"src_ip=a"}


def test_sequence_references_steps_and_keeps_other_steps() -> None:
    arts = [
        rule("bb_a", eq("UserName", "a"), bb=True),
        rule(
            "seq",
            None,
            stateful=Sequence(steps=[RuleRef(rules=["bb_a"]), eq("UserName", "b")], window_s=60),
        ),
    ]
    result = sigma(arts, "seq")
    step2, corr = docs(result)
    assert step2["name"] == "seq_step2"
    assert corr["correlation"]["rules"] == ["bb_a", "seq_step2"]


def test_rule_condition_prevents_referencing() -> None:
    """With an extra condition, a step is 'condition AND building block': inlined, not referenced."""
    arts = [
        rule("bb_a", eq("UserName", "a"), bb=True),
        rule(
            "seq",
            eq("EventName", "x"),
            stateful=Sequence(steps=[RuleRef(rules=["bb_a"]), eq("UserName", "b")], window_s=60),
        ),
    ]
    result = sigma(arts, "seq")
    assert [d["name"] for d in docs(result)] == ["seq_step1", "seq_step2", "seq"]
    assert result.context_files == []
    assert "SIGMA_BB_INLINED" in {f.code for f in result.findings}


def test_correlation_with_references_converts_and_validates() -> None:
    pytest.importorskip("sigma.backends.splunk")
    arts = [
        rule("bb_admin", eq("UserName", "admin"), bb=True),
        rule(
            "cnt",
            RuleRef(rules=["bb_admin"]),
            stateful=Counter(count=2, window_s=60, group_by=["SourceIp"]),
        ),
    ]
    result = sigma(arts, "cnt", {"pysigma_targets": "splunk"})
    assert [q.language for q in result.queries] == ["splunk"]
    content = next(f.content for f in result.files if f.path.endswith(".spl"))
    assert 'username="admin"' in content
    bad = [
        f
        for f in result.findings
        if f.code == "SIGMA_VALIDATION_ISSUE" and f.status is not Status.FULL
    ]
    assert bad == []
