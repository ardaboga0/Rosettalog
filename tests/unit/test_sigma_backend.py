"""Sigma backend: IR detection -> Sigma YAML, findings, pySigma validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from rosettalog.backends.sigma import SigmaBackend
from rosettalog.backends.sigma.backend import escape_value, sigma_level
from rosettalog.ir import (
    And,
    Artifact,
    Cond,
    DetectionSpec,
    FieldTest,
    LogSourceTest,
    Not,
    Opaque,
    Or,
    Provenance,
    QidTest,
    ReferenceTest,
    Response,
    RuleRef,
    Status,
)
from rosettalog.verify.emulators.sigma import SigmaRuleEvaluator


def artifact(cond: Cond, **spec: object) -> Artifact:
    detection = DetectionSpec(rule_id="1", name="Test rule", condition=cond, **spec)  # type: ignore[arg-type]
    return Artifact(
        id="test_rule",
        name="Test rule",
        kind="detection",
        source_format="qradar-rules",
        provenance=Provenance(file="x"),
        detection=detection,
    )


def generate(cond: Cond, options: dict[str, str] | None = None, **spec: object):
    return SigmaBackend().generate(artifact(cond, **spec), options or {})


def rule_of(result) -> dict:
    return yaml.safe_load(result.files[0].content)


def codes(result) -> list[str]:
    return [f.code for f in result.findings]


def eq(field: str, *values: str, cs: bool = True, path: str = "") -> FieldTest:
    return FieldTest(field=field, op="equals", values=list(values), case_sensitive=cs, path=path)


def test_structure_is_preserved() -> None:
    cond = And(
        items=[
            eq("SourceIp", "192.0.2.1"),
            Or(items=[eq("UserName", "a", cs=False), Not(item=eq("UserName", "b", cs=False))]),
        ]
    )
    result = generate(cond)
    rule = rule_of(result)
    assert rule["detection"] == {
        "sel_1": {"src_ip": "192.0.2.1"},
        "sel_2": {"username": "a"},
        "sel_3": {"username": "b"},
        "condition": "sel_1 and (sel_2 or not sel_3)",
    }
    assert not result.broadened
    assert "broader_than_source" not in rule["qradar"]


def test_cased_only_where_case_matters() -> None:
    rule = rule_of(
        generate(Or(items=[eq("DestinationPort", "22"), eq("UserName", "Bob", cs=False)]))
    )
    assert rule["detection"]["sel_1"] == {"dst_port": 22}
    assert rule["detection"]["sel_2"] == {"username": "Bob"}


def test_wildcards_are_escaped_and_matched_literally() -> None:
    assert escape_value(r"a*b?c\d") == r"a\*b\?c\\d"
    result = generate(eq("UserName", "a*b", cs=False))
    evaluator = SigmaRuleEvaluator(result.files[0].content)
    assert evaluator.matches({"username": "a*b"})
    assert not evaluator.matches({"username": "axxb"})


def test_contains_and_regex() -> None:
    cond = And(
        items=[
            FieldTest(field="UserName", op="contains", values=["adm"], case_sensitive=False),
            FieldTest(field="EventName", op="regex", values=[r"^x\d+$", r"(?i)y"]),
        ]
    )
    rule = rule_of(generate(cond))
    assert rule["detection"]["sel_1"] == {"username|contains": "adm"}
    assert rule["detection"]["sel_2"] == {"EventName|re": "^x[0-9]+$"}
    assert rule["detection"]["sel_3"] == {"EventName|re|i": "y"}
    assert rule["detection"]["condition"] == "sel_1 and (sel_2 or sel_3)"


@pytest.mark.parametrize(
    ("cond", "condition"),
    [
        # dropped where it counts positively: removed from the AND (broader)
        (And(items=[eq("UserName", "a"), RuleRef(rules=["bb1"])]), "sel_1"),
        # under NOT the dropped test counts as false, so "not (a and X)" becomes true (broader)
        (
            And(
                items=[
                    eq("UserName", "a"),
                    Not(item=And(items=[eq("UserName", "b"), Opaque(test="t")])),
                ]
            ),
            "sel_1",
        ),
        # "a or X" with X dropped is always true: the OR disappears from the AND
        (
            And(
                items=[
                    eq("UserName", "c"),
                    Or(items=[eq("UserName", "a"), ReferenceTest(collection="s")]),
                ]
            ),
            "sel_1",
        ),
        # "not X" with X dropped: true, removed
        (And(items=[eq("UserName", "a"), Not(item=Opaque(test="t"))]), "sel_1"),
    ],
)
def test_untranslatable_tests_only_broaden(cond: Cond, condition: str) -> None:
    result = generate(cond)
    rule = rule_of(result)
    assert rule["detection"]["condition"] == condition
    assert set(rule["detection"]) == {"sel_1", "condition"}
    assert "SIGMA_TEST_DROPPED" in codes(result)


def test_nothing_left_writes_no_rule() -> None:
    result = generate(Or(items=[eq("UserName", "a"), RuleRef(rules=["bb1"])]))
    assert result.files == []
    assert "SIGMA_CONDITION_EMPTY" in codes(result)
    assert not result.produced_output


def test_untranslatable_regex_is_dropped_with_reason() -> None:
    cond = And(
        items=[eq("UserName", "a"), FieldTest(field="EventName", op="regex", values=["(?<=a)b"])]
    )
    result = generate(cond)
    assert codes(result)[1:4] == [
        "SIGMA_CASE_BROADENED",
        "SIGMA_REGEX_UNSUPPORTED",
        "SIGMA_TEST_DROPPED",
    ]
    assert rule_of(result)["detection"]["condition"] == "sel_1"


def test_logsource_unmapped_keeps_condition(tmp_path: Path) -> None:
    cond = And(
        items=[LogSourceTest(by="log_source_type", values=["Acme Firewall"]), eq("UserName", "a")]
    )
    result = generate(cond)
    rule = rule_of(result)
    assert rule["logsource"] == {"product": "qradar"}
    assert rule["detection"]["sel_1"] == {"LogSourceType": "Acme Firewall"}
    assert {"SIGMA_LOGSOURCE_UNMAPPED", "SIGMA_LOGSOURCE_CONDITION_KEPT"} <= set(codes(result))


def test_logsource_map(tmp_path: Path) -> None:
    lsmap = tmp_path / "map.yaml"
    lsmap.write_text("log_source_types:\n  Acme Firewall: {category: firewall, product: acme}\n")
    cond = And(
        items=[LogSourceTest(by="log_source_type", values=["Acme Firewall"]), eq("UserName", "a")]
    )
    result = generate(cond, {"logsource_map": str(lsmap)})
    rule = rule_of(result)
    assert rule["logsource"] == {"category": "firewall", "product": "acme"}
    assert rule["detection"] == {"sel_1": {"username": "a"}, "condition": "sel_1"}
    assert "SIGMA_LOGSOURCE_MAPPED" in codes(result)
    assert "SIGMA_LOGSOURCE_UNMAPPED" not in codes(result)


def test_negated_logsource_is_not_moved_to_logsource(tmp_path: Path) -> None:
    lsmap = tmp_path / "map.yaml"
    lsmap.write_text("log_source_types:\n  Acme Firewall: {product: acme}\n")
    cond = And(
        items=[
            Not(item=LogSourceTest(by="log_source_type", values=["Acme Firewall"])),
            eq("UserName", "a"),
        ]
    )
    rule = rule_of(generate(cond, {"logsource_map": str(lsmap)}))
    assert rule["logsource"] == {"product": "qradar"}
    assert rule["detection"]["condition"] == "not sel_1 and sel_2"


def test_qid_is_kept_on_pseudo_field() -> None:
    result = generate(QidTest(values=["5000001"]))
    assert rule_of(result)["detection"]["sel_1"] == {"QID": 5000001}
    assert "SIGMA_QID_CONDITION" in codes(result)


@pytest.mark.parametrize(
    ("severity", "level"),
    [(0, "informational"), (1, "informational"), (2, "low"), (3, "low"), (4, "medium"),
     (6, "medium"), (7, "high"), (8, "high"), (9, "critical"), (10, "critical")],
)  # fmt: skip
def test_level_mapping(severity: int, level: str) -> None:
    assert sigma_level(severity) == level


def test_metadata_and_responses() -> None:
    result = generate(
        eq("UserName", "a"),
        severity=7,
        credibility=4,
        relevance=5,
        enabled=False,
        uuid="00000000-0000-4000-8000-000000000001",
        notes="Synthetic.",
        responses=[
            Response(kind="email", attributes={"to": "soc@example.org"}, path="responses/email")
        ],
    )
    rule = rule_of(result)
    assert rule["level"] == "high"
    assert rule["status"] == "experimental"
    assert rule["description"].startswith("Synthetic.\n\nRosettalog: this rule is BROADER")
    assert rule["qradar"]["enabled"] is False
    assert (rule["qradar"]["credibility"], rule["qradar"]["relevance"]) == (4, 5)
    assert {"SIGMA_LEVEL_MAPPED", "SIGMA_RULE_DISABLED", "SIGMA_RESPONSE_NOT_REPRESENTABLE"} <= set(
        codes(result)
    )
    # deterministic id
    assert (
        rule["id"]
        == rule_of(generate(eq("UserName", "a"), uuid="00000000-0000-4000-8000-000000000001"))["id"]
    )


def test_offense_rules_are_unsupported() -> None:
    result = generate(eq("UserName", "a"), rule_type="offense")
    assert result.files == []
    assert "SIGMA_RULE_TYPE_UNSUPPORTED" in codes(result)


def test_building_block_is_flagged() -> None:
    assert "SIGMA_BUILDING_BLOCK" in codes(generate(eq("UserName", "a"), building_block=True))


def test_generated_rules_pass_pysigma_validation() -> None:
    pytest.importorskip("sigma")
    cond = And(
        items=[
            eq("SourceIp", "192.0.2.1"),
            FieldTest(
                field="UserName", op="contains", values=["adm", "root"], case_sensitive=False
            ),
            Not(item=FieldTest(field="EventName", op="regex", values=[r"^x\d+$"])),
        ]
    )
    result = generate(cond, severity=5)
    issues = [f for f in result.findings if f.code == "SIGMA_VALIDATION_ISSUE"]
    assert [f.status for f in issues if f.status is not Status.FULL] == []


def test_pysigma_targets_produce_queries() -> None:
    pytest.importorskip("sigma.backends.splunk")
    result = generate(
        eq("UserName", "a", cs=False), {"pysigma_targets": "splunk,kusto,lucene,esql"}
    )
    assert [q.language for q in result.queries] == ["splunk", "kusto", "lucene", "esql"]
    assert {q.runner_target for q in result.queries} == {"splunk", "sentinel", "elastic"}
    files = {f.path: f.content for f in result.files}
    assert files["test_rule.kusto.kql"].strip() == 'username =~ "a"'


def test_case_sensitive_test_is_broadened_not_refused() -> None:
    result = generate(eq("UserName", "Admin"))
    rule = rule_of(result)
    assert rule["detection"]["sel_1"] == {"username": "Admin"}
    [finding] = [f for f in result.findings if f.code == "SIGMA_CASE_BROADENED"]
    assert finding.status is Status.PARTIAL
    assert finding.depends_on is not None
    assert finding.depends_on.topic == "rule-value-case"
    assert result.broadened
    assert rule["qradar"]["broader_than_source"] is True
    assert rule["qradar"]["dropped_tests"][0]["case_insensitive"].startswith("equals test")


def test_case_sensitive_exclusion_is_dropped_not_narrowed() -> None:
    cond = And(
        items=[eq("SourceIp", "192.0.2.1"), Not(item=eq("UserName", "Admin", path="test[2]"))]
    )
    result = generate(cond)
    rule = rule_of(result)
    # "not username: Admin" (case-insensitive) would also exclude "admin": narrower. Dropped.
    assert rule["detection"]["condition"] == "sel_1"
    assert "SIGMA_CASE_BROADENED" not in codes(result)
    assert {"SIGMA_TEST_DROPPED", "SIGMA_EXCLUSION_DROPPED"} <= set(codes(result))
    [entry] = rule["qradar"]["dropped_tests"]
    assert (entry["test"], entry["exclusion"]) == ("test[2]", True)
    assert "An exclusion was removed" in rule["description"]


def test_dropped_test_is_named_in_finding_and_rule() -> None:
    cond = And(
        items=[eq("UserName", "a", cs=False), ReferenceTest(collection="Blocked", path="test[4]")]
    )
    result = generate(cond)
    [finding] = [f for f in result.findings if f.code == "SIGMA_TEST_DROPPED"]
    assert finding.message.startswith(
        "Test test[4] was left out: Reference data test on 'Blocked'."
    )
    rule = rule_of(result)
    assert "tests: test[4]" in rule["description"]
    assert rule["qradar"]["dropped_tests"][0]["exclusion"] is False
    assert "SIGMA_EXCLUSION_DROPPED" not in codes(result)


def test_case_record_removed_when_its_test_is_absorbed() -> None:
    # "Admin or <reference>" is always true once the reference test is dropped: no case note.
    cond = And(
        items=[
            eq("SourceIp", "192.0.2.1"),
            Or(items=[eq("UserName", "Admin"), ReferenceTest(collection="S")]),
        ]
    )
    result = generate(cond)
    assert "SIGMA_CASE_BROADENED" not in codes(result)
    assert [e for e in rule_of(result)["qradar"]["dropped_tests"] if "case_insensitive" in e] == []
