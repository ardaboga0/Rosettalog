"""Rule verification: IR evaluator (source semantics), Sigma emulator, harness, examples."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from rosettalog.backends.sigma import SigmaBackend
from rosettalog.frontends.ir_json import IrJsonFrontend
from rosettalog.ir import And, FieldTest, LogSourceTest, Not, Or, QidTest, ReferenceTest, RuleRef
from rosettalog.pipeline import load_artifacts, run
from rosettalog.verify.emulators.rules import NotEvaluable, RuleEvaluator
from rosettalog.verify.emulators.sigma import SigmaEvalError, SigmaRuleEvaluator, wildcard_regex
from rosettalog.verify.rule_samples import RuleSampleSet, load_rule_samples
from tests.conftest import ROOT, rule_sample_sets

# --- IR evaluator (source semantics) ----------------------------------------------------------


def test_missing_field_is_false_and_negation_true() -> None:
    test = FieldTest(field="UserName", op="equals", values=["a"])
    assert not RuleEvaluator(test).matches({})
    assert RuleEvaluator(Not(item=test)).matches({})


def test_case_sensitivity_and_contains() -> None:
    cs = FieldTest(field="UserName", op="equals", values=["Admin"])
    ci = FieldTest(field="UserName", op="contains", values=["adm"], case_sensitive=False)
    assert not RuleEvaluator(cs).matches({"UserName": "admin"})
    assert RuleEvaluator(ci).matches({"UserName": "SysADMIN"})


def test_regex_is_find_semantics() -> None:
    test = FieldTest(field="EventName", op="regex", values=[r"fail\d"])
    assert RuleEvaluator(test).matches({"EventName": "auth_fail2_x"})


def test_log_source_qid_reference() -> None:
    cond = And(
        items=[
            LogSourceTest(by="log_source_type", values=["Acme Firewall"]),
            QidTest(values=["1"]),
            ReferenceTest(collection="S", fields=["SourceIp"]),
        ]
    )
    event = {"LogSourceType": "Acme Firewall", "QID": "1", "SourceIp": "192.0.2.1"}
    assert RuleEvaluator(cond, reference_data={"S": ["192.0.2.1"]}).matches(event)
    with pytest.raises(NotEvaluable):
        RuleEvaluator(cond).matches(event)


def test_rule_references_are_not_guessed() -> None:
    with pytest.raises(NotEvaluable):
        RuleEvaluator(Or(items=[RuleRef(rules=["x"])])).matches({})


# --- Sigma emulator ---------------------------------------------------------------------------


def sigma(detection: str) -> SigmaRuleEvaluator:
    return SigmaRuleEvaluator(f"title: t\nlogsource: {{product: x}}\ndetection:\n{detection}")


def test_sigma_plain_values_are_case_insensitive_wildcards() -> None:
    ev = sigma("  s:\n    f: 'ab*'\n  condition: s\n")
    assert ev.matches({"f": "ABc"})
    assert not ev.matches({"f": "xab"})
    assert not ev.matches({})


def test_sigma_escapes_and_cased() -> None:
    assert wildcard_regex(r"a\*b\\c") == r"a\*b\\c"
    ev = sigma("  s:\n    f|cased: 'a\\*'\n  condition: s\n")
    assert ev.matches({"f": "a*"})
    assert not ev.matches({"f": "A*"})
    assert not ev.matches({"f": "ab"})


def test_sigma_regex_flags_and_precedence() -> None:
    ev = sigma(
        "  a:\n    f|re|i: '^x'\n  b:\n    g: '1'\n  c:\n    g: '2'\n  condition: a and not b or c\n"
    )
    assert ev.matches({"f": "X", "g": "3"})
    assert not ev.matches({"f": "X", "g": "1"})
    assert ev.matches({"f": "y", "g": "2"})  # (a and not b) or c


def test_sigma_list_is_or_keys_are_and() -> None:
    ev = sigma("  s:\n    f: [a, b]\n    g|contains: z\n  condition: s\n")
    assert ev.matches({"f": "b", "g": "xzx"})
    assert not ev.matches({"f": "b", "g": "x"})


def test_sigma_unknown_constructs_raise() -> None:
    with pytest.raises(SigmaEvalError):
        sigma("  s:\n    f|base64: a\n  condition: s\n")
    with pytest.raises(SigmaEvalError):
        sigma("  s:\n    f: a\n  condition: 1 of s*\n")


# --- samples and frontend ---------------------------------------------------------------------


def test_rule_samples_reject_unknown_event_ids() -> None:
    with pytest.raises(ValidationError):
        RuleSampleSet.model_validate({"events": [{"id": "e1"}], "expected": {"r": ["e2"]}})


def test_ir_json_frontend_reports_invalid_ir(tmp_path: Path) -> None:
    bad = tmp_path / "bad.ir.json"
    bad.write_text('{"id": "x"}', encoding="utf-8")
    [artifact] = IrJsonFrontend().parse(bad)
    assert artifact.findings[0].code == "IR_INVALID"


# --- examples: every rule sample set agrees with its expected hits ------------------------------


@pytest.mark.parametrize(
    ("samples_path", "rules_path"), rule_sample_sets(), ids=lambda p: p.parent.name
)
def test_rule_examples(samples_path: Path, rules_path: Path) -> None:
    samples = load_rule_samples(samples_path)
    artifacts = load_artifacts([rules_path])
    report = run(artifacts, ["sigma"], samples=samples, require_ground_truth=True)
    for entry in report.artifacts:
        [tr] = entry.targets
        rv = tr.rule_verification
        assert rv is not None, entry.name
        source, emulator = rv.run("source"), rv.run("emulator")
        assert source is not None
        assert emulator is not None
        assert set(source.hits or []) == set(rv.expected or []), entry.name
        dropped = any(f.code == "SIGMA_TEST_DROPPED" for f in tr.findings)
        if dropped:  # the rule may only be broader, never miss an event
            assert set(emulator.hits or []) >= set(source.hits or []), entry.name
        else:
            assert emulator.hits == source.hits, entry.name


def test_generated_rules_are_deterministic() -> None:
    [artifact, *_] = load_artifacts([ROOT / "examples" / "rules" / "acme_rules.ir.json"])
    a = SigmaBackend().generate(artifact, {}).files[0].content
    b = SigmaBackend().generate(artifact, {}).files[0].content
    assert a == b
