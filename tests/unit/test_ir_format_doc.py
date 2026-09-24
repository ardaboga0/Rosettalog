"""Every JSON example in docs/rules-ir-format.md is valid IR and converts to Sigma."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from rosettalog.frontends.ir_json import IrJsonFrontend
from rosettalog.ir.references import resolve_references
from rosettalog.plugins import get_backend
from rosettalog.verify.rule_samples import RuleSampleSet
from tests.conftest import ROOT

DOC = (ROOT / "docs" / "rules-ir-format.md").read_text("utf-8")


def blocks(language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", DOC, re.S)


def test_json_examples_are_valid_ir_and_convert(tmp_path: Path) -> None:
    examples = blocks("json")
    assert len(examples) == 4
    for n, text in enumerate(examples):
        path = tmp_path / f"example{n}.ir.json"
        path.write_text(text, encoding="utf-8")
        artifacts = resolve_references(IrJsonFrontend().parse(path))
        for artifact in artifacts:
            assert not any(f.code == "IR_INVALID" for f in artifact.findings), artifact.findings
            assert not any(f.code.startswith("RULE_REF") for f in artifact.findings)
            result = get_backend("sigma").generate(artifact, {})
            assert result.produced_output, artifact.id
        assert isinstance(json.loads(text), list | dict)


def test_samples_example_is_valid() -> None:
    [text] = blocks("yaml")
    RuleSampleSet.model_validate(yaml.safe_load(text))
