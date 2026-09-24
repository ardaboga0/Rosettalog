"""QRadar rule assumption registry (``assumptions.yaml``) and the doc tables generated from it.

Regenerate the docs after editing the YAML (run from the repository root)::

    uv run python -m rosettalog.frontends.qradar_rules.docs_sync
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

import yaml

from rosettalog.ir.assumptions import Assumption, AssumptionSet, load_assumption_set

SOURCE = "src/rosettalog/frontends/qradar_rules/assumptions.yaml"
MATRIX_DOC = Path("docs/rules-support-matrix.md")
CONFIRMATION_DOC = Path("examples/confirmation-rules/README.md")


@cache
def rule_assumptions() -> AssumptionSet:
    return load_assumption_set("rosettalog.frontends.qradar_rules", "assumptions.yaml")


def _cell(text: str) -> str:
    return text.strip().replace("\n", " ").replace("|", "\\|")


def _scope(a: Assumption) -> str:
    if a.scope == "global":
        return "global: listed in every report while not confirmed"
    return "per artifact: " + ", ".join(f"`{c}`" for c in a.findings)


def _status(a: Assumption) -> str:
    label = f"**{a.status_label}**" if a.evidence_against else a.status
    if a.evidence_against and a.status == "unconfirmed":
        label += f": {_cell(a.evidence_against)}"
    return label + (f" ({_cell(a.evidence)})" if a.evidence else "")


def render_matrix_table(aset: AssumptionSet) -> str:
    base = f"../{aset.confirmation_dir}"
    lines = [
        "| ID | Question | Current assumption | Scope / finding | Case | Status |",
        "|---|---|---|---|---|---|",
    ]
    for a in aset.assumptions:
        lines.append(
            f"| {a.id} | {_cell(a.question)} | {_cell(a.assumption)} | {_scope(a)} "
            f"| [{a.case[:2]}]({base}/{a.case}) | {_status(a)} |"
        )
    return "\n".join(lines)


def _expected(case_dir: Path) -> str:
    data = yaml.safe_load((case_dir / "samples.yaml").read_text("utf-8"))
    return "<br>".join(
        f"`{rule}`: {', '.join(hits) or '(none)'}" for rule, hits in data["expected"].items()
    )


def render_confirmation_table(aset: AssumptionSet, root: Path) -> str:
    lines = [
        "| Case | Assumption | Question | Assumed hits (from `samples.yaml`) | Alternatives to "
        "look for | Status |",
        "|---|---|---|---|---|---|",
    ]
    for a in aset.assumptions:
        lines.append(
            f"| [{a.case[:2]}]({a.case}) | {a.id} | {_cell(a.question)} "
            f"| {_expected(root / aset.confirmation_dir / a.case)} | {_cell(a.alternatives)} "
            f"| {_status(a)} |"
        )
    return "\n".join(lines)


def _markers(name: str) -> tuple[str, str]:
    begin = (
        f"<!-- BEGIN GENERATED: {name} (from {SOURCE}; regenerate with "
        "`uv run python -m rosettalog.frontends.qradar_rules.docs_sync`) -->"
    )
    return begin, f"<!-- END GENERATED: {name} -->"


def replace_block(text: str, name: str, content: str) -> str:
    begin, end = _markers(name)
    start, stop = text.find(begin), text.find(end)
    if start == -1 or stop == -1:
        raise ValueError(f"generated block '{name}' markers not found")
    return text[: start + len(begin)] + "\n" + content + "\n" + text[stop:]


def generated_docs(root: Path) -> dict[Path, str]:
    aset = rule_assumptions()
    matrix = root / MATRIX_DOC
    confirmation = root / CONFIRMATION_DOC
    return {
        matrix: replace_block(
            matrix.read_text("utf-8"), "rule-assumptions", render_matrix_table(aset)
        ),
        confirmation: replace_block(
            confirmation.read_text("utf-8"),
            "rule-confirmation-cases",
            render_confirmation_table(aset, root),
        ),
    }
