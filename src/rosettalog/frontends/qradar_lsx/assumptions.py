"""QRadar LSX assumption registry (``assumptions.yaml``) and the doc tables generated from it.

Regenerate the docs after editing the YAML (run from the repository root)::

    uv run python -m rosettalog.frontends.qradar_lsx.docs_sync
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

import yaml

from rosettalog.ir.assumptions import Assumption, AssumptionSet, load_assumption_set

SOURCE = "src/rosettalog/frontends/qradar_lsx/assumptions.yaml"
MATRIX_DOC = Path("docs/lsx-support-matrix.md")
CONFIRMATION_DOC = Path("examples/confirmation/README.md")


@cache
def lsx_assumptions() -> AssumptionSet:
    return load_assumption_set("rosettalog.frontends.qradar_lsx", "assumptions.yaml")


def _cell(text: str) -> str:
    """Table-safe text. Whitespace is kept as is: it can be the point of a case."""
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


def _value(value: object) -> str:
    return "(none)" if value is None else f"`{_cell(str(value))}`"


def _lines(case_dir: Path) -> str:
    """Payload of each sample line and its assumed result, taken from ``samples.yaml``."""
    data = yaml.safe_load((case_dir / "samples.yaml").read_text("utf-8"))
    out = []
    for i, sample in enumerate(data["samples"], start=1):
        payload = sample["log"].split("rltest: ", 1)[-1]
        result = ", ".join(f"{k}={_value(v)}" for k, v in sample["expected"].items())
        note = " (contains consecutive spaces)" if "  " in payload else ""
        out.append(f"{i}: `{_cell(payload)}`{note} → {result}")
    return "<br>".join(out)


def render_confirmation_table(aset: AssumptionSet, root: Path) -> str:
    lines = [
        "| Case | Assumption | Question | Lines sent → assumed result (from `samples.yaml`) "
        "| Assumed behaviour | Alternatives to look for | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    by_case: dict[str, list[Assumption]] = {}
    for a in aset.assumptions:
        by_case.setdefault(a.case, []).append(a)
    for case, items in sorted(by_case.items()):

        def join(values: list[str]) -> str:
            return "<br>".join(_cell(v) for v in values)

        lines.append(
            f"| [{case[:2]}]({case}) | {', '.join(a.id for a in items)} "
            f"| {join([a.question for a in items])} "
            f"| {_lines(root / aset.confirmation_dir / case)} "
            f"| {join([a.assumption for a in items])} "
            f"| {join([a.alternatives for a in items])} "
            f"| {join([_status(a) for a in items])} |"
        )
    return "\n".join(lines)


def _markers(name: str) -> tuple[str, str]:
    begin = (
        f"<!-- BEGIN GENERATED: {name} (from {SOURCE}; regenerate with "
        "`uv run python -m rosettalog.frontends.qradar_lsx.docs_sync`) -->"
    )
    return begin, f"<!-- END GENERATED: {name} -->"


def replace_block(text: str, name: str, content: str) -> str:
    begin, end = _markers(name)
    start, stop = text.find(begin), text.find(end)
    if start == -1 or stop == -1:
        raise ValueError(f"generated block '{name}' markers not found")
    return text[: start + len(begin)] + "\n" + content + "\n" + text[stop:]


def generated_docs(root: Path) -> dict[Path, str]:
    """Full expected contents of every doc file with a generated assumptions table."""
    aset = lsx_assumptions()
    matrix = root / MATRIX_DOC
    confirmation = root / CONFIRMATION_DOC
    return {
        matrix: replace_block(matrix.read_text("utf-8"), "assumptions", render_matrix_table(aset)),
        confirmation: replace_block(
            confirmation.read_text("utf-8"),
            "confirmation-cases",
            render_confirmation_table(aset, root),
        ),
    }
