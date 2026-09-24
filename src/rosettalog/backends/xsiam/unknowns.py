"""Registry of XSIAM behaviour the backend relies on without documentation (``unknowns.yaml``),
and the doc tables generated from it. Regenerate after editing the YAML (from the repo root)::

    uv run python -m rosettalog.backends.xsiam.docs_sync
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

import yaml

from rosettalog.ir.assumptions import Assumption, AssumptionSet, load_assumption_set

SOURCE = "src/rosettalog/backends/xsiam/unknowns.yaml"
PACK_DOC = Path("examples/confirmation/xsiam/README.md")
MATRIX_DOC = Path("docs/lsx-support-matrix.md")


@cache
def xsiam_unknowns() -> AssumptionSet:
    return load_assumption_set("rosettalog.backends.xsiam", "unknowns.yaml")


def _cell(text: str) -> str:
    return text.strip().replace("\n", " ").replace("|", "\\|")


def _status(a: Assumption) -> str:
    return a.status + (f" ({_cell(a.evidence)})" if a.evidence else "")


def _expected(case_dir: Path) -> str:
    data = yaml.safe_load((case_dir / "expected.yaml").read_text("utf-8"))
    out = []
    for sample in data["samples"]:
        values = ", ".join(
            f"{k}={'(none)' if v is None else f'`{_cell(str(v))}`'}"
            for k, v in sample["expected"].items()
        )
        out.append(f"`{_cell(sample['log'])}` → {values}")
    return "<br>".join(out)


def render_pack_table(aset: AssumptionSet, root: Path) -> str:
    lines = [
        "| Case | ID | Question | Lines → assumed fields | Alternatives to look for | Status |",
        "|---|---|---|---|---|---|",
    ]
    for a in aset.assumptions:
        lines.append(
            f"| [{a.case[:2]}]({a.case}) | {a.id} | {_cell(a.question)} "
            f"| {_expected(root / aset.confirmation_dir / a.case)} | {_cell(a.alternatives)} "
            f"| {_status(a)} |"
        )
    return "\n".join(lines)


def render_matrix_table(aset: AssumptionSet) -> str:
    base = f"../{aset.confirmation_dir}"
    lines = [
        "| ID | Question | Current assumption | Scope / finding | Case | Status |",
        "|---|---|---|---|---|---|",
    ]
    for a in aset.assumptions:
        scope = (
            "global: listed in every report with an XSIAM target"
            if a.scope == "global"
            else "per artifact: " + ", ".join(f"`{c}`" for c in a.findings)
        )
        lines.append(
            f"| {a.id} | {_cell(a.question)} | {_cell(a.assumption)} | {scope} "
            f"| [{a.case[:2]}]({base}/{a.case}) | {_status(a)} |"
        )
    return "\n".join(lines)


def _markers(name: str) -> tuple[str, str]:
    begin = (
        f"<!-- BEGIN GENERATED: {name} (from {SOURCE}; regenerate with "
        "`uv run python -m rosettalog.backends.xsiam.docs_sync`) -->"
    )
    return begin, f"<!-- END GENERATED: {name} -->"


def replace_block(text: str, name: str, content: str) -> str:
    begin, end = _markers(name)
    start, stop = text.find(begin), text.find(end)
    if start == -1 or stop == -1:
        raise ValueError(f"generated block '{name}' markers not found")
    return text[: start + len(begin)] + "\n" + content + "\n" + text[stop:]


def generated_docs(root: Path) -> dict[Path, str]:
    aset = xsiam_unknowns()
    pack, matrix = root / PACK_DOC, root / MATRIX_DOC
    return {
        pack: replace_block(pack.read_text("utf-8"), "xsiam-cases", render_pack_table(aset, root)),
        matrix: replace_block(
            matrix.read_text("utf-8"), "xsiam-unknowns", render_matrix_table(aset)
        ),
    }
