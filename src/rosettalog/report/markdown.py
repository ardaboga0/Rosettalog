"""Render a :class:`MigrationReport` as Markdown for humans reviewing a migration."""

from __future__ import annotations

from rosettalog.ir import Finding, Status
from rosettalog.report.models import ArtifactReport, MigrationReport, TargetReport
from rosettalog.verify.harness import VerificationResult

ICON = {Status.FULL: "✅ FULL", Status.PARTIAL: "⚠️ PARTIAL", Status.UNSUPPORTED: "❌ UNSUPPORTED"}
LEGEND = (
    "**FULL**: translated faithfully (notes may still apply). "
    "**PARTIAL**: usable, but the listed elements need human review. "
    "**UNSUPPORTED**: no usable output; migrate by hand."
)


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _code(value: str | None) -> str:
    if value is None:
        return "*(none)*"
    return "`" + value.replace("`", "'").replace("|", "\\|") + "`"


def _findings_table(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["No findings.", ""]
    ordered = sorted(findings, key=lambda f: (-f.status.rank, f.path, f.code))
    lines = ["| Status | Code | Element | Line | Details |", "|---|---|---|---|---|"]
    for f in ordered:
        details = f.message + (f" **Suggestion:** {f.suggestion}" if f.suggestion else "")
        path = f"`{f.path}`" if f.path else "*(artifact)*"
        lines.append(
            f"| {f.status.value} | `{f.code}` | {_cell(path)} | {f.line or ''} | {_cell(details)} |"
        )
    return [*lines, ""]


def _verification(v: VerificationResult) -> list[str]:
    lines = [f"**Verification:** {v.passed}/{v.total} samples match. _{v.engine_note}_", ""]
    if v.error:
        lines += [f"> Emulation error: {_cell(v.error)}", ""]
    rows = [
        (s.name, c)
        for s in v.samples
        for c in s.checks
        if not c.ok or not c.source_matches_expected
    ]
    if rows:
        lines += [
            "| Sample | Field | Target field | QRadar (emulated) | Generated | Expected |",
            "|---|---|---|---|---|---|",
        ]
        for name, c in rows:
            expected = _code(c.expected) if c.has_expected else ""
            lines.append(
                f"| {_cell(name)} | {c.field} | {c.target_field or '*(not generated)*'} | "
                f"{_code(c.source)} | {_code(c.target)} | {expected} |"
            )
        lines.append("")
    return lines


def _target(tr: TargetReport) -> list[str]:
    lines = [f"### {tr.target}: {ICON[tr.status]}", ""]
    if tr.files:
        lines += ["Files: " + ", ".join(f"`{f}`" for f in tr.files), ""]
    if tr.field_names:
        lines += ["| Source field | Generated field |", "|---|---|"]
        lines += [f"| {k} | `{v}` |" for k, v in tr.field_names.items()]
        lines.append("")
    lines += _findings_table(tr.findings)
    if tr.verification is not None:
        lines += _verification(tr.verification)
    return lines


def _artifact(a: ArtifactReport) -> list[str]:
    lines = [f"## {a.name}", "", f"Source: `{a.source_file}` ({a.source_format})", ""]
    lines += ["#### Source findings (apply to every target)", ""]
    lines += _findings_table(a.source_findings)
    for tr in a.targets:
        lines += _target(tr)
    return lines


def render_markdown(report: MigrationReport) -> str:
    lines = [
        "# Rosettalog migration report",
        "",
        f"Generated {report.generated_at:%Y-%m-%d %H:%M UTC} by rosettalog {report.tool_version}.",
        "",
        LEGEND,
        "",
        "## Summary",
        "",
        "| Artifact | Format | " + " | ".join(report.targets) + " |",
        "|---|---|" + "---|" * len(report.targets),
    ]
    for a in report.artifacts:
        by_target = {tr.target: tr for tr in a.targets}
        cells = []
        for t in report.targets:
            tr = by_target.get(t)
            if tr is None:
                cells.append("n/a")
                continue
            cell = ICON[tr.status]
            if tr.verification is not None and tr.verification.total:
                cell += f" ({tr.verification.passed}/{tr.verification.total} samples)"
            cells.append(cell)
        lines.append(f"| {_cell(a.name)} | {a.source_format} | " + " | ".join(cells) + " |")
    lines.append("")
    for a in report.artifacts:
        lines += _artifact(a)
    return "\n".join(lines).rstrip() + "\n"
