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
    truth = ", ".join(f"{k} ({n})" for k, n in v.ground_truth.items()) or "none"
    lines = [
        f"**Verification:** {v.passed}/{v.total} samples match. _{v.engine_note}_",
        "",
        f'Ground truth of the samples: {truth}. Samples whose ground truth is "assumed" only '
        "confirm consistency with Rosettalog's reading of the source, not QRadar's behaviour.",
        "",
    ]
    if v.real_engine:
        lines += [
            f"**Real engine:** {v.real_engine}. Each field is compared four ways: QRadar "
            "(emulated) vs target emulator vs real target engine vs expected.",
            "",
        ]
    for label, error in (("Emulation error", v.error), ("Real engine error", v.real_error)):
        if error:
            lines += [f"> {label}: {_cell(error)}", ""]
    rows = [
        (s, c) for s in v.samples for c in s.checks if not c.ok or not c.source_matches_expected
    ]
    if rows:
        real = v.real_engine is not None
        head = (
            "| Sample | Ground truth | Field | Target field | Scope | QRadar (emulated) | Emulator "
        )
        head += "| Real engine | Expected |" if real else "| Expected |"
        lines += [head, "|---" * (9 if real else 8) + "|"]
        for sample, c in rows:
            expected = _code(c.expected) if c.has_expected else ""
            cells = [
                _cell(sample.name),
                _cell(sample.ground_truth_source or ""),
                c.field,
                c.target_field or "*(not generated)*",
                c.scope or "",
                _code(c.source),
                _code(c.target) + (" ⚠ diverges from real engine" if c.emulator_diverges else ""),
            ]
            if real:
                cells.append(_code(c.real) if c.has_real else f"*(not compared: {c.real_note})*")
            cells.append(expected)
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
    return lines


SCOPE_TEXT = {
    "index-time": "Index-time settings: take effect only for data indexed **after** deployment, "
    "on the instance that parses the data (e.g. Splunk indexers / heavy forwarders). Already "
    "indexed data is not changed.",
    "search-time": "Search-time extractions: deploy to search heads; they apply to all data at "
    "search time, including data indexed before deployment.",
    "query-time": "Query-time parser: applies to all data it is run against, including data "
    "ingested before deployment.",
}


def _settings(tr: TargetReport) -> list[str]:
    lines: list[str] = []
    for scope, text in SCOPE_TEXT.items():
        items = [s for s in tr.settings if s.scope == scope]
        if not items:
            continue
        lines += [f"**{text}**", "", "| Setting | File | Fields | Note |", "|---|---|---|---|"]
        for s in items:
            fields = ", ".join(f"`{f}`" for f in s.fields)
            lines.append(f"| `{_cell(s.setting)}` | {s.file} | {fields} | {_cell(s.note)} |")
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
    lines += _settings(tr)
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


def _assumptions(report: MigrationReport) -> list[str]:
    items = report.unconfirmed_global_assumptions
    if not items:
        return []
    lines = [
        "## Unconfirmed global assumptions",
        "",
        "These assumptions about the source SIEM apply to **every** artifact above. They are not "
        "reported per artifact. Each one has a minimal confirmation case (LSX plus sample logs) to "
        "run on the source SIEM. An assumption leaves this list once it is confirmed.",
        "",
        "| ID | Status | Question | Current assumption | Confirmation case |",
        "|---|---|---|---|---|",
    ]
    for a in items:
        if a.status == "refuted":
            status = "**REFUTED**: output known to differ, fix pending"
        elif a.evidence_against:
            status = f"**{a.status_label}**: {_cell(a.evidence_against)}"
        else:
            status = a.status
        lines.append(
            f"| {a.id} | {status} | {_cell(a.question)} | {_cell(a.assumption)} | `{a.case}` |"
        )
    return [*lines, ""]


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
    lines += _assumptions(report)
    for a in report.artifacts:
        lines += _artifact(a)
    return "\n".join(lines).rstrip() + "\n"
