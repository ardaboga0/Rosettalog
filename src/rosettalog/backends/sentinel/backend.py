"""Microsoft Sentinel backend: IR parser -> KQL parser function (ASIM-aligned field names).

Output shape (deterministic, and restricted to the subset the local KQL emulator understands)::

    let <Function> = (disabled: bool = false) {
        <Table>
        | where not(disabled)
        | extend <temporary columns: group selector, lookup keys, timestamp text>
        | extend <normalized fields>
        | project-away _rl_*
    };
    <Function>
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import ClassVar

from rosettalog.backends.common import (
    DropTracker,
    PatternTable,
    artifact_ready,
    camel,
    date_format_findings,
    describe,
)
from rosettalog.ir import (
    Artifact,
    Capture,
    Coalesce,
    Expr,
    FieldRule,
    Finding,
    IfMatch,
    Literal_,
    Lookup,
    MatchGroup,
    ParseTime,
    Status,
    Template,
)
from rosettalog.ir.fields import resolve_names
from rosettalog.plugins import BackendResult, GeneratedFile
from rosettalog.timefmt.joda import Comp, compile_format

NAME = "sentinel"
DEFAULT_MESSAGE_COLUMNS = {"Syslog": "SyslogMessage", "CommonSecurityLog": "Message"}
KNOWN_COLUMNS = {
    "Syslog": {
        "TenantId", "SourceSystem", "TimeGenerated", "Computer", "EventTime", "Facility",
        "HostName", "SeverityLevel", "SyslogMessage", "ProcessID", "HostIP", "ProcessName",
        "Type", "_ResourceId", "CollectorHostName",
    },
    "CommonSecurityLog": {
        "TimeGenerated", "DeviceVendor", "DeviceProduct", "DeviceEventClassID", "Activity",
        "LogSeverity", "SourceIP", "SourcePort", "DestinationIP", "DestinationPort", "Protocol",
        "SourceUserName", "DestinationUserName", "Message", "Computer", "DeviceAction",
    },
}  # fmt: skip
ASIM_MANDATORY = [
    "EventCount", "EventEndTime", "EventType", "EventResult", "EventProduct", "EventVendor",
    "EventSchemaVersion", "Dvc",
]  # fmt: skip
MONTHS = "janfebmaraprmayjunjulaugsepoctnovdec"


def kql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def kql_regex(pattern: str) -> str:
    return '@"' + pattern.replace('"', '""') + '"'


def is_time(expr: Expr) -> bool:
    if isinstance(expr, ParseTime):
        return True
    return isinstance(expr, Coalesce) and all(is_time(i) for i in expr.items)


@dataclass
class _Renderer:
    patterns: PatternTable
    msg: str
    drops: DropTracker
    findings: list[Finding]
    temps: list[tuple[str, str, int]] = field(default_factory=list)
    """(column, expression, stage). Stage 2 columns may reference stage 1 columns."""

    def temp(self, prefix: str, expr: str, stage: int = 1) -> str:
        for name, existing, _ in self.temps:
            if existing == expr and name.startswith(f"_rl_{prefix}"):
                return name
        name = f"_rl_{prefix}{len(self.temps) + 1}"
        self.temps.append((name, expr, stage))
        return name

    def matches(self, pid: str) -> str | None:
        rx = self.patterns.get(pid)
        return None if rx is None else f"{self.msg} matches regex {kql_regex(rx)}"

    def expr(self, e: Expr, rule: FieldRule) -> str | None:
        match e:
            case Capture(pattern_id=pid, group=g):
                rx = self.patterns.get(pid)
                return None if rx is None else f"extract({kql_regex(rx)}, {g}, {self.msg})"
            case Template(pattern_id=pid, parts=parts):
                rx = self.patterns.get(pid)
                if rx is None:
                    return None
                pieces = [
                    kql_string(p)
                    if isinstance(p, str)
                    else f"extract({kql_regex(rx)}, {p}, {self.msg})"
                    for p in parts
                ]
                return f'iff({self.matches(pid)}, strcat({", ".join(pieces)}), "")'
            case Literal_(value=v):
                return kql_string(v)
            case IfMatch(pattern_id=pid, value=v):
                cond = self.matches(pid)
                inner = self.expr(v, rule)
                if cond is None or inner is None:
                    return None
                return f'iff({cond}, {inner}, "")'
            case Coalesce(items=items):
                rendered = []
                for item in items:
                    r = self.expr(item, rule)
                    if r is None:
                        self.drops.dropped(rule.path, describe(item), field_name=rule.field,
                                           line=rule.line)  # fmt: skip
                    else:
                        rendered.append(r)
                if not rendered:
                    return None
                return rendered[0] if len(rendered) == 1 else f"coalesce({', '.join(rendered)})"
            case Lookup(key=k, table=table, default=d):
                key = self.expr(k, rule)
                default = self.expr(d, rule) if d is not None else None
                if d is not None and default is None:
                    self.drops.dropped(rule.path, "Fallback value (" + describe(d) + ")",
                                       field_name=rule.field, line=rule.line)  # fmt: skip
                if key is None:
                    self.drops.dropped(rule.path, "Event mapping table (its key)",
                                       field_name=rule.field, line=rule.line)  # fmt: skip
                    return default
                col = self.temp("key", key)
                branches = [
                    f"{col} == {kql_string(k_)}, {kql_string(v)}" for k_, v in table.items()
                ]
                fallback = default or '""'
                return f"case({', '.join(branches)}, {fallback})"
            case ParseTime(value=v, format=fmt):
                return self.parse_time(v, fmt, rule)
        raise AssertionError(e)  # pragma: no cover

    def parse_time(self, value: Expr, fmt_text: str, rule: FieldRule) -> str | None:
        fmt = compile_format(fmt_text)
        self.findings.extend(date_format_findings(fmt, path=rule.path, target=NAME, line=rule.line))
        text = self.expr(value, rule)
        if text is None or not fmt.usable:
            return None
        col = self.temp("ts", text)
        parts = self.temp("tp", f"extract_all({kql_regex('(?i)' + fmt.regex)}, {col})[0]", 2)
        comp = {c: f"tostring({parts}[{i}])" for i, c in enumerate(fmt.components)}
        if Comp.YEAR4 in comp:
            year = f"toint({comp[Comp.YEAR4]})"
        elif Comp.YEAR2 in comp:
            year = f"2000 + toint({comp[Comp.YEAR2]})"
        else:
            year = "getyear(now())"
        if Comp.MONTH_TEXT in comp:
            month = (
                f'indexof("{MONTHS}", tolower(substring({comp[Comp.MONTH_TEXT]}, 0, 3))) / 3 + 1'
            )
        else:
            month = f"toint({comp[Comp.MONTH_NUM]})"
        day = f"toint({comp[Comp.DAY]})"
        if Comp.HOUR12 in comp:
            hour = f"toint({comp[Comp.HOUR12]}) % 12"
            if Comp.AMPM in comp:
                hour += f' + iff(tolower({comp[Comp.AMPM]}) == "pm", 12, 0)'
        elif Comp.HOUR24 in comp:
            hour = f"toint({comp[Comp.HOUR24]})"
        else:
            hour = "0"
        minute = f"toint({comp[Comp.MINUTE]})" if Comp.MINUTE in comp else "0"
        second = f"toint({comp[Comp.SECOND]})" if Comp.SECOND in comp else "0"
        if Comp.FRACTION in comp:
            second += f' + toreal(strcat("0.", {comp[Comp.FRACTION]}))'
        dt = f"make_datetime({year}, {month}, {day}, {hour}, {minute}, {second})"
        if Comp.TZ_SIGN in comp:
            offset = (
                f'iff({comp[Comp.TZ_SIGN]} == "-", -1, 1) * '
                f"(toint({comp[Comp.TZ_HOURS]}) * 60 + toint({comp[Comp.TZ_MINUTES]}))"
            )
            dt = f'datetime_add("minute", -({offset}), {dt})'
        return dt


class SentinelBackend:
    name: ClassVar[str] = NAME
    description: ClassVar[str] = "Microsoft Sentinel: KQL parser function with ASIM field names"
    option_help: ClassVar[Mapping[str, str]] = {
        "source_table": "Table holding the raw events (default: Syslog).",
        "message_column": "Column with the raw event text (default depends on the table; "
        "SyslogMessage for Syslog, RawData for custom tables).",
        "function_name": "Name of the generated function (default derived from the artifact).",
        "asim_schema": "ASIM schema to align to, e.g. NetworkSession. Adds EventSchema and "
        "names the function vim<Schema><Name>.",
    }

    def supports(self, artifact: Artifact) -> bool:
        return artifact_ready(artifact)

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult:
        spec = artifact.parser
        if spec is None:
            return BackendResult(target=NAME, artifact_id=artifact.id)
        table = options.get("source_table", "Syslog")
        msg = options.get("message_column") or DEFAULT_MESSAGE_COLUMNS.get(table, "RawData")
        schema = options.get("asim_schema")
        default_fn = (
            f"vim{schema}{camel(artifact.name)}" if schema else f"{camel(artifact.name)}Parser"
        )
        function = options.get("function_name", default_fn)
        effective = {"source_table": table, "message_column": msg, "function_name": function}

        findings: list[Finding] = []
        patterns = PatternTable(spec, "re2", NAME)
        findings.extend(patterns.findings())
        naming = resolve_names(spec.fields(), "asim", target=NAME)
        findings.extend(naming.findings)
        drops = DropTracker(NAME)
        r = _Renderer(patterns, msg, drops, findings)

        multi = len(spec.match_groups) > 1
        if multi:
            branches = []
            for idx, group in enumerate(spec.match_groups, start=1):
                conds = [c for pid in group.selector_pattern_ids if (c := r.matches(pid))]
                if not conds:
                    findings.append(self._group_lost(group))
                    continue
                branches.append(f"{' or '.join(conds)}, {idx}")
            r.temps.append(("_rl_mg", f"case({', '.join(branches)}, 0)" if branches else "0", 1))

        columns: list[tuple[str, str]] = []
        field_names: dict[str, str] = {}
        for canonical in spec.fields():
            rendered: list[tuple[int, str]] = []
            last_rule: FieldRule | None = None
            timeish = False
            for idx, group in enumerate(spec.match_groups, start=1):
                for rule in group.rules:
                    if rule.field != canonical:
                        continue
                    last_rule = rule
                    timeish = timeish or is_time(rule.expr)
                    text = r.expr(rule.expr, rule)
                    if text is not None:
                        rendered.append((idx, text))
            assert last_rule is not None
            if not rendered:
                drops.field_lost(
                    last_rule.path, canonical, line=last_rule.line,
                    reason="every extraction candidate relies on constructs KQL cannot express.",
                )  # fmt: skip
                continue
            if multi:
                empty = "datetime(null)" if timeish else '""'
                cases = ", ".join(f"_rl_mg == {i}, {t}" for i, t in rendered)
                value = f"case({cases}, {empty})"
            else:
                value = rendered[0][1]
            target_name = naming.names[canonical]
            columns.append((target_name, value))
            field_names[canonical] = target_name

        for name in field_names.values():
            if name in KNOWN_COLUMNS.get(table, set()):
                findings.append(
                    Finding(
                        status=Status.PARTIAL,
                        code="KQL_COLUMN_OVERWRITE",
                        path=f"field[{name}]",
                        message=f"Output column '{name}' already exists in table '{table}' and is "
                        "overwritten by the parser.",
                        suggestion="Rename the output column if the original value is needed.",
                        target=NAME,
                    )
                )
        if schema:
            columns.append(("EventSchema", kql_string(schema)))
            missing = [f for f in ASIM_MANDATORY if f not in field_names.values()]
            findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="ASIM_MANDATORY_FIELDS",
                    path="",
                    message=f"ASIM '{schema}' requires fields the LSX does not provide: "
                    f"{', '.join(missing)}.",
                    suggestion="Add constant or derived values for them before deploying as an "
                    "ASIM parser.",
                    target=NAME,
                )
            )
        findings.append(
            Finding(
                status=Status.FULL,
                code="KQL_STRING_TYPES",
                path="",
                message="Extracted values are strings (timestamps are datetime). Cast ports or "
                "numeric fields with toint() if your schema requires it.",
                target=NAME,
            )
        )
        findings.extend(drops.findings)

        content = self._render(artifact, function, table, r.temps, columns)
        files = [GeneratedFile(path=f"{function}.kql", content=content)] if columns else []
        return BackendResult(
            target=NAME,
            artifact_id=artifact.id,
            files=files,
            findings=findings,
            field_names=field_names,
            options=effective,
        )

    @staticmethod
    def _group_lost(group: MatchGroup) -> Finding:
        return Finding(
            status=Status.UNSUPPORTED,
            code="MATCHGROUP_SELECTOR_UNTRANSLATABLE",
            path=group.path,
            message="None of the patterns that select this match group can be expressed in "
            "KQL, so the group is never applied.",
            target=NAME,
            line=group.line,
        )

    @staticmethod
    def _render(
        artifact: Artifact,
        function: str,
        table: str,
        temps: list[tuple[str, str, int]],
        columns: list[tuple[str, str]],
    ) -> str:
        ind = "        "
        lines = [
            f"// Generated by rosettalog from {PurePath(artifact.provenance.file).name}",
            "// Review the migration report before deploying. Do not edit by hand; regenerate.",
            f"let {function} = (disabled: bool = false) {{",
            f"    {table}",
            "    | where not(disabled)",
        ]
        for stage in sorted({t[2] for t in temps}):
            lines.append("    | extend")
            lines.extend(f"{ind}{n} = {v}," for n, v, st in temps if st == stage)
            lines[-1] = lines[-1].rstrip(",")
        lines.append("    | extend")
        lines.extend(f"{ind}{n} = {v}," for n, v in columns)
        lines[-1] = lines[-1].rstrip(",")
        if temps:
            lines.append("    | project-away _rl_*")
        lines += ["};", function, ""]
        return "\n".join(lines)
