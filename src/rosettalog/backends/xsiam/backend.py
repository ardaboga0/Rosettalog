"""Cortex XSIAM backend: IR parser -> Parsing Rules (``.xif``) for a raw dataset.

Output shape (deterministic, and restricted to the subset the local XSIAM emulator understands)::

    [INGEST:vendor="<v>", product="<p>", target_dataset="<v>_<p>_raw", no_hit=keep]
    config case_sensitive = true
    | alter _rl_p1 = regexcapture(_raw_log, "(?P<m>...(?P<g1>...)...)"), ...     // stage 1
    | alter <selector, lookup keys, timestamp parts>                            // stages 2-4
    | alter <extracted fields in snake_case>, _time = parse_timestamp(...)
    | fields - _rl_p1, ...;

Facts from Palo Alto's documentation (links in docs/lsx-support-matrix.md):

* The rules of an INGEST group "get evaluated independently", unlike firewall-like rules, so a
  log can be ingested more than once. All LSX match groups therefore go into **one** statement,
  and the group is chosen inside it (A01).
* XQL compares strings case-insensitively unless ``config case_sensitive = true`` is set; the
  backend sets it, so comparisons are exact as in QRadar.
* Regexes are RE2 (see :mod:`rosettalog.regex.xql`). Multiple groups are captured with
  ``regexcapture``, whose results are read with ``obj -> name``.
* Timestamps: the list of ``parse_timestamp`` format elements is not documented. Like the
  Sentinel backend, the components are captured with a regex and normalised by Rosettalog
  (month names to numbers, 12-hour clock, two-digit years), then parsed as
  ``%Y-%m-%d %H:%M:%S`` (or ``%E*S`` with fractions) with an explicit ``+HH:MM`` zone. These are
  the most common elements in Palo Alto's shipped Parsing Rules. A missing year is taken from
  the ingestion time (``current_time()``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import ClassVar

from rosettalog.backends.common import (
    DropTracker,
    artifact_ready,
    date_format_findings,
    describe,
    slugify,
    two_digit_year_finding,
)
from rosettalog.backends.xsiam.unknowns import xsiam_unknowns
from rosettalog.ir import (
    Artifact,
    AssumptionDependency,
    Capture,
    Coalesce,
    Expr,
    FieldRule,
    Finding,
    IfMatch,
    Literal_,
    Lookup,
    MatchGroup,
    ParserSpec,
    ParseTime,
    Status,
    Template,
    Variant,
    pattern_ids,
)
from rosettalog.ir.assumptions import AssumptionSet
from rosettalog.ir.fields import field_table
from rosettalog.plugins import BackendResult, DeploymentSetting, GeneratedFile
from rosettalog.regex.xql import XqlPattern, group_name, to_xql, xql_regex_literal
from rosettalog.timefmt.joda import MONTHS, Comp, compile_format

NAME = "xsiam"
TIME_FIELD = "_time"
#: XDM fields whose schema type needs a conversion from the extracted string (shipped Modeling
#: Rules use the same idioms: to_integer() for ports, arraycreate() for MAC addresses).
XDM_CASTS = {
    "xdm.source.port": "to_integer({})",
    "xdm.target.port": "to_integer({})",
    "xdm.source.host.mac_addresses": "arraycreate({})",
    "xdm.target.host.mac_addresses": "arraycreate({})",
}
MONTH_NAMES = ["january", "february", "march", "april", "may", "june", "july", "august",
               "september", "october", "november", "december"]  # fmt: skip


def xsiam_field_name(canonical: str) -> str:
    """Raw-dataset column for a canonical field: snake_case (``SourceIp`` -> ``source_ip``,
    ``NetBIOSName`` -> ``net_bios_name``). ``DeviceTime`` becomes the system field ``_time``."""
    if canonical == "DeviceTime":
        return TIME_FIELD
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", canonical)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return slugify(text).lower()


def xql_string(value: str) -> str | None:
    """A double-quoted XQL string for plain text, or ``None`` if the text cannot be written
    safely: backslashes are passed through unchanged (see :mod:`rosettalog.regex.xql`), so a
    backslash before a quote or at the end, or a line break, has no known spelling."""
    if value.endswith("\\") or '\\"' in value or "\n" in value or "\r" in value:
        return None
    return '"' + value.replace('"', '\\"') + '"'


def is_time(expr: Expr) -> bool:
    if isinstance(expr, ParseTime):
        return True
    return isinstance(expr, Coalesce) and all(is_time(i) for i in expr.items)


@dataclass
class _Patterns:
    spec: ParserSpec
    translations: dict[str, XqlPattern] = field(init=False)
    columns: dict[str, str] = field(default_factory=dict)
    """Pattern id -> temporary column holding its ``regexcapture`` result (only used ones)."""

    def __post_init__(self) -> None:
        self.translations = {
            pid: to_xql(p.source, case_insensitive=p.case_insensitive)
            for pid, p in self.spec.patterns.items()
        }

    def column(self, pid: str) -> str | None:
        if self.translations[pid].pattern is None:
            return None
        return self.columns.setdefault(pid, f"_rl_p{len(self.columns) + 1}")

    def findings(self) -> list[Finding]:
        users: dict[str, list[str]] = {}
        for group in self.spec.match_groups:
            for rule in group.rules:
                for pid in pattern_ids(rule.expr):
                    users.setdefault(pid, [])
                    if rule.field not in users[pid]:
                        users[pid].append(rule.field)
            for pid in group.selector_pattern_ids:
                users.setdefault(pid, [])
        out: list[Finding] = []
        for pid, tr in self.translations.items():
            if pid not in users:
                continue
            fields = ", ".join(users[pid]) or "match group selection"
            pattern = self.spec.patterns[pid]
            line = pattern.provenance.line if pattern.provenance else None
            for issue in tr.issues:
                message = f"{issue.message} Affects: {fields}."
                depends = None
                if issue.code == "XSIAM_REGEX_INLINE_FLAGS":
                    depends = linked(
                        "xsiam-inline-flags",
                        message,
                        confirmed=(
                            Status.FULL,
                            f"Inline regex flags work in XSIAM. Affects: {fields}.",
                        ),
                        refuted=(
                            Status.UNSUPPORTED,
                            f"XSIAM does not accept inline regex flags; this pattern fails. "
                            f"Affects: {fields}.",
                        ),
                    )
                out.append(
                    Finding(
                        status=issue.status,
                        code=issue.code,
                        path=f"pattern[id={pid}]",
                        message=message,
                        target=NAME,
                        line=line,
                        depends_on=depends,
                    )
                )
        return out


def linked(
    topic: str,
    unconfirmed: str,
    *,
    confirmed: tuple[Status, str],
    refuted: tuple[Status, str],
) -> AssumptionDependency:
    """A dependency on an XSIAM unknown (``unknowns.yaml``) that is still unconfirmed."""
    return AssumptionDependency(
        topic=topic,
        unconfirmed=Variant(status=Status.PARTIAL, message=unconfirmed),
        confirmed=Variant(status=confirmed[0], message=confirmed[1]),
        refuted=Variant(status=refuted[0], message=refuted[1]),
    )


@dataclass
class _Renderer:
    patterns: _Patterns
    drops: DropTracker
    findings: list[Finding]
    temps: list[tuple[str, str, int]] = field(default_factory=list)
    """(column, expression, stage). A stage may only reference columns of earlier stages; stage
    1 holds the regexcapture results, which the renderer adds itself."""

    def temp(self, prefix: str, expr: str, stage: int) -> str:
        for name, existing, _ in self.temps:
            if existing == expr and name.startswith(f"_rl_{prefix}"):
                return name
        name = f"_rl_{prefix}{len(self.temps) + 1}"
        self.temps.append((name, expr, stage))
        return name

    def matched(self, pid: str) -> str | None:
        col = self.patterns.column(pid)
        return None if col is None else f"{col} -> {group_name(0)} != null"

    def group(self, pid: str, group: int) -> str | None:
        col = self.patterns.column(pid)
        return None if col is None else f"{col} -> {group_name(group)}"

    def literal(self, value: str, rule: FieldRule) -> str | None:
        text = xql_string(value)
        if text is None:
            self.findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="XSIAM_STRING_LITERAL",
                    path=rule.path,
                    message=f"The literal text {value!r} contains a line break or a backslash "
                    "before a quote or at the end, which has no documented XQL spelling.",
                    target=NAME,
                    line=rule.line,
                )
            )
        return text

    def expr(self, e: Expr, rule: FieldRule) -> str | None:
        match e:
            case Capture(pattern_id=pid, group=g):
                value = self.group(pid, g)
                # An empty capture is "no value" (A07); a group that did not participate is
                # null either way.
                return None if value is None else f'if({value} = "", null, {value})'
            case Template(pattern_id=pid, parts=parts):
                cond = self.matched(pid)
                if cond is None:
                    return None
                pieces: list[str] = []
                for p in parts:
                    if isinstance(p, str):
                        lit = self.literal(p, rule)
                        if lit is None:
                            return None
                        pieces.append(lit)
                    else:
                        value = self.group(pid, p)
                        assert value is not None
                        pieces.append(f'coalesce({value}, "")')  # missing group -> "" (A08)
                return f"if({cond}, concat({', '.join(pieces)}), null)"
            case Literal_(value=v):
                return self.literal(v, rule)
            case IfMatch(pattern_id=pid, value=v):
                cond = self.matched(pid)
                inner = self.expr(v, rule)
                if cond is None or inner is None:
                    return None
                return f"if({cond}, {inner}, null)"
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
                col = self.temp("key", key, 2)
                branches = []
                for k_, v in table.items():
                    kk, vv = self.literal(k_, rule), self.literal(v, rule)
                    if kk is None or vv is None:
                        continue
                    branches.append(f"{col} = {kk}, {vv}")
                if not branches:
                    return default
                return f"if({', '.join(branches)}, {default or 'null'})"
            case ParseTime(value=v, format=fmt):
                return self.parse_time(v, fmt, rule)
        raise AssertionError(e)  # pragma: no cover

    def parse_time(self, value: Expr, fmt_text: str, rule: FieldRule) -> str | None:
        fmt = compile_format(fmt_text)
        self.findings.extend(date_format_findings(fmt, path=rule.path, target=NAME, line=rule.line))
        if Comp.YEAR2 in fmt.components:
            self.findings.append(
                two_digit_year_finding(
                    "the generated parsing rule (2000 + yy)",
                    "2000-2099",
                    fixed_2000=True,
                    path=rule.path,
                    target=NAME,
                    line=rule.line,
                )
            )
        text = self.expr(value, rule)
        if text is None or not fmt.usable:
            return None
        parts_rx = to_xql(fmt.regex, case_insensitive=True)
        if parts_rx.pattern is None:  # our own date regexes are plain RE2
            return None
        ts = self.temp("ts", text, 2)
        tp = self.temp("tp", f"regexcapture({ts}, {xql_regex_literal(parts_rx.pattern)})", 3)
        comp = {c: f"{tp} -> {group_name(i)}" for i, c in enumerate(fmt.components, start=1)}
        if Comp.YEAR4 in comp:
            year = f"to_integer({comp[Comp.YEAR4]})"
        elif Comp.YEAR2 in comp:
            year = f"add(2000, to_integer({comp[Comp.YEAR2]}))"
        else:
            year = 'to_integer(format_timestamp("%Y", current_time()))'
            self.findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="XSIAM_YEAR_FROM_INGEST_TIME",
                    path=rule.path,
                    message="The date has no year; the parsing rule uses the year of the "
                    "ingestion time (current_time()). Around New Year, events ingested late get "
                    "the wrong year.",
                    target=NAME,
                    line=rule.line,
                )
            )
        if Comp.MONTH_TEXT in comp:
            names = comp[Comp.MONTH_TEXT]
            branches = ", ".join(
                f'lowercase({names}) = "{short}" or lowercase({names}) = "{full}", {n}'
                for n, (short, full) in enumerate(zip(MONTHS, MONTH_NAMES, strict=True), start=1)
            )
            month = self.temp("mon", f"if({branches}, null)", 4)
        else:
            month = f"to_integer({comp[Comp.MONTH_NUM]})"
        day = f"to_integer({comp[Comp.DAY]})"
        if Comp.HOUR12 in comp:
            hour = f"mod(to_integer({comp[Comp.HOUR12]}), 12)"
            if Comp.AMPM in comp:
                hour = f'add({hour}, if(lowercase({comp[Comp.AMPM]}) = "pm", 12, 0))'
        elif Comp.HOUR24 in comp:
            hour = f"to_integer({comp[Comp.HOUR24]})"
        else:
            hour = "0"
        minute = f"to_integer({comp[Comp.MINUTE]})" if Comp.MINUTE in comp else "0"
        second = f"to_integer({comp[Comp.SECOND]})" if Comp.SECOND in comp else "0"
        normalized = (
            f'format_string("%04d-%02d-%02d %02d:%02d:%02d", '
            f"{year}, {month}, {day}, {hour}, {minute}, {second})"
        )
        pattern = "%Y-%m-%d %H:%M:%S"
        if Comp.FRACTION in comp:
            normalized = f'concat({normalized}, ".", {comp[Comp.FRACTION]})'
            pattern = "%Y-%m-%d %H:%M:%E*S"
        args = f'"{pattern}", {normalized}'
        if Comp.TZ_SIGN in comp:
            zone = (
                f'concat({comp[Comp.TZ_SIGN]}, {comp[Comp.TZ_HOURS]}, ":", {comp[Comp.TZ_MINUTES]})'
            )
            args += f", {zone}"
        guard = f"{tp} -> {group_name(0)} != null"
        if Comp.MONTH_TEXT in comp:
            guard += f" and {month} != null"
        return f"if({guard}, parse_timestamp({args}), null)"


def _options(artifact: Artifact, options: Mapping[str, str]) -> dict[str, str]:
    vendor = options.get("vendor", "custom")
    product = options.get("product", slugify(artifact.id).lower())
    dataset = options.get("target_dataset", f"{slugify(vendor)}_{slugify(product)}_raw".lower())
    return {"vendor": vendor, "product": product, "target_dataset": dataset}


class XsiamBackend:
    name: ClassVar[str] = NAME
    description: ClassVar[str] = (
        "Cortex XSIAM: Parsing Rules (XQL) for a raw dataset (emulator-verified only)"
    )
    option_help: ClassVar[Mapping[str, str]] = {
        "vendor": "Vendor the rule applies to; must match the collector (default: custom).",
        "product": "Product the rule applies to; must match the collector (default: the "
        "artifact id).",
        "target_dataset": "Dataset to write to (default: <vendor>_<product>_raw).",
    }

    def supports(self, artifact: Artifact) -> bool:
        return artifact_ready(artifact)

    def assumptions(self) -> AssumptionSet:
        """Undocumented XSIAM behaviour the output relies on (target-side registry)."""
        return xsiam_unknowns()

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult:
        spec = artifact.parser
        if spec is None:
            return BackendResult(target=NAME, artifact_id=artifact.id)
        effective = _options(artifact, options)
        findings: list[Finding] = []
        patterns = _Patterns(spec)
        drops = DropTracker(NAME)
        r = _Renderer(patterns, drops, findings)

        multi = len(spec.match_groups) > 1
        if multi:
            branches = []
            for idx, group in enumerate(spec.match_groups, start=1):
                conds = [c for pid in group.selector_pattern_ids if (c := r.matched(pid))]
                if not conds:
                    findings.append(self._group_lost(group))
                    continue
                branches.append(f"{' or '.join(conds)}, {idx}")
            r.temps.append(("_rl_mg", f"if({', '.join(branches)}, 0)" if branches else "0", 2))

        columns: list[tuple[str, str]] = []
        field_names: dict[str, str] = {}
        used_names: dict[str, str] = {}
        for canonical in spec.fields():
            rendered: list[tuple[int, str]] = []
            last_rule: FieldRule | None = None
            for idx, group in enumerate(spec.match_groups, start=1):
                for rule in group.rules:
                    if rule.field != canonical:
                        continue
                    last_rule = rule
                    text = r.expr(rule.expr, rule)
                    if text is not None:
                        rendered.append((idx, text))
            assert last_rule is not None
            if not rendered:
                drops.field_lost(
                    last_rule.path, canonical, line=last_rule.line,
                    reason="every extraction candidate relies on constructs the parsing rule "
                    "cannot express.",
                )  # fmt: skip
                continue
            if multi:
                cases = ", ".join(f"_rl_mg = {i}, {t}" for i, t in rendered)
                value = f"if({cases}, null)"
            else:
                value = rendered[0][1]
            name = xsiam_field_name(canonical)
            if name in used_names:
                findings.append(
                    Finding(
                        status=Status.PARTIAL,
                        code="FIELD_NAME_COLLISION",
                        path=f"field[{canonical}]",
                        message=f"Fields '{canonical}' and '{used_names[name]}' both become "
                        f"'{name}'; '{canonical}' is written as '{name}_2' instead.",
                        target=NAME,
                    )
                )
                name = f"{name}_2"
            used_names[name] = canonical
            columns.append((name, value))
            field_names[canonical] = name

        findings.extend(patterns.findings())
        findings.extend(self._notes(field_names, bool(patterns.columns)))
        findings.extend(drops.findings)
        if not columns:
            return BackendResult(
                target=NAME, artifact_id=artifact.id, findings=findings, options=effective
            )
        file_name = f"{slugify(artifact.id)}.xif"
        content = self._render(artifact, effective, patterns, r.temps, columns)
        files = [GeneratedFile(path=file_name, content=content)]
        model, xdm_names = self._model(artifact, effective, field_names, findings)
        if model is not None:
            files.append(GeneratedFile(path=f"{slugify(artifact.id)}.model.xif", content=model))
        return BackendResult(
            target=NAME,
            artifact_id=artifact.id,
            files=files,
            findings=findings,
            field_names={c: xdm_names.get(c, n) for c, n in field_names.items()},
            options=effective,
            settings=[
                DeploymentSetting(
                    scope="index-time",
                    file=file_name,
                    setting=f"INGEST {effective['vendor']}/{effective['product']} -> "
                    f"{effective['target_dataset']}",
                    fields=list(field_names.values()),
                    note="Parsing Rules run at ingestion; logs ingested before deployment keep "
                    "their stored fields",
                )
            ],
        )

    @staticmethod
    def _model(
        artifact: Artifact,
        opts: Mapping[str, str],
        field_names: dict[str, str],
        findings: list[Finding],
    ) -> tuple[str | None, dict[str, str]]:
        """Data Model Rule mapping raw columns to XDM, only for schema fields (M5b)."""
        table = field_table()
        mapped: dict[str, str] = {}
        assigns: list[str] = []
        casts: list[str] = []
        for canonical, column in field_names.items():
            if column == TIME_FIELD:
                continue  # XDM system fields (_time, ...) are mapped automatically
            xdm = table.get(canonical, {}).get("xdm")
            if xdm is None:
                findings.append(
                    Finding(
                        status=Status.PARTIAL,
                        code="FIELD_UNMAPPED",
                        path=f"field[{canonical}]",
                        message=f"Field '{canonical}' has no XDM equivalent; it is kept in the raw "
                        f"dataset as '{column}' (XDM accepts only schema fields).",
                        suggestion="Map it to an XDM field by hand if one fits, or use XSIAM's "
                        "'Generate data model rules with AI' and review the result.",
                        target=NAME,
                    )
                )
                continue
            if xdm in XDM_CASTS:
                casts.append(f"{xdm} ({XDM_CASTS[xdm].format('...')})")
            if XDM_CASTS.get(xdm, "").startswith("to_integer"):
                head = (
                    f"'{canonical}' becomes the Number field {xdm} through to_integer(): the "
                    'text is normalised, e.g. "0443" becomes 443, so the modeled value can '
                    "differ from QRadar's text."
                )
                findings.append(
                    Finding(
                        status=Status.PARTIAL,
                        code="XSIAM_XDM_INTEGER_NORMALIZATION",
                        path=f"field[{canonical}]",
                        message=f"{head} A non-numeric value is assumed to become null.",
                        suggestion=f"Keep the raw column '{column}' if the exact text matters.",
                        target=NAME,
                        depends_on=linked(
                            "xsiam-to-integer",
                            f"{head} A non-numeric value is assumed to become null.",
                            confirmed=(
                                Status.PARTIAL,
                                f"{head} A non-numeric value becomes null.",
                            ),
                            refuted=(
                                Status.PARTIAL,
                                f"{head} A non-numeric value makes XSIAM reject the modeled "
                                "event; check the parsing and modeling errors.",
                            ),
                        ),
                    )
                )
            assigns.append(f"{xdm} = {XDM_CASTS.get(xdm, '{}').format(column)}")
            mapped[canonical] = xdm
        if not assigns:
            return None, {}
        findings.append(
            Finding(
                status=Status.FULL,
                code="XSIAM_XDM_MAPPED",
                path="",
                message=f"A Data Model Rule maps {len(assigns)} field(s) to XDM"
                + (f"; type conversions: {', '.join(casts)}" if casts else "")
                + ". _time is an XDM system field and is mapped automatically.",
                target=NAME,
            )
        )
        lines = [
            f"// Generated by rosettalog from {PurePath(artifact.provenance.file).name}",
            "// Review the migration report before deploying. Do not edit by hand; regenerate.",
            f'[MODEL: dataset="{opts["target_dataset"]}"]',
            "config case_sensitive = true",
            "| alter",
            *(f"    {a}," for a in assigns),
        ]
        lines[-1] = lines[-1].rstrip(",") + ";"
        return "\n".join(lines) + "\n", mapped

    @staticmethod
    def _notes(field_names: dict[str, str], uses_regex: bool) -> list[Finding]:
        out = [
            Finding(
                status=Status.PARTIAL,
                code="XSIAM_UNVERIFIED_TARGET",
                path="",
                message="Emulator-verified only: there is no local XSIAM engine, so this parsing "
                "rule was checked with Rosettalog's emulator of the documented XQL behaviour, not "
                "on a tenant.",
                suggestion="Paste the rule into the Parsing Rules editor and check it with "
                "Simulate on real logs before deploying, or verify it on your tenant with "
                "`rosettalog verify --engine real --runner xsiam` (see docs/verification.md).",
                target=NAME,
            ),
            Finding(
                status=Status.PARTIAL,
                code="XSIAM_INGEST_TIME_DEPENDENCY",
                path="",
                message="Parsing Rules run at ingestion: only logs ingested after deployment get "
                f"the fields ({', '.join(field_names.values())}).",
                target=NAME,
            ),
            Finding(
                status=Status.FULL,
                code="XSIAM_CASE_SENSITIVE",
                path="",
                message="The rule sets 'config case_sensitive = true': XQL compares strings "
                "case-insensitively by default, QRadar does not.",
                target=NAME,
            ),
            Finding(
                status=Status.FULL,
                code="XSIAM_NO_HIT_KEEP",
                path="",
                message="no_hit=keep: logs the rule does not parse are still stored, with only "
                "_raw_log set.",
                target=NAME,
            ),
            Finding(
                status=Status.FULL,
                code="XSIAM_STRING_TYPES",
                path="",
                message="Extracted values are strings (_time is a timestamp). Data Model Rules "
                "cast them where the XDM schema needs another type.",
                target=NAME,
            ),
        ]
        if uses_regex:
            relies = (
                "The rule relies on regexcapture() returning an empty object when the pattern "
                "does not match, so that 'obj -> m' is null."
            )
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="XSIAM_REGEXCAPTURE_SEMANTICS",
                    path="",
                    message=f"{relies} Palo Alto's shipped rules test exactly this "
                    '(to_string(x) = "{}"), but it is not documented.',
                    target=NAME,
                    depends_on=linked(
                        "xsiam-regexcapture",
                        f"{relies} Palo Alto's shipped rules test exactly this "
                        '(to_string(x) = "{}"), but it is not documented.',
                        confirmed=(Status.FULL, f"{relies} XSIAM does this."),
                        refuted=(
                            Status.UNSUPPORTED,
                            f"{relies} XSIAM does not, so the generated rule cannot tell "
                            "whether a pattern matched.",
                        ),
                    ),
                )
            )
        return out

    @staticmethod
    def _group_lost(group: MatchGroup) -> Finding:
        return Finding(
            status=Status.UNSUPPORTED,
            code="MATCHGROUP_SELECTOR_UNTRANSLATABLE",
            path=group.path,
            message="None of the patterns that select this match group can be expressed in "
            "XQL, so the group is never applied.",
            target=NAME,
            line=group.line,
        )

    @staticmethod
    def _render(
        artifact: Artifact,
        opts: Mapping[str, str],
        patterns: _Patterns,
        temps: list[tuple[str, str, int]],
        columns: list[tuple[str, str]],
    ) -> str:
        ind = "    "
        stages: dict[int, list[tuple[str, str]]] = {}
        for pid, col in patterns.columns.items():
            rx = patterns.translations[pid].pattern
            assert rx is not None
            stages.setdefault(1, []).append(
                (col, f"regexcapture(_raw_log, {xql_regex_literal(rx)})")
            )
        for name, expr, stage in temps:
            stages.setdefault(stage, []).append((name, expr))
        stages[max(stages, default=0) + 1] = columns
        lines = [
            f"// Generated by rosettalog from {PurePath(artifact.provenance.file).name}",
            "// Review the migration report before deploying. Do not edit by hand; regenerate.",
            f'[INGEST:vendor="{opts["vendor"]}", product="{opts["product"]}", '
            f'target_dataset="{opts["target_dataset"]}", no_hit=keep]',
            "config case_sensitive = true",
        ]
        for stage in sorted(stages):
            lines.append("| alter")
            lines.extend(f"{ind}{n} = {v}," for n, v in stages[stage])
            lines[-1] = lines[-1].rstrip(",")
        temp_names = [*patterns.columns.values(), *(t[0] for t in temps)]
        if temp_names:
            lines.append(f"| fields - {', '.join(temp_names)}")
        lines[-1] += ";"
        return "\n".join(lines) + "\n"
