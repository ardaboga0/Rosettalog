"""Splunk backend: IR parser -> props.conf + transforms.conf (CIM field names).

* Every capture becomes a search-time transform (``REPORT-``). When a field is a single capture
  the transform writes the final field directly; otherwise it writes an ``rl_<n>_<field>``
  intermediate field that an ``EVAL-`` combines (fallback order via ``coalesce``, event
  mapping tables via ``case``, match-group selection via ``match(_raw, ...)``).
* ``DeviceTime`` becomes index-time ``TIME_PREFIX``/``TIME_FORMAT`` when derivable.

Note: Splunk evaluates all ``EVAL-`` statements in parallel, so an EVAL never references the
output of another EVAL; shared sub-expressions are inlined instead.
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
    date_format_findings,
    describe,
    slugify,
    two_digit_year_finding,
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
    ParseTime,
    Status,
    Template,
)
from rosettalog.ir.fields import resolve_names
from rosettalog.ir.findings import AssumptionDependency, Variant
from rosettalog.plugins import BackendResult, DeploymentSetting, GeneratedFile
from rosettalog.regex.tokenizer import GroupKind, Kind, RegexSyntaxError, tokenize
from rosettalog.regex.translate import translate_tokens
from rosettalog.timefmt.joda import Comp, compile_format

NAME = "splunk"
TIME_FIELD = "_time"


def eval_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def conf_value(value: str) -> str:
    """Protect leading/trailing spaces, which .conf parsing would strip."""
    if value[:1] == " ":
        value = "[ ]" + value[1:]
    if value[-1:] == " " and not value.endswith("\\ "):
        value = value[:-1] + "[ ]"
    return value


@dataclass
class Transform:
    name: str
    regex: str
    format: str


@dataclass
class _Renderer:
    artifact_id: str
    patterns: PatternTable
    drops: DropTracker
    transforms: list[Transform] = field(default_factory=list)
    cache: dict[tuple[str, int], str] = field(default_factory=dict)

    def _transform(self, regex: str, fmt_pairs: list[tuple[str, str]]) -> None:
        name = f"rl_{self.artifact_id}_{len(self.transforms) + 1}"
        fmt = " ".join(f"{f}::{v}" for f, v in fmt_pairs)
        self.transforms.append(Transform(name, conf_value(regex), fmt))

    def capture_field(self, pid: str, group: int, out_field: str | None = None) -> str | None:
        """Field holding capture ``group`` of ``pid``; creates the transform on first use."""
        rx = self.patterns.get(pid)
        if rx is None:
            return None
        if out_field is None and (pid, group) in self.cache:
            return self.cache[(pid, group)]
        name = out_field or f"rl_{len(self.transforms) + 1}_{slugify(pid)}"
        if group == 0:
            self._transform(f"({rx})", [(name, "$1")])
        else:
            self._transform(rx, [(name, f"${group}")])
        self.cache.setdefault((pid, group), name)
        return name

    def template(self, pid: str, parts: list[str | int]) -> str | None:
        rx = self.patterns.get(pid)
        if rx is None:
            return None
        n = len(self.transforms) + 1
        groups = sorted({p for p in parts if isinstance(p, int)})
        names = {g: f"rl_{n}_{slugify(pid)}_{g}" for g in groups}
        self._transform(rx, [(names[g], f"${g}") for g in groups])
        pieces = [
            eval_string(p) if isinstance(p, str) else f'coalesce({names[p]}, "")' for p in parts
        ]
        present = " OR ".join(f"isnotnull({names[g]})" for g in groups) or "false()"
        return f"if({present}, {' . '.join(pieces)}, null())"

    def match(self, pid: str) -> str | None:
        rx = self.patterns.get(pid)
        return None if rx is None else f"match(_raw, {eval_string(rx)})"

    def expr(self, e: Expr, rule: FieldRule) -> str | None:
        match e:
            case Capture(pattern_id=pid, group=g):
                return self.capture_field(pid, g)
            case Template(pattern_id=pid, parts=parts):
                return self.template(pid, parts)
            case Literal_(value=v):
                return eval_string(v)
            case IfMatch(pattern_id=pid, value=v):
                cond = self.match(pid)
                inner = self.expr(v, rule)
                return None if cond is None or inner is None else f"if({cond}, {inner}, null())"
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
                branches = [
                    f"{key}=={eval_string(k_)}, {eval_string(v)}" for k_, v in table.items()
                ]
                return f"case({', '.join(branches)}, true(), {default or 'null()'})"
            case ParseTime():
                return None  # handled by _timestamp for DeviceTime; unsupported elsewhere
        raise AssertionError(e)  # pragma: no cover


class SplunkBackend:
    name: ClassVar[str] = NAME
    description: ClassVar[str] = "Splunk: props.conf / transforms.conf with CIM field names"
    option_help: ClassVar[Mapping[str, str]] = {
        "sourcetype": "Sourcetype stanza name (default: the artifact id).",
    }

    def supports(self, artifact: Artifact) -> bool:
        return artifact_ready(artifact)

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult:
        spec = artifact.parser
        if spec is None:
            return BackendResult(target=NAME, artifact_id=artifact.id)
        sourcetype = options.get("sourcetype", artifact.id)
        findings: list[Finding] = []
        patterns = PatternTable(spec, "pcre", NAME)
        findings.extend(patterns.findings())
        naming = resolve_names(spec.fields(), "cim", target=NAME)
        findings.extend(naming.findings)
        drops = DropTracker(NAME)
        r = _Renderer(artifact.id, patterns, drops)
        multi = len(spec.match_groups) > 1
        selectors: dict[int, str] = {}
        if multi:
            for group in spec.match_groups:
                conds = [c for pid in group.selector_pattern_ids if (c := r.match(pid))]
                if conds:
                    selectors[group.order] = " OR ".join(conds)
                else:
                    findings.append(
                        Finding(
                            status=Status.UNSUPPORTED,
                            code="MATCHGROUP_SELECTOR_UNTRANSLATABLE",
                            path=group.path,
                            message="None of the patterns selecting this match group can be "
                            "expressed for Splunk, so the group is never applied.",
                            target=NAME,
                            line=group.line,
                        )
                    )

        evals: list[tuple[str, str]] = []
        props_extra: list[tuple[str, str]] = []
        field_names: dict[str, str] = {}
        for canonical in spec.fields():
            target_name = naming.names[canonical]
            rules = [
                (g.order, rule)
                for g in spec.match_groups
                for rule in g.rules
                if rule.field == canonical
            ]
            if canonical == "DeviceTime" or target_name == TIME_FIELD:
                settings = self._timestamp(rules, patterns, findings)
                if settings:
                    props_extra.extend(settings)
                    field_names[canonical] = TIME_FIELD
                continue
            if not multi and isinstance(rules[0][1].expr, Capture):
                expr = rules[0][1].expr
                if r.capture_field(expr.pattern_id, expr.group, out_field=target_name):
                    field_names[canonical] = target_name
                else:
                    rule0 = rules[0][1]
                    drops.field_lost(
                        rule0.path,
                        canonical,
                        line=rule0.line,
                        reason="its pattern cannot be expressed for Splunk.",
                    )
                continue
            rendered = []
            for order, rule in rules:
                text = r.expr(rule.expr, rule)
                if text is not None and (not multi or order in selectors):
                    rendered.append((order, text))
            if not rendered:
                drops.field_lost(rules[0][1].path, canonical, line=rules[0][1].line,
                                 reason="every extraction candidate relies on untranslatable "
                                 "constructs.")  # fmt: skip
                continue
            if multi:
                # Every group's selector must appear, in order: a group that wins but does not
                # set this field must yield null, not fall through to a later group.
                by_order = dict(rendered)
                last = max(by_order)
                branches = [
                    f"{sel}, {by_order.get(order, 'null()')}"
                    for order, sel in selectors.items()
                    if order <= last
                ]
                value = "case(" + ", ".join(branches) + ")"
            else:
                value = rendered[0][1]
            evals.append((target_name, value))
            field_names[canonical] = target_name

        findings.append(
            Finding(
                status=Status.FULL,
                code="SPLUNK_EVENT_BREAKING_ASSUMED",
                path="",
                message="props.conf sets SHOULD_LINEMERGE = false (one event per line, as QRadar "
                "receives one event per syslog message). This is an index-time setting: it only "
                "affects data indexed after deployment on indexers/heavy forwarders.",
                target=NAME,
            )
        )
        findings.append(
            Finding(
                status=Status.FULL,
                code="SPLUNK_KV_MODE_NONE",
                path="",
                message="props.conf sets KV_MODE = none: Splunk's automatic key=value extraction "
                "is disabled for this sourcetype, so only the translated fields appear (with "
                "KV_MODE=auto, e.g. 'user=alice' would populate 'user' even where the LSX does "
                "not extract it).",
                suggestion="Remove it only if you want Splunk's automatic fields in addition.",
                target=NAME,
            )
        )
        if r.transforms:
            findings.append(self._trim_finding())
        findings.append(
            Finding(
                status=Status.FULL,
                code="SPLUNK_APP_SCOPE",
                path="",
                message="If you deploy these files inside a Splunk app, export its knowledge "
                "objects (metadata: export = system); otherwise the search-time extractions only "
                "apply to searches run in that app.",
                target=NAME,
            )
        )
        if any(t.format.startswith("rl_") or " rl_" in t.format for t in r.transforms):
            findings.append(
                Finding(
                    status=Status.FULL,
                    code="SPLUNK_INTERMEDIATE_FIELDS",
                    path="",
                    message="Intermediate fields named rl_* are extracted to implement fallback "
                    "order and mappings; they are visible at search time.",
                    target=NAME,
                )
            )
        findings.extend(drops.findings)
        props = self._props(artifact, sourcetype, props_extra, r.transforms, evals)
        transforms = self._transforms(artifact, r.transforms)
        files = [
            GeneratedFile(path="props.conf", content=props),
            GeneratedFile(path="transforms.conf", content=transforms),
        ]
        return BackendResult(
            target=NAME,
            artifact_id=artifact.id,
            files=files if field_names else [],
            findings=findings,
            field_names=field_names,
            options={"sourcetype": sourcetype},
            settings=self._settings(artifact, props_extra, r.transforms, evals),
        )

    @staticmethod
    def _settings(
        artifact: Artifact,
        index_time: list[tuple[str, str]],
        transforms: list[Transform],
        evals: list[tuple[str, str]],
    ) -> list[DeploymentSetting]:
        report = f"REPORT-rl_{artifact.id}"
        out = [
            DeploymentSetting(
                scope="index-time",
                file="props.conf",
                setting="SHOULD_LINEMERGE",
                note="event breaking: one event per line",
            )
        ]
        out += [
            DeploymentSetting(
                scope="index-time",
                file="props.conf",
                setting=key,
                fields=[TIME_FIELD],
                note="timestamp recognition",
            )
            for key, _ in index_time
        ]
        out.append(
            DeploymentSetting(
                scope="search-time",
                file="props.conf",
                setting="KV_MODE",
                note="automatic key=value extraction disabled",
            )
        )
        out += [
            DeploymentSetting(
                scope="search-time",
                file="props.conf + transforms.conf",
                setting=f"{report} -> [{t.name}]",
                fields=[pair.split("::", 1)[0] for pair in t.format.split()],
            )
            for t in transforms
        ]
        out += [
            DeploymentSetting(
                scope="search-time", file="props.conf", setting=f"EVAL-{name}", fields=[name]
            )
            for name, _ in evals
        ]
        return out

    def _timestamp(
        self,
        rules: list[tuple[int, FieldRule]],
        patterns: PatternTable,
        findings: list[Finding],
    ) -> list[tuple[str, str]]:
        _, rule = rules[0]
        expr = rule.expr
        first = expr.items[0] if isinstance(expr, Coalesce) else expr
        if len(rules) > 1 or first is not expr:
            findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="SPLUNK_SINGLE_TIMESTAMP",
                    path=rule.path,
                    message="Splunk supports one TIME_PREFIX/TIME_FORMAT per sourcetype; only the "
                    "first DeviceTime candidate was translated.",
                    target=NAME,
                    line=rule.line,
                )
            )
        if not isinstance(first, ParseTime) or not isinstance(first.value, Capture):
            findings.append(
                Finding(
                    status=Status.UNSUPPORTED,
                    code="SPLUNK_TIMESTAMP_UNSUPPORTED",
                    path=rule.path,
                    message="The timestamp is not a single capture group, which Splunk "
                    "timestamp settings cannot express.",
                    target=NAME,
                    line=rule.line,
                )
            )
            return []
        fmt = compile_format(first.format)
        findings.extend(date_format_findings(fmt, path=rule.path, target=NAME, line=rule.line))
        if Comp.YEAR2 in fmt.components:
            findings.append(
                two_digit_year_finding(
                    "Splunk's %y (not documented by Splunk; measured on Splunk 10.4.3 with "
                    "strptime(): 50 -> 2050, 68 -> 2068, 69 -> 1969)",
                    "1969-2068 (69-99 -> 19xx, 00-68 -> 20xx)",
                    fixed_2000=False,
                    path=rule.path,
                    target=NAME,
                    line=rule.line,
                )
            )
        if not fmt.usable or fmt.strptime is None:
            return []
        settings: list[tuple[str, str]] = []
        prefix = self._time_prefix(first.value, patterns)
        if prefix is None:
            findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="SPLUNK_TIME_PREFIX_UNDERIVABLE",
                    path=rule.path,
                    message="TIME_PREFIX could not be derived from the pattern (the timestamp "
                    "group is nested, quantified, or the pattern uses top-level alternation); "
                    "Splunk will search for the timestamp from the start of the event.",
                    suggestion="Set TIME_PREFIX by hand.",
                    target=NAME,
                    line=rule.line,
                )
            )
        else:
            settings.append(("TIME_PREFIX", conf_value(prefix)))
        settings.append(("TIME_FORMAT", fmt.strptime))
        findings.append(
            Finding(
                status=Status.PARTIAL,
                code="SPLUNK_TIMESTAMP_FALLBACK",
                path=rule.path,
                message="When TIME_FORMAT does not match an event, Splunk falls back to automatic "
                "timestamp recognition or the previous event's time, where QRadar would leave "
                "DeviceTime unset (observed with Splunk 10.4.3).",
                target=NAME,
                line=rule.line,
            )
        )
        findings.append(
            Finding(
                status=Status.PARTIAL,
                code="SPLUNK_TIME_WINDOW",
                path=rule.path,
                message="Splunk only accepts extracted timestamps up to MAX_DAYS_AGO (default "
                "2000 days) in the past and MAX_DAYS_HENCE (default 2 days) in the future; "
                "others get the timestamp of the last acceptable event. Historical or "
                "future-dated QRadar events may therefore get a different _time.",
                suggestion="Raise MAX_DAYS_AGO (up to 10951) when importing historical data.",
                target=NAME,
                line=rule.line,
            )
        )
        if not fmt.has_year:
            findings.append(
                Finding(
                    status=Status.PARTIAL,
                    code="SPLUNK_YEAR_INFERENCE",
                    path=rule.path,
                    message="The timestamp has no year: Splunk infers it from neighbouring "
                    "events, so an out-of-order event can get the next year and be rejected by "
                    "MAX_DAYS_HENCE (observed with Splunk 10.4.3).",
                    target=NAME,
                    line=rule.line,
                )
            )
        findings.append(
            Finding(
                status=Status.PARTIAL,
                code="SPLUNK_INDEX_TIME_DEPENDENCY",
                path=rule.path,
                message="DeviceTime is translated to _time through index-time settings "
                f"({', '.join(k for k, _ in settings)}). They take effect only on the first full "
                "Splunk instance that parses the data (indexer or heavy forwarder) and only for "
                "events indexed after deployment; already indexed events keep their _time.",
                suggestion="Deploy the index-time section of props.conf to indexers/heavy "
                "forwarders before onboarding the source; re-index historical data if its "
                "_time must change.",
                target=NAME,
                line=rule.line,
            )
        )
        return settings

    @staticmethod
    def _trim_finding() -> Finding:
        """Splunk trims extracted values; whether that differs from QRadar depends on A06."""
        base = (
            "Splunk trims leading and trailing whitespace from values extracted by transforms "
            "(observed with Splunk 10.4.3)."
        )
        dep = AssumptionDependency(
            topic="value-whitespace",
            unconfirmed=Variant(
                status=Status.PARTIAL,
                message=f"{base} This only matters if QRadar preserves such whitespace, which "
                "Rosettalog assumes but has not confirmed.",
            ),
            confirmed=Variant(
                status=Status.PARTIAL,
                message=f"{base} QRadar preserves it, so values with surrounding whitespace "
                "differ.",
            ),
            refuted=Variant(
                status=Status.FULL,
                message=f"{base} QRadar trims too, so the values agree.",
            ),
        )
        return Finding(
            status=dep.unconfirmed.status,
            code="SPLUNK_VALUE_TRIMMED",
            path="",
            message=dep.unconfirmed.message,
            target=NAME,
            depends_on=dep,
        )

    @staticmethod
    def _time_prefix(capture: Capture, patterns: PatternTable) -> str | None:
        pattern = patterns.spec.patterns[capture.pattern_id]
        if patterns.get(capture.pattern_id) is None or capture.group == 0:
            return None if capture.group else "^"
        try:
            tokens = tokenize(pattern.source)
        except RegexSyntaxError:
            return None
        depth = 0
        for tok in tokens:
            if tok.kind is Kind.GROUP_OPEN:
                depth += 1
            elif tok.kind is Kind.GROUP_CLOSE:
                depth -= 1
            elif tok.kind is Kind.ALT and depth == 0:
                return None  # top-level alternation: the prefix is not a single sequence
        seen = 0
        for idx, tok in enumerate(tokens):
            if tok.kind is Kind.GROUP_OPEN and tok.group in (GroupKind.CAPTURE, GroupKind.NAMED):
                seen += 1
                if seen == capture.group:
                    opened = sum(
                        1 if t.kind is Kind.GROUP_OPEN else -1
                        for t in tokens[:idx]
                        if t.kind in (Kind.GROUP_OPEN, Kind.GROUP_CLOSE)
                    )
                    if opened != 0:
                        return None
                    prefix = translate_tokens(tokens[:idx], "pcre").pattern
                    if prefix is None:
                        return None
                    flags = "(?i)" if pattern.case_insensitive else ""
                    return flags + prefix if prefix else "^"
        return None

    @staticmethod
    def _header(artifact: Artifact) -> list[str]:
        return [
            f"# Generated by rosettalog from {PurePath(artifact.provenance.file).name}",
            "# Review the migration report before deploying. Do not edit by hand; regenerate.",
        ]

    def _props(
        self,
        artifact: Artifact,
        sourcetype: str,
        extra: list[tuple[str, str]],
        transforms: list[Transform],
        evals: list[tuple[str, str]],
    ) -> str:
        lines = [
            *self._header(artifact),
            "",
            f"[{sourcetype}]",
            "# ---- Index-time settings -------------------------------------------------------",
            "# Deploy to indexers / heavy forwarders (the first full instance parsing the data).",
            "# They affect ONLY events indexed after deployment; indexed data is not changed.",
            "SHOULD_LINEMERGE = false",
        ]
        lines += [f"{k} = {v}" for k, v in extra]
        lines += [
            "# ---- Search-time extractions ---------------------------------------------------",
            "# Deploy to search heads. They apply at search time to all events of this",
            "# sourcetype, including data indexed before deployment.",
            "# KV_MODE = none: Splunk's automatic key=value extraction would add fields QRadar",
            "# never extracted (e.g. user=... -> user), masking the translated extractions.",
            "KV_MODE = none",
        ]
        if transforms:
            lines.append(f"REPORT-rl_{artifact.id} = " + ", ".join(t.name for t in transforms))
        lines += [f"EVAL-{name} = {value}" for name, value in evals]
        return "\n".join(lines) + "\n"

    def _transforms(self, artifact: Artifact, transforms: list[Transform]) -> str:
        lines = [
            *self._header(artifact),
            "# Search-time field extractions referenced by REPORT- in props.conf (search heads).",
        ]
        for t in transforms:
            lines += ["", f"[{t.name}]", f"REGEX = {t.regex}", f"FORMAT = {t.format}"]
        return "\n".join(lines) + "\n"
