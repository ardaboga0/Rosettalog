"""Elastic backend: IR parser -> Elasticsearch ingest pipeline (JSON) with ECS field names.

Only declarative processors are used, with semantics taken from Elastic's documentation:

* ``grok`` extracts; patterns are Oniguruma (Joni, Ruby syntax) and only named captures become
  fields, so every pattern comes from :func:`rosettalog.regex.grok.to_grok`. Grok fails when
  nothing matches, hence ``ignore_failure``
  (https://www.elastic.co/docs/reference/enrich-processor/grok-processor).
* ``set`` combines values: ``{{{field}}}`` templates, ``override: false`` for first-wins fallback
  and ``ignore_empty_value`` so that an empty capture counts as "no value" (assumption A07)
  (https://www.elastic.co/docs/reference/enrich-processor/set-processor).
* ``date`` parses timestamps with java.time patterns
  (https://www.elastic.co/docs/reference/enrich-processor/date-processor).
* ``remove`` deletes the temporary ``rl_*`` fields.

Conditions (``if``) are Painless expressions without regular expressions.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any, ClassVar

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
from rosettalog.plugins import BackendResult, DeploymentSetting, GeneratedFile
from rosettalog.regex.grok import GrokPattern, to_grok
from rosettalog.timefmt.javatime import to_java_pattern
from rosettalog.timefmt.joda import Comp, compile_format

NAME = "elastic"
MG = "rl_mg"


def painless_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _and(*conds: str | None) -> str | None:
    parts = [c for c in conds if c]
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else " && ".join(f"({c})" for c in parts)


def _mustache_safe(text: str) -> bool:
    return "{{" not in text and "}}" not in text


@dataclass
class _Compiler:
    artifact: Artifact
    patterns: PatternTable
    source_field: str
    drops: DropTracker
    findings: list[Finding]
    groks: dict[str, GrokPattern | None] = field(default_factory=dict)
    grok_procs: list[dict[str, Any]] = field(default_factory=list)
    procs: list[dict[str, Any]] = field(default_factory=list)
    temps: list[str] = field(default_factory=list)

    def temp(self, kind: str) -> str:
        name = f"rl_{kind}{len(self.temps) + 1}"
        self.temps.append(name)
        return name

    def grok(self, pid: str) -> GrokPattern | None:
        if pid in self.groks:
            return self.groks[pid]
        pattern = self.patterns.spec.patterns[pid]
        g: GrokPattern | None = None
        if self.patterns.get(pid) is not None:
            g = to_grok(pattern.source, f"rl_p{len(self.groks) + 1}",
                        case_insensitive=pattern.case_insensitive)  # fmt: skip
            if g.pattern is None:
                self.findings.extend(
                    Finding(
                        status=i.status,
                        code=i.code,
                        path=f"pattern[id={pid}]",
                        message=i.message,
                        target=NAME,
                    )
                    for i in g.issues
                    if i.code == "REGEX_COMPILE_ERROR"
                )
                g = None
        self.groks[pid] = g
        if g is not None:
            assert g.pattern is not None
            self.temps.extend([g.match_field, *(g.group_field(n) for n in range(1, g.groups + 1))])
            self.grok_procs.append(
                {
                    "grok": {
                        "tag": f"rl-pattern-{slugify(pid)}",
                        "field": self.source_field,
                        "patterns": [g.pattern],
                        "ignore_failure": True,
                    }
                }
            )
        return g

    def matched(self, pid: str) -> str | None:
        g = self.grok(pid)
        return None if g is None else f"ctx.{g.match_field} != null"

    def _set(self, dest: str, value: Any, guard: str | None) -> None:
        body: dict[str, Any] = {
            "field": dest,
            "value": value,
            "override": False,
            "ignore_empty_value": True,
        }
        if guard:
            body["if"] = guard
        self.procs.append({"set": body})

    def _literal_ok(self, text: str, rule: FieldRule) -> bool:
        if _mustache_safe(text):
            return True
        self.findings.append(
            Finding(
                status=Status.UNSUPPORTED,
                code="ELASTIC_TEMPLATE_LITERAL",
                path=rule.path,
                message=f"Literal text {text!r} contains '{{{{' or '}}}}', which the set "
                "processor would interpret as a mustache template.",
                target=NAME,
                line=rule.line,
            )
        )
        return False

    def compile(self, e: Expr, dest: str, guard: str | None, rule: FieldRule) -> bool:
        """Emit processors that give ``dest`` the value of ``e`` unless it already has one."""
        match e:
            case Capture(pattern_id=pid, group=group):
                g = self.grok(pid)
                if g is None:
                    return False
                self._set(dest, "{{{" + g.group_field(group) + "}}}", guard)
                return True
            case Template(pattern_id=pid, parts=parts):
                g = self.grok(pid)
                if g is None or not all(
                    self._literal_ok(p, rule) for p in parts if isinstance(p, str)
                ):
                    return False
                value = "".join(
                    p if isinstance(p, str) else "{{{" + g.group_field(p) + "}}}" for p in parts
                )
                self._set(dest, value, _and(guard, f"ctx.{g.match_field} != null"))
                return True
            case Literal_(value=v):
                if not self._literal_ok(v, rule):
                    return False
                self._set(dest, v, guard)
                return True
            case IfMatch(pattern_id=pid, value=v):
                cond = self.matched(pid)
                return cond is not None and self.compile(v, dest, _and(guard, cond), rule)
            case Coalesce(items=items):
                produced = False
                for item in items:
                    if self.compile(item, dest, guard, rule):
                        produced = True
                    else:
                        self.drops.dropped(rule.path, describe(item), field_name=rule.field,
                                           line=rule.line)  # fmt: skip
                return produced
            case Lookup(key=k, table=table, default=d):
                key = self.temp("k")
                key_ok = self.compile(k, key, guard, rule)
                if key_ok:
                    for name, value in table.items():
                        if self._literal_ok(value, rule):
                            self._set(
                                dest, value, _and(guard, f"ctx.{key} == {painless_string(name)}")
                            )
                else:
                    self.drops.dropped(rule.path, "Event mapping table (its key)",
                                       field_name=rule.field, line=rule.line)  # fmt: skip
                default_ok = False
                if d is not None:
                    default_ok = self.compile(d, dest, guard, rule)
                    if not default_ok:
                        self.drops.dropped(rule.path, "Fallback value (" + describe(d) + ")",
                                           field_name=rule.field, line=rule.line)  # fmt: skip
                return key_ok or default_ok
            case ParseTime(value=v, format=fmt_text):
                return self._parse_time(v, fmt_text, dest, guard, rule)
        raise AssertionError(e)  # pragma: no cover

    def _parse_time(
        self, value: Expr, fmt_text: str, dest: str, guard: str | None, rule: FieldRule
    ) -> bool:
        fmt = compile_format(fmt_text)
        self.findings.extend(date_format_findings(fmt, path=rule.path, target=NAME, line=rule.line))
        if Comp.YEAR2 in fmt.components:
            self.findings.append(
                two_digit_year_finding(
                    "the Elasticsearch date processor (java.time 'uu', base 2000)",
                    "2000-2099",
                    fixed_2000=True,
                    path=rule.path,
                    target=NAME,
                    line=rule.line,
                )
            )
        if not fmt.usable:
            return False
        java = to_java_pattern(fmt)
        self.findings.extend(
            Finding(
                status=i.status,
                code=i.code,
                path=rule.path,
                message=i.message,
                target=NAME,
                line=rule.line,
            )
            for i in java.issues
        )
        text = self.temp("ts")
        if not self.compile(value, text, guard, rule):
            return False
        parsed = self.temp("d")
        body: dict[str, Any] = {
            "field": text,
            "target_field": parsed,
            "formats": [java.pattern],
            "timezone": "UTC",
            # No explicit "locale": the documented default is ENGLISH, but Elasticsearch 9.5.4
            # rejects the literal value "ENGLISH" ("Unknown language") - found by the real-engine
            # differential test. Leaving it out keeps the (working) default.
            "ignore_failure": True,
            "if": _and(guard, f"ctx.{text} != null"),
        }
        self.procs.append({"date": body})
        self._set(dest, "{{{" + parsed + "}}}", guard)
        return True


class ElasticBackend:
    name: ClassVar[str] = NAME
    description: ClassVar[str] = (
        "Elastic: Elasticsearch ingest pipeline (JSON) with ECS field names"
    )
    option_help: ClassVar[Mapping[str, str]] = {
        "source_field": "Document field holding the raw event text (default: message).",
        "pipeline_name": "Pipeline id / file name (default: rosettalog-<artifact>).",
    }

    def supports(self, artifact: Artifact) -> bool:
        return artifact_ready(artifact)

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult:
        spec = artifact.parser
        if spec is None:
            return BackendResult(target=NAME, artifact_id=artifact.id)
        source_field = options.get("source_field", "message")
        pipeline = options.get("pipeline_name", f"rosettalog-{artifact.id.replace('_', '-')}")
        findings: list[Finding] = []
        patterns = PatternTable(spec, "onig", NAME)
        findings.extend(patterns.findings())
        naming = resolve_names(spec.fields(), "ecs", target=NAME)
        findings.extend(naming.findings)
        drops = DropTracker(NAME)
        c = _Compiler(artifact, patterns, source_field, drops, findings)

        multi = len(spec.match_groups) > 1
        selector_procs: list[dict[str, Any]] = []
        if multi:
            c.temps.append(MG)
            for idx, group in enumerate(spec.match_groups, start=1):
                conds = [m for pid in group.selector_pattern_ids if (m := c.matched(pid))]
                if not conds:
                    findings.append(
                        Finding(
                            status=Status.UNSUPPORTED,
                            code="MATCHGROUP_SELECTOR_UNTRANSLATABLE",
                            path=group.path,
                            message="None of the patterns selecting this match group can be "
                            "expressed as grok patterns, so the group is never applied.",
                            target=NAME,
                            line=group.line,
                        )
                    )
                    continue
                either = " || ".join(conds)
                selector_procs.append(
                    {"set": {"field": MG, "value": idx, "if": f"ctx.{MG} == null && ({either})"}}
                )

        finals: list[dict[str, Any]] = []
        field_names: dict[str, str] = {}
        for canonical in spec.fields():
            dest = c.temp("v")
            produced = False
            last: FieldRule | None = None
            for idx, group in enumerate(spec.match_groups, start=1):
                for rule in group.rules:
                    if rule.field == canonical:
                        last = rule
                        guard = f"ctx.{MG} == {idx}" if multi else None
                        produced = c.compile(rule.expr, dest, guard, rule) or produced
            assert last is not None
            if not produced:
                drops.field_lost(last.path, canonical, line=last.line,
                                 reason="every extraction candidate relies on constructs grok "
                                 "cannot express.")  # fmt: skip
                continue
            target = naming.names[canonical]
            finals.append(
                {
                    "set": {
                        "field": target,
                        "value": "{{{" + dest + "}}}",
                        "ignore_empty_value": True,
                    }
                }
            )
            field_names[canonical] = target

        findings.extend(self._notes(field_names))
        findings.extend(drops.findings)
        processors = [
            *c.grok_procs,
            *selector_procs,
            *c.procs,
            *finals,
            {"remove": {"field": sorted(set(c.temps)), "ignore_missing": True}},
        ]
        source_name = PurePath(artifact.provenance.file).name
        document = {
            "description": f"Generated by rosettalog from {source_name}. Review the migration "
            "report before deploying. Do not edit by hand; regenerate.",
            "processors": processors,
        }
        file_name = f"{pipeline}.json"
        content = json.dumps(document, indent=2) + "\n"
        settings = [
            DeploymentSetting(
                scope="index-time",
                file=file_name,
                setting=f"ingest pipeline {pipeline}",
                fields=list(field_names.values()),
                note="applies to documents ingested through the pipeline after deployment; "
                "already indexed documents are unchanged",
            )
        ]
        return BackendResult(
            target=NAME,
            artifact_id=artifact.id,
            files=[GeneratedFile(path=file_name, content=content)] if field_names else [],
            findings=findings,
            field_names=field_names,
            options={"source_field": source_field, "pipeline_name": pipeline},
            settings=settings if field_names else [],
        )

    @staticmethod
    def _notes(field_names: dict[str, str]) -> list[Finding]:
        if not field_names:
            return []
        notes = [
            Finding(
                status=Status.PARTIAL,
                code="ELASTIC_INGEST_TIME_DEPENDENCY",
                path="",
                message="All fields are extracted by an ingest pipeline. It only processes "
                "documents ingested through it after deployment; documents already indexed keep "
                "their fields.",
                suggestion="Attach the pipeline (e.g. index.default_pipeline) before onboarding "
                "the source; reindex historical data through it if needed.",
                target=NAME,
            ),
            Finding(
                status=Status.FULL,
                code="ELASTIC_STRING_TYPES",
                path="",
                message="Extracted values are strings; the index mapping decides their final "
                "type (e.g. source.port as long, source.ip as ip).",
                target=NAME,
            ),
        ]
        if field_names.get("DeviceTime") == "@timestamp":
            notes.append(
                Finding(
                    status=Status.FULL,
                    code="ELASTIC_TIMESTAMP_OVERWRITE",
                    path="field[DeviceTime]",
                    message="When DeviceTime parses, it replaces any existing @timestamp (e.g. "
                    "the shipper's read time).",
                    target=NAME,
                )
            )
        return notes
