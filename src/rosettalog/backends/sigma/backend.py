"""Sigma backend: detection artifacts -> Sigma rules (YAML).

Target-specific queries are *not* produced here: that is pySigma's job (see
:mod:`rosettalog.backends.sigma.pysigma`). This module only writes Sigma that means what the
source rule means, and reports every element that Sigma cannot express.

Specification: Sigma rules v2.1.0
(https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).

* Plain values are case-insensitive and ``*``/``?`` are wildcards; a literal ``*``/``?``/``\\`` is
  escaped with a backslash. Case-sensitive tests use the ``cased`` modifier.
* ``re`` values use the Sigma regex subset (:mod:`rosettalog.regex.translate`, dialect ``sigma``).
* Each leaf test becomes one search identifier (``sel_N``); the condition reproduces the source's
  boolean structure exactly.
* A leaf that cannot be expressed is removed **only** where that makes the rule broader (it is
  replaced by *true* where it counts positively, by *false* under a negation), so that the rule
  never misses events the source would catch. The rule is then PARTIAL
  (``SIGMA_TEST_DROPPED``). If nothing is left, no rule is written.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import yaml

from rosettalog.backends.sigma import pysigma
from rosettalog.errors import InputError
from rosettalog.ir import (
    And,
    Artifact,
    AssumptionDependency,
    Cond,
    Counter,
    DetectionSpec,
    FieldTest,
    Finding,
    LogSourceTest,
    Not,
    Opaque,
    Or,
    QidTest,
    ReferenceTest,
    ResolvedRef,
    RuleRef,
    Sequence,
    Status,
    Variant,
    leaves,
)
from rosettalog.ir.fields import resolve_names
from rosettalog.plugins import BackendResult, GeneratedFile
from rosettalog.regex.translate import translate

NAME = "sigma"
#: Namespace for the deterministic Sigma rule ids (UUIDv5 of the source rule's identity).
ID_NAMESPACE = uuid.UUID("6f1d8a52-3c1b-4f4e-9a55-2f0f4c8f7e21")
TITLE_MAX = 256
#: Pseudo-fields used when a QRadar-specific condition is kept in the detection.
LOG_SOURCE_FIELD = {"log_source": "LogSource", "log_source_type": "LogSourceType"}
QID_FIELD = "QID"
#: Assumption topic: are QRadar equals/contains tests case-sensitive? (rule registry, R01)
CASE_TOPIC = "rule-value-case"

#: QRadar severity (0-10) -> Sigma level. A Rosettalog convention, not an IBM mapping; see
#: docs/rules-support-matrix.md.
LEVELS = [
    (1, "informational"),
    (3, "low"),
    (6, "medium"),
    (8, "high"),
    (10, "critical"),
]


def sigma_level(severity: int) -> str:
    for upper, level in LEVELS:
        if severity <= upper:
            return level
    return "critical"


def escape_value(value: str) -> str:
    """Escape Sigma wildcards and the escape character itself, so ``value`` is matched literally."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


@dataclass(frozen=True)
class LogSourceMap:
    """User-supplied mapping of QRadar log sources / log source types to Sigma log sources."""

    log_source_types: dict[str, dict[str, str]] = field(default_factory=dict)
    log_sources: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | None) -> LogSourceMap:
        if not path:
            return cls()
        try:
            data = yaml.safe_load(Path(path).read_text("utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise InputError(f"Invalid sigma.logsource_map {path}: {exc}") from exc
        out: dict[str, dict[str, dict[str, str]]] = {}
        for key in ("log_source_types", "log_sources"):
            section = data.get(key) or {}
            if not isinstance(section, dict):
                raise InputError(f"sigma.logsource_map {path}: '{key}' must be a mapping")
            for name, logsource in section.items():
                if (
                    not isinstance(logsource, dict)
                    or not logsource
                    or not set(logsource)
                    <= {
                        "category",
                        "product",
                        "service",
                    }
                ):
                    raise InputError(
                        f"sigma.logsource_map {path}: '{name}' needs a mapping with category, "
                        "product and/or service"
                    )
            out[key] = {str(k): {str(a): str(b) for a, b in v.items()} for k, v in section.items()}
        return cls(out.get("log_source_types", {}), out.get("log_sources", {}))

    def lookup(self, test: LogSourceTest) -> dict[str, str] | None:
        table = self.log_source_types if test.by == "log_source_type" else self.log_sources
        return table.get(test.values[0]) if len(test.values) == 1 else None


class _True:
    """Marker: the sub-condition was dropped and counts as always true."""


class _False:
    """Marker: the sub-condition was dropped and counts as always false."""


TRUE = _True()
FALSE = _False()
Approx = Cond | _True | _False


@dataclass
class _Builder:
    spec: DetectionSpec
    lsmap: LogSourceMap
    findings: list[Finding] = field(default_factory=list)
    selections: list[tuple[str | None, str, list[str]]] = field(default_factory=list)
    """(canonical field or None for pseudo-fields, field name + modifiers, values)."""
    logsource: dict[str, str] | None = None
    broadened: list[dict[str, object]] = field(default_factory=list)
    """Every place where the Sigma rule matches more than the source rule (also written into
    the rule itself, for users who never read the report)."""
    case_entries: dict[int, dict[str, object]] = field(default_factory=dict)
    case_findings: dict[int, int] = field(default_factory=dict)
    """Case-broadened selections (index -> entry / finding position); kept only if used."""

    def finish_case(self, used: list[int]) -> None:
        """Keep case-broadening records only for selections the final rule still contains."""
        drop = {pos for sel, pos in self.case_findings.items() if sel not in used}
        self.findings = [f for i, f in enumerate(self.findings) if i not in drop]
        self.broadened += [e for sel, e in sorted(self.case_entries.items()) if sel in used]

    def finding(self, status: Status, code: str, path: str, message: str, **kw: str) -> None:
        self.findings.append(
            Finding(status=status, code=code, path=path, message=message, target=NAME, **kw)
        )

    # --- log source -----------------------------------------------------------------------

    def pick_logsource(self, cond: Cond | None) -> Cond | _True:
        """Move one top-level, single-valued, mapped log source test into ``logsource``."""
        if cond is None:
            return TRUE
        conjuncts = cond.items if isinstance(cond, And) else [cond]
        for i, item in enumerate(conjuncts):
            if not isinstance(item, LogSourceTest):
                continue
            mapped = self.lsmap.lookup(item)
            if mapped is None:
                continue
            self.logsource = mapped
            self.finding(
                Status.FULL,
                "SIGMA_LOGSOURCE_MAPPED",
                item.path,
                f"Log source condition '{item.values[0]}' became the Sigma logsource "
                f"{mapped} (from sigma.logsource_map).",
            )
            rest = [c for j, c in enumerate(conjuncts) if j != i]
            if not rest:
                return TRUE
            return rest[0] if len(rest) == 1 else And(items=rest)
        return cond

    # --- condition ------------------------------------------------------------------------

    def approx(self, cond: Cond, positive: bool) -> Approx:
        match cond:
            case And(items=items) | Or(items=items):
                parts = [self.approx(i, positive) for i in items]
                is_and = isinstance(cond, And)
                absorbing, neutral = (FALSE, TRUE) if is_and else (TRUE, FALSE)
                if any(p is absorbing for p in parts):
                    return absorbing
                kept = [p for p in parts if not isinstance(p, _True | _False)]
                if not kept:
                    return neutral
                if len(kept) == 1:
                    return kept[0]
                return And(items=kept) if is_and else Or(items=kept)
            case Not(item=item):
                inner = self.approx(item, not positive)
                if isinstance(inner, _True):
                    return FALSE
                if isinstance(inner, _False):
                    return TRUE
                return Not(item=inner)
        return self.leaf(cond, positive)

    def drop(self, path: str, what: str, positive: bool, *, suggestion: str) -> _True | _False:
        where = f"Test {path}" if path else "A test"
        self.finding(
            Status.PARTIAL,
            "SIGMA_TEST_DROPPED",
            path,
            f"{where} was left out: {what} Sigma cannot express it, so the Sigma rule matches "
            "more events than the source rule (it never misses one).",
            suggestion=suggestion,
        )
        self.broadened.append({"test": path or "?", "dropped": what, "exclusion": not positive})
        if not positive:
            self.finding(
                Status.PARTIAL,
                "SIGMA_EXCLUSION_DROPPED",
                path,
                f"{where} was an exclusion (it sits under NOT): without it, every event it "
                "excluded now matches, so the rule may alert far more often than the original.",
                suggestion="Re-add the exclusion on the target by hand before enabling the rule.",
            )
        return TRUE if positive else FALSE

    def leaf(self, cond: Cond, positive: bool) -> Approx:
        match cond:
            case FieldTest():
                return self.field_test(cond, positive)
            case LogSourceTest():
                name = LOG_SOURCE_FIELD[cond.by]
                self.finding(
                    Status.PARTIAL,
                    "SIGMA_LOGSOURCE_CONDITION_KEPT",
                    cond.path,
                    f"The {cond.by.replace('_', ' ')} condition ({', '.join(cond.values)}) has no "
                    f"Sigma logsource mapping; it is kept as a test on the field '{name}', "
                    "which target events do not have unless you add it.",
                    suggestion="Add the log source (type) to sigma.logsource_map, or map "
                    f"'{name}' to a target field in your pySigma pipeline.",
                )
                return self.add_selection(None, name, [escape_value(v) for v in cond.values])
            case QidTest():
                self.finding(
                    Status.PARTIAL,
                    "SIGMA_QID_CONDITION",
                    cond.path,
                    f"QID condition ({', '.join(cond.values)}) is kept as a test on the field "
                    f"'{QID_FIELD}'. QIDs are QRadar event identifiers that target events do not "
                    "carry.",
                    suggestion="Replace the QIDs with the target's event identifiers "
                    "(e.g. vendor event IDs) or map the field in your pySigma pipeline.",
                )
                return self.add_selection(None, QID_FIELD, list(cond.values))
            case RuleRef():
                return self.rule_ref(cond, positive)
            case ReferenceTest():
                self.reference_data(cond)
                return self.drop(
                    cond.path,
                    f"Reference data test on '{cond.collection}'.",
                    positive,
                    suggestion="See SIGMA_REFERENCE_DATA for the target mechanism.",
                )
            case Opaque():
                return self.drop(
                    cond.path,
                    f"Source test '{cond.test}' was not understood.",
                    positive,
                    suggestion="Translate this test by hand.",
                )
        raise AssertionError(cond)  # pragma: no cover

    def rule_ref(self, ref: RuleRef, positive: bool) -> Approx:
        """Inline referenced rules/building blocks: Sigma detections cannot reference rules."""
        names = ", ".join(ref.rules)
        if ref.resolved is None:
            return self.drop(
                ref.path,
                f"Reference to rule(s)/building block(s) {names}, which could not be resolved "
                "(see the RULE_REF_* finding).",
                positive,
                suggestion="Load the referenced rules too, or inline their tests by hand.",
            )
        parts: list[Cond] = []
        for target in ref.resolved:
            spec = target.spec
            if spec.stateful is not None or spec.condition is None:
                return self.drop(
                    ref.path,
                    f"Reference to '{target.name}', a counter/sequence rule; a Sigma detection "
                    "cannot contain a correlation.",
                    positive,
                    suggestion="Rebuild the combined logic as a correlation on the target.",
                )
            parts.append(spec.condition)
        listed = ", ".join(f"'{t.name}' ({t.artifact_id}.yml)" for t in ref.resolved)
        self.finding(
            Status.FULL,
            "SIGMA_BB_INLINED",
            ref.path,
            f"The tests of {listed} were inlined ({ref.mode} of them), because a Sigma detection "
            "cannot reference another rule. Changes to the building block must be repeated here.",
        )
        inlined: Cond = (
            parts[0]
            if len(parts) == 1
            else (Or(items=parts) if ref.mode == "any" else And(items=parts))
        )
        return self.approx(inlined, positive)

    def reference_data(self, test: ReferenceTest) -> None:
        fields = ", ".join(test.fields) or "(unknown fields)"
        self.finding(
            Status.PARTIAL,
            "SIGMA_REFERENCE_DATA",
            test.path,
            f"The test checks {fields} against the reference {test.collection_type} "
            f"'{test.collection}'. Sigma has no reference data, so it was left out, and nothing "
            "was generated for it.",
            suggestion=f"Recreate '{test.collection}' on the target and add the lookup to the "
            "converted query: a Microsoft Sentinel watchlist (_GetWatchlist('<alias>')), a "
            "Splunk lookup (| lookup / inputlookup), or an Elasticsearch enrich policy or terms "
            "lookup.",
        )

    def field_test(self, test: FieldTest, positive: bool) -> Approx:
        if test.op in ("equals", "contains"):
            # Case only matters for values with cased characters (not for "22").
            has_case = any(v.lower() != v.upper() for v in test.values)
            # Most pinned pySigma backends refuse Sigma's "cased" (G0), so a case-sensitive
            # test is written case-insensitively. That broadens it where it counts positively;
            # under NOT it would narrow the rule, so the test is dropped there.
            if test.case_sensitive and has_case and not positive:
                return self.drop(
                    test.path,
                    f"case-sensitive {test.op} test on '{test.field}' "
                    f"({', '.join(test.values)}) inside an exclusion; a case-insensitive "
                    "exclusion would also exclude other letter cases.",
                    positive,
                    suggestion="Add the case-sensitive exclusion on the target by hand.",
                )
            mods = "|contains" if test.op == "contains" else ""
            ref = self.add_selection(test.field, mods, [escape_value(v) for v in test.values])
            if test.case_sensitive and has_case:
                self.case_broadened(test, len(self.selections) - 1)
            return ref
        # regex: every value translated separately; values with the same flags share a selection
        by_flags: dict[str, list[str]] = {}
        for value in test.values:
            tr = translate(value, "sigma", case_insensitive=not test.case_sensitive)
            for issue in tr.issues:
                message = f"Regex '{value}': {issue.message}"
                self.finding(issue.status, issue.code, test.path, message)
            if tr.pattern is None:
                return self.drop(
                    test.path,
                    f"Regex test on '{test.field}' ('{value}') cannot be translated.",
                    positive,
                    suggestion="Rewrite the regex using only the Sigma regex subset.",
                )
            by_flags.setdefault(tr.flags, []).append(tr.pattern)
        parts: list[Cond] = []
        for flags, patterns in by_flags.items():
            mods = "|re" + "".join(f"|{f}" for f in flags)
            parts.append(self.add_selection(test.field, mods, patterns))
        return parts[0] if len(parts) == 1 else Or(items=parts)

    def case_broadened(self, test: FieldTest, selection: int) -> None:
        values = ", ".join(test.values)
        what = f"{test.op} test on '{test.field}' ({values})"
        written = (
            "is written without Sigma's 'cased' modifier (the pinned Splunk, Kusto, Lucene and "
            "ES|QL pySigma backends refuse it), so it also matches other letter cases: the rule "
            "is broader."
        )
        self.case_findings[selection] = len(self.findings)
        self.findings.append(
            Finding(
                status=Status.PARTIAL,
                code="SIGMA_CASE_BROADENED",
                path=test.path,
                message=f"The {what} {written}",
                suggestion="Add a case-sensitive check on the target if the letter case matters.",
                target=NAME,
                depends_on=AssumptionDependency(
                    topic=CASE_TOPIC,
                    unconfirmed=Variant(
                        status=Status.PARTIAL,
                        message=f"The {what} is assumed to be case-sensitive in QRadar; it "
                        f"{written}",
                    ),
                    confirmed=Variant(
                        status=Status.PARTIAL,
                        message=f"The {what} is case-sensitive in QRadar; it {written}",
                    ),
                    refuted=Variant(
                        status=Status.FULL,
                        message=f"The {what} is case-insensitive in QRadar, so writing it "
                        "without 'cased' is exact.",
                    ),
                ),
            )
        )
        self.case_entries[selection] = {"test": test.path or "?", "case_insensitive": what}

    def add_selection(self, fieldname: str | None, key: str, values: list[str]) -> Cond:
        """Register a selection; returns a placeholder leaf that refers to it by index.

        ``fieldname`` is the canonical field (renamed later), or ``None`` when ``key`` already is
        the final field name plus modifiers.
        """
        if fieldname is not None:
            self.selections.append((fieldname, key, values))
        else:
            self.selections.append((None, key, values))
        return Opaque(test=f"#{len(self.selections) - 1}")

    def used(self, cond: Cond) -> list[int]:
        """Indices of the selections the final condition refers to, in order of appearance."""
        return [int(leaf.test[1:]) for leaf in leaves(cond) if isinstance(leaf, Opaque)]


def render_condition(cond: Cond, keys: Mapping[int, str], *, top: bool = True) -> str:
    match cond:
        case And(items=items) | Or(items=items):
            op = " and " if isinstance(cond, And) else " or "
            text = op.join(render_condition(i, keys, top=False) for i in items)
            return text if top else f"({text})"
        case Not(item=item):
            return f"not {render_condition(item, keys, top=False)}"
        case Opaque(test=ref):
            return keys[int(ref[1:])]
    raise AssertionError(cond)  # pragma: no cover


class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_Dumper.add_representer(str, _str)


def dump_yaml(data: object) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100)


def _values(key: str, values: list[str]) -> object:
    """Plain values that are canonical integers are written as YAML numbers (pySigma's
    NumberAsStringIssue); "007" stays a string. Regex and modified values stay strings."""
    plain = "|" not in key or key.endswith("|cased")
    out: list[object] = [
        int(v) if plain and v.isascii() and v.isdigit() and str(int(v)) == v else v for v in values
    ]
    return out[0] if len(out) == 1 else out


def rule_uuid(spec: DetectionSpec, suffix: str = "") -> str:
    return str(uuid.uuid5(ID_NAMESPACE, f"qradar-rule:{spec.uuid or spec.rule_id}{suffix}"))


def _single_ref(cond: Cond | _True) -> ResolvedRef | None:
    """The one plain (non-stateful) rule a condition consists of, if it is just a reference."""
    if not isinstance(cond, RuleRef) or cond.resolved is None or len(cond.resolved) != 1:
        return None
    target = cond.resolved[0]
    if target.spec.stateful is not None or target.spec.condition is None:
        return None
    return target


def timespan(seconds: int) -> str:
    """A Sigma timespan (number + s/m/h/d), in the largest unit that is exact."""
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


class SigmaBackend:
    name: ClassVar[str] = NAME
    description: ClassVar[str] = (
        "Sigma rules (YAML) from QRadar rules; pySigma validates them and converts them to "
        "target queries."
    )
    option_help: ClassVar[Mapping[str, str]] = {
        "logsource_map": "YAML file mapping QRadar log source types (log_source_types:) and log "
        "sources (log_sources:) to Sigma logsources ({category, product, service}).",
        "pysigma_targets": "Comma-separated pySigma backends to convert the rules with: "
        + ", ".join(pysigma.TARGETS)
        + " (needs the 'sigma-backends' extra).",
    }

    def supports(self, artifact: Artifact) -> bool:
        return artifact.kind == "detection" and artifact.detection is not None

    def verification_targets(self, options: Mapping[str, str]) -> list[str]:
        """Real-engine runners that can run the pySigma queries requested in ``options``."""
        names = pysigma.parse_targets(options.get("pysigma_targets", ""))
        return list(dict.fromkeys(pysigma.TARGETS[n].runner_target for n in names))

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult:
        spec = artifact.detection
        if spec is None:
            return BackendResult(target=NAME, artifact_id=artifact.id, output_kind="detection")
        b = _Builder(spec, LogSourceMap.load(options.get("logsource_map")))
        self._metadata_findings(spec, b)

        def empty() -> BackendResult:
            return BackendResult(
                target=NAME, artifact_id=artifact.id, findings=b.findings, output_kind="detection"
            )

        base = b.pick_logsource(spec.condition)
        # (name suffix, title suffix, condition) of every single-event rule to write
        # Rules a correlation can reference by name instead of copying them (building blocks).
        context: dict[str, str] = {}
        context_names: dict[str, str] = {}
        """Field names used by the referenced rules (they are part of what the output tests)."""

        def reference(cond: Cond | _True) -> ResolvedRef | None:
            target = _single_ref(cond)
            if target is None or spec.stateful is None:
                return None
            if target.artifact_id not in context:
                bb = Artifact(
                    id=target.artifact_id,
                    name=target.name,
                    kind="detection",
                    source_format=artifact.source_format,
                    provenance=artifact.provenance,
                    detection=target.spec,
                )
                bb_options = {k: v for k, v in options.items() if k != "pysigma_targets"}
                bb_result = self.generate(bb, bb_options)
                rule = next((f for f in bb_result.files), None)
                if rule is None:
                    return None
                context[target.artifact_id] = rule.content
                context_names.update(bb_result.field_names)
            b.finding(
                Status.FULL,
                "SIGMA_BB_REFERENCED",
                getattr(cond, "path", ""),
                f"The correlation references the Sigma rule '{target.artifact_id}' (building "
                f"block '{target.name}', written to {target.artifact_id}.yml) by name. Deploy "
                "both files together.",
            )
            return target

        parts: list[tuple[str, str, Cond | _True | ResolvedRef]] = []
        match spec.stateful:
            case None:
                parts.append(("", "", base))
            case Counter():
                parts.append(("_events", " (counted events)", reference(base) or base))
            case Sequence(steps=steps):
                for n, step in enumerate(steps, 1):
                    both = step if isinstance(base, _True) else And(items=[base, step])
                    ref = reference(step) if isinstance(base, _True) else None
                    parts.append((f"_step{n}", f" (step {n})", ref or both))
        approxes: list[Cond] = []
        for suffix, _, part in parts:
            if isinstance(part, ResolvedRef):
                continue
            approx = TRUE if isinstance(part, _True) else b.approx(part, True)
            if isinstance(approx, _True | _False):
                what = f"step {suffix.removeprefix('_step')}" if "step" in suffix else "rule"
                b.finding(
                    Status.UNSUPPORTED,
                    "SIGMA_CONDITION_EMPTY",
                    "",
                    f"No test of this {what} could be expressed in Sigma, so no rule was written "
                    "(it would match every event).",
                )
                return empty()
            approxes.append(approx)
        if spec.rule_type == "offense":
            return empty()
        used_all = list(dict.fromkeys(i for a in approxes for i in b.used(a)))
        b.finish_case(used_all)
        stateful_fields = self._stateful_fields(spec)
        canonical = [b.selections[i][0] for i in used_all]
        naming = resolve_names(
            list(dict.fromkeys([*(f for f in canonical if f is not None), *stateful_fields])),
            "sigma",
            target=NAME,
        )
        b.findings.extend(naming.findings)
        if b.logsource is None:
            b.finding(
                Status.PARTIAL,
                "SIGMA_LOGSOURCE_UNMAPPED",
                "",
                "No Sigma logsource could be derived, so the rule uses 'product: qradar'. That "
                "names where the rule came from, not a data source; pySigma pipelines will not "
                "select a target table/index from it.",
                suggestion="Provide sigma.logsource_map, or edit the logsource before deploying.",
            )
        logsource = b.logsource or {"product": "qradar"}
        detections = [self._detection(b, a, naming.names) for a in approxes]
        if spec.stateful is None:
            docs = [self._rule(artifact, spec, logsource, detections[0], broadened=b.broadened)]
        else:
            docs = []
            rules: list[str] = []
            own = iter(detections)
            for suffix, title, part in parts:
                if isinstance(part, ResolvedRef):
                    rules.append(part.artifact_id)
                    continue
                docs.append(self._base_rule(artifact, spec, suffix, title, logsource, next(own)))
                rules.append(artifact.id + suffix)
            docs.append(self._correlation(artifact, spec, rules, naming.names, b))
        text = "---\n".join(dump_yaml(d) for d in docs)
        files = [GeneratedFile(path=f"{artifact.id}.yml", content=text)]
        context_files = [GeneratedFile(path=f"{k}.yml", content=v) for k, v in context.items()]
        group_by = [naming.names[f] for f in spec.stateful.group_by] if spec.stateful else None
        check = pysigma.check_and_convert(
            "---\n".join([text, *context.values()]),
            options.get("pysigma_targets", ""),
            artifact.id,
            group_by=group_by,
        )
        files.extend(check.files)
        b.findings.extend(check.findings)
        return BackendResult(
            target=NAME,
            artifact_id=artifact.id,
            files=files,
            findings=b.findings,
            field_names={**context_names, **naming.names},
            options=dict(options),
            queries=check.queries,
            output_kind="detection",
            broadened=bool(b.broadened),
            context_files=context_files,
        )

    @staticmethod
    def _stateful_fields(spec: DetectionSpec) -> list[str]:
        st = spec.stateful
        if st is None:
            return []
        extra = [st.distinct_field] if isinstance(st, Counter) and st.distinct_field else []
        return [*st.group_by, *extra]

    @staticmethod
    def _detection(b: _Builder, approx: Cond, names: Mapping[str, str]) -> dict[str, object]:
        used = list(dict.fromkeys(b.used(approx)))
        keys = {index: f"sel_{n}" for n, index in enumerate(used, 1)}
        detection: dict[str, object] = {}
        for index in used:
            fieldname, key, values = b.selections[index]
            name = key if fieldname is None else names[fieldname] + key
            detection[keys[index]] = {name: _values(name, values)}
        detection["condition"] = render_condition(approx, keys)
        return detection

    @staticmethod
    def _base_rule(
        artifact: Artifact,
        spec: DetectionSpec,
        suffix: str,
        title: str,
        logsource: dict[str, str],
        detection: dict[str, object],
    ) -> dict[str, object]:
        return {
            "title": (spec.name[: TITLE_MAX - len(title)] + title),
            "id": rule_uuid(spec, suffix),
            "name": artifact.id + suffix,
            "status": "experimental",
            "description": f"Events for the correlation rule '{artifact.id}' (same file).",
            "logsource": logsource,
            "detection": detection,
        }

    def _correlation(
        self,
        artifact: Artifact,
        spec: DetectionSpec,
        rules: list[str],
        names: Mapping[str, str],
        b: _Builder,
    ) -> dict[str, object]:
        st = spec.stateful
        assert st is not None
        corr: dict[str, object] = {}
        if isinstance(st, Counter):
            corr["type"] = "value_count" if st.distinct_field else "event_count"
        else:
            corr["type"] = "temporal_ordered" if st.ordered else "temporal"
        corr["rules"] = rules
        if st.group_by:
            corr["group-by"] = [names[f] for f in st.group_by]
        corr["timespan"] = timespan(st.window_s)
        if isinstance(st, Counter):
            condition: dict[str, object] = {"gte": st.count}
            if st.distinct_field:
                condition["field"] = names[st.distinct_field]
            corr["condition"] = condition
        self._stateful_findings(st, b)
        rule = self._rule(artifact, spec, None, None, broadened=b.broadened)
        rule["correlation"] = corr
        # correlation rules have no logsource/detection; keep the key order readable
        order = ["title", "id", "name", "status", "description", "correlation", "level", "qradar"]
        return {k: rule[k] for k in order if k in rule}

    @staticmethod
    def _stateful_findings(st: Counter | Sequence, b: _Builder) -> None:
        def linked(
            code: str, topic: str, what: str, variants: dict[str, tuple[Status, str]]
        ) -> None:
            v = {k: Variant(status=s, message=f"{what} {m}") for k, (s, m) in variants.items()}
            b.findings.append(
                Finding(
                    status=v["unconfirmed"].status,
                    code=code,
                    path=st.path,
                    message=v["unconfirmed"].message,
                    target=NAME,
                    depends_on=AssumptionDependency(topic=topic, **v),
                )
            )

        if isinstance(st, Counter):
            what = (
                f"The counter (at least {st.count} "
                + (f"different {st.distinct_field} values" if st.distinct_field else "events")
                + f" within {timespan(st.window_s)}) became a Sigma "
                + ("value_count" if st.distinct_field else "event_count")
                + " correlation, whose window is sliding (any interval of that length)."
            )
            linked(
                "SIGMA_COUNTER_WINDOW",
                "rule-counter-window",
                what,
                {
                    "unconfirmed": (
                        Status.PARTIAL,
                        "QRadar counters are assumed to be sliding too.",
                    ),
                    "confirmed": (Status.FULL, "QRadar counters are sliding too."),
                    "refuted": (
                        Status.PARTIAL,
                        "QRadar counts in fixed windows, so the Sigma rule also fires for events "
                        "spread over two QRadar windows (broader).",
                    ),
                },
            )
            if len(st.group_by) > 1:
                linked(
                    "SIGMA_COUNTER_GROUPING",
                    "rule-counter-grouping",
                    f"Events are counted per combination of {', '.join(st.group_by)} "
                    "(Sigma group-by).",
                    {
                        "unconfirmed": (Status.PARTIAL, "QRadar is assumed to do the same."),
                        "confirmed": (Status.FULL, "QRadar does the same."),
                        "refuted": (
                            Status.UNSUPPORTED,
                            "QRadar groups differently, so the Sigma rule does not mean the same.",
                        ),
                    },
                )
            return
        kind = "temporal_ordered" if st.ordered else "temporal"
        what = f"The sequence of {len(st.steps)} steps became a Sigma {kind} correlation"
        linked(
            "SIGMA_SEQUENCE_GAPS",
            "rule-sequence-gaps",
            what + ", in which other events may occur between the steps.",
            {
                "unconfirmed": (Status.PARTIAL, "QRadar is assumed to allow them too."),
                "confirmed": (Status.FULL, "QRadar allows them too."),
                "refuted": (
                    Status.PARTIAL,
                    "QRadar does not, so the Sigma rule also fires when other events interleave "
                    "(broader).",
                ),
            },
        )
        linked(
            "SIGMA_SEQUENCE_WINDOW",
            "rule-sequence-window",
            what + f", in which all steps fall within {timespan(st.window_s)} of each other.",
            {
                "unconfirmed": (
                    Status.PARTIAL,
                    "QRadar is assumed to measure its window from the first to the last step.",
                ),
                "confirmed": (Status.FULL, "QRadar measures from the first to the last step."),
                "refuted": (
                    Status.UNSUPPORTED,
                    "QRadar measures differently, so the Sigma rule misses sequences QRadar "
                    "detects.",
                ),
            },
        )

    @staticmethod
    def _rule(
        artifact: Artifact,
        spec: DetectionSpec,
        logsource: dict[str, str] | None,
        detection: dict[str, object] | None,
        *,
        broadened: list[dict[str, object]],
    ) -> dict[str, object]:
        rule: dict[str, object] = {"title": spec.name[:TITLE_MAX], "id": rule_uuid(spec)}
        rule["name"] = artifact.id
        rule["status"] = "experimental"
        description = spec.notes.strip()
        if broadened:
            tests = ", ".join(str(e["test"]) for e in broadened)
            note = (
                f"Rosettalog: this rule is BROADER than the source QRadar rule (tests: {tests}); "
                "it may match events the original does not. See qradar.dropped_tests."
            )
            if any(e.get("exclusion") for e in broadened):
                note += " An exclusion was removed: expect many more alerts."
            description = f"{description}\n\n{note}" if description else note
        if description:
            rule["description"] = description
        if logsource is not None:
            rule["logsource"] = logsource
        if detection is not None:
            rule["detection"] = detection
        if spec.severity is not None:
            rule["level"] = sigma_level(spec.severity)
        qradar: dict[str, object] = {"rule_id": spec.rule_id}
        if spec.uuid:
            qradar["uuid"] = spec.uuid
        qradar["enabled"] = spec.enabled
        qradar["building_block"] = spec.building_block
        qradar["rule_type"] = spec.rule_type
        for key in ("severity", "credibility", "relevance"):
            value = getattr(spec, key)
            if value is not None:
                qradar[key] = value
        if broadened:
            qradar["broader_than_source"] = True
            qradar["dropped_tests"] = broadened
        rule["qradar"] = qradar
        return rule

    @staticmethod
    def _metadata_findings(spec: DetectionSpec, b: _Builder) -> None:
        if len(spec.name) > TITLE_MAX:
            b.finding(
                Status.PARTIAL,
                "SIGMA_TITLE_TRUNCATED",
                "name",
                f"The rule name is longer than Sigma's {TITLE_MAX}-character title limit and was "
                "truncated.",
            )
        if spec.severity is None:
            b.finding(
                Status.FULL,
                "SIGMA_LEVEL_NOT_SET",
                "",
                "The rule has no event response with a severity, so the Sigma rule has no level.",
            )
        else:
            b.finding(
                Status.FULL,
                "SIGMA_LEVEL_MAPPED",
                "",
                f"Severity {spec.severity} became level '{sigma_level(spec.severity)}' "
                "(Rosettalog convention: 0-1 informational, 2-3 low, 4-6 medium, 7-8 high, "
                "9-10 critical). Credibility and relevance are kept under 'qradar'.",
            )
        if not spec.enabled:
            b.finding(
                Status.FULL,
                "SIGMA_RULE_DISABLED",
                "",
                "The source rule is disabled. Sigma has no enabled flag; this is recorded as "
                "'qradar.enabled: false'. Deploy the converted rule disabled.",
            )
        if spec.building_block:
            b.finding(
                Status.PARTIAL,
                "SIGMA_BUILDING_BLOCK",
                "",
                "This is a building block: in QRadar it never raises an alert by itself, but a "
                "deployed Sigma rule does.",
                suggestion="Deploy it disabled or as a reusable search, not as an alerting rule.",
            )
        if spec.rule_type == "offense":
            b.finding(
                Status.UNSUPPORTED,
                "SIGMA_RULE_TYPE_UNSUPPORTED",
                "",
                "Offense rules test QRadar offenses, not events; Sigma has no equivalent.",
            )
        elif spec.rule_type == "flow":
            b.finding(
                Status.PARTIAL,
                "SIGMA_FLOW_RULE",
                "",
                "Flow rules test QRadar flow records; the target needs an equivalent network "
                "flow data source and field mapping.",
            )
        for response in spec.responses:
            attrs = ", ".join(f"{k}={v}" for k, v in sorted(response.attributes.items()))
            b.finding(
                Status.PARTIAL,
                "SIGMA_RESPONSE_NOT_REPRESENTABLE",
                response.path,
                f"Response '{response.kind}'"
                + (f" ({attrs})" if attrs else "")
                + " has no Sigma equivalent and was not translated.",
                suggestion="Configure the equivalent alert action in the target SIEM.",
            )
