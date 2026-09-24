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
    Cond,
    DetectionSpec,
    FieldTest,
    Finding,
    LogSourceTest,
    Not,
    Opaque,
    Or,
    QidTest,
    ReferenceTest,
    RuleRef,
    Status,
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

    def finding(self, status: Status, code: str, path: str, message: str, **kw: str) -> None:
        self.findings.append(
            Finding(status=status, code=code, path=path, message=message, target=NAME, **kw)
        )

    # --- log source -----------------------------------------------------------------------

    def pick_logsource(self, cond: Cond) -> Cond | _True:
        """Move one top-level, single-valued, mapped log source test into ``logsource``."""
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
        self.finding(
            Status.PARTIAL,
            "SIGMA_TEST_DROPPED",
            path,
            f"{what} Sigma cannot express it, so it was left out; the Sigma rule therefore "
            "matches more events than the source rule (it never misses one).",
            suggestion=suggestion,
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
                return self.drop(
                    cond.path,
                    f"Reference to rule(s)/building block(s) {', '.join(cond.rules)}.",
                    positive,
                    suggestion="Inline the referenced building block's tests by hand.",
                )
            case ReferenceTest():
                return self.drop(
                    cond.path,
                    f"Reference data test on '{cond.collection}'.",
                    positive,
                    suggestion="Recreate the reference data on the target (watchlist, lookup, "
                    "enrich policy) and add the lookup to the converted query.",
                )
            case Opaque():
                return self.drop(
                    cond.path,
                    f"Source test '{cond.test}' was not understood.",
                    positive,
                    suggestion="Translate this test by hand.",
                )
        raise AssertionError(cond)  # pragma: no cover

    def field_test(self, test: FieldTest, positive: bool) -> Approx:
        # Case only matters for values with cased characters; "|cased" on "22" would be a no-op
        # that pySigma backends nevertheless refuse.
        has_case = any(v.lower() != v.upper() for v in test.values)
        cased = "|cased" if test.case_sensitive and has_case and test.op != "regex" else ""
        if test.op == "equals":
            values = [escape_value(v) for v in test.values]
            return self.add_selection(test.field, cased, values)
        if test.op == "contains":
            values = [escape_value(v) for v in test.values]
            return self.add_selection(test.field, "|contains" + cased, values)
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


def rule_uuid(spec: DetectionSpec) -> str:
    return str(uuid.uuid5(ID_NAMESPACE, f"qradar-rule:{spec.uuid or spec.rule_id}"))


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
        cond = b.pick_logsource(spec.condition)
        approx = TRUE if isinstance(cond, _True) else b.approx(cond, True)
        if isinstance(approx, _True | _False) or spec.rule_type == "offense":
            if isinstance(approx, _True | _False):
                b.finding(
                    Status.UNSUPPORTED,
                    "SIGMA_CONDITION_EMPTY",
                    "",
                    "No test of this rule could be expressed in Sigma, so no rule was written "
                    "(it would match every event).",
                )
            return BackendResult(
                target=NAME, artifact_id=artifact.id, findings=b.findings, output_kind="detection"
            )
        used = list(dict.fromkeys(b.used(approx)))
        canonical = [b.selections[i][0] for i in used]
        naming = resolve_names(
            list(dict.fromkeys(f for f in canonical if f is not None)), "sigma", target=NAME
        )
        b.findings.extend(naming.findings)
        keys = {index: f"sel_{n}" for n, index in enumerate(used, 1)}
        selections: dict[str, dict[str, list[str]]] = {}
        for index in used:
            fieldname, key, values = b.selections[index]
            name = key if fieldname is None else naming.names[fieldname] + key
            selections[keys[index]] = {name: values}
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
        condition = render_condition(approx, keys)
        rule = self._rule(artifact, spec, logsource, selections, condition=condition)
        text = dump_yaml(rule)
        files = [GeneratedFile(path=f"{artifact.id}.yml", content=text)]
        check = pysigma.check_and_convert(text, options.get("pysigma_targets", ""), artifact.id)
        files.extend(check.files)
        b.findings.extend(check.findings)
        field_names = {f: naming.names[f] for f in naming.names}
        return BackendResult(
            target=NAME,
            artifact_id=artifact.id,
            files=files,
            findings=b.findings,
            field_names=field_names,
            options=dict(options),
            queries=check.queries,
            output_kind="detection",
        )

    @staticmethod
    def _rule(
        artifact: Artifact,
        spec: DetectionSpec,
        logsource: dict[str, str],
        selections: dict[str, dict[str, list[str]]],
        *,
        condition: str,
    ) -> dict[str, object]:
        rule: dict[str, object] = {"title": spec.name[:TITLE_MAX], "id": rule_uuid(spec)}
        rule["name"] = artifact.id
        rule["status"] = "experimental"
        if spec.notes.strip():
            rule["description"] = spec.notes.strip()
        rule["logsource"] = logsource
        detection: dict[str, object] = {
            key: {k: _values(k, v) for k, v in sel.items()} for key, sel in selections.items()
        }
        detection["condition"] = condition
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
