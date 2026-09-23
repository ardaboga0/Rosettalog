"""QRadar Log Source Extension (LSX) XML -> IR.

Element and attribute semantics follow IBM's public "Log source extensions" documentation.
Where the documentation leaves behaviour open, the parser records the assumption it makes as a
finding (e.g. ``LSX_MATCHGROUP_SELECTION_ASSUMED``) instead of silently picking one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

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
    ParserSpec,
    ParseTime,
    Pattern,
    Provenance,
    Status,
    Template,
    pattern_ids,
)
from rosettalog.ir.fields import EVENT_SEVERITY
from rosettalog.regex.tokenizer import RegexSyntaxError, capture_count, tokenize

ROOT = "device-extension"
MATCHER_FIELDS = frozenset(
    [
        "EventName",
        "EventCategory",
        "SourceIp",
        "SourcePort",
        "SourceIpPreNAT",
        "SourceIpPostNAT",
        "SourceMAC",
        "SourcePortPreNAT",
        "SourcePortPostNAT",
        "DestinationIp",
        "DestinationPort",
        "DestinationIpPreNAT",
        "DestinationIpPostNAT",
        "DestinationPortPreNAT",
        "DestinationPortPostNAT",
        "DestinationMAC",
        "DeviceTime",
        "Protocol",
        "UserName",
        "HostName",
        "GroupName",
        "IdentityIp",
        "IdentityMac",
        "IdentityIpv6",
        "NetBIOSName",
        "ExtraIdentityData",
        "SourceIpv6",
        "DestinationIpv6",
    ]
)
OTHER_MATCHERS = {"json-matcher", "leef-matcher", "cef-matcher", "xml-matcher"}
SEND_IDENTITY = {"UseDSMResults", "SendIfAbsent", "OverrideAndAlwaysSend", "OverrideAndNeverSend"}
_ATTRS = {
    "pattern": {"id", "case-insensitive", "trim-whitespace", "use-default-pattern"},
    "match-group": {"order", "description", "device-type-id-override"},
    "matcher": {
        "field",
        "pattern-id",
        "order",
        "capture-group",
        "enable-substitutions",
        "ext-data",
    },
    "event-match-single": {"event-name", "device-event-category", "severity", "send-identity"},
    "event-match-multiple": {
        "pattern-id",
        "capture-group-index",
        "device-event-category",
        "severity",
        "send-identity",
    },
}


def _local(tag: object) -> str:
    return etree.QName(tag).localname if isinstance(tag, str) else ""


def _line(elem: etree._Element) -> int | None:
    line = elem.sourceline
    return line if isinstance(line, int) else None


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "artifact"


def secure_parser() -> etree.XMLParser:
    """XML parser hardened for untrusted input (no entities, DTDs or network access)."""
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        load_dtd=False,
        dtd_validation=False,
        remove_comments=True,
        remove_pis=True,
    )


def is_lsx(path: Path) -> bool:
    try:
        for _event, elem in etree.iterparse(
            str(path), events=("start",), resolve_entities=False, no_network=True, load_dtd=False
        ):
            return _local(elem.tag) == ROOT
    except (etree.XMLSyntaxError, OSError):
        return False
    return False


@dataclass
class _Matcher:
    field: str
    order: int
    index: int
    expr: Expr
    path: str
    line: int | None


@dataclass
class _GroupDraft:
    order: int
    description: str
    path: str
    line: int | None
    matchers: list[_Matcher] = field(default_factory=list)
    singles: list[tuple[str, str | None, str | None]] = field(default_factory=list)
    multiples: list[tuple[str, int, str | None, str | None, str, int | None]] = field(
        default_factory=list
    )


class LsxParser:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[Finding] = []
        self.patterns: dict[str, Pattern] = {}
        self.pattern_groups: dict[str, int | None] = {}

    # -- helpers --------------------------------------------------------------------------

    def _add(
        self,
        status: Status,
        code: str,
        path: str,
        message: str,
        *,
        line: int | None = None,
        suggestion: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                status=status,
                code=code,
                path=path,
                message=message,
                suggestion=suggestion,
                line=line,
            )
        )

    def _check_attrs(self, elem: etree._Element, kind: str, path: str) -> None:
        for name in elem.attrib:
            local = _local(name)
            if local not in _ATTRS[kind]:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_UNKNOWN_ATTRIBUTE",
                    path,
                    f"Attribute '{local}' on <{kind}> is not understood and was not translated.",
                    line=_line(elem),
                )

    def _bool(self, elem: etree._Element, name: str, path: str) -> bool:
        raw = elem.get(name)
        if raw is None:
            return False
        if raw.strip().lower() in ("true", "false"):
            return raw.strip().lower() == "true"
        self._add(
            Status.PARTIAL,
            "LSX_INVALID_VALUE",
            path,
            f"Attribute {name}='{raw}' is not a boolean; treated as false.",
            line=_line(elem),
        )
        return False

    def _int(self, elem: etree._Element, name: str, path: str, *, required: bool) -> int | None:
        raw = elem.get(name)
        if raw is None:
            if required:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_MISSING_ATTRIBUTE",
                    path,
                    f"Required attribute '{name}' is missing; element skipped.",
                    line=_line(elem),
                )
            return None
        try:
            return int(raw.strip())
        except ValueError:
            self._add(
                Status.UNSUPPORTED,
                "LSX_INVALID_VALUE",
                path,
                f"Attribute {name}='{raw}' is not an integer; element skipped.",
                line=_line(elem),
            )
            return None

    # -- elements -------------------------------------------------------------------------

    def _pattern(self, elem: etree._Element) -> None:
        pid = elem.get("id")
        path = f"pattern[id={pid}]"
        self._check_attrs(elem, "pattern", path)
        if not pid:
            self._add(
                Status.UNSUPPORTED,
                "LSX_MISSING_ATTRIBUTE",
                "pattern",
                "A <pattern> without 'id' cannot be referenced; skipped.",
                line=_line(elem),
            )
            return
        if pid in self.patterns:
            self._add(
                Status.UNSUPPORTED,
                "LSX_DUPLICATE_PATTERN",
                path,
                f"Pattern id '{pid}' is defined more than once; only the first is used.",
                line=_line(elem),
            )
            return
        if len(elem):
            # Unresolved entity references or nested markup: the text we see would be truncated.
            self._add(
                Status.UNSUPPORTED,
                "LSX_PATTERN_MARKUP",
                path,
                "The pattern contains entity references or nested markup, which are not expanded "
                "(for security); the pattern was not translated.",
                line=_line(elem),
                suggestion="Inline the regex text in a CDATA section.",
            )
            return
        source = elem.text or ""
        if self._bool(elem, "trim-whitespace", path) and any(ch.isspace() for ch in source):
            self._add(
                Status.PARTIAL,
                "LSX_TRIM_WHITESPACE",
                path,
                "trim-whitespace='true' on a pattern containing whitespace. IBM documents it as "
                "'whitespace and carriage returns are ignored' without specifying where; the "
                "pattern is translated exactly as written.",
                line=_line(elem),
                suggestion="Check whether the whitespace in this pattern is significant.",
            )
        self.patterns[pid] = Pattern(
            id=pid,
            source=source,
            case_insensitive=self._bool(elem, "case-insensitive", path),
            provenance=Provenance(file=str(self.path), line=_line(elem)),
        )
        self._bool(elem, "use-default-pattern", path)
        try:
            self.pattern_groups[pid] = capture_count(tokenize(source))
        except RegexSyntaxError:
            self.pattern_groups[pid] = None  # reported per target by the regex translators

    def _pattern_ref(self, elem: etree._Element, attr: str, path: str) -> str | None:
        pid = elem.get(attr)
        if pid is None:
            self._add(
                Status.UNSUPPORTED,
                "LSX_MISSING_ATTRIBUTE",
                path,
                f"Required attribute '{attr}' is missing; element skipped.",
                line=_line(elem),
            )
            return None
        if pid not in self.patterns:
            self._add(
                Status.UNSUPPORTED,
                "LSX_UNKNOWN_PATTERN",
                path,
                f"Referenced pattern '{pid}' is not defined; element skipped.",
                line=_line(elem),
            )
            return None
        return pid

    def _check_group(self, pid: str, group: int, path: str, line: int | None) -> bool:
        available = self.pattern_groups.get(pid)
        if available is not None and group > available:
            self._add(
                Status.UNSUPPORTED,
                "LSX_CAPTURE_GROUP_OUT_OF_RANGE",
                path,
                f"Capture group {group} does not exist in pattern '{pid}' "
                f"(it has {available}); element skipped.",
                line=line,
            )
            return False
        return True

    def _identity(self, elem: etree._Element, path: str) -> None:
        value = elem.get("send-identity")
        if value is None or value == "UseDSMResults":
            return
        if value == "OverrideAndNeverSend":
            self._add(
                Status.FULL,
                "LSX_IDENTITY_SUPPRESSED",
                path,
                "send-identity='OverrideAndNeverSend' suppresses QRadar identity events; target "
                "SIEMs have no identity-event stream, so nothing needs translating.",
                line=_line(elem),
            )
            return
        if value not in SEND_IDENTITY:
            msg = f"Unknown send-identity value '{value}'."
        else:
            msg = (
                f"send-identity='{value}' makes QRadar create identity (asset model) events. "
                "Target SIEMs have no equivalent; identity enrichment must be rebuilt separately."
            )
        self._add(
            Status.UNSUPPORTED,
            "LSX_IDENTITY_EVENTS",
            path,
            msg,
            line=_line(elem),
            suggestion="Use the target's UEBA / identity features or an enrichment lookup.",
        )

    def _matcher(self, elem: etree._Element, draft: _GroupDraft, index: int) -> None:
        fld = elem.get("field") or ""
        order = elem.get("order")
        path = f"{draft.path}/matcher[field={fld},order={order}]"
        line = _line(elem)
        self._check_attrs(elem, "matcher", path)
        if not fld:
            self._add(
                Status.UNSUPPORTED,
                "LSX_MISSING_ATTRIBUTE",
                path,
                "Matcher without 'field'; skipped.",
                line=line,
            )
            return
        order_i = self._int(elem, "order", path, required=True)
        pid = self._pattern_ref(elem, "pattern-id", path)
        if order_i is None or pid is None:
            return
        if fld not in MATCHER_FIELDS:
            self._add(
                Status.PARTIAL,
                "LSX_UNKNOWN_FIELD",
                path,
                f"'{fld}' is not a documented LSX matcher field; it is migrated as a custom field.",
                line=line,
            )
        substitutions = self._bool(elem, "enable-substitutions", path)
        raw_group = elem.get("capture-group", "0").strip()
        expr: Expr
        if substitutions:
            parts: list[str | int] = []
            for piece in re.split(r"(\\[1-9])", raw_group):
                if re.fullmatch(r"\\[1-9]", piece):
                    parts.append(int(piece[1]))
                elif piece:
                    parts.append(piece)
            groups = [p for p in parts if isinstance(p, int)]
            if any(not self._check_group(pid, g, path, line) for g in groups):
                return
            expr = Template(pattern_id=pid, parts=parts)
        else:
            if not raw_group.isdigit():
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_INVALID_VALUE",
                    path,
                    f"capture-group='{raw_group}' is not a number and enable-substitutions is "
                    "not set; skipped.",
                    line=line,
                )
                return
            if not self._check_group(pid, int(raw_group), path, line):
                return
            expr = Capture(pattern_id=pid, group=int(raw_group))
        ext = elem.get("ext-data")
        if fld == "DeviceTime":
            if not ext:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_DEVICETIME_NO_FORMAT",
                    path,
                    "DeviceTime without ext-data relies on QRadar's built-in date detection, "
                    "which cannot be reproduced; the timestamp was not migrated.",
                    line=line,
                    suggestion="Add an explicit ext-data date format and re-run.",
                )
                return
            expr = ParseTime(value=expr, format=ext)
        elif ext:
            self._add(
                Status.PARTIAL,
                "LSX_EXT_DATA_IGNORED",
                path,
                f"ext-data='{ext}' on field '{fld}' has no documented meaning and was ignored.",
                line=line,
            )
        draft.matchers.append(_Matcher(fld, order_i, index, expr, path, line))

    def _match_group(self, elem: etree._Element) -> _GroupDraft | None:
        order = elem.get("order")
        path = f"match-group[order={order}]"
        self._check_attrs(elem, "match-group", path)
        order_i = self._int(elem, "order", path, required=True)
        if order_i is None:
            return None
        if elem.get("device-type-id-override"):
            self._add(
                Status.PARTIAL,
                "LSX_DEVICE_TYPE_OVERRIDE",
                path,
                "device-type-id-override makes QRadar resolve QIDs against another log source "
                "type. Field extraction is migrated; the QID resolution is not.",
                line=_line(elem),
            )
        draft = _GroupDraft(order_i, elem.get("description", ""), path, _line(elem))
        for index, child in enumerate(c for c in elem if isinstance(c.tag, str)):
            kind = _local(child.tag)
            if kind == "matcher":
                self._matcher(child, draft, index)
            elif kind == "event-match-single":
                self._event_single(child, draft)
            elif kind == "event-match-multiple":
                self._event_multiple(child, draft)
            elif kind in OTHER_MATCHERS:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_MATCHER_TYPE_UNSUPPORTED",
                    f"{path}/{kind}",
                    f"<{kind}> is not supported yet; its fields were not migrated.",
                    line=_line(child),
                    suggestion="Track support in the issue tracker or translate by hand.",
                )
            else:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_UNKNOWN_ELEMENT",
                    f"{path}/{kind}",
                    f"Unknown element <{kind}> inside a match group was not translated.",
                    line=_line(child),
                )
        return draft

    def _severity(self, elem: etree._Element, path: str) -> str | None:
        raw = elem.get("severity")
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if not 1 <= value <= 10:
            self._add(
                Status.FULL,
                "LSX_SEVERITY_DEFAULTED",
                path,
                f"severity='{raw}' is outside 1-10; QRadar uses 5, and so does the translation.",
                line=_line(elem),
            )
            value = 5
        return str(value)

    def _event_single(self, elem: etree._Element, draft: _GroupDraft) -> None:
        name = elem.get("event-name")
        path = f"{draft.path}/event-match-single[event-name={name}]"
        self._check_attrs(elem, "event-match-single", path)
        self._identity(elem, path)
        if name is None:
            self._add(
                Status.UNSUPPORTED,
                "LSX_MISSING_ATTRIBUTE",
                path,
                "event-match-single without 'event-name'; skipped.",
                line=_line(elem),
            )
            return
        draft.singles.append((name, elem.get("device-event-category"), self._severity(elem, path)))

    def _event_multiple(self, elem: etree._Element, draft: _GroupDraft) -> None:
        pid = elem.get("pattern-id")
        path = f"{draft.path}/event-match-multiple[pattern-id={pid}]"
        self._check_attrs(elem, "event-match-multiple", path)
        self._identity(elem, path)
        pid = self._pattern_ref(elem, "pattern-id", path)
        group = self._int(elem, "capture-group-index", path, required=True)
        if pid is None or group is None or not self._check_group(pid, group, path, _line(elem)):
            return
        self._add(
            Status.PARTIAL,
            "LSX_EVENT_MATCH_MULTIPLE_ASSUMED",
            path,
            "event-match-multiple is interpreted as: EventName = capture group "
            f"{group} of '{pid}', and its category/severity apply when '{pid}' matches. IBM's "
            "documentation does not fully specify this; verify with sample events.",
            line=_line(elem),
        )
        draft.multiples.append(
            (
                pid,
                group,
                elem.get("device-event-category"),
                self._severity(elem, path),
                path,
                _line(elem),
            )
        )

    # -- assembly -------------------------------------------------------------------------

    def _build_group(self, draft: _GroupDraft) -> MatchGroup:
        by_field: dict[str, list[_Matcher]] = {}
        for m in draft.matchers:
            by_field.setdefault(m.field, []).append(m)

        def chain(items: list[Expr]) -> Expr | None:
            if not items:
                return None
            return items[0] if len(items) == 1 else Coalesce(items=items)

        def candidates(fld: str) -> list[_Matcher]:
            found = sorted(by_field.get(fld, []), key=lambda m: (m.order, m.index))
            orders = [m.order for m in found]
            if len(orders) != len(set(orders)):
                self._add(
                    Status.PARTIAL,
                    "LSX_DUPLICATE_ORDER",
                    f"{draft.path}/matcher[field={fld}]",
                    f"Several matchers for '{fld}' share the same order; document order is used.",
                    line=found[0].line,
                )
            return found

        rules: list[FieldRule] = []
        name_items: list[Expr] = [m.expr for m in candidates("EventName")]
        name_items += [Capture(pattern_id=pid, group=g) for pid, g, *_ in draft.multiples]
        event_name = chain(name_items)

        for fld in by_field:
            if fld in ("EventName", "EventCategory"):
                continue
            found = candidates(fld)
            expr = chain([m.expr for m in found])
            assert expr is not None
            rules.append(
                FieldRule(
                    field=fld, expr=expr, path=f"{draft.path}/field[{fld}]", line=found[0].line
                )
            )

        def mapped(fld: str, index: int, matcher_field: str | None) -> None:
            table = {name: vals[index] for name, *vals in draft.singles if vals[index] is not None}
            base: list[Expr] = [m.expr for m in candidates(matcher_field)] if matcher_field else []
            base += [
                IfMatch(pattern_id=mul[0], value=Literal_(value=v))
                for mul in draft.multiples
                if (v := mul[2 + index]) is not None
            ]
            default = chain(base)
            if table and event_name is None:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_EVENT_MATCH_WITHOUT_EVENTNAME",
                    draft.path,
                    f"event-match-single entries set {fld} but the group extracts no EventName, "
                    "so they can never apply.",
                    line=draft.line,
                )
                table = {}
            expr: Expr | None
            if table and event_name is not None:
                expr = Lookup(key=event_name, table=table, default=default)
            else:
                expr = default
            if expr is not None:
                rules.append(FieldRule(field=fld, expr=expr, path=f"{draft.path}/field[{fld}]"))

        if event_name is not None:
            rules.insert(
                0,
                FieldRule(
                    field="EventName", expr=event_name, path=f"{draft.path}/field[EventName]"
                ),
            )
        mapped("EventCategory", 0, "EventCategory")
        mapped(EVENT_SEVERITY, 1, None)

        selector = pattern_ids(event_name) if event_name is not None else []
        if not selector:
            seen: dict[str, None] = {}
            for rule in rules:
                for pid in pattern_ids(rule.expr):
                    seen.setdefault(pid, None)
            selector = list(seen)
        return MatchGroup(
            order=draft.order,
            description=draft.description,
            selector_pattern_ids=selector,
            rules=rules,
            path=draft.path,
            line=draft.line,
        )

    def parse(self) -> Artifact:
        name = self.path.name.removesuffix(".xml")
        base = Artifact(
            id=slugify(name),
            name=name,
            source_format="qradar-lsx",
            provenance=Provenance(file=str(self.path)),
        )
        try:
            tree = etree.parse(str(self.path), secure_parser())
        except (etree.XMLSyntaxError, OSError) as exc:
            finding = Finding(
                status=Status.UNSUPPORTED,
                code="LSX_INVALID_XML",
                path="",
                message=f"The file could not be parsed as XML: {exc}",
            )
            return base.model_copy(update={"findings": [finding]})
        root = tree.getroot()
        if _local(root.tag) != ROOT:
            finding = Finding(
                status=Status.UNSUPPORTED,
                code="LSX_NOT_AN_LSX",
                path="",
                message=f"Root element is <{_local(root.tag)}>, expected <{ROOT}>.",
            )
            return base.model_copy(update={"findings": [finding]})

        children = [c for c in root if isinstance(c.tag, str)]
        for child in children:
            if _local(child.tag) == "pattern":
                self._pattern(child)
        drafts: list[_GroupDraft] = []
        for child in children:
            kind = _local(child.tag)
            if kind == "pattern":
                continue
            if kind == "match-group":
                draft = self._match_group(child)
                if draft is not None:
                    drafts.append(draft)
            else:
                self._add(
                    Status.UNSUPPORTED,
                    "LSX_UNKNOWN_ELEMENT",
                    kind,
                    f"Unknown top-level element <{kind}> was not translated.",
                    line=_line(child),
                )

        drafts.sort(key=lambda d: d.order)
        orders = [d.order for d in drafts]
        if len(orders) != len(set(orders)):
            self._add(
                Status.PARTIAL,
                "LSX_DUPLICATE_ORDER",
                "match-groups",
                "Match group orders must be unique; document order is used for ties.",
            )
        groups = [g for g in (self._build_group(d) for d in drafts) if g.rules]
        for draft in drafts:
            if not any(g.order == draft.order for g in groups):
                self._add(
                    Status.PARTIAL,
                    "LSX_EMPTY_MATCH_GROUP",
                    draft.path,
                    "Match group produced no translatable field rules.",
                    line=draft.line,
                )
        if len(groups) > 1:
            self._add(
                Status.PARTIAL,
                "LSX_MATCHGROUP_SELECTION_ASSUMED",
                "match-groups",
                "Several match groups: the translation applies the first group (by order) whose "
                "EventName pattern matches the event (or any of its patterns, if it has no "
                "EventName). IBM does not document the exact selection rule.",
                suggestion="Verify group selection with sample events for every group.",
            )
        if any(r.field in ("EventName", "EventCategory") for g in groups for r in g.rules):
            self._add(
                Status.FULL,
                "LSX_QID_MAPPING_EXTERNAL",
                "",
                "QRadar resolves EventName/EventCategory to a QID (normalized name, low-level "
                "category) via the QID map, which is not part of the LSX. Only the raw values "
                "are migrated.",
                suggestion="Export the custom QID map and migrate it as a lookup table.",
            )
        if not groups:
            self._add(
                Status.UNSUPPORTED,
                "LSX_NOTHING_TO_TRANSLATE",
                "",
                "No match group produced any translatable field rule.",
            )
            return base.model_copy(update={"findings": self.findings})
        spec = ParserSpec(patterns=self.patterns, match_groups=groups)
        return base.model_copy(update={"parser": spec, "findings": self.findings})
