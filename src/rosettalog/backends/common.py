"""Helpers shared by backends: pattern translation bookkeeping and drop tracking."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from rosettalog.ir import Artifact, Expr, Finding, ParserSpec, Status, pattern_ids
from rosettalog.regex.translate import RegexTranslation, Target, translate
from rosettalog.timefmt.joda import DateFormat, compile_format


def slugify(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_") or "x"


def camel(text: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"[^A-Za-z0-9]+", text))


@dataclass
class PatternTable:
    """Translates every pattern of a parser once and turns regex issues into findings."""

    spec: ParserSpec
    engine: Target
    target: str
    translations: dict[str, RegexTranslation] = field(init=False)

    def __post_init__(self) -> None:
        self.translations = {
            pid: translate(p.source, self.engine, case_insensitive=p.case_insensitive)
            for pid, p in self.spec.patterns.items()
        }

    def get(self, pid: str) -> str | None:
        return self.translations[pid].pattern

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
                out.append(
                    Finding(
                        status=issue.status,
                        code=issue.code,
                        path=f"pattern[id={pid}]",
                        message=f"{issue.message} Affects: {fields}.",
                        target=self.target,
                        line=line,
                    )
                )
        return out


@dataclass
class DropTracker:
    """Records rule parts a backend could not express, so they become findings."""

    target: str
    findings: list[Finding] = field(default_factory=list)

    def dropped(self, path: str, what: str, *, field_name: str, line: int | None) -> None:
        self.findings.append(
            Finding(
                status=Status.PARTIAL,
                code="CANDIDATE_DROPPED",
                path=path,
                message=(
                    f"{what} could not be translated and was left out; events that only match "
                    f"it will not get a value for '{field_name}'."
                ),
                target=self.target,
                line=line,
            )
        )

    def field_lost(self, path: str, field_name: str, *, line: int | None, reason: str) -> None:
        self.findings.append(
            Finding(
                status=Status.UNSUPPORTED,
                code="FIELD_NOT_TRANSLATED",
                path=path,
                message=f"Field '{field_name}' was not generated: {reason}",
                target=self.target,
                line=line,
            )
        )


def date_format_findings(
    fmt: DateFormat, *, path: str, target: str, line: int | None
) -> list[Finding]:
    return [
        Finding(
            status=i.status,
            code=i.code,
            path=path,
            message=i.message,
            target=target,
            line=line,
        )
        for i in fmt.issues
    ]


def describe(expr: Expr) -> str:
    ids = pattern_ids(expr)
    return f"candidate using pattern '{ids[0]}'" if ids else "candidate"


def artifact_ready(artifact: Artifact) -> bool:
    return artifact.kind == "parser" and artifact.parser is not None


__all__ = [
    "DropTracker",
    "PatternTable",
    "artifact_ready",
    "camel",
    "compile_format",
    "date_format_findings",
    "describe",
    "slugify",
]
