"""Resolve rule references (rules and building blocks referring to other rules) among artifacts.

Source-independent: a :class:`~rosettalog.ir.RuleRef` names rules by the identifier the source
used. It is matched against each detection artifact's ``rule_id``, ``uuid`` and ``name``, since
which one a source stores is source-specific (for QRadar it is open question Q3). A reference is
resolved only when every rule it names is found, unambiguously, without a cycle. Otherwise it
stays unresolved and the artifact gets a finding:

* ``RULE_REF_MISSING``: a named rule is not among the loaded artifacts;
* ``RULE_REF_AMBIGUOUS``: a name matches several artifacts;
* ``RULE_REF_CYCLE``: following the references leads back to a rule already being resolved
  (the cycle is spelled out).

Resolved references embed the referenced rule's :class:`~rosettalog.ir.DetectionSpec`, with its
own references resolved in turn, so that backends and evaluators need no rule library.
"""

from __future__ import annotations

from collections.abc import Sequence

from rosettalog.ir.findings import Finding, Status
from rosettalog.ir.models import (
    And,
    Artifact,
    Cond,
    DetectionSpec,
    Not,
    Or,
    ResolvedRef,
    RuleRef,
)
from rosettalog.ir.models import Sequence as SequenceTest

REF_CODES = frozenset(
    {"RULE_REF_MISSING", "RULE_REF_AMBIGUOUS", "RULE_REF_CYCLE", "RULE_REF_NESTED"}
)


class _Resolver:
    def __init__(self, artifacts: Sequence[Artifact]) -> None:
        self.by_id = {a.id: a for a in artifacts if a.detection is not None}
        self.keys: dict[str, list[str]] = {}
        for a in self.by_id.values():
            spec = a.detection
            assert spec is not None
            for key in dict.fromkeys(k for k in (spec.rule_id, spec.uuid, spec.name) if k):
                self.keys.setdefault(key, []).append(a.id)
        self.done: dict[str, DetectionSpec] = {}
        self.findings: dict[str, list[Finding]] = {}
        self.broken: set[str] = set()
        """Artifacts whose resolved spec still contains an unresolved reference (transitively)."""

    def spec(self, artifact_id: str, stack: tuple[str, ...]) -> DetectionSpec:
        if artifact_id in self.done:
            return self.done[artifact_id]
        original = self.by_id[artifact_id].detection
        assert original is not None
        path = (*stack, artifact_id)
        condition = None if original.condition is None else self.cond(original.condition, path)
        stateful = original.stateful
        if isinstance(stateful, SequenceTest):
            steps = [self.cond(s, path) for s in stateful.steps]
            stateful = stateful.model_copy(update={"steps": steps})
        resolved = original.model_copy(update={"condition": condition, "stateful": stateful})
        self.done[artifact_id] = resolved
        return resolved

    def note(self, artifact_id: str, finding: Finding) -> None:
        """Record a finding for an artifact (also one resolved only as someone's reference)."""
        if finding not in self.findings.setdefault(artifact_id, []):
            self.findings[artifact_id].append(finding)

    def cond(self, cond: Cond, path: tuple[str, ...]) -> Cond:
        match cond:
            case And(items=items) | Or(items=items):
                return cond.model_copy(update={"items": [self.cond(i, path) for i in items]})
            case Not(item=item):
                return cond.model_copy(update={"item": self.cond(item, path)})
            case RuleRef():
                return self.ref(cond, path)
        return cond

    def ref(self, ref: RuleRef, path: tuple[str, ...]) -> RuleRef:
        owner = path[-1]
        resolved: list[ResolvedRef] = []
        for name in ref.rules:
            matches = self.keys.get(name, [])
            if not matches:
                self.note(
                    owner,
                    Finding(
                        status=Status.PARTIAL,
                        code="RULE_REF_MISSING",
                        path=ref.path,
                        message=f"Referenced rule '{name}' is not among the loaded rules, so "
                        "this reference cannot be resolved.",
                        suggestion="Export the referenced rule or building block together with "
                        "this rule.",
                    ),
                )
                self.broken.add(owner)
                return ref
            if len(matches) > 1:
                self.note(
                    owner,
                    Finding(
                        status=Status.PARTIAL,
                        code="RULE_REF_AMBIGUOUS",
                        path=ref.path,
                        message=f"Reference '{name}' matches several rules "
                        f"({', '.join(matches)}), so it cannot be resolved.",
                    ),
                )
                self.broken.add(owner)
                return ref
            target = matches[0]
            if target in path:
                members = path[path.index(target) :]
                cycle = " -> ".join((*members, target))
                for member in members:  # every rule in the cycle is affected
                    self.note(
                        member,
                        Finding(
                            status=Status.UNSUPPORTED,
                            code="RULE_REF_CYCLE",
                            path=ref.path if member == owner else "",
                            message=f"Rule references form a cycle: {cycle}. The rules in it "
                            "cannot be evaluated as written; the reference that closes the cycle "
                            f"(in '{owner}') is left unresolved.",
                            suggestion="Fix the cycle in the source rules.",
                        ),
                    )
                self.broken.update(members)
                return ref
            spec = self.spec(target, path)
            if target in self.broken:
                self.broken.add(owner)
                if not any(f.code in REF_CODES for f in self.findings.get(owner, [])):
                    self.note(
                        owner,
                        Finding(
                            status=Status.PARTIAL,
                            code="RULE_REF_NESTED",
                            path=ref.path,
                            message=f"Referenced rule '{name}' contains a reference that could "
                            "not be resolved (see its RULE_REF_* finding), so part of its logic "
                            "is missing here too.",
                        ),
                    )
            resolved.append(
                ResolvedRef(ref=name, artifact_id=target, name=self.by_id[target].name, spec=spec)
            )
        return ref.model_copy(update={"resolved": resolved})


def resolve_references(artifacts: Sequence[Artifact]) -> list[Artifact]:
    """Artifacts with every resolvable :class:`RuleRef` resolved (see the module docstring)."""
    resolver = _Resolver(artifacts)
    out: list[Artifact] = []
    for artifact in artifacts:
        if artifact.detection is not None and _has_refs(artifact.detection):
            resolver.spec(artifact.id, ())
    for artifact in artifacts:
        if artifact.detection is None or not _has_refs(artifact.detection):
            out.append(artifact)
            continue
        spec = resolver.spec(artifact.id, ())
        findings = [*artifact.findings, *resolver.findings.get(artifact.id, [])]
        out.append(artifact.model_copy(update={"detection": spec, "findings": findings}))
    return out


def _has_refs(spec: DetectionSpec) -> bool:
    conds: list[Cond] = [spec.condition] if spec.condition is not None else []
    if isinstance(spec.stateful, SequenceTest):
        conds += spec.stateful.steps
    stack = list(conds)
    while stack:
        c = stack.pop()
        if isinstance(c, RuleRef):
            return True
        if isinstance(c, And | Or):
            stack += c.items
        elif isinstance(c, Not):
            stack.append(c.item)
    return False


__all__ = ["resolve_references"]
