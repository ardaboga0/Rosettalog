"""Run samples through the source emulator and each target emulator; compare per field."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

from rosettalog.ir import Artifact, Finding, Status, pattern_ids
from rosettalog.plugins import BackendResult, get_emulator
from rosettalog.verify.emulators.source import SourceEmulator
from rosettalog.verify.samples import SampleSet

_MISSING = object()


class FieldCheck(BaseModel):
    field: str
    target_field: str | None
    source: str | None
    target: str | None
    expected: str | None = None
    has_expected: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def matches_source(self) -> bool:
        return self.source == self.target

    @computed_field  # type: ignore[prop-decorator]
    @property
    def matches_expected(self) -> bool:
        return not self.has_expected or self.expected == self.target

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        return self.matches_source and self.matches_expected

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_matches_expected(self) -> bool:
        return not self.has_expected or self.expected == self.source


class SampleResult(BaseModel):
    name: str
    log: str
    ground_truth_source: str | None = None
    checks: list[FieldCheck] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


class VerificationResult(BaseModel):
    target: str
    engine_note: str = ""
    error: str | None = None
    source_not_emulated: dict[str, str] = Field(default_factory=dict)
    unknown_expected_fields: list[str] = Field(default_factory=list)
    samples: list[SampleResult] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ground_truth(self) -> dict[str, int]:
        """Ground truth source -> number of samples ("none" = no expected values)."""
        counts: dict[str, int] = {}
        for s in self.samples:
            has_expected = any(c.has_expected for c in s.checks)
            key = (s.ground_truth_source or "unspecified") if has_expected else "none"
            counts[key] = counts.get(key, 0) + 1
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> int:
        return sum(1 for s in self.samples if s.ok)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> int:
        return len(self.samples)

    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        if self.error:
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_EMULATION_ERROR",
                    path="",
                    message=f"Generated content could not be emulated: {self.error}",
                    target=self.target,
                )
            )
        for pid, reason in self.source_not_emulated.items():
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_SOURCE_NOT_EMULATED",
                    path=f"pattern[id={pid}]",
                    message=f"The source pattern could not be emulated locally ({reason}); "
                    "fields depending on it were not verified.",
                    target=self.target,
                )
            )
        if self.unknown_expected_fields:
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_UNKNOWN_EXPECTED_FIELD",
                    path="",
                    message="Samples list expected values for field(s) this parser does not "
                    f"produce: {', '.join(self.unknown_expected_fields)}. They were not checked.",
                    suggestion="Fix the field names (canonical QRadar names) in the samples file.",
                    target=self.target,
                )
            )
        bad: dict[str, list[tuple[str, FieldCheck]]] = {}
        for sample in self.samples:
            for check in sample.checks:
                if not check.ok:
                    bad.setdefault(check.field, []).append((sample.name, check))
        for fld, items in bad.items():
            name, check = items[0]
            want = check.expected if check.has_expected and check.matches_source else check.source
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_MISMATCH",
                    path=f"field[{fld}]",
                    message=f"{len(items)} of {self.total} sample(s) extract a different value "
                    f"for '{fld}'; e.g. '{name}': expected {want!r}, generated content gave "
                    f"{check.target!r}.",
                    target=self.target,
                )
            )
        return out


def verify(artifact: Artifact, result: BackendResult, samples: SampleSet) -> VerificationResult:
    spec = artifact.parser
    emulator_cls = get_emulator(result.target)
    if spec is None or emulator_cls is None:
        return VerificationResult(
            target=result.target,
            error="no parser" if spec is None else f"no emulator for '{result.target}'",
        )
    source = SourceEmulator(spec)
    try:
        emulator = emulator_cls(result)
    except Exception as exc:
        return VerificationResult(
            target=result.target, engine_note=emulator_cls.engine_note, error=str(exc)
        )
    outcome = VerificationResult(
        target=result.target,
        engine_note=emulator_cls.engine_note,
        source_not_emulated=dict(source.unavailable),
    )
    unverifiable = {
        rule.field
        for group in spec.match_groups
        for rule in group.rules
        if any(pid in source.unavailable for pid in pattern_ids(rule.expr))
    }
    now = samples.reference_time
    for index, sample in enumerate(samples.samples):
        src = source.extract(sample.log, now=now)
        try:
            tgt = emulator.extract(sample.log, now=now)
        except Exception as exc:
            outcome.error = f"{samples.label(index)}: {exc}"
            break
        res = SampleResult(
            name=samples.label(index),
            log=sample.log,
            ground_truth_source=sample.ground_truth_source,
        )
        for fld in sample.expected or {}:
            if fld not in spec.fields() and fld not in outcome.unknown_expected_fields:
                outcome.unknown_expected_fields.append(fld)
        for fld in spec.fields():
            if fld in unverifiable:
                continue
            tname = result.field_names.get(fld)
            expected = (sample.expected or {}).get(fld, _MISSING)
            res.checks.append(
                FieldCheck(
                    field=fld,
                    target_field=tname,
                    source=src.get(fld),
                    target=tgt.get(tname) if tname else None,
                    expected=None if expected is _MISSING else expected,
                    has_expected=expected is not _MISSING,
                )
            )
        outcome.samples.append(res)
    return outcome
