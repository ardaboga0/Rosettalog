"""Run samples through the source emulator, the target emulator and (opt-in) the real target
engine; compare per field.

Per field and sample up to four values are compared: the source (QRadar) emulator, the target
emulator, the real target engine and the sample's ``expected`` value. See docs/verification.md.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field, computed_field

from rosettalog.ir import (
    Artifact,
    Coalesce,
    Expr,
    Finding,
    IfMatch,
    Lookup,
    ParseTime,
    Status,
    pattern_ids,
)
from rosettalog.plugins import (
    BackendResult,
    NotComparable,
    RealEngineSession,
    RealValue,
    get_emulator,
)
from rosettalog.timefmt.joda import compile_format
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
    real: str | None = None
    has_real: bool = False
    real_note: str | None = None
    """Why the real engine's value was not compared (e.g. it depends on the engine's clock)."""
    scope: str | None = None
    """When the generated setting producing this field takes effect (index-time, ...)."""

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
    def real_matches(self) -> bool:
        """Real engine agrees with the source semantics and the expected value."""
        if not self.has_real:
            return True
        return self.real == self.source and (not self.has_expected or self.expected == self.real)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def emulator_diverges(self) -> bool:
        """The target emulator disagrees with the real engine: an emulator bug."""
        return self.has_real and self.real != self.target

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        return (
            self.matches_source
            and self.matches_expected
            and self.real_matches
            and not self.emulator_diverges
        )

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
    real_engine: str | None = None
    """Description of the real engine used, when verification ran with ``--engine real``."""
    real_error: str | None = None
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
        if self.real_error:
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_REAL_ENGINE_ERROR",
                    path="",
                    message=f"The real engine ({self.real_engine}) could not run the generated "
                    f"content: {self.real_error}",
                    target=self.target,
                )
            )
        out.extend(self._real_findings())
        bad: dict[str, list[tuple[str, FieldCheck]]] = {}
        for sample in self.samples:
            for check in sample.checks:
                if not (check.matches_source and check.matches_expected):
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

    def _real_findings(self) -> list[Finding]:
        mismatch: dict[str, list[tuple[str, FieldCheck]]] = {}
        diverge: dict[str, list[tuple[str, FieldCheck]]] = {}
        notes: dict[str, str] = {}
        for sample in self.samples:
            for c in sample.checks:
                if c.real_note:
                    notes.setdefault(c.field, c.real_note)
                if not c.has_real:
                    continue
                if not c.real_matches:
                    mismatch.setdefault(c.field, []).append((sample.name, c))
                if c.emulator_diverges:
                    diverge.setdefault(c.field, []).append((sample.name, c))
        out: list[Finding] = []
        for fld, items in mismatch.items():
            name, c = items[0]
            want = c.expected if c.has_expected else c.source
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_REAL_MISMATCH",
                    path=f"field[{fld}]",
                    message=f"On the real engine ({self.real_engine}), {len(items)} of "
                    f"{self.total} sample(s) give a different value for '{fld}'; e.g. "
                    f"'{name}': expected {want!r}, real engine gave {c.real!r}.",
                    target=self.target,
                )
            )
        for fld, items in diverge.items():
            name, c = items[0]
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_EMULATOR_DIVERGENCE",
                    path=f"field[{fld}]",
                    message=f"Emulator bug: the {self.target} emulator disagrees with the real "
                    f"engine for '{fld}' in {len(items)} sample(s); e.g. '{name}': emulator "
                    f"{c.target!r}, real engine {c.real!r}.",
                    suggestion="Fix the emulator and add a regression test with this sample "
                    "(tests/unit/test_emulator_regressions.py).",
                    target=self.target,
                )
            )
        for fld, note in notes.items():
            out.append(
                Finding(
                    status=Status.FULL,
                    code="VERIFY_REAL_NOT_COMPARABLE",
                    path=f"field[{fld}]",
                    message=f"'{fld}' was not compared with the real engine: {note}",
                    target=self.target,
                )
            )
        return out


def _clock_dependent_fields(artifact: Artifact) -> set[str]:
    """Fields whose value depends on "now" (timestamps without a year)."""
    spec = artifact.parser
    assert spec is not None

    def uses_clock(e: Expr) -> bool:
        match e:
            case ParseTime(format=fmt):
                return not compile_format(fmt).has_year
            case Coalesce(items=items):
                return any(uses_clock(i) for i in items)
            case Lookup(key=k, default=d):
                return uses_clock(k) or (d is not None and uses_clock(d))
            case IfMatch(value=v):
                return uses_clock(v)
        return False

    return {r.field for g in spec.match_groups for r in g.rules if uses_clock(r.expr)}


def verify(
    artifact: Artifact,
    result: BackendResult,
    samples: SampleSet,
    real: RealEngineSession | None = None,
) -> VerificationResult:
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
        real_engine=real.description if real is not None else None,
    )
    real_rows: list[dict[str, RealValue]] | None = None
    if real is not None:
        try:
            real_rows = list(
                real.extract_batch(
                    result, [s.log for s in samples.samples], now=samples.reference_time
                )
            )
        except Exception as exc:  # engine/transport errors are reported, not raised
            outcome.real_error = str(exc)
    clock_fields = _clock_dependent_fields(artifact)
    clock_mismatch = samples.reference_time.astimezone(UTC).year != datetime.now(UTC).year
    scopes = {f: s.scope for s in result.settings for f in s.fields}
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
            check = FieldCheck(
                field=fld,
                target_field=tname,
                source=src.get(fld),
                target=tgt.get(tname) if tname else None,
                expected=None if expected is _MISSING else expected,
                has_expected=expected is not _MISSING,
                scope=scopes.get(tname) if tname else None,
            )
            if real_rows is not None:
                value = real_rows[index].get(tname) if tname else None
                if isinstance(value, NotComparable):
                    check.real_note = value.reason
                elif fld in clock_fields and clock_mismatch:
                    check.real_note = (
                        "the format has no year; the real engine uses the current year while "
                        f"samples use reference_time ({samples.reference_time:%Y})."
                    )
                else:
                    check.real = value if isinstance(value, str) or value is None else str(value)
                    check.has_real = True
            res.checks.append(check)
        outcome.samples.append(res)
    return outcome
