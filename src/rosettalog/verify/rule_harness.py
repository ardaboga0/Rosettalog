"""Verify a translated detection rule: which sample events does each side match?

Per event up to four answers are compared:

* **source**: the IR evaluator (:mod:`rosettalog.verify.emulators.rules`), i.e. Rosettalog's
  reading of the source rule;
* **target emulator**: the target's own evaluator of the generated rule text, if it has one
  (``Emulator.matches``);
* **real engines**: each generated query (``BackendResult.queries``) run on a real engine;
* **expected**: the sample file's ground truth.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, Field

from rosettalog.ir import Artifact, Finding, Status
from rosettalog.plugins import (
    EVENT_ID_FIELD,
    EVENT_TIME_FIELD,
    BackendResult,
    DetectionSession,
    RealEngineSession,
    get_emulator,
)
from rosettalog.verify.emulators.rules import NotEvaluable, RuleEvaluator
from rosettalog.verify.emulators.windows import ALL, TimedEvent
from rosettalog.verify.rule_samples import RuleSampleSet


class EngineRun(BaseModel):
    name: str
    """E.g. "source (IR evaluator)", "sigma emulator", "splunk: pysigma-backend-splunk 2.1.0"."""
    kind: str
    """``source``, ``emulator`` or ``real``."""
    hits: list[str] | None = None
    error: str | None = None
    engine: str | None = None
    """Real engine description (image/version)."""


class RuleVerificationResult(BaseModel):
    events: list[str]
    unit: str = "event"
    """``event``: hits are sample event ids. ``group``: a stateful rule; hits are the group keys
    it alerts on (``field=value,...`` with canonical field names, or ``(all)``)."""
    rows: list[str] = Field(default_factory=list)
    """What is compared: the events, or every group key any side reported or expected."""
    ground_truth: str | None = None
    expected: list[str] | None = None
    runs: list[EngineRun] = Field(default_factory=list)
    dropped_tests: bool = False
    """The generated rule is broader than the source on purpose (dropped tests, letter case)."""

    def run(self, kind: str) -> EngineRun | None:
        return next((r for r in self.runs if r.kind == kind), None)

    def findings(self, target: str) -> list[Finding]:
        out: list[Finding] = []
        source = self.run("source")
        emulator = self.run("emulator")

        def diff(a: list[str], b: list[str]) -> str:
            extra = [e for e in self.rows if e in a and e not in b]
            missing = [e for e in self.rows if e in b and e not in a]
            parts = []
            if extra:
                parts.append(f"also matches {', '.join(extra)}")
            if missing:
                parts.append(f"misses {', '.join(missing)}")
            return "; ".join(parts)

        for run in self.runs:
            if run.error is not None:
                real = run.kind == "real"
                code = "VERIFY_REAL_ENGINE_ERROR" if real else "VERIFY_RULE_NOT_EVALUABLE"
                out.append(
                    Finding(
                        status=Status.PARTIAL,
                        code=code,
                        path="",
                        message=f"{run.name}: {run.error}",
                        target=target,
                    )
                )
        if (
            source
            and source.hits is not None
            and self.expected is not None
            and set(source.hits) != set(self.expected)
        ):
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_RULE_MISMATCH",
                    path="",
                    message="Rosettalog's reading of the source rule disagrees with the "
                    f"expected hits ({self.ground_truth or 'no ground truth source'}): it "
                    f"{diff(source.hits, self.expected)}.",
                    suggestion="If the expected hits were observed on QRadar, the frontend "
                    "or an assumption is wrong: report it.",
                    target=target,
                )
            )
        reference = source.hits if source and source.hits is not None else self.expected
        if reference is None:
            return out
        if emulator and emulator.hits is not None and set(emulator.hits) != set(reference):
            broader = set(emulator.hits) >= set(reference)
            note = (
                " This is expected: the generated rule is intentionally broader (see its findings)."
                if broader and self.dropped_tests
                else " The generated rule misses events the source rule matches: a Rosettalog "
                "bug unless a finding explains it."
                if not broader
                else ""
            )
            out.append(
                Finding(
                    status=Status.PARTIAL,
                    code="VERIFY_RULE_TARGET_MISMATCH",
                    path="",
                    message=f"{emulator.name} {diff(emulator.hits, reference)} compared with the "
                    f"source rule.{note}",
                    target=target,
                )
            )
        for run in self.runs:
            if run.kind != "real" or run.hits is None:
                continue
            sigma_hits = emulator.hits if emulator and emulator.hits is not None else None
            if sigma_hits is not None and set(run.hits) != set(sigma_hits):
                out.append(
                    Finding(
                        status=Status.PARTIAL,
                        code="VERIFY_RULE_DOWNSTREAM_GAP",
                        path="",
                        message=f"{run.name} on {run.engine} "
                        f"{diff(run.hits, sigma_hits)} compared with the Sigma rule itself: the "
                        "converted query does not mean what the Sigma rule means.",
                        suggestion="A gap in the downstream converter or engine; fix the query "
                        "by hand for this target and report it upstream.",
                        target=target,
                    )
                )
            elif sigma_hits is None and set(run.hits) != set(reference):
                out.append(
                    Finding(
                        status=Status.PARTIAL,
                        code="VERIFY_RULE_TARGET_MISMATCH",
                        path="",
                        message=f"{run.name} on {run.engine} {diff(run.hits, reference)} "
                        "compared with the source rule.",
                        target=target,
                    )
                )
        return out


def target_event(fields: Mapping[str, str], names: Mapping[str, str]) -> dict[str, str]:
    """A sample event with the generated rule's field names (unmapped fields keep theirs)."""
    return {names.get(k, k): v for k, v in fields.items()}


def _canonical_int(value: str) -> bool:
    return value.isascii() and value.isdigit() and str(int(value)) == value


def typed_events(events: list[dict[str, str]]) -> list[dict[str, str | int]]:
    """Give fields whose sample values are all integers a numeric type, as a target schema would
    (e.g. ports); everything else stays a string. Real engines compare types strictly."""
    numeric = {
        name
        for name in {k for e in events for k in e}
        if name != EVENT_ID_FIELD and all(_canonical_int(e[name]) for e in events if name in e)
    }
    return [{k: int(v) if k in numeric else v for k, v in e.items()} for e in events]


def _reverse_key(key: str, names: Mapping[str, str]) -> str:
    """A group key in generated field names -> canonical field names."""
    if key == ALL:
        return key
    back = {v: k for k, v in names.items()}
    parts = []
    for part in key.split(","):
        name, _, value = part.partition("=")
        parts.append(f"{back.get(name, name)}={value}")
    return ",".join(parts)


def verify_rule(
    artifact: Artifact,
    result: BackendResult,
    samples: RuleSampleSet,
    sessions: Mapping[str, RealEngineSession] | None = None,
) -> RuleVerificationResult:
    spec = artifact.detection
    assert spec is not None
    stateful = spec.stateful is not None
    ids = [e.id for e in samples.events]
    expected = samples.expected_for(artifact.id, spec.name)
    verification = RuleVerificationResult(
        events=ids,
        unit="group" if stateful else "event",
        ground_truth=samples.ground_truth_source,
        expected=expected,
        dropped_tests=result.broadened,
    )
    times = [samples.event_time(i) for i in range(len(ids))]
    source = EngineRun(name="source (IR evaluator)", kind="source")
    evaluator = RuleEvaluator(spec.condition, reference_data=samples.reference_data)
    try:
        if stateful:
            timed = [TimedEvent(t, e.fields) for t, e in zip(times, samples.events, strict=True)]
            source.hits = sorted(evaluator.alerting_groups(spec, timed))
        else:
            source.hits = [e.id for e in samples.events if evaluator.matches(e.fields)]
    except NotEvaluable as exc:
        source.error = str(exc)
    verification.runs.append(source)

    names = result.field_names
    events = typed_events(
        [{**target_event(e.fields, names), EVENT_ID_FIELD: e.id} for e in samples.events]
    )
    emulator_cls = get_emulator(result.target)
    method = "alerting_groups" if stateful else "matches"
    if emulator_cls is not None and getattr(emulator_cls, method, None) is not None:
        run = EngineRun(name=f"{result.target} emulator", kind="emulator")
        try:
            emulator = emulator_cls(result)
            if stateful:
                timed_target = [TimedEvent(t, e) for t, e in zip(times, events, strict=True)]
                groups = emulator.alerting_groups(timed_target)  # type: ignore[attr-defined]
                run.hits = sorted(_reverse_key(k, names) for k in groups)
            else:
                run.hits = [str(ev[EVENT_ID_FIELD]) for ev in events if emulator.matches(ev)]  # type: ignore[attr-defined]
        except Exception as exc:  # emulator errors are findings, not crashes
            run.error = f"{type(exc).__name__}: {exc}"
        verification.runs.append(run)

    files = {f.path: f.content for f in result.files}
    real_events = [
        {**e, EVENT_TIME_FIELD: t.strftime("%Y-%m-%dT%H:%M:%SZ")}
        for e, t in zip(events, times, strict=True)
    ]
    for query in result.queries:
        session = (sessions or {}).get(query.runner_target)
        if session is None:
            continue
        run = EngineRun(
            name=f"{query.language}: {query.label}",
            kind="real",
            engine=session.description,
        )
        if not isinstance(session, DetectionSession):
            run.error = f"the {query.runner_target} runner cannot run detection queries"
        else:
            try:
                found = session.run_detection(query, files[query.path], real_events)
                if stateful:
                    run.hits = sorted(_reverse_key(k, names) for k in found)
                else:
                    run.hits = sorted(found, key=ids.index)
            except Exception as exc:  # engine errors are findings, not crashes
                run.error = f"{type(exc).__name__}: {exc}"
        verification.runs.append(run)
    if stateful:
        seen = {h for r in verification.runs for h in (r.hits or [])} | set(expected or [])
        verification.rows = sorted(seen)
    else:
        verification.rows = ids
    return verification
