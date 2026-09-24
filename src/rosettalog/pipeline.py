"""Orchestration: inputs -> frontends -> IR -> backends (-> verification) -> report.

This module only talks to plugins through the contracts in :mod:`rosettalog.plugins`; it has
no knowledge of any particular SIEM.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path

from rosettalog import __version__
from rosettalog.errors import InputError
from rosettalog.ir import Artifact, Finding, Provenance, Status, aggregate_status
from rosettalog.ir.assumptions import Assumption, AssumptionSet, resolve_dependencies
from rosettalog.ir.references import resolve_references
from rosettalog.plugins import (
    Backend,
    RealEngineSession,
    frontends,
    get_backend,
    get_runner,
    runners,
)
from rosettalog.report import ArtifactReport, MigrationReport, TargetReport
from rosettalog.verify.harness import verify
from rosettalog.verify.rule_harness import verify_rule
from rosettalog.verify.rule_samples import RuleSampleSet, rule_ground_truth_problems
from rosettalog.verify.samples import SampleSet, ground_truth_problems

Samples = SampleSet | RuleSampleSet


def _unsupported_input(path: Path, message: str) -> Artifact:
    return Artifact(
        id=path.stem,
        name=path.name,
        source_format="unknown",
        provenance=Provenance(file=str(path)),
        findings=[Finding(status=Status.UNSUPPORTED, code="NO_FRONTEND", path="", message=message)],
    )


def assumption_set(source_format: str) -> AssumptionSet | None:
    """The assumption registry of the frontend handling ``source_format``, if it has one."""
    for cls in frontends().values():
        provider = getattr(cls(), "assumptions", None)
        if provider is None:
            continue
        aset = provider()
        if isinstance(aset, AssumptionSet) and aset.source_format == source_format:
            return aset
    return None


def open_global_assumptions(source_formats: set[str]) -> list[Assumption]:
    """Unconfirmed/refuted global assumptions of the frontends for ``source_formats``."""
    out: list[Assumption] = []
    for fmt in sorted(source_formats):
        aset = assumption_set(fmt)
        if aset is not None:
            out.extend(aset.open_global())
    return out


def discover(paths: Sequence[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file() and p.suffix == ".xml"))
        elif path.is_file():
            files.append(path)
        else:
            raise InputError(f"Input not found: {path}")
    return files


def load_artifacts(paths: Sequence[Path]) -> list[Artifact]:
    """Parse every input with the first frontend that accepts it."""
    available = [cls() for cls in frontends().values()]
    artifacts: list[Artifact] = []
    explicit = {p for p in paths if p.is_file()}
    for path in discover(paths):
        frontend = next((f for f in available if f.accepts(path)), None)
        if frontend is None:
            if path in explicit:
                names = ", ".join(f.name for f in available)
                artifacts.append(
                    _unsupported_input(path, f"No frontend recognises this file (tried: {names}).")
                )
            continue
        artifacts.extend(frontend.parse(path))
    seen: dict[str, int] = {}
    unique: list[Artifact] = []
    for artifact in artifacts:
        count = seen.get(artifact.id, 0)
        seen[artifact.id] = count + 1
        if count:
            artifact = artifact.model_copy(update={"id": f"{artifact.id}_{count + 1}"})
        unique.append(artifact)
    return resolve_references(unique)


def run(
    artifacts: Sequence[Artifact],
    targets: Sequence[str],
    *,
    options: Mapping[str, Mapping[str, str]] | None = None,
    out_dir: Path | None = None,
    samples: Samples | None = None,
    require_ground_truth: bool = False,
    engine: str = "emulator",
    runner_names: Sequence[str] = (),
    inputs: Sequence[str] = (),
) -> MigrationReport:
    """Translate ``artifacts`` for every target.

    With ``require_ground_truth``, every sample must carry ``expected`` values for every field the
    parser produces plus a ``ground_truth_source``; otherwise :class:`InputError` is raised.
    """
    options = options or {}
    if engine not in ("emulator", "real"):
        raise InputError(f"Unknown engine '{engine}'; use 'emulator' or 'real'.")
    if engine == "real" and samples is None:
        raise InputError("--engine real needs a samples file.")
    if require_ground_truth:
        if samples is None:
            raise InputError("--require-ground-truth needs a samples file.")
        if isinstance(samples, RuleSampleSet):
            rules = [(a.id, a.detection.name) for a in artifacts if a.detection is not None]
            problems = rule_ground_truth_problems(samples, rules)
        else:
            problems = [
                f"{a.name}: {p}"
                for a in artifacts
                if a.parser is not None
                for p in ground_truth_problems(samples, a.parser.fields())
            ]
        if problems:
            raise InputError("Samples are not usable as ground truth:\n  " + "\n  ".join(problems))
    backends = {t: get_backend(t) for t in targets}
    with ExitStack() as stack:
        runner_targets: list[str] = []
        for target, backend in backends.items():
            provider = getattr(backend, "verification_targets", None)
            runner_targets += provider(options.get(target, {})) if provider else [target]
        runner_targets = list(dict.fromkeys(runner_targets))
        sessions = _open_sessions(stack, runner_targets, runner_names) if engine == "real" else {}
        return _run(artifacts, backends, options, out_dir, samples, sessions, inputs)


def _open_sessions(
    stack: ExitStack, targets: Sequence[str], runner_names: Sequence[str]
) -> dict[str, RealEngineSession]:
    chosen: dict[str, str] = {}
    for name in runner_names:
        cls = runners().get(name)
        if cls is None:
            raise InputError(f"Unknown runner '{name}'. Available: {', '.join(sorted(runners()))}.")
        chosen[cls.target] = name
    sessions: dict[str, RealEngineSession] = {}
    for target in targets:
        runner = get_runner(target, chosen.get(target))
        reason = runner.unavailable_reason()
        if reason is not None:
            raise InputError(f"Real-engine runner '{runner.name}' cannot run here: {reason}")
        sessions[target] = stack.enter_context(runner.session())
    return sessions


def _run(
    artifacts: Sequence[Artifact],
    backends: Mapping[str, Backend],
    options: Mapping[str, Mapping[str, str]],
    out_dir: Path | None,
    samples: Samples | None,
    sessions: Mapping[str, RealEngineSession],
    inputs: Sequence[str],
) -> MigrationReport:
    targets = list(backends)
    report = MigrationReport(
        tool_version=__version__,
        generated_at=datetime.now(UTC),
        inputs=list(inputs),
        targets=list(targets),
    )
    for artifact in artifacts:
        entry = ArtifactReport(
            id=artifact.id,
            name=artifact.name,
            source_file=artifact.provenance.file,
            source_format=artifact.source_format,
            source_findings=list(artifact.findings),
        )
        for target, backend in backends.items():
            if not backend.supports(artifact):
                entry.targets.append(
                    TargetReport(
                        target=target,
                        status=Status.UNSUPPORTED,
                        findings=[
                            Finding(
                                status=Status.UNSUPPORTED,
                                code="TARGET_NOT_APPLICABLE",
                                path="",
                                message=f"The {target} backend cannot translate this artifact.",
                                target=target,
                            )
                        ],
                    )
                )
                continue
            result = backend.generate(artifact, options.get(target, {}))
            findings = resolve_dependencies(
                list(result.findings), assumption_set(artifact.source_format)
            )
            verification = None
            rule_verification = None
            if isinstance(samples, SampleSet) and result.produced_output and artifact.parser:
                verification = verify(artifact, result, samples, sessions.get(target))
                findings.extend(verification.findings())
            elif (
                isinstance(samples, RuleSampleSet) and result.produced_output and artifact.detection
            ):
                rule_verification = verify_rule(artifact, result, samples, sessions)
                findings.extend(rule_verification.findings(target))
            written: list[str] = []
            if out_dir is not None:
                for f in result.files:
                    rel = Path(target) / artifact.id / f.path
                    dest = out_dir / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(f.content, encoding="utf-8")
                    written.append(rel.as_posix())
            else:
                written = [f"{target}/{artifact.id}/{f.path}" for f in result.files]
            status = aggregate_status(
                [*artifact.findings, *findings], produced_output=result.produced_output
            )
            entry.targets.append(
                TargetReport(
                    target=target,
                    status=status,
                    findings=findings,
                    files=written,
                    field_names=result.field_names,
                    settings=result.settings,
                    verification=verification,
                    rule_verification=rule_verification,
                )
            )
        report.artifacts.append(entry)
    report.unconfirmed_global_assumptions = open_global_assumptions(
        {a.source_format for a in artifacts}
    )
    return report
