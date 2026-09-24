"""Command line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from rosettalog import __version__
from rosettalog.errors import RosettalogError
from rosettalog.ir import Status
from rosettalog.pipeline import load_artifacts, run
from rosettalog.plugins import backends, emulators, frontends, runners
from rosettalog.report import MigrationReport, json_schema_text, render_json, render_markdown
from rosettalog.report.models import TargetReport
from rosettalog.verify.samples import load_sample_file

app = typer.Typer(
    name="rosettalog",
    help="Migrate QRadar detection content to other SIEMs, with honest translation reports.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_OK, EXIT_ERROR, EXIT_NOT_FULL = 0, 1, 2

Inputs = Annotated[
    list[Path], typer.Argument(help="Input files or directories (directories: *.xml).")
]
Targets = Annotated[
    list[str],
    typer.Option("--to", "-t", help="Target backend; repeatable. See `rosettalog plugins`."),
]
Options = Annotated[
    list[str] | None,
    typer.Option(
        "--option",
        "-O",
        help="Backend option as target.key=value (or key=value for every target).",
    ),
]
SourceTable = Annotated[
    str | None, typer.Option(help="Sentinel: table with raw events (default Syslog).")
]
MessageColumn = Annotated[
    str | None, typer.Option(help="Sentinel: column with the raw event text.")
]
AsimSchema = Annotated[
    str | None, typer.Option(help="Sentinel: ASIM schema to align to, e.g. NetworkSession.")
]
Sourcetype = Annotated[str | None, typer.Option(help="Splunk: sourcetype stanza name.")]
RequireGroundTruth = Annotated[
    bool,
    typer.Option(
        "--require-ground-truth",
        help="Fail unless every sample has 'expected' values for all fields and a "
        "'ground_truth_source'.",
    ),
]
EngineOpt = Annotated[
    str,
    typer.Option(
        "--engine",
        help="'emulator' (default, local only) or 'real': also run the generated content on the "
        "real target engine (local container, see docs/verification.md) and compare.",
    ),
]
RunnerOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--runner",
        help="Real-engine runner to use instead of the target's default, e.g. sentinel-adx. "
        "Repeatable. See `rosettalog plugins`.",
    ),
]
SamplesOpt = Annotated[
    Path | None, typer.Option("--samples", "-s", help="Samples YAML for verification.")
]


def _version(value: bool) -> None:
    if value:
        typer.echo(f"rosettalog {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """Rosettalog command line."""


def _parse_options(
    raw: list[str] | None,
    targets: list[str],
    *,
    source_table: str | None = None,
    message_column: str | None = None,
    asim_schema: str | None = None,
    sourcetype: str | None = None,
) -> dict[str, dict[str, str]]:
    options: dict[str, dict[str, str]] = {t: {} for t in targets}
    for item in raw or []:
        key, sep, value = item.partition("=")
        if not sep:
            raise typer.BadParameter(f"expected key=value, got {item!r}", param_hint="-O")
        target, dot, name = key.partition(".")
        if dot and target in options:
            options[target][name] = value
        elif dot:
            raise typer.BadParameter(f"unknown target in option {item!r}", param_hint="-O")
        else:
            for opts in options.values():
                opts[key] = value
    shortcuts = {
        "sentinel": {
            "source_table": source_table,
            "message_column": message_column,
            "asim_schema": asim_schema,
        },
        "splunk": {"sourcetype": sourcetype},
    }
    for target, values in shortcuts.items():
        if target in options:
            options[target].update({k: v for k, v in values.items() if v is not None})
    return options


def _print_summary(report: MigrationReport) -> None:
    for artifact in report.artifacts:
        typer.echo(f"{artifact.name}")
        for tr in artifact.targets:
            color = {
                Status.FULL: typer.colors.GREEN,
                Status.PARTIAL: typer.colors.YELLOW,
                Status.UNSUPPORTED: typer.colors.RED,
            }[tr.status]
            status = typer.style(f"{tr.status.value:<11}", fg=color, bold=True)
            issues = sum(1 for f in tr.findings if f.status is not Status.FULL)
            issues += sum(1 for f in artifact.source_findings if f.status is not Status.FULL)
            extra = f"{issues} item(s) need review"
            if tr.verification is not None:
                v = tr.verification
                extra += f", samples {v.passed}/{v.total}"
                if v.error:
                    extra += " (emulation error)"
            if tr.rule_verification is not None:
                rv = tr.rule_verification
                agree = sum(1 for f in tr.findings if f.code.startswith("VERIFY_")) == 0
                extra += f", {len(rv.events)} events: " + ("all agree" if agree else "differences")
            typer.echo(f"  {tr.target:<10} {status} {extra}")


@app.command()
def convert(
    inputs: Inputs,
    to: Targets,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory.")] = Path(
        "rosettalog-out"
    ),
    option: Options = None,
    source_table: SourceTable = None,
    message_column: MessageColumn = None,
    asim_schema: AsimSchema = None,
    sourcetype: Sourcetype = None,
    samples: SamplesOpt = None,
    require_ground_truth: RequireGroundTruth = False,
    strict: Annotated[
        bool, typer.Option(help="Exit with code 2 unless every translation is FULL.")
    ] = False,
) -> None:
    """Translate artifacts and write target content plus report.md / report.json."""
    try:
        opts = _parse_options(
            option,
            to,
            source_table=source_table,
            message_column=message_column,
            asim_schema=asim_schema,
            sourcetype=sourcetype,
        )
        sample_set = load_sample_file(samples) if samples else None
        artifacts = load_artifacts(inputs)
        output.mkdir(parents=True, exist_ok=True)
        report = run(
            artifacts,
            to,
            options=opts,
            out_dir=output,
            samples=sample_set,
            require_ground_truth=require_ground_truth,
            inputs=[str(p) for p in inputs],
        )
    except RosettalogError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    (output / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (output / "report.json").write_text(render_json(report), encoding="utf-8")
    _print_summary(report)
    typer.echo(f"\nWrote {output}/ (see report.md)")
    if strict and report.worst_status() is not Status.FULL:
        raise typer.Exit(EXIT_NOT_FULL)


@app.command()
def verify(
    inputs: Inputs,
    samples: Annotated[Path, typer.Option("--samples", "-s", help="Samples YAML.")],
    to: Targets,
    option: Options = None,
    source_table: SourceTable = None,
    message_column: MessageColumn = None,
    asim_schema: AsimSchema = None,
    sourcetype: Sourcetype = None,
    require_ground_truth: RequireGroundTruth = False,
    engine: EngineOpt = "emulator",
    runner: RunnerOpt = None,
    report_md: Annotated[
        Path | None, typer.Option("--report", help="Also write a Markdown report here.")
    ] = None,
) -> None:
    """Translate in memory and compare extracted fields on sample logs (exit 2 on mismatch)."""
    try:
        opts = _parse_options(
            option,
            to,
            source_table=source_table,
            message_column=message_column,
            asim_schema=asim_schema,
            sourcetype=sourcetype,
        )
        report = run(
            load_artifacts(inputs),
            to,
            options=opts,
            samples=load_sample_file(samples),
            require_ground_truth=require_ground_truth,
            engine=engine,
            runner_names=runner or [],
            inputs=[str(p) for p in inputs],
        )
    except RosettalogError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    failed = False
    for artifact in report.artifacts:
        for tr in artifact.targets:
            if tr.rule_verification is not None:
                failed |= _echo_rule_verification(artifact.name, tr)
                continue
            v = tr.verification
            if v is None:
                typer.echo(f"{artifact.name} -> {tr.target}: not verified (no output)")
                failed = True
                continue
            truth = ", ".join(f"{k}: {n}" for k, n in v.ground_truth.items())
            typer.echo(
                f"{artifact.name} -> {tr.target}: {v.passed}/{v.total} samples match "
                f"(ground truth: {truth})"
            )
            if v.real_engine:
                typer.echo(f"  real engine: {v.real_engine}")
            for label, error in (("emulation", v.error), ("real engine", v.real_error)):
                if error:
                    typer.secho(f"  {label} error: {error}", fg=typer.colors.RED)
                    failed = True
            for sample in v.samples:
                for c in sample.checks:
                    if not c.ok:
                        failed = True
                        exp = f" expected={c.expected!r}" if c.has_expected else ""
                        real = f" real={c.real!r}" if c.has_real else ""
                        tag = " [EMULATOR DIVERGES FROM REAL ENGINE]" if c.emulator_diverges else ""
                        typer.echo(
                            f"  [{sample.name}] {c.field}: qradar={c.source!r} "
                            f"{tr.target}-emulator={c.target!r}{real}{exp}{tag}"
                        )
    if report_md:
        report_md.write_text(render_markdown(report), encoding="utf-8")
    if failed:
        raise typer.Exit(EXIT_NOT_FULL)


def _echo_rule_verification(name: str, tr: TargetReport) -> bool:
    """Print which events each side matched; return True if anything disagrees."""
    rv = tr.rule_verification
    assert rv is not None
    typer.echo(f"{name} -> {tr.target}: {len(rv.events)} events (ground truth: {rv.ground_truth})")
    if rv.expected is not None:
        typer.echo(f"  expected: {', '.join(rv.expected) or '(none)'}")
    for er in rv.runs:
        engine = f" on {er.engine}" if er.engine else ""
        if er.error is not None:
            typer.secho(f"  {er.name}{engine}: error: {er.error}", fg=typer.colors.RED)
        else:
            typer.echo(f"  {er.name}{engine}: {', '.join(er.hits or []) or '(none)'}")
    problems = [f for f in tr.findings if f.code.startswith("VERIFY_")]
    for f in problems:
        typer.secho(f"  {f.code}: {f.message}", fg=typer.colors.YELLOW)
    return bool(problems)


@app.command()
def inspect(inputs: Inputs) -> None:
    """Print the vendor-neutral IR of the inputs as JSON."""
    try:
        artifacts = load_artifacts(inputs)
    except RosettalogError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    for artifact in artifacts:
        typer.echo(artifact.model_dump_json(indent=2, exclude_none=True))


@app.command()
def plugins() -> None:
    """List installed frontends, backends (with options) and emulators."""
    typer.echo("Frontends (sources):")
    for name, fe in sorted(frontends().items()):
        typer.echo(f"  {name:<12} {fe.description}")
    typer.echo("Backends (targets):")
    for name, be in sorted(backends().items()):
        typer.echo(f"  {name:<12} {be.description}")
        for key, text in be.option_help.items():
            typer.echo(f"      -O {name}.{key}=...  {text}")
    typer.echo("Emulators (verification):")
    for name, em in sorted(emulators().items()):
        typer.echo(f"  {name:<12} {em.engine_note}")
    typer.echo("Real-engine runners (verify --engine real):")
    for name, rn in sorted(runners().items()):
        typer.echo(f"  {name:<12} target={rn.target}  {rn.image}")


@app.command()
def schema() -> None:
    """Print the JSON schema of report.json."""
    typer.echo(json_schema_text(), nl=False)


if __name__ == "__main__":  # pragma: no cover
    app()
