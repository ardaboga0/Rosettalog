# Contributing to Rosettalog

Thanks for helping security teams migrate their detection content safely. This guide covers
the development setup, the project rules, and a walkthrough for adding a new target SIEM
(backend).

## Ground rules

1. **Honesty over coverage.** Never drop logic or guess silently. When a construct cannot be
   translated exactly, emit a `Finding`: PARTIAL if output was produced but may differ,
   UNSUPPORTED if it was not translated. Add every new code to
   [docs/findings-codes.md](docs/findings-codes.md); a test enforces this.
2. **Fixture policy.** Test fixtures and examples must be **synthetic** (written by you for
   Rosettalog) or taken from **public documentation**, with the source noted. **Never** commit
   vendor-shipped content (for example IBM's DSMs or content packs), real customer logs, or
   anything containing real hostnames, IPs, user names or secrets. Use documentation ranges
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and fictional vendors.
3. **Defensive scope.** Rosettalog translates detection and parsing content. Contributions that
   evade detection, or that exfiltrate or tamper with data, are out of scope.
4. **The core stays SIEM-agnostic.** `pipeline.py`, `ir/`, `report/` and `verify/harness.py`
   must not import or special-case any frontend or backend.

## Development setup

```bash
uv sync                        # creates .venv with runtime + dev dependencies
uv run pytest                  # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy src                # strict typing
uv run pytest --update-golden  # after an intentional change to generated output
```

Python 3.11+, type hints everywhere (`mypy --strict`), pydantic v2 models, ruff for lint and
format (line length 100). Keep modules small and add docstrings where behaviour is not obvious.

## Pull requests

- One logical change per PR, with tests. For generated-output changes, commit updated golden
  files and explain the diff in the PR description.
- Changing how something is translated? Update `docs/lsx-support-matrix.md`.
- Fill in the PR template checklist, including the fixture-policy confirmation.

## Adding a new backend (target SIEM)

This walkthrough uses a fictional target called `acmesiem`. A backend can live in this
repository (`src/rosettalog/backends/acmesiem/`) or in a separate package. Either way, it is
only registered through entry points.

### 1. Implement the `Backend` protocol

```python
# src/rosettalog/backends/acmesiem/backend.py
from collections.abc import Mapping
from typing import ClassVar

from rosettalog.backends.common import DropTracker, PatternTable, artifact_ready
from rosettalog.ir import Artifact, Finding, Status
from rosettalog.ir.fields import resolve_names
from rosettalog.plugins import BackendResult, GeneratedFile


class AcmeSiemBackend:
    name: ClassVar[str] = "acmesiem"
    description: ClassVar[str] = "AcmeSIEM: parser rules"
    option_help: ClassVar[Mapping[str, str]] = {"index": "Target index name."}

    def supports(self, artifact: Artifact) -> bool:
        return artifact_ready(artifact)  # parser artifacts with an IR

    def generate(self, artifact: Artifact, options: Mapping[str, str]) -> BackendResult:
        spec = artifact.parser
        assert spec is not None
        patterns = PatternTable(spec, "pcre", self.name)  # or "re2"; issues -> findings
        findings = patterns.findings()
        naming = resolve_names(spec.fields(), "cim", target=self.name)
        findings += naming.findings
        ...  # render each FieldRule.expr; report anything you cannot express
        return BackendResult(
            target=self.name,
            artifact_id=artifact.id,
            files=[GeneratedFile(path="parser.acme", content=text)],
            findings=findings,
            field_names={...},  # canonical field -> generated field name
            options=dict(options),  # effective options, used by your emulator
        )
```

Walk the expression tree (`Capture`, `Template`, `Literal_`, `IfMatch`, `Coalesce`, `Lookup`,
`ParseTime`) with `match`. The existing backends are the reference. Every branch that cannot be
expressed must end in a finding. `DropTracker` provides the standard `CANDIDATE_DROPPED` and
`FIELD_NOT_TRANSLATED` findings.

Add a taxonomy for your target (for example ECS) to `src/rosettalog/data/field_map.yaml` and to
`ir.fields.Taxonomy` if the existing `asim`/`cim` names do not fit.

### 2. Register it

```toml
# pyproject.toml
[project.entry-points."rosettalog.backends"]
acmesiem = "rosettalog.backends.acmesiem:AcmeSiemBackend"
```

Run `uv sync` so the entry point is installed, then check `rosettalog plugins`.

### 3. Add an emulator (strongly recommended)

An emulator makes `rosettalog verify` work for your target. It must interpret the generated
files, not your backend's internal state. Otherwise it cannot catch rendering bugs.

```python
class AcmeSiemEmulator:
    target: ClassVar[str] = "acmesiem"
    engine_note: ClassVar[str] = "How faithful this emulation is, in one sentence."

    def __init__(self, result: BackendResult) -> None: ...  # parse result.files
    def extract(self, log: str, *, now: datetime) -> dict[str, str | None]: ...
```

Register it under `[project.entry-points."rosettalog.emulators"]` with the same name. Raise an
error on any construct you do not emulate, so it is never silently skipped. Use the real regex
engine when a Python binding exists (as `google-re2` is used for KQL).

### 4. Test it

- Unit tests for tricky rendering.
- Golden files: add your target to `tests/golden/test_golden.py`, then run
  `pytest --update-golden`.
- The "nothing dropped silently" test in `tests/unit/test_backends.py` should be parametrized
  with your backend.
- Run the synthetic fixtures in `tests/fixtures/lsx/` through `verify`.

### 5. Document it

Add your backend's findings to `docs/findings-codes.md`, add a column to
`docs/lsx-support-matrix.md`, and add a line to the README.

## Adding a frontend (source format)

Implement the `Frontend` protocol (`accepts(path)`, `parse(path) -> list[Artifact]`), register it
under `rosettalog.frontends`, and map source constructs onto the IR. If the IR cannot represent
something, propose an IR extension in an issue first. Frontends must never raise on bad
content: report `UNSUPPORTED` findings instead.

## Reporting translation gaps

Use the **Translation gap** issue template. Include a *minimal, synthetic* snippet that
reproduces the problem, the output you got, and the output you expected.
