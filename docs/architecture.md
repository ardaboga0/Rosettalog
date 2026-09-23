# Architecture

```
 source artifact ──► frontend ──► IR (+ findings) ──► backend ──► target files (+ findings)
  (QRadar LSX)       plugin       vendor-neutral      plugin      (KQL, props/transforms)
                                        │                               │
                                        ▼                               ▼
                               source emulator  ◄── samples ──►  target emulator
                                        └──────── per-field comparison ─┘
                                                        │
                                           report.md / report.json
```

## Principles

1. **Honesty over coverage.** Each element of each artifact gets one of three statuses:
   translated faithfully, translated with a known difference, or not translated. Every
   difference and every gap is a [finding](findings-codes.md). Nothing is dropped silently.
   Where IBM's documentation is ambiguous, the assumption is stated as a PARTIAL finding.
2. **Pluggable at both ends.** Frontends, backends and emulators are discovered through entry
   points (`rosettalog.frontends`, `rosettalog.backends`, `rosettalog.emulators`). The core
   (`pipeline.py`, `ir/`, `report/`, `verify/harness.py`) has no knowledge of any specific SIEM.
3. **Verify the artifact you ship.** Target emulators parse the *generated text* rather than
   re-using backend internals, so a rendering bug shows up as a verification mismatch.

## Packages

| Package | Responsibility |
|---|---|
| `rosettalog.ir` | Pydantic IR models, findings and status aggregation, and the canonical field taxonomy (`data/field_map.yaml`). |
| `rosettalog.regex` | Java regex tokenizer, plus translators to RE2, PCRE and Python `regex`. Each translator reports issues. |
| `rosettalog.timefmt` | Joda-Time format parsing, conversion to regex and strptime, and a reference parser. |
| `rosettalog.frontends.qradar_lsx` | LSX XML to IR. XML parsing is hardened: no DTDs, entities or network access. |
| `rosettalog.backends.sentinel` | IR to a KQL parser function with ASIM field names. |
| `rosettalog.backends.splunk` | IR to props.conf and transforms.conf with CIM field names. |
| `rosettalog.verify` | Sample loading, the source emulator (an IR evaluator), target emulators, and the harness. |
| `rosettalog.report` | Report models, JSON (with a schema) and Markdown rendering. |
| `rosettalog.pipeline` | Orchestration: discover inputs, pick frontends, run backends, verify, build the report. |
| `rosettalog.cli` | Typer CLI: `convert`, `verify`, `inspect`, `plugins`, `schema`. |

## Status aggregation

For each artifact and target, the status is computed from the source findings plus the
target findings:

- **UNSUPPORTED** if no usable output was produced, or if there is an artifact-level
  (`path == ""`) UNSUPPORTED finding.
- **PARTIAL** if any finding is PARTIAL or UNSUPPORTED. The report lists exactly which elements
  those findings are about.
- **FULL** otherwise. FULL findings are notes only.

Verification mismatches add `VERIFY_MISMATCH` findings, so a translation that looks complete
but behaves differently on samples is reported as PARTIAL.

## Design notes

- The IR models an LSX as an *extraction program*: ordered match groups, each holding field
  rules whose values are expression trees (`Capture`, `Template`, `Coalesce`, `Lookup`,
  `IfMatch`, `ParseTime`, `Literal`). This covers LSX today and should extend to other
  regex-based parser formats.
- Backends render expressions straight to target syntax. They keep the output grammar small and
  deterministic, which is what lets the emulators parse it and what keeps golden tests stable.
- Splunk evaluates `EVAL-` statements in parallel. Shared sub-expressions are therefore inlined
  and never referenced across EVALs.
