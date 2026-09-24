# Architecture

## Positioning: parsing migration first; integrate with, don't duplicate, rule converters

Rosettalog's core value is migrating **parsing logic** (log source extensions and field
extraction) with honest findings and field-level verification against sample logs. Existing
open-source projects already cover rule and query translation, for example
[Uncoder.io](https://uncoder.io), [pySigma](https://github.com/SigmaHQ/pySigma) and ARuleCon.
Rosettalog does **not** re-implement them:

- **AQL queries (M2):** there is no AQL grammar in Rosettalog. A documented integration point
  hands queries to an external translator. Rosettalog records that translator's output and
  reported gaps as findings in the same migration report.
- **QRadar rules and building blocks (M3):** Rosettalog translates rule logic into an IR
  detection model and emits **Sigma** only. Conversion from Sigma to a target query language is
  delegated to pySigma.

```
 source artifact ──► frontend ──► IR (+ findings) ──► backend ──► target files (+ findings)
  (QRadar LSX)       plugin       vendor-neutral      plugin      (KQL, props/transforms)
                                        │                               │
                                        ▼                               ▼
                               source emulator  ◄── samples ──►  target emulator
                                        └──────── per-field comparison ─┘
                                                        │
                                           report.md / report.json

 planned:  AQL query ──► external translator adapter (M2) ──► output + gaps as findings
           QRadar rule ──► IR detection model ──► Sigma (M3) ──► pySigma ──► target query
```

## Principles

1. **Honesty over coverage.** Each element of each artifact gets one of three statuses:
   translated faithfully, translated with a known difference, or not translated. Every
   difference and every gap is a [finding](findings-codes.md). Nothing is dropped silently.
   Where IBM's documentation is ambiguous, the assumption is registered in one data file per
   frontend (`frontends/qradar_lsx/assumptions.yaml`), and each one has a QRadar CE
   confirmation case. *Per-artifact* assumptions emit a finding where they apply. *Global*
   assumptions are listed in every report's "Unconfirmed global assumptions" section until
   confirmed. The doc tables are generated from the same file (see the
   [support matrix](lsx-support-matrix.md#assumed-behaviours-awaiting-qradar-ce-confirmation)).
2. **Pluggable at both ends.** Frontends, backends and emulators are discovered through entry
   points (`rosettalog.frontends`, `rosettalog.backends`, `rosettalog.emulators`). The core
   (`pipeline.py`, `ir/`, `report/`, `verify/harness.py`) has no knowledge of any specific SIEM.
3. **Verify the artifact you ship.** Target emulators parse the *generated text* rather than
   re-using backend internals, so a rendering bug shows up as a verification mismatch.
4. **Integrate, don't duplicate.** Rule and query translation is delegated to existing
   converters. Rosettalog adds its reporting and verification around them.

## Packages

| Package | Responsibility |
|---|---|
| `rosettalog.ir` | Pydantic IR models, findings and status aggregation, and the canonical field taxonomy (`data/field_map.yaml`). |
| `rosettalog.regex` | Java regex tokenizer, plus translators to RE2, PCRE and Python `regex`. Each translator reports issues. |
| `rosettalog.timefmt` | Joda-Time format parsing, conversion to regex and strptime, and a reference parser. |
| `rosettalog.frontends.qradar_lsx` | LSX XML to IR. XML parsing is hardened: no DTDs, entities or network access. |
| `rosettalog.backends.sentinel` | IR to a KQL parser function with ASIM field names. |
| `rosettalog.backends.splunk` | IR to props.conf and transforms.conf with CIM field names. |
| `rosettalog.backends.elastic` | IR to an Elasticsearch ingest pipeline (grok, set, date, remove) with ECS field names. |
| `rosettalog.regex.grok`, `rosettalog.regex.onig_emulation` | Grok patterns (every group renamed as a named capture) and their Python emulation. |
| `rosettalog.timefmt.javatime` | Joda → java.time patterns for the Elasticsearch `date` processor, and a STRICT, case-sensitive parser for emulation. |
| `rosettalog.verify.real` | Opt-in real-engine runners (entry-point group `rosettalog.runners`) and a small Docker CLI wrapper. |
| `rosettalog.verify` | Sample loading and ground-truth checks, the source emulator (an IR evaluator), target emulators, and the harness. |
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

## Deployment scope of generated content

Backends list every generated setting with the point at which it takes effect
(`BackendResult.settings`). The report shows each scope in its own section:

| Scope | Meaning | Examples |
|---|---|---|
| index-time | Applied while data is ingested, on the instance that parses the data. Affects **only data indexed after deployment**. | Splunk `SHOULD_LINEMERGE`, `TIME_PREFIX`, `TIME_FORMAT` |
| search-time | Applied when searching. Affects all data, including events indexed before deployment. | Splunk `REPORT-`/`EXTRACT-`/`EVAL-`/`FIELDALIAS-` |
| query-time | A saved function or query. Applies to all data it runs over. | Sentinel KQL parser function |

A translated field that depends on index-time configuration gets a finding
(`SPLUNK_INDEX_TIME_DEPENDENCY`, PARTIAL). Its correctness depends on where the setting is
deployed and on when the data was indexed.

### Findings linked to assumptions

Some target differences only matter under a particular source behaviour. For example, Splunk
trims extracted values, but that only differs from QRadar if QRadar preserves whitespace
(assumption A06). Such findings carry `depends_on` with a source-independent **topic**
(`value-whitespace`, `two-digit-year-pivot`) and a status/text variant for each assumption
status. The pipeline looks the topic up in the source frontend's registry and applies the
matching variant, so reports update automatically when an assumption is confirmed or refuted.

## Real-engine runners

`RealEngineRunner` plugins (group `rosettalog.runners`) run the *generated* content on the real
target engine. `rosettalog verify --engine real` uses them, as does the opt-in
`@pytest.mark.real_engine` differential suite:

- Each runner pins its image, reports why it cannot run on the current host
  (`unavailable_reason`), and opens a `session()` that returns field values per sample, or a
  `NotComparable` value when a result cannot be compared.
- Containers publish ports on 127.0.0.1 only, carry the label `rosettalog.verify=1`, and are
  always removed. An existing engine can be reused through an environment variable URL.
- The harness compares four values per field: QRadar (emulated), target emulator, real engine
  and expected. Target emulator ≠ real engine is an emulator bug
  (`VERIFY_EMULATOR_DIVERGENCE`). It must be fixed together with a container-free regression
  test.
- The core stays SIEM-agnostic: the harness only knows the runner protocol.
- Runners today are `elastic` (Elasticsearch 9.5.4), `splunk` (Splunk 10.4.3, amd64),
  `sentinel` (Kusto emulator, x86-64 with AVX2 only) and `sentinel-adx` (opt-in; your Azure Data
  Explorer cluster, the only runner that sends data off the machine). See
  [verification.md](verification.md) for images, platforms and resources.

## Verification and ground truth

The harness compares three values per field and sample: the **source emulator** (QRadar
semantics as Rosettalog understands them), the **target emulator** (the generated files), and
the optional **expected** value from the samples file. Each sample carries a
`ground_truth_source` (for example "observed on QRadar CE 7.5", "derived from IBM docs" or
"assumed"), and the report shows it next to every comparison.

- A match against **assumed** ground truth only shows that the generated content is consistent
  with Rosettalog's reading of the source.
- A match against **observed** ground truth shows that it reproduces QRadar.

`expected` is optional for users. Every sample shipped in `examples/` and used by tests must have
`expected` values covering every field the parser produces, plus a `ground_truth_source`. The
test suite fails otherwise, and `--require-ground-truth` enforces the same rule on the CLI.

### How the QRadar (source) emulator approximates Java regex

QRadar executes LSX patterns with Java regular expressions: `java.util.regex`, or IBM's
"Adaptive Patterns" when `use-default-pattern` is false (confirmation case 11). There is no JVM
in the loop. The source emulator tokenizes each Java pattern, rewrites the Java-only syntax
(`\Q…\E`, `\p{Alpha}` and the other POSIX classes, `\h`, `\v`, `\R`, `\z`, `\Z`, `\uXXXX`,
named backreferences), and runs it with the Python [`regex`](https://pypi.org/project/regex/)
module in **ASCII mode**. ASCII mode matches Java's defaults for `\w \d \s \b` and `(?i)`.

Known differences that remain:

| Area | Java (QRadar) | Emulator (`regex`) |
|---|---|---|
| `.` without DOTALL | excludes `\n`, `\r`, `\u0085`, `\u2028`, `\u2029` | excludes only `\n` |
| `$` without MULTILINE | end of input, or before a final line terminator of any kind | end, or before a final `\n` only |
| `\b` | JDK-version dependent (older JDKs treat some non-ASCII letters as word characters for `\b`) | ASCII |
| Flag `u` (UNICODE_CASE) | Unicode case folding with `(?i)` | dropped (ASCII) and reported as `REGEX_FLAG_DROPPED` |
| Flag `d` (UNIX_LINES) | only `\n` is a line terminator | dropped; `.`, `^` and `$` already treat only `\n` specially |
| Lookbehind | must have a bounded maximum length, otherwise Java rejects the pattern | unbounded lookbehind is accepted, so an invalid Java pattern may still "work" here |
| Invalid patterns in general | rejected by QRadar at upload | the tokenizer rejects what it cannot parse; some invalid Java constructs may still compile |
| Catastrophic backtracking | no timeout (QRadar may time out the pattern) | 2-second timeout per search, then no value |
| "Adaptive Patterns" engine | IBM-internal, undocumented | assumed identical to java.util.regex |
| Joda-Time `ext-data` parsing | Joda `DateTimeFormatter` | reimplemented subset (`rosettalog.timefmt.joda`); unsupported letters are reported |

Target emulators have their own notes: KQL runs on real RE2, and Splunk runs PCRE through
`regex` in ASCII mode. See [verification.md](verification.md).

## Planned integration points (not implemented; M2/M3 need approval)

- **M2, external query translators:** an `rosettalog.query_translators` entry-point group. An
  adapter receives an AQL query and a target, calls the external tool (for example Uncoder's
  open-source core, installed separately), and returns the translated text plus the tool's own
  warnings and unsupported parts. Rosettalog maps these onto findings with the source of truth
  stated (`translator=<name>@<version>`) and never claims more fidelity than the tool reports.
  If no adapter is installed, queries are reported as UNSUPPORTED with a pointer to this
  integration point.
- **M3, rules to Sigma:** QRadar custom rule and building-block exports are parsed into an IR
  detection model and emitted as Sigma rules. Target queries come from pySigma backends. Rule
  tests with no Sigma equivalent (offense handling, reference-set operations, stateful sequence
  tests) become findings.

## Design notes

- The IR models an LSX as an *extraction program*: ordered match groups, each holding field
  rules whose values are expression trees (`Capture`, `Template`, `Coalesce`, `Lookup`,
  `IfMatch`, `ParseTime`, `Literal`). This covers LSX today and should extend to other
  regex-based parser formats.
- Backends render expressions straight to target syntax. They keep the output grammar small and
  deterministic, which is what lets the emulators parse it and what keeps golden tests stable.
- Splunk evaluates `EVAL-` statements in parallel. Shared sub-expressions are therefore inlined
  and never referenced across EVALs. With several match groups, every group's selector appears
  in each `case()`. A group that wins but does not set a field therefore yields no value, instead of leaking a later group's value.
