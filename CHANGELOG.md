# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-09-24

Cortex XSIAM as a parsing target (M5). The XSIAM output is **emulator-verified only**.

### Added
- **`xsiam` backend: LSX → Cortex XSIAM Parsing Rules (`<name>.xif`)**, with the same
  semantics as the other backends.
  - One INGEST statement, because the rules in a group run independently; match groups are
    selected inside it (A01).
  - `config case_sensitive = true`, one `regexcapture()` per pattern, and
    `coalesce`/`concat`/`if` for fallbacks, substitutions and event mappings.
  - Timestamps are rebuilt from the captured components (month names, 12-hour clock, `yy`, UTC
    offset) and parsed with `%Y-%m-%d %H:%M:%S`. A missing year comes from the ingestion time
    (`XSIAM_YEAR_FROM_INGEST_TIME`).
  - Options `xsiam.vendor`, `xsiam.product` and `xsiam.target_dataset`. Raw columns are the
    snake_case canonical names.
- **Data Model Rules (`<name>.model.xif`)** map the extracted fields to XDM, for the
  schema-verified names in the new `xdm` column of `field_map.yaml`. Ports go through
  `to_integer` and MAC addresses through `arraycreate`. Everything else stays in the raw dataset
  with `FIELD_UNMAPPED`; no XDM names are invented, and a test locks the column to the verified
  list.
- **`xql` regex dialect** (`rosettalog.regex.xql`): RE2, every group renamed `gN` and wrapped in
  `m`, one leading `(?i)`, and XQL string literals spelled as in Palo Alto's shipped content.
- **XSIAM emulator.** It interprets the emitted `.xif` subset (Parsing Rule, then Data Model
  Rule) with real RE2 and raises on anything else. It agrees with the Sentinel emulator on every
  shipped sample set; the one remaining difference (literal backslashes) is reported.
- **XSIAM findings:**
  - `XSIAM_UNVERIFIED_TARGET` (emulator-verified only), `XSIAM_INGEST_TIME_DEPENDENCY` and
    `XSIAM_STRING_LITERAL`.
  - `XSIAM_REGEXCAPTURE_SEMANTICS` (X01), `XSIAM_REGEX_INLINE_FLAGS` (X03) and
    `XSIAM_XDM_INTEGER_NORMALIZATION`, a PARTIAL finding. A port modeled as an XDM Number loses
    its text form (`"0443"` becomes 443), and a non-numeric port is assumed to become null (X05).
  - Informational: `XSIAM_XDM_MAPPED`, `XSIAM_CASE_SENSITIVE`, `XSIAM_NO_HIT_KEEP` and
    `XSIAM_STRING_TYPES`.
- **XSIAM confirmation pack** (`examples/confirmation/xsiam/`). It has one minimal `rule.xif`,
  `sample.log` and `expected.yaml` for each undocumented XSIAM behaviour the output relies on
  (X01-X05), plus instructions for the Parsing Rules editor's Simulate view and `send.sh` for an
  HTTP log collector. The registry is `backends/xsiam/unknowns.yaml`, with the same status
  tracking as the QRadar assumptions. The doc tables are generated from it
  (`python -m rosettalog.backends.xsiam.docs_sync`).
- **Target-side assumption registries.** A backend can provide its own registry
  (`assumptions()`). Findings that depend on a target behaviour follow its status, and every
  report with that target lists its open global entries (X02, X04) under "Unconfirmed global
  assumptions".
- **Opt-in XSIAM tenant runner** (`--runner xsiam`, `verify/real/xsiam.py`). It uses only
  documented interfaces: the HTTP log collector and the XQL API, reading modeled values with
  `datamodel dataset in(...)`.
  - You install the generated rules yourself, since no API exists for that, in a dedicated
    collector and dataset.
  - The dataset is deleted only with `ROSETTALOG_XSIAM_DELETE_DATASET=1`.
  - The `xsiam` job in `real-engines.yml` runs on manual dispatch only, configured from
    repository secrets.
- **XQL for rules: documented gap.** `-O sigma.pysigma_targets=xql` (also `xsiam` or
  `cortexxdr`) fails with an explanation: no pySigma 1.x XQL backend exists. See the known
  limitations.

### Changed
- `field_names` for XSIAM report the XDM name where a field is mapped, and the raw column
  otherwise.
- `resolve_dependencies` accepts several registries (source and target).
- The report's "Unconfirmed global assumptions" section now also covers target behaviour (IDs
  starting with X).
- CI runs the end-to-end example and the installed-wheel check with `--to xsiam`.

### Fixed
Nothing that was in v0.1.0. The problems found while building M5 (the XSIAM emulator's null
tests, and "(KQL)" labels in XSIAM regex findings) never shipped.

### Known limitations
- **XSIAM output is emulator-verified only.** No local XSIAM engine exists. The output was
  checked against Rosettalog's emulator of the documented XQL behaviour, and never on a tenant.
  The tenant runner exists but has **never been run**: it is covered by stubbed-HTTP tests only.
- **Five XSIAM behaviours are unconfirmed** (X01-X05, 2 of them global). They are undocumented,
  so they are inferred from Palo Alto's shipped content. Each has a Simulate case in
  `examples/confirmation/xsiam/`.
- **No XSIAM (XQL) rule conversion.** pySigma-backend-cortexxdr 0.1.5 requires
  `pysigma<1.0.0` (upstream
  [issue #20](https://github.com/7RedViolin/pySigma-backend-cortexxdr/issues/20), open) and has
  no correlation support. Rosettalog pins pySigma 1.5.1 and does not write its own XQL renderer.
- **XDM coverage is partial.** Protocol and severity are `XDM_CONST` enums and stay unmapped, as
  do NAT fields and any other field without a verified XDM name.
- **The QRadar rule-export parser is pending.** It waits for QRadar CE answers to Q1-Q5: the
  test-parameter encoding in the rule XML, test class names, how references are stored, the
  boolean structure, and value semantics. See
  [docs/rules-support-matrix.md](docs/rules-support-matrix.md). Until then, rules must be
  written as `*.ir.json`.
- **Unconfirmed QRadar assumptions.** Wherever IBM's documentation is silent, QRadar's behaviour
  is assumed. Nothing has been observed on QRadar CE yet:
  - 16 LSX assumptions (A01-A16), 9 of them global;
  - 9 rule assumptions (R01-R09), 4 of them global.

  A11 (two-digit years) is "unconfirmed, evidence against".
- **pySigma downstream gaps G0-G8** are unchanged since v0.1.0; see
  [0.1.0](#010---2026-09-24) and
  [docs/rules-support-matrix.md](docs/rules-support-matrix.md#known-downstream-gaps-observed).
- **Real-engine coverage:** the Kusto emulator runs only on x86-64 (CI). The ADX and XSIAM
  runners are covered by stubbed tests only.
- **Distribution:** the package is not on PyPI; install it from source.

## [0.1.0] - 2026-09-24

The first public release. It covers QRadar Log Source Extension (LSX) parsing migration to three
SIEMs, and QRadar-style detection rules → Sigma, with target queries from pySigma. Every
translation is FULL, PARTIAL or UNSUPPORTED, with findings, and can be verified on sample data,
with local emulators or (opt-in) real engines.

### Added

**Parsing migration (LSX)**
- QRadar LSX frontend: patterns, match groups, matchers (order fallback, capture groups,
  substitutions, Joda-Time `ext-data`), event-match-single/multiple. Everything else becomes a
  finding. It uses a hardened XML parser (no entities, no network, no DTD).
- Backends:
  - Microsoft Sentinel: a KQL parser function with ASIM names (`asim_schema` option).
  - Splunk: props.conf / transforms.conf with CIM names. The index-time and search-time
    sections are separate, and every setting has a declared scope.
  - Elastic: an Elasticsearch ingest pipeline (grok, set, date, remove) with ECS names.
- A Java regex tokenizer and translators to RE2 (KQL), PCRE (Splunk), Oniguruma (Elastic grok)
  and Python (emulation). Every semantic difference is reported.
- Joda-Time → strptime (Splunk), java.time (Elastic) and KQL `make_datetime` conversion, with
  findings for year inference, two-digit years, time zones and case-sensitivity.
- Canonical field taxonomy (`data/field_map.yaml`) mapped to ASIM, CIM, ECS and Sigma names.

**Detection rules → Sigma**
- Detection IR (`Artifact(kind="detection")`): boolean conditions over field, log source, QID,
  rule-reference, reference-data and opaque tests; counters (`event_count` / `value_count`)
  and sequences (`temporal` / `temporal_ordered`); building blocks and their references
  (resolved by rule id, uuid or name, with cycle / missing / ambiguous detection).
- `rosettalog-ir` frontend: rules are written as `*.ir.json`, documented for hand-written
  rules in [docs/rules-ir-format.md](docs/rules-ir-format.md). `rosettalog schema --ir` prints
  the JSON Schema.
- Sigma backend (`--to sigma`):
  - The source's boolean structure is kept. Tests Sigma cannot express are dropped **only where
    that broadens the rule**, and the generated `.yml` says so in its `description` and
    `qradar:` block.
  - Building blocks are inlined, or referenced by name from correlations.
  - Reference data is named, together with the target mechanism.
  - The logsource comes only from a user-supplied `sigma.logsource_map` (never invented).
  - Severity becomes the level (a documented convention), and ids are deterministic UUIDv5.
- `sigma` regex dialect (the Sigma `re` subset).
- Optional, pinned pySigma extras (`sigma`, `sigma-backends`: pySigma 1.5.1; Splunk 2.1.0,
  Kusto 1.0.1, Elasticsearch 2.1.1 backends). Rules are validated with every pySigma validator,
  and `-O sigma.pysigma_targets=splunk,kusto,lucene,esql,eql` converts them. Downstream
  refusals and known semantic gaps are findings (`PYSIGMA_*`), never patched.

**Verification**
- Sample-based verification. Parsers are compared per field: QRadar (emulated) vs target
  emulator vs expected. Rules are compared per event (single-event) or per alerting group
  (counters, sequences): source IR evaluator vs Sigma emulator vs expected.
- `ground_truth_source` per sample and `--require-ground-truth`. Shipped samples must be
  complete (enforced by tests).
- Opt-in real-engine verification (`--engine real`, `@pytest.mark.real_engine`, and the
  weekly/manual `real-engines.yml` workflow). The engines run locally and are pinned:
  - Elasticsearch 9.5.4, Splunk 10.4.3, and the Kusto emulator (x86-64 only).
  - An opt-in Azure Data Explorer runner.

  For rules, each pySigma query runs on the matching engine. Emulator-vs-engine divergences are
  treated as emulator bugs, with regression tests.

**Assumptions and reports**
- Assumption registries for LSX (A01-A16) and rules (R01-R09). Each assumption has a QRadar CE
  confirmation case: `examples/confirmation/` (15 LSX cases) and `examples/confirmation-rules/`
  (9 rule cases, timed where needed). Doc tables are generated from the registries.
- Findings can depend on an assumption (`depends_on`), so their status and text follow it.
  Assumptions can record `evidence_against` ("unconfirmed, evidence against").
- Markdown and JSON reports (`rosettalog schema`). Every report lists the unconfirmed global
  assumptions of its source formats.
- CLI: `convert`, `verify`, `inspect`, `plugins`, `schema`. Plugins (frontends, backends,
  emulators, runners) are discovered through entry points.
- Packaging: sdist and wheel via hatchling. The wheel ships the data files (`field_map.yaml`,
  both assumption registries) and a `py.typed` marker. A CI `package` job installs the built
  wheel into a clean venv and runs the examples from it.

### Changed
- Scope: parsing migration first; rules → Sigma only, with target queries from pySigma; AQL
  (M2) as a future integration point for external translators, not an in-house translator.
- Emulators run Java and PCRE patterns in ASCII mode, as both engines do by default for
  `\w \d \s \b` and `(?i)`.
- Case-sensitive rule tests are written without Sigma's `cased`, because the pinned Splunk,
  Kusto, Lucene and ES|QL backends refuse it. This broadens them (`SIGMA_CASE_BROADENED`,
  linked to R01). Under NOT such a test is dropped instead, since it would otherwise narrow the
  rule.
- `PYSIGMA_BACKEND_GAP` is scoped to the backend (`pysigma[<name>]`), so a refused conversion
  does not make the Sigma rule UNSUPPORTED.

### Fixed
These were found during development by confirmation cases and by differential testing against
real engines. Each has a regression test.
- Splunk: with several match groups, a field extracted only by a later group was applied even
  when an earlier group had been selected (confirmation case 01).
- Splunk: props.conf sets `KV_MODE = none`, because automatic key=value extraction added fields
  QRadar never extracts. Named groups are no longer emitted in `REGEX`, because Splunk skipped
  `FORMAT $N`. The emulator now trims values and models `MAX_DAYS_AGO`/`MAX_DAYS_HENCE`, as
  real Splunk does. Splunk's `%y` pivot was measured (POSIX: 69 → 1969).
- Elastic: no `locale: ENGLISH` on date processors (rejected by Elasticsearch 9.5.4).
- Rules: a correlation that references a building block now includes that block's field names
  (the Sigma emulator found no group without them).

### Known limitations
- **The QRadar rule-export parser is pending.** It waits for QRadar CE answers to Q1-Q5: the
  test-parameter encoding in the rule XML, test class names, how references are stored, the
  boolean structure, and value semantics. See
  [docs/rules-support-matrix.md](docs/rules-support-matrix.md). Until then, rules must be
  written as `*.ir.json`.
- **Unconfirmed assumptions.** QRadar's behaviour is assumed wherever IBM's documentation is
  silent. Nothing has been observed on QRadar CE yet:
  - **16 LSX assumptions** (A01-A16), 9 of them global.
  - **9 rule assumptions** (R01-R09), 4 of them global.

  Every report lists the unconfirmed global ones. Help is welcome: see the confirmation packs.
- **A11 is "unconfirmed, evidence against".** Two-digit years (`yy`) are assumed to map to
  2000-2099, but Joda-Time's default is a sliding window (1946-2045 in 2026). Behaviour is
  unchanged until QRadar CE confirms it; the targets' own pivots are reported
  (`DATE_TWO_DIGIT_YEAR_PIVOT`).
- **pySigma downstream gaps** (pinned versions, observed on real engines; details and upstream
  issue drafts in [docs/rules-support-matrix.md](docs/rules-support-matrix.md#known-downstream-gaps-observed)
  and [docs/upstream/](docs/upstream/README.md)):
  - G1: Elasticsearch Lucene / ES|QL match Sigma's case-insensitive values case-sensitively
    (ES|QL: [pySigma-backend-elasticsearch#107](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/107)).
  - G2: Elasticsearch regexes have no `^`/`$` anchors and always match the whole value
    ([draft](docs/upstream/g2-regex-anchors.md)).
  - G3: Splunk and ES|QL correlations use fixed time buckets. The Sigma spec tolerates this but
    asks for a warning, which Rosettalog provides (ES|QL:
    [#182](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/182); Splunk:
    [draft](docs/upstream/g3-splunk-fixed-window.md)).
  - G4: EQL `value_count` counts repeats of one value instead of distinct values
    ([#218](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/218), fixed upstream
    after 2.1.1).
  - G5/G6: EQL `temporal_ordered` produces an invalid query, and `temporal` ignores the timespan
    ([draft](docs/upstream/g5-g6-eql-temporal.md)).
  - G7: EQL compares numbers with `:`, which Elasticsearch rejects
    ([draft](docs/upstream/g7-eql-numeric-colon.md)).
  - G8: EQL renders Sigma regexes with the case-insensitive `regex~`
    ([draft](docs/upstream/g8-eql-regex-case.md)).
  - Also: the Splunk, Kusto, Lucene and ES|QL backends refuse `cased` (G0); Kusto and Lucene
    have no correlation support.
- **Real-engine coverage:** the Kusto emulator runs only on x86-64 (CI). The ADX runner is
  covered by stubbed tests only.
- **Distribution:** the package is not on PyPI; install it from source.

[Unreleased]: https://github.com/ardaboga0/Rosettalog/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ardaboga0/Rosettalog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ardaboga0/Rosettalog/releases/tag/v0.1.0
