# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

No release has been tagged yet.

### Added (M4a)
- Elastic backend: Elasticsearch ingest pipeline (grok, set, date, remove) with ECS field names
  (new `ecs` column in `field_map.yaml`).
- `onig` regex dialect for Elastic grok (Oniguruma, Ruby syntax) with explicit ASCII classes,
  lookaround-based `\b`, and rejection of non-fixed-width lookbehind
  (`ONIG_LOOKBEHIND_NOT_FIXED`).
- Joda → java.time date conversion for the `date` processor, with findings for case-sensitive
  text fields and fixed-width numeric fields.
- Elastic emulator (grok/set/date/remove, strict Painless-condition subset).
- Opt-in real-engine verification: `rosettalog verify --engine real`, `RealEngineRunner` plugins,
  the Elasticsearch 9.5.4 runner (`_simulate` API), a four-way comparison in the report, the
  `@pytest.mark.real_engine` differential suite, and the weekly/manual
  `real-engines.yml` workflow.
- New findings: `VERIFY_REAL_MISMATCH`, `VERIFY_EMULATOR_DIVERGENCE`, `VERIFY_REAL_ENGINE_ERROR`,
  `VERIFY_REAL_NOT_COMPARABLE`, `ELASTIC_*` and `ONIG_*`.

### Changed / Fixed (after the first CI real-engine run, run 35937389853)
- The Splunk emulator trims surrounding whitespace from extracted values, as real Splunk does
  (confirmation case 06). New finding `SPLUNK_VALUE_TRIMMED`, linked to assumption A06: it only
  matters if QRadar preserves the whitespace, and its status and text follow A06.
- The Splunk emulator models the `MAX_DAYS_AGO`/`MAX_DAYS_HENCE` window (defaults 2000 / 2 days,
  per props.conf 10.4). Real Splunk replaced `01/02/69` (→ 1969) with another event's time
  (confirmation case 10). New finding `SPLUNK_TIME_WINDOW`. The real runner reports `_time` as
  not comparable when the window verdict depends on today's date.
- Two-digit years were checked against sources:
  - Joda-Time `yy` is a sliding window (current year −80…+19), per DateTimeFormat.java.
  - Python strptime and (assumed) Splunk `%y` use POSIX (69–99 → 19xx).
  - Elasticsearch `uu` and our KQL use 2000–2099.

  The new per-target finding `DATE_TWO_DIGIT_YEAR_PIVOT` is linked to assumption A11 and
  replaces `DATE_TWO_DIGIT_YEAR`. A11 now records that Joda's default differs from the assumed
  2000–2099; behaviour is unchanged until QRadar CE results exist. Confirmation case 10 gains a
  year-50 line that separates the three hypotheses. A real-engine test measures Splunk's `%y`
  pivot.
- Splunk's `%y` pivot was measured on Splunk 10.4.3 (real-engines run 35976943392): 50 → 2050,
  68 → 2068, 69 → 1969, i.e. the POSIX strptime pivot. The Splunk `DATE_TWO_DIGIT_YEAR_PIVOT`
  text now states the measurement instead of an assumption.
- Assumptions can record `evidence_against` while unconfirmed. Reports, report JSON
  (`status_label`) and generated docs show "unconfirmed, evidence against". A11 uses it: Joda's
  default sliding window (1946–2045 in 2026) contradicts the assumed 2000–2099.
- Generic mechanism: findings can depend on a registry assumption by topic
  (`Finding.depends_on`), and the pipeline resolves status and text from the assumption's
  current status.

### Added (M4c)
- Real KQL runners. `sentinel` uses the Kusto emulator (kustainer-linux pinned by digest,
  `ACCEPT_EULA=Y`), is x86-64 with AVX2 only, and refuses ARM hosts with the documented reason.
  `sentinel-adx` is opt-in and uses your Azure Data Explorer cluster via
  `ROSETTALOG_ADX_CLUSTER/_DATABASE/_TOKEN`. Both ingest samples into a random temporary table,
  run the generated KQL unmodified behind `let <table> = <temp>;`, and always drop the table.
- `--runner` option on `rosettalog verify`, and a Sentinel job in the real-engines workflow.
- Not yet run against a real engine: the Kusto emulator cannot run on the development Mac
  (Apple Silicon), and no ADX cluster was available. Both runners are covered by stubbed-HTTP
  unit tests. The CI job is the first real run.

### Added (M4b)
- Real Splunk runner (`splunk/splunk:10.4.3`, amd64): installs the generated app with
  system-wide export, restarts so index-time settings apply, ingests via oneshot and reads
  fields via search export. `_time` counts only with `timestartpos`; splunkd's certificate is
  pinned. It has a weekly/manual workflow job.
- Findings `SPLUNK_KV_MODE_NONE` and `SPLUNK_APP_SCOPE` (notes).
- The runner waits for the image healthcheck and restarts with the CLI. An early REST restart
  aborted provisioning, and the REST self-restart left splunkd down under Rosetta.
- The Docker helper no longer uses `--rm`, so an engine that exits stays inspectable until
  cleanup; `Container.healthy()` fails fast when a container has stopped.

### Fixed (M4b), found by real-Splunk differential testing
- props.conf now sets `KV_MODE = none`. Splunk's default automatic key=value extraction added
  fields QRadar never extracts (e.g. `user`), and the emulator did not model that. The emulator
  now refuses auto KV.
- Named groups are no longer emitted in Splunk `REGEX`. Splunk extracted them as fields and
  skipped `FORMAT $N`, which nulled `EVAL-user` on the Acme sample. The emulator refuses named
  groups.

- Real Splunk timestamps: year-less formats are inferred from event order (an out-of-order
  sample got 2027 and was rejected), and when `TIME_FORMAT` fails Splunk falls back to automatic
  recognition. Both are now reported (`SPLUNK_YEAR_INFERENCE`, `SPLUNK_TIMESTAMP_FALLBACK`, both
  PARTIAL). The runner marks such `_time` values as not comparable instead of reporting a false
  emulator divergence.

### Fixed (M4a)
- The Elastic backend no longer sets `locale: ENGLISH` on date processors. Elasticsearch 9.5.4
  rejects that literal although the docs name it as the default; this was found by the first
  differential run and has a regression test.

### Changed
- Roadmap re-scoped. M2 is now an integration point plus an optional adapter for external AQL
  translators (no AQL grammar). M3 is QRadar rules → Sigma only, with pySigma for targets.
- Splunk props.conf now has separate, commented index-time and search-time sections.
- Emulators run Java and PCRE patterns in ASCII mode, which matches both engines' defaults for
  `\w \d \s \b` and `(?i)`.
- `SPLUNK_INDEX_TIME_SETTINGS` (FULL note) is replaced by `SPLUNK_INDEX_TIME_DEPENDENCY`
  (PARTIAL: `_time` depends on index-time settings that only affect newly indexed data).

- The Globex test fixture is renamed to Tessivor (an invented vendor name; "Globex" is a real
  trading platform).
- The fixture IP policy now allows RFC 5737 and RFC 1918 addresses, plus `0.0.0.0` where it has
  a documented meaning. A test enforces it.

### Fixed
- Splunk: with several match groups, a field extracted only by a later group was applied even
  when an earlier group had been selected. Found by confirmation case 01.

### Added
- `ground_truth_source` per sample, `--require-ground-truth`, and a ground-truth summary in the
  report. Shipped samples must have complete expected values (enforced by tests).
- `BackendResult.settings`: each generated setting is declared as index-time, search-time or
  query-time, and the report lists them in separate sections.
- New findings: `SPLUNK_INDEX_TIME_DEPENDENCY`, `SPLUNK_EVENT_BREAKING_ASSUMED`,
  `VERIFY_UNKNOWN_EXPECTED_FIELD`.
- `examples/confirmation/`: 15 minimal QRadar CE cases covering 16 assumed LSX behaviours.
- Assumption registry (`frontends/qradar_lsx/assumptions.yaml`). Every report has a top-level
  "Unconfirmed global assumptions" section (MD + JSON), and the doc tables are generated from
  the same file.
- Vendor-neutral IR for regex-based parsers, with findings (FULL / PARTIAL / UNSUPPORTED).
- QRadar Log Source Extension (LSX) frontend: patterns, match groups, matchers (order,
  capture groups, substitutions, Joda `ext-data` timestamps), event-match-single/multiple.
- Java regex tokenizer and translators to RE2 (KQL) and PCRE (Splunk), reporting every difference.
- Microsoft Sentinel backend: KQL parser function with ASIM field names.
- Splunk backend: props.conf / transforms.conf with CIM field names and timestamp settings.
- Verification harness with local emulators for QRadar semantics, KQL (on RE2) and Splunk .conf.
- Markdown and JSON migration reports; `rosettalog schema` prints the JSON schema.
- CLI: `convert`, `verify`, `inspect`, `plugins`, `schema`.

[Unreleased]: https://github.com/ardaboga0/Rosettalog/commits/main
