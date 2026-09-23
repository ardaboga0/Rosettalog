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

[Unreleased]: https://github.com/ardaboga0/rosettalog/commits/main
