# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Vendor-neutral IR for regex-based parsers, with findings (FULL / PARTIAL / UNSUPPORTED).
- QRadar Log Source Extension (LSX) frontend: patterns, match groups, matchers (order,
  capture groups, substitutions, Joda `ext-data` timestamps), event-match-single/multiple.
- Java regex tokenizer and translators to RE2 (KQL) and PCRE (Splunk), reporting every difference.
- Microsoft Sentinel backend: KQL parser function with ASIM field names.
- Splunk backend: props.conf / transforms.conf with CIM field names and timestamp settings.
- Verification harness with local emulators for QRadar semantics, KQL (on RE2) and Splunk .conf.
- Markdown and JSON migration reports; `rosettalog schema` prints the JSON schema.
- CLI: `convert`, `verify`, `inspect`, `plugins`, `schema`.
