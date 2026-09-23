# Rosettalog

**Move your QRadar detection content to another SIEM, and know exactly what did not make it.**

Rosettalog is an open-source, community-driven migration toolkit for SOC and detection
engineering teams leaving IBM QRadar. It parses QRadar artifacts into a vendor-neutral
intermediate representation (IR) and generates content for the target SIEM through
pluggable backends. Every translation gets one of three statuses:

| Status | Meaning |
|---|---|
| **FULL** | Translated faithfully. |
| **PARTIAL** | Usable. The report lists exactly which parts need human review, and why. |
| **UNSUPPORTED** | Not translated. The report says why. Nothing is guessed. |

A trustworthy partial result beats a wrong complete one.

**Parsing migration first; integrate with, don't duplicate, rule converters.** Rosettalog's
focus is migrating *parsing logic* (log source extensions and field extraction), with honest
findings and field-level verification against sample logs. Existing open-source projects already
handle rule and query translation (for example Uncoder.io, pySigma and ARuleCon). Rosettalog
integrates with them instead of competing: AQL queries go to an external translator whose gaps
are recorded as findings, and QRadar rules are exported to Sigma so that pySigma converts them
to target queries.

> Status: **alpha** (milestone M1). Supported today: QRadar **Log Source Extensions** →
> **Microsoft Sentinel** (KQL parser functions, ASIM field names) and **Splunk**
> (props.conf / transforms.conf, CIM field names). Integration with rule and query converters
> is on the [roadmap](#roadmap).

## Quickstart

Requires Python 3.11+.

```bash
git clone https://github.com/rosettalog/rosettalog && cd rosettalog
uv sync                      # or: pip install -e .

# Translate the bundled synthetic example to both targets, verifying against sample logs
uv run rosettalog convert examples/acme_firewall/acme_fw.lsx.xml \
    --to sentinel --to splunk --sourcetype acme:firewall \
    --samples examples/acme_firewall/samples.yaml -o out/
```

```
acme_fw.lsx
  sentinel   PARTIAL     8 item(s) need review, samples 2/4
  splunk     PARTIAL     2 item(s) need review, samples 4/4
```

`out/` now contains:

```
out/
├── report.md                                  ← start here
├── report.json                                ← machine-readable (`rosettalog schema`)
├── sentinel/acme_fw_lsx/AcmeFwLsxParser.kql
└── splunk/acme_fw_lsx/{props.conf,transforms.conf}
```

The report explains, for example, that the example's `UserName` fallback pattern uses a
lookbehind. RE2, which KQL uses, cannot express a lookbehind, so the KQL parser drops that
fallback. The sample that depends on it then fails verification for Sentinel and passes for
Splunk.

### Your own content

```bash
rosettalog convert my_extensions/ --to sentinel --source-table MyDevice_CL --message-column RawData
rosettalog verify my_lsx.xml --samples my_samples.yaml --to splunk   # exit 2 on any mismatch
rosettalog verify ... --require-ground-truth   # every sample needs full `expected` + source
rosettalog inspect my_lsx.xml      # dump the vendor-neutral IR
rosettalog plugins                 # installed sources/targets and their -O options
rosettalog convert ... --strict    # exit 2 unless everything is FULL (useful in CI)
```

Use only content you are allowed to process. Scrub real log samples before sharing them in
issues.

## How it works

```
QRadar LSX ─► frontend ─► IR + findings ─► backend ─► target content + findings ─► report
                              │                              │
                        source emulator ◄── sample logs ──► target emulator ─► per-field diff
```

- **Findings.** Every approximation or gap is a finding with a stable code, for example
  `RE2_NO_LOOKAROUND` or `LSX_MATCHGROUP_SELECTION_ASSUMED`. See
  [docs/findings-codes.md](docs/findings-codes.md).
- **Regex dialects.** Java regexes are tokenized and re-emitted for RE2 or PCRE. Every construct
  that differs between them is reported. See the
  [support matrix](docs/lsx-support-matrix.md).
- **Verification.** Emulators run the *generated* KQL (on real RE2) and the *generated* .conf
  files on your samples, and compare the results field by field with the QRadar semantics and
  with your `expected` values. Each sample records its `ground_truth_source` ("observed on
  QRadar", "derived from IBM docs" or "assumed"), and the report shows it. See
  [docs/verification.md](docs/verification.md).
- **Assumptions are testable.** Where IBM's documentation is ambiguous, Rosettalog states its
  assumption, and every report lists the global ones that are still unconfirmed.
  [`examples/confirmation/`](examples/confirmation/README.md) provides a minimal LSX plus
  sample logs for each one, ready to load into QRadar CE.
- **Deployment scope.** Splunk index-time settings (they affect only newly indexed data) are
  separated from search-time extractions in both the generated props.conf and the report.
- **Architecture.** Frontends and backends are plugins discovered through entry points, so
  adding a SIEM never touches the core. See [docs/architecture.md](docs/architecture.md).

## Roadmap

| Milestone | Scope |
|---|---|
| M0 ✅ | Scaffolding, IR, plugin system, report, CI |
| M1 ✅ | LSX → Sentinel KQL + Splunk props/transforms, report, verification harness |
| M2 | AQL: a documented integration point plus an optional adapter that hands queries to an external translator (e.g. Uncoder) and records its output and gaps as findings. No AQL grammar of our own. |
| M3 | QRadar custom rules and building blocks → IR detection model → **Sigma** only; target conversion is delegated to pySigma |
| M4 | Elastic ingest pipelines; opt-in verification against real Splunk / ADX |
| M5 | Cortex XSIAM (XQL parsing rules) |

## Contributing

New backends, frontends, test fixtures and bug reports are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md). It includes a step-by-step guide for adding a target SIEM,
and the fixture policy: **synthetic or public-documentation content only, never vendor-shipped
DSMs or real customer logs.**

## Scope

Rosettalog is defensive tooling. It helps security teams keep their detection coverage while
changing platforms. It does not connect to any SIEM and sends no data anywhere.

QRadar, Microsoft Sentinel, Splunk and other product names are trademarks of their respective
owners. This project is not affiliated with or endorsed by any of them.

## License

[Apache License 2.0](LICENSE)
