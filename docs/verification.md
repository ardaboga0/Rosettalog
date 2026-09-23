# Verification harness

`rosettalog verify` (or `convert --samples`) runs sample logs through two paths and compares the
fields they produce:

1. **Source emulator**: evaluates the IR with Java regex semantics, approximated with the
   Python `regex` module. It stands in for what QRadar would extract.
2. **Target emulator**: parses the **generated files** and executes them:
   - **Sentinel**: a mini KQL interpreter for exactly the operators and functions the backend
     emits. Regexes run on **Google RE2**, the engine Kusto uses. Anything else raises an error.
   - **Splunk**: reads `props.conf` and `transforms.conf`, and applies REPORT transforms, then
     EVALs (evaluated in parallel, as Splunk does), then `TIME_PREFIX`/`TIME_FORMAT`. PCRE is
     approximated with the `regex` module.

Mismatches are reported per sample and per field, and they add `VERIFY_MISMATCH` findings.

## Samples file

```yaml
reference_time: "2026-06-01T00:00:00Z"   # used as "now" (for formats without a year)
samples:
  - name: tcp deny
    log: '<134>Mar 14 09:26:53 fw01 ... action=deny src=10.1.2.3'
    expected:                # optional; canonical (QRadar) field names
      SourceIp: 10.1.2.3
      UserName: null         # asserts "no value"
```

Timestamps are compared in the canonical form `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC).
Empty strings and missing values are treated the same.

## Limits (be aware)

- The emulators are **not** the real engines. They catch regex-dialect problems (RE2 is the
  real RE2), rendering bugs and logic errors, but not every engine quirk. Running against a real
  Splunk or Kusto is planned (milestone M4).
- The source emulator reflects Rosettalog's *reading* of the LSX. Where that reading is an
  assumption, the matching finding says so. `expected` values in samples are the way to anchor
  behaviour to what you observe in QRadar.
- Joda literal matching is exact. Syslog's space-padded day (`Mar  4`) does not match
  `MMM d`, either in QRadar or here.
