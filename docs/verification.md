# Verification harness

`rosettalog verify` (or `convert --samples`) runs sample logs through two paths and compares the
fields they produce:

1. **Source emulator**: evaluates the IR with Java regex semantics, approximated with the
   Python `regex` module in ASCII mode. It stands in for what QRadar would extract. The known
   differences from Java are listed in
   [architecture.md](architecture.md#how-the-qradar-source-emulator-approximates-java-regex).
2. **Target emulator**: parses the **generated files** and executes them:
   - **Sentinel**: a mini KQL interpreter for exactly the operators and functions the backend
     emits. Regexes run on **Google RE2**, the engine Kusto uses. Anything else raises an error.
   - **Splunk**: reads `props.conf` and `transforms.conf`, and applies REPORT transforms, then
     EVALs (evaluated in parallel, as Splunk does), then `TIME_PREFIX`/`TIME_FORMAT`. PCRE is
     approximated with the `regex` module in ASCII mode (PCRE's default without UCP).

Mismatches are reported per sample and per field, and they add `VERIFY_MISMATCH` findings.

## Samples file

```yaml
reference_time: "2026-06-01T00:00:00Z"   # used as "now" (for formats without a year)
samples:
  - name: tcp deny
    log: '<134>Mar 14 09:26:53 fw01 ... action=deny src=192.0.2.3'
    ground_truth_source: "observed on QRadar CE 7.5"   # or "derived from IBM docs", "assumed"
    expected:                # optional for users; canonical (QRadar) field names
      SourceIp: 192.0.2.3
      UserName: null         # asserts "no value"
```

### Ground truth

`ground_truth_source` says where the `expected` values come from. The report shows it next to
every comparison and summarises it per target. Be precise:

- A pass against **assumed** values only shows that the generated content agrees with
  Rosettalog's reading of the LSX.
- A pass against values **observed on QRadar** shows that it reproduces QRadar.

`--require-ground-truth` (on `convert` and `verify`) fails unless every sample has
`ground_truth_source` and `expected` values for **every** field the parser produces, and no
unknown fields. The samples shipped in `examples/` and used by the tests are held to this rule by
the test suite. Unknown field names in `expected` are reported as
`VERIFY_UNKNOWN_EXPECTED_FIELD`.

Timestamps are compared in the canonical form `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC).
Empty strings and missing values are treated the same.

## Limits (be aware)

- The emulators are **not** the real engines. They catch regex-dialect problems (RE2 is the
  real RE2), rendering bugs and logic errors, but not every engine quirk. Running against a real
  Splunk or Kusto is planned (milestone M4).
- The source emulator reflects Rosettalog's *reading* of the LSX. Where that reading is an
  assumption, it is listed in the support matrix with a QRadar CE confirmation case
  ([`examples/confirmation/`](../examples/confirmation/README.md)). `expected` values observed
  on QRadar are the way to anchor behaviour to reality.
- Joda literal matching is *assumed* to be exact, so syslog's space-padded day (`Mar  4`) does
  not match `MMM d`. This is unconfirmed; see confirmation case 09.
