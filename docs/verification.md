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

## Real engines: four-way comparison (opt-in)

The emulators are Rosettalog's own code, so they can be wrong. `--engine real` also runs the
**generated content on the real target engine**, in a local container, and compares four
values for every field of every sample:

| Value | Where it comes from | What a difference means |
|---|---|---|
| **QRadar (emulated)** | Source emulator over the IR | Rosettalog's reading of the LSX (assumptions A01–A16 apply) |
| **Target emulator** | Local interpreter of the generated files | The translation as Rosettalog's emulator executes it |
| **Real engine** | The real target engine running the generated files | What the SIEM actually does |
| **Expected** | `expected` in the samples file | Ground truth (see `ground_truth_source`) |

- Target emulator ≠ real engine → **`VERIFY_EMULATOR_DIVERGENCE`**: an *emulator bug*. It is
  reported with the sample and field. Fix the emulator and add a regression test to
  `tests/unit/test_emulator_regressions.py` (container-free, naming the engine version that
  exposed it).
- Real engine ≠ QRadar (emulated) or expected → **`VERIFY_REAL_MISMATCH`**: the translation
  really differs on that engine.
- A value that depends on the engine's clock cannot be compared: for example, a timestamp
  without a year while the samples' `reference_time` is in another year. It is reported as
  **`VERIFY_REAL_NOT_COMPARABLE`** (a note) instead of guessed.
- Each field shows the **scope** of the setting that produced it (index-time, search-time or
  query-time). This matters because, e.g., index-time settings only apply to data ingested after
  deployment.

```sh
rosettalog verify examples/acme_firewall/acme_fw.lsx.xml \
    -s examples/acme_firewall/samples.yaml --to elastic --engine real
uv run pytest -m real_engine --real-engine --real-targets elastic   # differential test suite
```

Only the synthetic samples being verified are sent to the engine. Containers publish their
ports on `127.0.0.1` only, carry the label `rosettalog.verify=1`, and are removed afterwards.
To reuse an engine you already run, set its URL (e.g. `ROSETTALOG_ELASTIC_URL`).

### Runners and pinned images

| Target | Runner | Image (pinned) | Platforms | Resources |
|---|---|---|---|---|
| elastic | `elastic` | `docker.elastic.co/elasticsearch/elasticsearch:9.5.4` (ingest `_simulate` API) | linux/amd64, linux/arm64 (native on Apple Silicon) | ~2 GB RAM (1 GB heap), ~2 GB image |

### Running locally

- **Linux:** Docker Engine; nothing else is needed.
- **macOS (Apple Silicon included):** any Docker runtime. With Colima, amd64-only images (see
  the table) need Rosetta: `colima start --vm-type vz --vz-rosetta --cpu 4 --memory 8`.
- **CI:** `.github/workflows/real-engines.yml` runs the differential suite weekly and on demand
  (`workflow_dispatch` with a `targets` input). The default CI never starts containers.
