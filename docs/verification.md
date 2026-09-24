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

## Detection rules

Rule samples are already-parsed events with the rules' expected hits. The file is recognised by
its `events` key:

```yaml
reference_time: 2026-01-05T10:00:00Z
ground_truth_source: assumed          # or "observed on QRadar CE x.y", "derived from IBM docs"
reference_data: {Acme Blocked Hosts: [198.51.100.7]}
events:
  - id: e1
    fields: {SourceIp: 192.0.2.10, UserName: sysadmin}   # canonical names; absent = no value
expected:
  acme_admin_login_test_net: [e1]     # artifact id (or rule name) -> matching event ids
```

For every event up to four answers are compared:

| Answer | Where it comes from |
|---|---|
| **source** | the IR evaluator: Rosettalog's reading of the source rule |
| **target emulator** | the Sigma emulator, which interprets the generated YAML per the Sigma spec |
| **real engines** | each pySigma query (`sigma.pysigma_targets`) run on a real engine (`--engine real`) |
| **expected** | the sample file |

- Source ≠ expected → `VERIFY_RULE_MISMATCH`.
- Sigma rule or query ≠ source → `VERIFY_RULE_TARGET_MISMATCH`. Extra matches are expected when
  tests were dropped (`SIGMA_TEST_DROPPED`); a missed event is a bug unless a finding explains
  it.
- **Counters and sequences** are compared by the **groups they alert on**
  (`SourceIp=192.0.2.20`, or `(all)` without group-by), because that is what the engines'
  aggregation queries return. Rule samples give each event a `time`. The window semantics
  (sliding window, per-combination grouping, gaps allowed in sequences, window from first to
  last step) are in `verify/emulators/windows.py` and follow R04-R08. How *often* a rule fires
  (R06) is not compared.
- Query on a real engine ≠ the Sigma rule → `VERIFY_RULE_DOWNSTREAM_GAP`: pySigma or the engine
  does not implement the Sigma semantics. Known cases are listed in the
  [rules support matrix](rules-support-matrix.md#known-downstream-gaps-observed).

How the engines see the events (the only environment choices Rosettalog makes):

- Field names are the Sigma rule's (canonical names mapped through the `sigma` column), with no
  pySigma pipeline.
- A field whose sample values are all integers is numeric (like ports in a real schema);
  everything else is a string.
- **Splunk:** JSON lines with sourcetype `rl_rules_json` (index-time JSON fields, `_time` from
  the sample time; installed once per session, which costs one restart). They go into a fresh
  index that becomes the admin role's only default search index, so pySigma's query runs
  **unmodified** (`| multisearch` must be the first command), prefixed only by `search`.
- **Kusto:** a `datatable` (string, or `long` for numeric fields; a missing string is empty, as
  in a Log Analytics table) piped into `where <query>`.
- **Elasticsearch:** a temporary index with every string field mapped as `keyword` (the common
  ECS convention) and the sample time as `@timestamp`. Lucene queries run as `query_string`.
  ES|QL queries run unchanged except that pySigma's `from *` is pointed at that index. EQL runs
  through `_eql/search`, with the event category field set to the event id: EQL requires a
  category field, and `any where` does not look at it. The index is always deleted.

```sh
rosettalog verify examples/rules/acme_rules.ir.json -s examples/rules/samples.yaml --to sigma \
    -O sigma.pysigma_targets=splunk,kusto,lucene,esql --engine real
uv run pytest -m real_engine --real-engine tests/real/test_rules_differential.py
```

### Runners and pinned images

| Target | Runner | Image (pinned) | Platforms | Resources |
|---|---|---|---|---|
| elastic | `elastic` | `docker.elastic.co/elasticsearch/elasticsearch:9.5.4` (ingest `_simulate` API) | linux/amd64, linux/arm64 (native on Apple Silicon) | ~2 GB RAM (1 GB heap), ~2 GB image |
| splunk | `splunk` | `splunk/splunk:10.4.3` (REST oneshot input + search export) | linux/amd64 only (Apple Silicon: Rosetta) | ~4 GB RAM, ~1.5 GB image; ~80 s to provision, ~60–80 s per artifact under Rosetta (a restart is needed per artifact) |
| sentinel | `sentinel` (default) | Kusto emulator `mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest@sha256:a44a0015…` (REST `/v1/rest/query`, `/v1/rest/mgmt`) | **linux/amd64 only, x86-64 CPU with SSE4.2/AVX2; ARM is not supported** (Microsoft docs), so it does not run on Apple Silicon, even with Rosetta | ≥ 4 GB RAM (`-m 4G`), image "several GBs"; license: `ACCEPT_EULA=Y` (Microsoft Software License Terms, which forbid benchmarking) |
| sentinel | `sentinel-adx` (opt-in) | Your Azure Data Explorer cluster | any | None locally; **sends the synthetic samples to your cluster** |

**How the Splunk runner reads results.**

- The generated `props.conf`/`transforms.conf` are installed as app `rosettalog_verify`, with
  knowledge objects exported system-wide (without `export = system`, search-time extractions
  in an app apply only inside that app).
- Splunk is restarted, and only then are the samples ingested. Index-time settings
  (`SHOULD_LINEMERGE`, `TIME_PREFIX`, `TIME_FORMAT`) therefore apply to them, just as they would
  for data indexed after deployment.
- `_time` counts as extracted only if Splunk reports `timestartpos`, i.e. it found the timestamp
  in the event. Otherwise it is "no value", not the index time.
- The report's **Scope** column shows, per field, whether it came from an index-time or a
  search-time setting.
- License acceptance uses only the documented variables `SPLUNK_START_ARGS=--accept-license`
  and `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com`. A random admin password is
  generated per run.
- splunkd's TLS certificate is read from the container and pinned; verification is never
  disabled.
- The runner waits for the image's healthcheck (its Ansible provisioning) before touching
  Splunk. Restarting earlier makes the container exit. Restarts use the synchronous
  `splunk restart` CLI inside the container; the REST self-restart sometimes left splunkd down
  under Rosetta.
- **Where to run the full suite:** on Apple Silicon, Splunk runs emulated and needs about a minute
  per artifact, so run a subset locally
  (`-k "splunk and (acme or tessivor)"`) and the full suite through the `real-engines`
  workflow on GitHub's x86-64 runners.
- To reuse a running instance, set `ROSETTALOG_SPLUNK_URL`, `ROSETTALOG_SPLUNK_PASSWORD` and
  `ROSETTALOG_SPLUNK_CONTAINER` (the runner copies files into that container and restarts it).

**Kusto runners.**

- Both runners ingest the samples into a uniquely named temporary table
  (`.set-or-append … <| datatable(…)`). They run the generated file **unmodified**, preceded by
  `let <source_table> = <temp table>;` (a `let` shadows the table name, so none of your tables
  is read or written), and always drop the temporary table.
- **Kusto emulator on Apple Silicon:** not possible. Microsoft states that "ARM processors
  aren't supported" and that the emulator needs SSE4.2/AVX2, which Rosetta does not provide.
  The runner refuses with that reason. Use a Linux x86-64 host, the `real-engines` GitHub
  workflow (ubuntu-latest, x86-64), or the ADX runner.
- **ADX runner (`--runner sentinel-adx`):** set `ROSETTALOG_ADX_CLUSTER` (https URL),
  `ROSETTALOG_ADX_DATABASE` and `ROSETTALOG_ADX_TOKEN` (e.g.
  `az account get-access-token --resource <cluster-url> --query accessToken -o tsv`). The token
  needs rights to create and drop tables in that database. It is the **only** runner that sends
  data off your machine, and it runs only when you set these variables.
  **Status: tested only with a stubbed HTTP layer**; no real ADX cluster has been used yet.

### Two-digit years across engines

| Engine | `yy` / `%y` expansion | Source |
|---|---|---|
| QRadar (Joda-Time `ext-data`) | Rosettalog assumes 2000–2099 (A11, unconfirmed). Joda's documented default is a sliding window from the current year −80 to +19 | Joda `DateTimeFormat.java`, `DateTimeFormatterBuilder.appendTwoDigitYear` |
| Splunk `%y` | 69–99 → 19xx, 00–68 → 20xx (standard strptime). Not documented by Splunk; **measured** on Splunk 10.4.3 with `strptime()`: 50 → 2050, 68 → 2068, 69 → 1969 (`tests/real/test_splunk_year_pivot.py`, real-engines run 35976943392) | Measurement; props.conf reference (TIME_FORMAT = strptime) |
| Elasticsearch `uu` | 2000–2099 (base 2000) | JDK `DateTimeFormatter` |
| KQL (generated) | 2000–2099 (`2000 + yy`, following A11) | Rosettalog |
| Python `strptime` (reference) | 69–99 → 19xx, 00–68 → 20xx | python.org `time` docs |

Each target reports its behaviour as `DATE_TWO_DIGIT_YEAR_PIVOT`, linked to A11. Splunk also
rejects timestamps outside `MAX_DAYS_AGO` (default 2000 days) / `MAX_DAYS_HENCE` (default
2 days) and uses the last acceptable event's time instead (`SPLUNK_TIME_WINDOW`).

### Running locally

- **Linux:** Docker Engine; nothing else is needed.
- **macOS (Apple Silicon included):** any Docker runtime. With Colima, amd64-only images (see
  the table) need Rosetta: `colima start --vm-type vz --vz-rosetta --cpu 4 --memory 8`.
  Elasticsearch runs natively and Splunk runs under Rosetta. The Kusto emulator cannot run (ARM
  is not supported): use the GitHub workflow, a Linux x86-64 host, or `--runner sentinel-adx`.
- **CI:** `.github/workflows/real-engines.yml` runs the differential suite weekly and on demand
  (`workflow_dispatch` with a `targets` input). The default CI never starts containers.
