# Rules support matrix (QRadar rules → Sigma → pySigma)

Rosettalog translates QRadar custom rules and building blocks into an IR detection model and
emits **Sigma** rules ([specification v2.1.0](https://github.com/SigmaHQ/sigma-specification)).
Target queries (SPL, KQL, Lucene, ES|QL) come from **pySigma** backends. Rosettalog does not
write its own query renderers, and it does not patch pySigma's output. When a backend refuses a
construct or changes its meaning, that is reported as a gap in the downstream tool.

> [!NOTE]
> **Status (M3a in progress).** The detection IR, the Sigma backend, pySigma validation and
> conversion, and rule verification (IR evaluator, Sigma emulator, real engines) are
> implemented. The **QRadar rule export parser is not yet implemented**. IBM publishes no schema
> for the rule XML inside content-management exports, and its test-parameter encoding must be
> confirmed first. Until then, detection artifacts are read from Rosettalog IR
> (`*.ir.json`, e.g. [`examples/rules/`](../examples/rules/)).

## Rule tests (IR) → Sigma

| IR test | Sigma | Status |
|---|---|---|
| Field equals one of values | `field: [values]`, wildcards escaped; `\|cased` for case-sensitive tests whose values contain letters; integers written as numbers | FULL |
| Field contains | `field\|contains` (+ `\|cased`) | FULL |
| Field matches regex (Java) | `field\|re` in the Sigma regex subset (below), flags as `\|i \|m \|s` | FULL, PARTIAL or UNSUPPORTED per construct |
| AND / OR / NOT | one search identifier per test; the condition keeps the source's structure | FULL |
| Log source / log source type | the Sigma `logsource`, **only** from a `sigma.logsource_map` you provide; otherwise kept as a test on `LogSource`/`LogSourceType` | FULL (mapped) / PARTIAL |
| QID in list | kept as a test on the pseudo-field `QID` | PARTIAL (`SIGMA_QID_CONDITION`) |
| Rule / building-block reference | not yet translated (M3c); dropped, broadening the rule | PARTIAL (`SIGMA_TEST_DROPPED`) |
| Reference set/map test | not translated (M3c: named, with the target mechanism); dropped, broadening the rule | PARTIAL (`SIGMA_TEST_DROPPED`) |
| Test not understood by the frontend | dropped, broadening the rule | PARTIAL (`SIGMA_TEST_DROPPED`) |
| Counters / sequences | M3b (Sigma correlation rules) | not yet |

**Dropping a test only ever broadens a rule.** A test Sigma cannot express counts as *true*
where it counts positively and as *false* under a negation. The Sigma rule may therefore raise
more alerts than the source rule, but it never misses an event the source rule would catch. If
nothing is left, no rule is written (`SIGMA_CONDITION_EMPTY`).

### Regex subset

The Sigma modifiers appendix allows "PCRE with the following metacharacters: `.`, `^ $`,
`* + ? {n,m}`, `[a-z] [^a-z]`, `|`, `()`. Other metacharacters are unsupported"
([appendix](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md)).
The `sigma` dialect of the regex translator therefore:

- expands `\d \w \s` (and their negations) and POSIX `\p{Alpha}`-style classes into explicit
  ASCII classes;
- writes other characters literally and escapes metacharacters;
- turns non-capturing and named groups into plain groups, and lazy quantifiers into greedy ones
  (whether a value matches does not depend on either);
- maps `\A`/`\Z` to `^`/`$`, and `\z` to `$` with a PARTIAL finding;
- turns leading global flags into sub-modifiers;
- reports lookaround, backreferences, `\b`, `\G`, possessive/atomic constructs, scoped or
  mid-pattern flags, and Unicode properties as UNSUPPORTED (`SIGMA_REGEX_UNSUPPORTED`).

### Metadata

| QRadar | Sigma | Note |
|---|---|---|
| name | `title` (256 characters max) | |
| notes | `description` | |
| rule uuid (or id) | `id`: UUIDv5, deterministic | |
| artifact id | `name` | used by correlation rules (M3b) |
| event response severity 0-10 | `level` | **Rosettalog convention**, not an IBM mapping: 0-1 informational, 2-3 low, 4-6 medium, 7-8 high, 9-10 critical |
| severity, credibility, relevance, enabled, building block, rule type, rule id | custom attribute `qradar:` | |
| enabled = false | `qradar.enabled: false` | Sigma has no enabled flag (`SIGMA_RULE_DISABLED`) |
| — | `status: experimental` | migrated rules are untested on the target |
| responses/actions | not translated | each is listed (`SIGMA_RESPONSE_NOT_REPRESENTABLE`) |
| building block | standalone rule | PARTIAL: it would alert on its own (`SIGMA_BUILDING_BLOCK`) |
| offense rule | none | UNSUPPORTED |

### Log sources

pySigma rejects an empty logsource ("Sigma log source can't be empty"), and Rosettalog never
invents a target log source. Without a mapping the rule uses `logsource: {product: qradar}`,
which names where the rule came from (`SIGMA_LOGSOURCE_UNMAPPED`). Provide a mapping with
`-O sigma.logsource_map=map.yaml`:

```yaml
log_source_types:
  Acme Firewall: {category: firewall, product: acme_firewall}
log_sources: {}
```

A mapped log source (type) test that is a top-level, non-negated, single-valued condition moves
into `logsource`; any other one stays in the detection.

### Field names

Canonical (QRadar) field names map to the Sigma taxonomy's `category: firewall` names where one
exists (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `username`;
[taxonomy](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md)).
Every other field keeps its name (`FIELD_UNMAPPED`). Map it in your pySigma processing pipeline.

## pySigma backends (pinned)

`pip install 'rosettalog[sigma-backends]'` installs `pysigma==1.5.1`,
`pysigma-backend-splunk==2.1.0`, `pysigma-backend-kusto==1.0.1` and
`pysigma-backend-elasticsearch==2.1.1`. Convert with
`-O sigma.pysigma_targets=splunk,kusto,lucene,esql`. Conversion runs without a processing
pipeline (`PYSIGMA_CONVERTED`); add your data model's pipeline for production.

### Correlation support (read from the pinned sources; used from M3b)

| Backend | event_count | value_count | temporal | temporal_ordered |
|---|---|---|---|---|
| Splunk (`stats`) | yes, `bin _time span=` (**fixed buckets**, not a sliding window) | yes, fixed buckets | yes, fixed buckets | no |
| Kusto | no correlation support | no | no | no |
| Elasticsearch Lucene | no | no | no | no |
| Elasticsearch ES\|QL (`stats`) | yes, `date_trunc` (fixed buckets) | yes, fixed buckets | yes, fixed buckets | no |
| Elasticsearch EQL | `sequence ... with runs=` | partly | `sample` | `sequence ... maxspan` |

### Known downstream gaps (observed)

Every difference between a converted query on a real engine and the Sigma rule itself is pinned
in `tests/real/test_rules_differential.py` and listed here.

| # | Backend | Construct | Observed | Evidence |
|---|---|---|---|---|
| G0 | all four (splunk 2.1.0, kusto 1.0.1, elasticsearch 2.1.1) | `\|cased` | conversion refused: "Case-sensitive string matching is not supported by backend" (`PYSIGMA_BACKEND_GAP`) | `tests/unit/test_pysigma_gaps.py` |
| G1 | elasticsearch 2.1.1 (lucene, esql) | plain/`contains` values (case-insensitive in Sigma) | matched case-sensitively on keyword fields: `username\|contains: adm` misses `SysADM` | Elasticsearch 9.5.4, `examples/rules` e3 |
| G2 | elasticsearch 2.1.1 (lucene, esql) | `\|re` with `^`/`$` | passed through unchanged, but Lucene regular expressions have no anchors and always match the whole value ([regexp syntax](https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax)): `/^auth.../` matches nothing | Elasticsearch 9.5.4, `examples/rules` e4, e7 |

Splunk 10.4.3 (local) and the Kusto emulator (`real-engines` workflow run 35982350005, x86-64)
agreed with the Sigma rule on every example event.
