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
| Field equals one of values | `field: [values]`, wildcards escaped; integers written as numbers | FULL |
| Field contains | `field\|contains` | FULL |
| Case-sensitive equals/contains (values with letters) | written **without** `\|cased` (the Splunk, Kusto, Lucene and ES\|QL backends refuse it, G0): broader. Under NOT that would narrow the rule, so the test is dropped there instead | PARTIAL (`SIGMA_CASE_BROADENED`, linked to R01; or `SIGMA_TEST_DROPPED` + `SIGMA_EXCLUSION_DROPPED`) |
| Field matches regex (Java) | `field\|re` in the Sigma regex subset (below), flags as `\|i \|m \|s` | FULL, PARTIAL or UNSUPPORTED per construct |
| AND / OR / NOT | one search identifier per test; the condition keeps the source's structure | FULL |
| Log source / log source type | the Sigma `logsource`, **only** from a `sigma.logsource_map` you provide; otherwise kept as a test on `LogSource`/`LogSourceType` | FULL (mapped) / PARTIAL |
| QID in list | kept as a test on the pseudo-field `QID` | PARTIAL (`SIGMA_QID_CONDITION`) |
| Rule / building-block reference | not yet translated (M3c); dropped, broadening the rule | PARTIAL (`SIGMA_TEST_DROPPED`) |
| Reference set/map test | not translated (M3c: named, with the target mechanism); dropped, broadening the rule | PARTIAL (`SIGMA_TEST_DROPPED`) |
| Test not understood by the frontend | dropped, broadening the rule | PARTIAL (`SIGMA_TEST_DROPPED`) |
| Counter: at least N events, same X, within T | a base rule (`<id>_events`) plus an `event_count` correlation (`group-by`, `timespan`, `condition: {gte: N}`), in one multi-document `.yml` | PARTIAL until R04 (sliding window) and, for several fields, R05 (per-combination grouping) are confirmed (`SIGMA_COUNTER_WINDOW`, `SIGMA_COUNTER_GROUPING`) |
| Counter: at least N different values of F | `value_count` correlation with `condition.field` | as above |
| Sequence: steps in order within T | one base rule per step (`<id>_stepN`, the rule's condition AND the step) plus a `temporal_ordered` correlation | PARTIAL until R07 (gaps allowed) and R08 (window from first to last step) are confirmed (`SIGMA_SEQUENCE_GAPS`, `SIGMA_SEQUENCE_WINDOW`) |
| Sequence: steps in any order within T | `temporal` correlation | as above |

**Dropping a test only ever broadens a rule.** A test Sigma cannot express counts as *true*
where it counts positively and as *false* under a negation. The Sigma rule may therefore raise
more alerts than the source rule, but it never misses an event the source rule would catch. If
nothing is left, no rule is written (`SIGMA_CONDITION_EMPTY`).

A broadened rule says so **in the rule file itself**, for users who deploy the `.yml` without
reading the report. Its `description` ends with a "Rosettalog: this rule is BROADER…" note, and
the `qradar:` block has `broader_than_source: true` and `dropped_tests` (each entry has the test
path, what was dropped or made case-insensitive, and whether it was an exclusion). A dropped
exclusion (a test under NOT) also raises `SIGMA_EXCLUSION_DROPPED`: the rule may alert far more
often than the original.

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

## Assumed rule behaviours (awaiting QRadar CE confirmation)

Where IBM's documentation leaves rule semantics open, Rosettalog states what it currently does.
Each assumption has a confirmation case in
[`examples/confirmation-rules/`](../examples/confirmation-rules/README.md). Q1-Q4 (the rule XML
encoding) are not assumptions: the rule-export parser waits for them.

<!-- BEGIN GENERATED: rule-assumptions (from src/rosettalog/frontends/qradar_rules/assumptions.yaml; regenerate with `uv run python -m rosettalog.frontends.qradar_rules.docs_sync`) -->
| ID | Question | Current assumption | Scope / finding | Case | Status |
|---|---|---|---|---|---|
| R01 | Are event-property "equals" and "contains" tests case-sensitive? | Yes, unless the test is marked case-insensitive. Sigma output is written case-insensitively anyway (pySigma backends refuse 'cased'), which makes such rules broader. | per artifact: `SIGMA_CASE_BROADENED` | [01](../examples/confirmation-rules/01-value-case) | unconfirmed |
| R02 | Does a "matches regex" test match anywhere in the value, or must it match the whole value? | Anywhere in the value (java.util.regex find semantics), like LSX patterns. | global: listed in every report while not confirmed | [02](../examples/confirmation-rules/02-regex-find) | unconfirmed |
| R03 | How does a test on a property the event does not have evaluate, and its negation? | The test is false, so its negation is true: an event without a username matches "NOT username equals bob". | global: listed in every report while not confirmed | [03](../examples/confirmation-rules/03-missing-property) | unconfirmed |
| R04 | Is the "in N minutes" window of a counter test sliding, or fixed time buckets? | Sliding: the rule fires when the threshold is reached within any N-minute interval (Sigma correlation windows are sliding as well). | per artifact: `SIGMA_COUNTER_WINDOW` | [04](../examples/confirmation-rules/04-counter-window) | unconfirmed |
| R05 | With "the same Source IP and Username", are events counted per combination of both properties? | Per combination (like Sigma group-by with several fields). | per artifact: `SIGMA_COUNTER_GROUPING` | [05](../examples/confirmation-rules/05-counter-grouping) | unconfirmed |
| R06 | Once a counter's threshold is reached, does the rule fire once, or again for every further event in the window? | Once per group and window, at the event that reaches the threshold (e2). Verification compares which groups alert, not how often, so this only affects the number of alerts. | global: listed in every report while not confirmed | [06](../examples/confirmation-rules/06-counter-firing) | unconfirmed |
| R07 | In a sequence ("in the order"), may other events occur between the steps? | Yes. Only the order of the step events matters (Sigma temporal_ordered). | per artifact: `SIGMA_SEQUENCE_GAPS` | [07](../examples/confirmation-rules/07-sequence-gaps) | unconfirmed |
| R08 | Is a sequence's "within N minutes" measured from the first to the last step? | Yes. All steps must fall within N minutes of the first one (Sigma: all events inside the timespan). | per artifact: `SIGMA_SEQUENCE_WINDOW` | [08](../examples/confirmation-rules/08-sequence-window) | unconfirmed |
<!-- END GENERATED: rule-assumptions -->

## pySigma backends (pinned)

`pip install 'rosettalog[sigma-backends]'` installs `pysigma==1.5.1`,
`pysigma-backend-splunk==2.1.0`, `pysigma-backend-kusto==1.0.1` and
`pysigma-backend-elasticsearch==2.1.1`. Convert with
`-O sigma.pysigma_targets=splunk,kusto,lucene,esql`. Conversion runs without a processing
pipeline (`PYSIGMA_CONVERTED`); add your data model's pipeline for production.

### Correlation support (pinned versions, checked on real engines)

| Backend | event_count | value_count | temporal | temporal_ordered |
|---|---|---|---|---|
| Splunk 2.1.0 (`stats`) | fixed buckets, G3 | fixed buckets, G3 | `multisearch`, fixed buckets, G3 | refused |
| Kusto 1.0.1 | refused (no correlation support) | refused | refused | refused |
| Elasticsearch Lucene | refused | refused | refused | refused |
| Elasticsearch ES\|QL (`stats`) | fixed buckets, G3 | fixed buckets, G3 | fixed buckets, G3 | refused |
| Elasticsearch EQL | `sequence ... with runs=` (agreed on the examples) | **wrong**: joins on the counted field, G4 | `sample`, **no time window**, G6 | **invalid query**, G5 |

"Refused" conversions are reported as `PYSIGMA_BACKEND_GAP` for that backend only; the Sigma rule
is still produced. Fixed buckets are reported at conversion time
(`PYSIGMA_CORRELATION_FIXED_WINDOW`).

### Known downstream gaps (observed)

Every difference between a converted query on a real engine and the Sigma rule itself is pinned
in `tests/real/test_rules_differential.py` and listed here. Upstream reports (drafts, existing
issues, and filed issues) are tracked in [upstream/](upstream/README.md).

| # | Backend | Construct | Observed | Evidence |
|---|---|---|---|---|
| G0 | splunk 2.1.0, kusto 1.0.1, elasticsearch 2.1.1 (lucene, esql; **not** eql) | `\|cased` | conversion refused: "Case-sensitive string matching is not supported by backend". Rosettalog therefore does not emit `cased` (see above) | `tests/unit/test_pysigma_gaps.py` |
| G1 | elasticsearch 2.1.1 (lucene, esql) | plain/`contains` values (case-insensitive in Sigma) | matched case-sensitively on keyword fields: `username\|contains: adm` misses `SysADM` | Elasticsearch 9.5.4, `examples/rules` e3 |
| G2 | elasticsearch 2.1.1 (lucene, esql) | `\|re` with `^`/`$` | passed through unchanged, but Lucene regular expressions have no anchors and always match the whole value ([regexp syntax](https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax)): `/^auth.../` matches nothing | Elasticsearch 9.5.4, `examples/rules` e4, e7 |

| G3 | splunk 2.1.0, elasticsearch 2.1.1 (esql) | correlations | fixed time buckets (`bin _time span=`, `date_trunc`) instead of a sliding window: groups whose events straddle a bucket boundary are missed | Splunk 10.4.3 and Elasticsearch 9.5.4, `examples/rules-stateful` (192.0.2.21, ivan) |
| G4 | elasticsearch 2.1.1 (eql) | `value_count` | `[...] by <field> with runs=N`: N events with the **same** value, not N distinct values | Elasticsearch 9.5.4, `examples/rules-stateful` (alerts on .31, misses .30) |
| G5 | elasticsearch 2.1.1 (eql) | `temporal_ordered` | `... by  with runs=2`: invalid EQL, rejected with a parse error | Elasticsearch 9.5.4, `examples/rules-stateful`, cases 07/08 |
| G6 | elasticsearch 2.1.1 (eql) | `temporal` | `sample by ...` without `maxspan`: the timespan is ignored | Elasticsearch 9.5.4, `examples/rules-stateful` (alerts on heidi, an hour apart) |
| G7 | elasticsearch 2.1.1 (eql) | numeric values | `field:22`; Elasticsearch rejects `:` on numeric fields ("consider using [==] instead") | Elasticsearch 9.5.4, `examples/rules` (dst_port, QID) |
| G8 | elasticsearch 2.1.1 (eql) | `\|re` | rendered with `regex~`, EQL's case-insensitive regex operator (Sigma regexes are case-sensitive); whole-value like G2 | Elasticsearch 9.5.4, case 02 (matches `ADM`, misses `sysadmin`) |

Splunk 10.4.3 (local) and the Kusto emulator (`real-engines` workflow run 35982350005, x86-64)
agreed with the Sigma rule on every single-event example; Splunk also on every correlation apart
from G3. Kusto has no correlation support.
