# G5 + G6 (EQL): temporal correlations - `temporal_ordered` is invalid, `temporal` ignores the timespan

**Recommendation:** one new issue in SigmaHQ/pySigma-backend-elasticsearch. Both come from the
EQL temporal correlation templates. No existing report found (searched: temporal_ordered,
temporal ordered, sample, maxspan, with runs, EQL sequence, EQL temporal). The templates are
unchanged on `main` as of 2026-09-24.

---

**Title:** EQL: `temporal_ordered` produces an invalid query, and `temporal` (`sample`) ignores the timespan

**Body:**

> **Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1 (templates unchanged on
> `main`), Elasticsearch 9.5.4 (`docker.elastic.co/elasticsearch/elasticsearch:9.5.4`). No
> processing pipeline. Queries run with `_eql/search` on an index with `keyword` fields and
> `@timestamp`.
>
> **Base rules** (for both cases):
> ```yaml
> title: step a
> name: r_a
> logsource: {product: test}
> detection: {sel: {EventName: login_fail}, condition: sel}
> ---
> title: step b
> name: r_b
> logsource: {product: test}
> detection: {sel: {EventName: login_ok}, condition: sel}
> ```
>
> **1. `temporal_ordered` renders invalid EQL.**
> ```yaml
> title: fail then success
> name: seq
> correlation: {type: temporal_ordered, rules: [r_a, r_b], group-by: [src_ip], timespan: 2m}
> ```
> Generated:
> ```
> sequence by src_ip with maxspan=2m
>  [any where EventName:"login_fail"]
>  [any where EventName:"login_ok"] by  with runs=2
> ```
> Elasticsearch rejects it: `parsing_exception: line 3:...: extraneous input 'with' expecting
> {...}`. The trailing `by  with runs=2` comes from the `temporal_ordered` aggregation/condition
> expressions (`by {field}` with an empty field, and `with runs={count}`). An ordered sequence of
> the referenced rules needs neither. The expected query is
> `sequence by src_ip with maxspan=2m [any where ...] [any where ...]`.
>
> **2. `temporal` uses `sample`, which has no time window.**
> ```yaml
> title: config change and login in any order within 10 minutes
> name: cfg_login
> correlation: {type: temporal, rules: [r_a, r_b], group-by: [user], timespan: 10m}
> ```
> Generated:
> ```
> sample by user
>  [any where EventName:"login_fail"]
>  [any where EventName:"login_ok"]
> ```
> The `sample` query has no `maxspan` (or any other time bound), so the `timespan` is lost. Observed: for user `heidi`, with the two events an **hour** apart,
> the query matches, while the Sigma rule (10m) does not. (For users whose events fall within
> 10 minutes it matches correctly.)
>
> **Suggestion:** for (1), render the plain sequence. For (2), raise an error or warning that the
> timespan cannot be enforced (the spec's Compatibility section requires an error for
> unsupported "must" features, and a warning for "should" restrictions), or emulate it
> otherwise.
