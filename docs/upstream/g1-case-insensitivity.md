# G1: Sigma's case-insensitive matching is not kept (Lucene, ES|QL)

**Recommendation:** ES|QL is already reported in
[#107](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/107) (open), so add the
reproduction there as a comment (part A). For Lucene, the closest reports are
[#21](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/21) and
[#178](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/178). Both are closed, #178
without a comment, so open a new issue that references them (part B), or reopen #178 if you
prefer.

---

## Part A: comment on #107

> Reproduced with current versions, without any processing pipeline, on a plain `keyword` field.
>
> **Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1, Elasticsearch 9.5.4
> (`docker.elastic.co/elasticsearch/elasticsearch:9.5.4`, single node).
>
> **Rule:**
> ```yaml
> title: G1 contains is case-insensitive
> logsource: {product: test}
> detection:
>   sel:
>     username|contains: adm
>   condition: sel
> ```
> **Generated (ES|QL backend):**
> ```
> from * metadata _id, _index, _version | where username like "*adm*"
> ```
> **Index:** `username` mapped as `keyword`. Documents: `{"username": "sysadmin"}` (d1),
> `{"username": "SysADM"}` (d2).
>
> **Expected:** d1 and d2. Sigma plain and `contains` values are case-insensitive: "All values
> are treated as case-insensitive strings"
> ([rules spec v2.1.0](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)).
> **Actual:** d1 only.

## Part B: new issue (Lucene)

**Title:** Lucene: case-insensitive Sigma values are matched case-sensitively on keyword fields

**Body:**

> Sigma plain and `contains` values are case-insensitive ("All values are treated as
> case-insensitive strings",
> [rules spec v2.1.0](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)).
> The Lucene backend emits a wildcard/term query on the field as is. On a `keyword` field (the
> ECS type of most string fields), that match is case-sensitive, so the query misses values that
> differ only in letter case. Related: #21 and #178 (both closed).
>
> **Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1, Elasticsearch 9.5.4
> (`docker.elastic.co/elasticsearch/elasticsearch:9.5.4`, single node). No processing pipeline.
>
> **Rule:**
> ```yaml
> title: G1 contains is case-insensitive
> logsource: {product: test}
> detection:
>   sel:
>     username|contains: adm
>   condition: sel
> ```
> **Generated:** `username:*adm*`
>
> **Index:** `username` mapped as `keyword`. Documents: `{"username": "sysadmin"}` (d1),
> `{"username": "SysADM"}` (d2). The query was run as a `query_string` query.
>
> **Expected:** d1 and d2. **Actual:** d1 only.
>
> The same happens for plain values (`username: Admin` does not match `admin`). Possible
> directions: the `case_insensitive` option of `wildcard`/`term` queries (query DSL output), or
> documenting that keyword fields need a lowercase normalizer or a caseless subfield via a
> pipeline, as in #178.
