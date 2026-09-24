# G7 (EQL): numbers are compared with `:`, which Elasticsearch rejects for numeric fields

**Recommendation:** new issue in SigmaHQ/pySigma-backend-elasticsearch. Related:
[#103](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/103) (open) mentions a
similar EQL error in a comment ("second argument of [:] must be [string], found value [4697] type
[integer]"). That issue is about wildcards on `text` fields, and its type part was split off
into [#109](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/109), which covers
ES|QL and is closed. No open issue tracks EQL numeric equality. `eq_token = ":"` is unchanged on
`main` as of 2026-09-24.

---

**Title:** EQL: numeric values are compared with `:`, rejected by Elasticsearch for numeric fields

**Body:**

> The EQL backend renders every equality with `:` (`eq_token = ":"`), including numbers:
> `dst_port: 22` becomes `any where dst_port:22`. In EQL, `:` is the case-insensitive
> equality for **strings**, and Elasticsearch rejects the query when the field is numeric:
>
> ```
> verification_exception: Found 1 problem
> line 1:11: first argument of [:] must be [string], found value [dst_port] type [long];
> consider using [==] instead
> ```
>
> **Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1, Elasticsearch 9.5.4
> (`docker.elastic.co/elasticsearch/elasticsearch:9.5.4`). No processing pipeline.
>
> **Rule:**
> ```yaml
> title: G7 numeric equality
> logsource: {product: test}
> detection:
>   sel:
>     dst_port: 22
>   condition: sel
> ```
> **Generated:** `any where dst_port:22`
>
> **Index:** `dst_port` mapped as `long` (ECS types ports as `long`). Document:
> `{"dst_port": 22, "@timestamp": "..."}`.
>
> **Expected:** the document matches. **Actual:** HTTP 400 with the error above.
> We observed the same for a `long` field `QID`.
>
> **Suggestion:** use `==` for numeric values (Sigma numbers), and keep `:` for strings.
