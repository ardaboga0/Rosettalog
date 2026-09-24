# G2: `|re` with `^`/`$` never matches (Lucene, ES|QL)

**Recommendation:** new issue; no existing report found.

---

**Title:** `|re`: `^`/`$` are passed through, but Elasticsearch regexps treat them as literal characters (Lucene, ES|QL, EQL)

**Body:**

> The Lucene and ES|QL backends pass a Sigma regular expression through unchanged
> (`field:/…/`, `rlike "…"`). Elasticsearch's regular expression engine does not support anchors:
> "Lucene's regular expression engine does not support anchor operators, such as `^` (beginning
> of line) or `$` (end of line). To match a term, the regular expression must match the entire
> string" ([regexp syntax](https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax)).
> Two things follow:
>
> 1. `^` and `$` are matched as literal characters, so a Sigma regex starting with `^` or ending
>    with `$` matches (almost) nothing. `^`/`$` are explicitly part of the Sigma regex subset
>    ([modifiers appendix](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md)).
> 2. Unanchored Sigma regexes become whole-value matches (`abc` does not match `xabcx`).
>    SigmaHQ rules generally use `re` with search semantics (anchors where needed).
>
> **Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1, Elasticsearch 9.5.4
> (`docker.elastic.co/elasticsearch/elasticsearch:9.5.4`, single node). No processing pipeline.
>
> **Rule:**
> ```yaml
> title: G2 anchored regex
> logsource: {product: test}
> detection:
>   sel:
>     event_name|re: '^auth_fail[0-9]*$'
>   condition: sel
> ```
> **Generated:**
> - Lucene: `event_name:/^auth_fail[0-9]*$/`
> - ES|QL: `from * metadata _id, _index, _version | where event_name rlike "^auth_fail[0-9]*$"`
>
> **Index:** `event_name` mapped as `keyword`. Documents: `{"event_name": "auth_fail2"}` (d1),
> `{"event_name": "xauth_fail2"}` (d2), `{"event_name": "^auth_fail2$"}` (d3, a control).
>
> | Query | Expected | Actual |
> |---|---|---|
> | generated Lucene / ES\|QL (`^auth_fail[0-9]*$`) | d1 | **d3 only**: the literal value `^auth_fail2$` (no hits without d3) |
> | `auth_fail[0-9]*` without anchors (Lucene and ES\|QL) | – | d1 (whole-value match; d2 not matched) |
>
> Lucene was run as a `query_string` query on the index.
>
> **EQL** has the same root cause: the EQL backend's `regex~` also has to match the whole value.
> With `user|re: 'adm'` (`any where user regex~ "adm"`), `sysadmin` is not matched, while the
> Sigma rule matches it. (That `regex~` is also case-insensitive is a separate issue.)
>
> **Possible fix:** remove a leading `^` / trailing `$`, and wrap unanchored ends in `.*`
> (e.g. `abc` → `.*abc.*`, `^abc` → `abc.*`). This needs care with escaped `\^`/`\$` and with
> alternations at the top level (`^a|b$`).
