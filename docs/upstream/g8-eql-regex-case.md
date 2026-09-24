# G8 (EQL): `|re` is rendered with `regex~`, EQL's case-insensitive regex operator

**Recommendation:** new issue in SigmaHQ/pySigma-backend-elasticsearch. No existing report found
(searched: regex~, EQL regex, regex case, insensitive regex). `re_expression` is unchanged on
`main` as of 2026-09-24. EQL regexes must also match the whole value; that part has the same
root cause as G2 and is included in the G2 draft.

---

**Title:** EQL: Sigma `|re` (case-sensitive) is rendered with the case-insensitive `regex~` operator

**Body:**

> Sigma regular expressions are case-sensitive unless the `i` sub-modifier is given: "Regex is
> matched case-sensitive by default"
> ([modifiers appendix](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md)).
> The EQL backend renders `|re` as `field regex~ "..."` (`re_expression`); `regex~` is EQL's
> case-**insensitive** variant of `regex`
> ([EQL syntax](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)). With
> `|re|i` it additionally prefixes `(?i)`.
>
> **Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1, Elasticsearch 9.5.4. No
> processing pipeline.
>
> **Rule:**
> ```yaml
> title: G8 case-sensitive regex
> logsource: {product: test}
> detection:
>   sel:
>     user|re: 'adm'
>   condition: sel
> ```
> **Generated:** `any where user regex~ "adm"`
>
> **Documents** (`user` as `keyword`): `adm` (d1), `ADM` (d2).
>
> **Expected:** d1 only. **Actual:** d1 and d2.
>
> **Suggestion:** render `|re` with `regex`, and `|re|i` with `regex~` (without the `(?i)` prefix).
