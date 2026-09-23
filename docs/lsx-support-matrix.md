# QRadar LSX support matrix

Based on IBM's public *Log source extensions* documentation. Fixtures in this repository are
synthetic. See [findings-codes.md](findings-codes.md) for the meaning of each code.

## Elements and attributes

| LSX construct | Status | Sentinel (KQL) | Splunk | Notes |
|---|---|---|---|---|
| `<pattern id>` + regex text | ✅ | `extract()` (RE2) | transform `REGEX` (PCRE) | See the regex table below. |
| `case-insensitive="true"` | ✅ | `(?i)` prefix | `(?i)` prefix | |
| `trim-whitespace` | ⚠️ | as written | as written | Semantics unclear (`LSX_TRIM_WHITESPACE`). |
| `use-default-pattern` | ✅ | n/a | n/a | Java regex semantics are assumed either way. |
| `<match-group order description>` | ✅ | | | |
| Several match groups | ⚠️ | `case()` on a selector column | `case(match(_raw,…))` in EVAL | The selection rule is an assumption (`LSX_MATCHGROUP_SELECTION_ASSUMED`). |
| `device-type-id-override` | ⚠️ | ignored | ignored | Only affects QID resolution. |
| `<matcher field pattern-id order capture-group>` | ✅ | | | Order becomes `coalesce()` fallback. |
| `capture-group` omitted (whole match) | ✅ | group 0 | wrapped in a group | |
| `enable-substitutions` (`\1:\2`) | ✅ | `strcat(extract…)` | multi-group `FORMAT` + EVAL concatenation | |
| `ext-data` on DeviceTime (Joda format) | ✅ / ⚠️ | `make_datetime()` | `TIME_PREFIX`/`TIME_FORMAT` | Splunk: one timestamp per sourcetype. |
| DeviceTime without `ext-data` | ❌ | | | `LSX_DEVICETIME_NO_FORMAT` |
| `<event-match-single>` | ✅ | `case()` lookup | `case()` lookup | EventCategory and EventSeverity keyed by EventName. |
| `<event-match-multiple>` | ⚠️ | | | Interpretation stated in `LSX_EVENT_MATCH_MULTIPLE_ASSUMED`. |
| `send-identity` (sending variants) | ❌ | | | No identity-event concept in the targets. |
| `json-matcher`, `leef-matcher`, `cef-matcher`, `xml-matcher` | ❌ | | | Planned. |
| QID map (outside the LSX) | n/a | | | Raw EventName and EventCategory are migrated; export the QID map separately. |

## Assumed behaviours (awaiting QRadar CE confirmation)

IBM's documentation does not settle these points, so Rosettalog makes the assumption below. Each
one has a minimal case in [`examples/confirmation/`](../examples/confirmation/README.md): an LSX
plus sample log lines to load into QRadar CE and observe. **Status: unconfirmed.** The semantics
stay as they are until observed results are recorded.

<!-- BEGIN GENERATED: assumptions (from src/rosettalog/frontends/qradar_lsx/assumptions.yaml; regenerate with `uv run python -m rosettalog.frontends.qradar_lsx.docs_sync`) -->
| ID | Question | Current assumption | Scope / finding | Case | Status |
|---|---|---|---|---|---|
| A01 | With several match groups, which one applies? | The first group (by order) whose EventName pattern matches is applied (any of its patterns if it has no EventName). Only that group is applied; groups do not merge. | per artifact: `LSX_MATCHGROUP_SELECTION_ASSUMED` | [01](../examples/confirmation/01-matchgroup-selection) | unconfirmed |
| A02 | Does a single match group apply when its EventName pattern does not match? | Yes. The only group is always applied, so other fields are still extracted. | global: listed in every report while not confirmed | [02](../examples/confirmation/02-single-group-without-eventname) | unconfirmed |
| A03 | What does event-match-multiple do? | EventName comes from matchers first, otherwise from the multiple's capture. The multiple's category and severity apply when its pattern matches, unless an event-match-single entry matched the EventName. | per artifact: `LSX_EVENT_MATCH_MULTIPLE_ASSUMED` | [03](../examples/confirmation/03-event-match-multiple) | unconfirmed |
| A04 | Does event-match-single take precedence over an EventCategory matcher? | Yes. It is derived from IBM's docs (EventCategory is "for any event with a category not handled by an event-match-single entity"). | global: listed in every report while not confirmed | [04](../examples/confirmation/04-event-match-single-vs-category) | unconfirmed |
| A05 | Does trim-whitespace change the pattern? | No. The pattern is used exactly as written, whitespace included. | per artifact: `LSX_TRIM_WHITESPACE` | [05](../examples/confirmation/05-trim-whitespace-pattern) | unconfirmed |
| A06 | Does trim-whitespace (or QRadar in general) trim captured values? | No. Captured values keep surrounding whitespace. | global: listed in every report while not confirmed | [06](../examples/confirmation/06-trim-whitespace-value) | unconfirmed |
| A07 | Does an empty capture fall back to the next matcher order? | Yes. An empty capture counts as "no value", so the next order is tried. | global: listed in every report while not confirmed | [07](../examples/confirmation/07-empty-capture-fallback) | unconfirmed |
| A08 | In a substitution, what does a group that did not participate produce? | An empty string. For example, the template '\2/\1' applied to "user=bob" (group 2 absent) gives "/bob". | global: listed in every report while not confirmed | [08](../examples/confirmation/08-substitution-missing-group) | unconfirmed |
| A09 | DeviceTime without a year or UTC offset. Which year and time zone are used? | The current year, interpreted as UTC. | per artifact: `DATE_NO_YEAR`, `DATE_NO_TIMEZONE` | [09](../examples/confirmation/09-devicetime-year-timezone-leniency) | unconfirmed |
| A10 | How lenient is Joda parsing of ext-data formats? | Literals match exactly (so "Mar  4" with two spaces does not match "MMM d"); month names are case-insensitive. | global: listed in every report while not confirmed | [09](../examples/confirmation/09-devicetime-year-timezone-leniency) | unconfirmed |
| A11 | How are two-digit years (yy) expanded? | To 2000-2099 (69 becomes 2069). | per artifact: `DATE_TWO_DIGIT_YEAR` | [10](../examples/confirmation/10-devicetime-two-digit-year) | unconfirmed |
| A12 | Does QRadar's default ("Adaptive") pattern engine support possessive quantifiers, lookbehind and backreferences like java.util.regex? | Yes. Patterns have java.util.regex semantics regardless of use-default-pattern. | global: listed in every report while not confirmed | [11](../examples/confirmation/11-regex-engine-constructs) | unconfirmed |
| A13 | Two matchers for one field with the same order. Which wins? | Document order; the matcher listed first wins. | per artifact: `LSX_DUPLICATE_ORDER` | [12](../examples/confirmation/12-duplicate-matcher-order) | unconfirmed |
| A14 | What happens to a matcher with an undocumented field name? | It is migrated as a custom field. | per artifact: `LSX_UNKNOWN_FIELD` | [13](../examples/confirmation/13-custom-matcher-field) | unconfirmed |
| A15 | Is literal text in a substitution template (including backslashes) copied verbatim? | Yes. There is no escape processing, so '\1\\\2' gives 'alice\\corp'. | global: listed in every report while not confirmed | [14](../examples/confirmation/14-substitution-literal-backslash) | unconfirmed |
| A16 | Are patterns matched against the full payload, including the syslog header? | Yes. | global: listed in every report while not confirmed | [15](../examples/confirmation/15-payload-includes-syslog-header) | unconfirmed |
<!-- END GENERATED: assumptions -->

**How assumptions surface.**

- **per artifact:** the listed finding is emitted wherever the construct occurs.
- **global:** the assumption applies to every artifact. Instead of a per-artifact finding, it is
  listed in the "Unconfirmed global assumptions" section of every migration report (Markdown and
  JSON) until its status is `confirmed`.

The table is generated from `src/rosettalog/frontends/qradar_lsx/assumptions.yaml`, the single
source that the report uses too. To record a result, edit that file (`status`, `evidence`) and
regenerate; a test fails if the docs are stale.

## Java regex constructs

| Construct | RE2 (KQL) | PCRE (Splunk) |
|---|---|---|
| Groups, classes, `\d\w\s`, anchors `^ $ \b \A \z`, lazy quantifiers | ✅ | ✅ |
| Named groups `(?<n>…)` | ✅ `(?P<n>…)` | ✅ |
| `\Q…\E`, `\uXXXX`, `\x{…}`, `\0oo`, `\cX`, `\e` | ✅ (rewritten) | ✅ (rewritten) |
| POSIX `\p{Alpha}` and similar (ASCII in Java) | ✅ expanded | ✅ expanded |
| Unicode categories `\p{Lu}` | ✅ | ✅ |
| `\h`, `\v` | ✅ expanded | ✅ |
| `\R` | ⚠️ non-atomic | ✅ |
| Lookahead and lookbehind | ❌ | ✅ (⚠️ variable-length lookbehind) |
| Backreferences | ❌ | ✅ |
| Possessive `*+`, atomic `(?>…)` | ⚠️ made greedy | ✅ |
| `\Z` | ⚠️ becomes `\z` | ✅ |
| `\G` | ❌ | ✅ |
| Flags `i m s` | ✅ | ✅ |
| Flags `u d` | ⚠️ dropped | ⚠️ dropped |
| Flag `U`, comments mode `x`, class union or intersection | ❌ | ❌ |

## Known semantic gaps, not reported per pattern

These differences only show up on unusual input. They are documented here because flagging
them on every pattern would bury the real findings:

- Java's `.` also excludes `\r`, `\u0085`, `\u2028` and `\u2029`, and its `$` also matches before a
  final line terminator of any kind. RE2 and PCRE only treat `\n` specially.
- Java's `\s` includes `\x0B`; RE2's does not.
- Java's `(?i)` is ASCII-only unless `u` is set.
