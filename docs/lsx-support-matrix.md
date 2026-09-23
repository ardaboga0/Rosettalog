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

| # | Assumption (current behaviour) | Finding emitted | Case |
|---|---|---|---|
| 1 | With several match groups, the first group (by `order`) whose EventName pattern matches is applied (any of its patterns, if it has no EventName). Only that group is applied; groups do not merge. | `LSX_MATCHGROUP_SELECTION_ASSUMED` (PARTIAL) | [01](../examples/confirmation/01-matchgroup-selection) |
| 2 | A single match group applies even when its EventName pattern does not match. | none (global assumption) | [02](../examples/confirmation/02-single-group-without-eventname) |
| 3 | `event-match-multiple`: EventName is taken from matchers first, then from the multiple's capture. Its category and severity apply when its pattern matches and no event-match-single entry matched. | `LSX_EVENT_MATCH_MULTIPLE_ASSUMED` (PARTIAL) | [03](../examples/confirmation/03-event-match-multiple) |
| 4 | `event-match-single` takes precedence over an EventCategory matcher (derived from IBM docs). | none (derived from docs) | [04](../examples/confirmation/04-event-match-single-vs-category) |
| 5 | `trim-whitespace` does not alter the pattern; it is used exactly as written. | `LSX_TRIM_WHITESPACE` (PARTIAL, only when the pattern contains whitespace) | [05](../examples/confirmation/05-trim-whitespace-pattern) |
| 6 | `trim-whitespace` does not trim captured values. | none (global assumption) | [06](../examples/confirmation/06-trim-whitespace-value) |
| 7 | An empty capture counts as "no value", so the next matcher `order` is tried. | none (global assumption) | [07](../examples/confirmation/07-empty-capture-fallback) |
| 8 | In a substitution, a group that did not participate becomes an empty string. | none (global assumption) | [08](../examples/confirmation/08-substitution-missing-group) |
| 9 | DeviceTime without a year uses the current year; without an offset it is treated as UTC. Joda literals match exactly (so `Mar  4` does not match `MMM d`), and month names are case-insensitive. | `DATE_NO_YEAR` (PARTIAL), `DATE_NO_TIMEZONE` (FULL note) | [09](../examples/confirmation/09-devicetime-year-timezone-leniency) |
| 10 | Two-digit years map to 2000-2099. | `DATE_TWO_DIGIT_YEAR` (PARTIAL) | [10](../examples/confirmation/10-devicetime-two-digit-year) |
| 11 | QRadar's default ("Adaptive") pattern engine has java.util.regex semantics, including lookbehind, backreferences and possessive quantifiers. | none (global assumption) | [11](../examples/confirmation/11-regex-engine-constructs) |
| 12 | Matchers for one field that share an `order` are tried in document order. | `LSX_DUPLICATE_ORDER` (PARTIAL) | [12](../examples/confirmation/12-duplicate-matcher-order) |
| 13 | A matcher with an undocumented field name is migrated as a custom field. | `LSX_UNKNOWN_FIELD` (PARTIAL) | [13](../examples/confirmation/13-custom-matcher-field) |
| 14 | Literal text in a substitution template is copied verbatim; `\\` is not an escape. | none (global assumption) | [14](../examples/confirmation/14-substitution-literal-backslash) |
| 15 | Patterns are matched against the full payload, including the syslog header. | none (global assumption) | [15](../examples/confirmation/15-payload-includes-syslog-header) |

Rows marked "none (global assumption)" apply to every artifact and are not reported per
artifact. After confirmation, each will either be dropped (confirmed) or become a correction
plus a finding (refuted).

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
