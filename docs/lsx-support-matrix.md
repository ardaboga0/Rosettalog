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
