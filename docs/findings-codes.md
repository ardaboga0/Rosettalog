# Finding codes

Every translation decision that is not a faithful 1:1 conversion produces a **finding** with a
stable code. Codes never change meaning; new behaviour gets a new code. A finding's `status` is:

- **FULL**: an informational note. The element was translated faithfully.
- **PARTIAL**: output was produced but may behave differently. A human should review it.
- **UNSUPPORTED**: the element was *not* translated. Its logic is missing from the output.

A test (`tests/unit/test_docs.py`) checks that every code emitted by the source tree is listed here.

## Source: QRadar LSX frontend

| Code | Status | Meaning |
|---|---|---|
| `LSX_INVALID_XML` | UNSUPPORTED | The file is not well-formed XML. |
| `LSX_NOT_AN_LSX` | UNSUPPORTED | The root element is not `<device-extension>`. |
| `LSX_NOTHING_TO_TRANSLATE` | UNSUPPORTED | No match group produced a translatable rule. |
| `LSX_UNKNOWN_ELEMENT` | UNSUPPORTED | An element the frontend does not understand. It is never ignored silently. |
| `LSX_UNKNOWN_ATTRIBUTE` | UNSUPPORTED | An attribute the frontend does not understand. |
| `LSX_MISSING_ATTRIBUTE` | UNSUPPORTED | A required attribute is missing, so the element is skipped. |
| `LSX_INVALID_VALUE` | PARTIAL / UNSUPPORTED | The attribute value has the wrong type. Booleans default to false (PARTIAL); other elements are skipped (UNSUPPORTED). |
| `LSX_DUPLICATE_PATTERN` | UNSUPPORTED | A pattern id is defined twice. Only the first definition is used. |
| `LSX_DUPLICATE_ORDER` | PARTIAL | Matchers or match groups share an `order`. Document order breaks the tie. |
| `LSX_UNKNOWN_PATTERN` | UNSUPPORTED | A matcher references an undefined pattern id. |
| `LSX_PATTERN_MARKUP` | UNSUPPORTED | The pattern contains entity references or markup. Entities are never expanded, as an XXE defence. |
| `LSX_CAPTURE_GROUP_OUT_OF_RANGE` | UNSUPPORTED | The capture group does not exist in the pattern. |
| `LSX_UNKNOWN_FIELD` | PARTIAL | The matcher field is not in IBM's documented list. It is migrated as a custom field. |
| `LSX_EXT_DATA_IGNORED` | PARTIAL | `ext-data` appears on a field where it has no documented meaning. |
| `LSX_DEVICETIME_NO_FORMAT` | UNSUPPORTED | DeviceTime has no `ext-data` format. QRadar's automatic date detection cannot be reproduced. |
| `LSX_TRIM_WHITESPACE` | PARTIAL | `trim-whitespace="true"` is set on a pattern that contains whitespace, and IBM's semantics for it are unclear. |
| `LSX_DEVICE_TYPE_OVERRIDE` | PARTIAL | `device-type-id-override` changes QID resolution, which has no target equivalent. |
| `LSX_MATCHER_TYPE_UNSUPPORTED` | UNSUPPORTED | `json-matcher`, `leef-matcher`, `cef-matcher` and `xml-matcher` are not supported yet. |
| `LSX_MATCHGROUP_SELECTION_ASSUMED` | PARTIAL | There are several match groups. The translation assumes the first group whose EventName pattern matches wins. |
| `LSX_EMPTY_MATCH_GROUP` | PARTIAL | The match group yielded no translatable rules. |
| `LSX_EVENT_MATCH_MULTIPLE_ASSUMED` | PARTIAL | The documented semantics of `event-match-multiple` are incomplete, so the interpretation is stated in the message. |
| `LSX_EVENT_MATCH_WITHOUT_EVENTNAME` | UNSUPPORTED | `event-match-single` is used, but no EventName is extracted, so it can never apply. |
| `LSX_SEVERITY_DEFAULTED` | FULL | The severity is outside 1-10. QRadar uses 5, and so does the translation. |
| `LSX_IDENTITY_EVENTS` | UNSUPPORTED | `send-identity` creates QRadar identity events. There is no target equivalent. |
| `LSX_IDENTITY_SUPPRESSED` | FULL | `OverrideAndNeverSend`: nothing needs translating. |
| `LSX_QID_MAPPING_EXTERNAL` | FULL | QID mapping lives outside the LSX. Only raw EventName and EventCategory values are migrated. |
| `NO_FRONTEND` | UNSUPPORTED | No installed frontend recognises the input file. |

## Regular expressions (Java → target engine)

| Code | Status | Meaning |
|---|---|---|
| `REGEX_PARSE_ERROR` | UNSUPPORTED | The Java regex could not be parsed. This includes comments mode `(?x)`. |
| `REGEX_CLASS_SET_OPERATION` | UNSUPPORTED | Java character-class union or intersection (`[a[b]]`, `&&`). |
| `REGEX_UNICODE_PROPERTY` | UNSUPPORTED | A Java-only property such as `\p{javaLowerCase}` or `\p{InGreek}`. |
| `REGEX_UNICODE_SCRIPT` | PARTIAL | `\p{IsX}` is assumed to be a Unicode script name. |
| `REGEX_FLAG_UNSUPPORTED` | UNSUPPORTED | Java flag `U` (UNICODE_CHARACTER_CLASS). |
| `REGEX_FLAG_DROPPED` | PARTIAL | Java flag `u` or `d` was dropped. |
| `RE2_NO_LOOKAROUND` | UNSUPPORTED | RE2 (KQL) has no lookahead or lookbehind. |
| `RE2_NO_BACKREFERENCE` | UNSUPPORTED | RE2 (KQL) has no backreferences. |
| `RE2_NO_G_ANCHOR` | UNSUPPORTED | RE2 has no `\G`. |
| `RE2_REPEAT_LIMIT` | UNSUPPORTED | A counted repetition exceeds 1000. |
| `RE2_COMPILE_ERROR` | UNSUPPORTED | The translated pattern was rejected by the real RE2 engine. |
| `RE2_POSSESSIVE_APPROX` | PARTIAL | A possessive quantifier became greedy, so it may match more. |
| `RE2_ATOMIC_APPROX` | PARTIAL | An atomic group became a plain group, so it may match more. |
| `RE2_END_ANCHOR_APPROX` | PARTIAL | Java `\Z` became `\z`. |
| `RE2_LINEBREAK_APPROX` | PARTIAL | `\R` is emulated without atomicity. |
| `PCRE_VARIABLE_LOOKBEHIND` | PARTIAL | A variable-length lookbehind may be rejected by the target PCRE. |
| `EMULATION_COMPILE_ERROR` | UNSUPPORTED | The pattern cannot be compiled for local emulation. |
| `REGEX_COMPILE_ERROR` | UNSUPPORTED | A generated pattern for an engine without a local compiler (grok) failed Rosettalog's own validity check. This indicates a translator bug; please report it. |
| `ONIG_LOOKBEHIND_NOT_FIXED` | UNSUPPORTED | Oniguruma (grok) needs fixed-width lookbehind; Java allows bounded variable width. An invalid grok pattern would make the whole pipeline unusable, so the candidate is dropped. |
| `ONIG_MULTILINE_ANCHORS` | PARTIAL | The pattern uses Java's MULTILINE flag. `^`/`$` are emitted as Ruby line anchors for the whole pattern, which may differ where the flag was scoped. |

## Timestamps (Joda-Time `ext-data`)

| Code | Status | Meaning |
|---|---|---|
| `DATE_UNSUPPORTED_TOKEN` | UNSUPPORTED | A format letter we cannot reproduce (era, week-year, zone names, and so on). |
| `DATE_INCOMPLETE` | UNSUPPORTED | The format has no month or day. |
| `DATE_NO_YEAR` | PARTIAL | The current year is assumed. |
| `DATE_TWO_DIGIT_YEAR` | PARTIAL | The century pivot differs between engines. |
| `DATE_12H_WITHOUT_AMPM` | PARTIAL | A 12-hour clock without an AM/PM marker. |
| `DATE_TZ_COLON_OFFSET` | PARTIAL | Offset `+hh:mm` maps to Splunk `%:z`. |
| `DATE_NO_TIMEZONE` | FULL | No offset in the format, so timestamps are treated as UTC. |

## Field naming

| Code | Status | Meaning |
|---|---|---|
| `FIELD_UNMAPPED` | PARTIAL | No ASIM or CIM equivalent is defined. The original name is kept. |
| `FIELD_NAME_COLLISION` | PARTIAL | Two source fields map to the same target field. |
| `FIELD_NOT_TRANSLATED` | UNSUPPORTED | No candidate for the field could be expressed in the target. |
| `CANDIDATE_DROPPED` | PARTIAL | One fallback candidate, or a mapping table, was left out. |
| `MATCHGROUP_SELECTOR_UNTRANSLATABLE` | UNSUPPORTED | No pattern selecting the match group is expressible in the target. |
| `TARGET_NOT_APPLICABLE` | UNSUPPORTED | The backend cannot handle this kind of artifact. |

## Microsoft Sentinel backend

| Code | Status | Meaning |
|---|---|---|
| `KQL_COLUMN_OVERWRITE` | PARTIAL | An output column already exists in the source table. |
| `ASIM_MANDATORY_FIELDS` | PARTIAL | With `asim_schema` set, ASIM mandatory fields that the LSX cannot provide are listed. |
| `KQL_STRING_TYPES` | FULL | Values are emitted as strings. Cast them as needed. |

## Splunk backend

| Code | Status | Meaning |
|---|---|---|
| `SPLUNK_SINGLE_TIMESTAMP` | PARTIAL | Only one TIME_FORMAT is allowed per sourcetype, so only the first DeviceTime candidate is used. |
| `SPLUNK_TIME_PREFIX_UNDERIVABLE` | PARTIAL | TIME_PREFIX could not be derived from the pattern. |
| `SPLUNK_TIMESTAMP_UNSUPPORTED` | UNSUPPORTED | The timestamp is not a single capture group. |
| `SPLUNK_INDEX_TIME_DEPENDENCY` | PARTIAL | A translated field (`_time` from DeviceTime) depends on index-time settings (`TIME_PREFIX`, `TIME_FORMAT`). These take effect only on the instance that parses the data (indexer or heavy forwarder), and only for events indexed after deployment. |
| `SPLUNK_EVENT_BREAKING_ASSUMED` | FULL | `SHOULD_LINEMERGE = false` (one event per line) is an index-time setting and only affects newly indexed data. |
| `SPLUNK_INTERMEDIATE_FIELDS` | FULL | `rl_*` helper fields are visible at search time. |

## Elastic backend

| Code | Status | Meaning |
|---|---|---|
| `ELASTIC_INGEST_TIME_DEPENDENCY` | PARTIAL | Fields come from an ingest pipeline. It only processes documents ingested through it after deployment; indexed documents keep their fields. |
| `ELASTIC_DATE_CASE_SENSITIVE` | PARTIAL | The Elasticsearch `date` processor (java.time, STRICT) parses month/day names and AM/PM case-sensitively, but QRadar's Joda parsing is assumed case-insensitive (A10). |
| `ELASTIC_DATE_FIXED_WIDTH` | PARTIAL | Adjacent numeric date fields without a separator must be fixed-width in java.time. |
| `ELASTIC_TEMPLATE_LITERAL` | UNSUPPORTED | Literal text containing `{{` or `}}` would be read as a mustache template by the `set` processor. |
| `ELASTIC_TIMESTAMP_OVERWRITE` | FULL | A parsed DeviceTime replaces any existing `@timestamp`. |
| `ELASTIC_STRING_TYPES` | FULL | Values are strings; the index mapping decides the final types. |

## Verification

| Code | Status | Meaning |
|---|---|---|
| `VERIFY_MISMATCH` | PARTIAL | For a field, the emulated target output differs from the emulated source, or from the expected value, on at least one sample. |
| `VERIFY_EMULATION_ERROR` | PARTIAL | The generated content could not be emulated. |
| `VERIFY_SOURCE_NOT_EMULATED` | PARTIAL | A source pattern could not be emulated, so its fields were not verified. |
| `VERIFY_REAL_MISMATCH` | PARTIAL | On the real target engine (`--engine real`), a field differs from the source semantics or the expected value. |
| `VERIFY_EMULATOR_DIVERGENCE` | PARTIAL | **Emulator bug:** the target emulator disagrees with the real engine for a field. It must be fixed and get a regression test. |
| `VERIFY_REAL_ENGINE_ERROR` | PARTIAL | The real engine could not run the generated content (for example, it rejected it). |
| `VERIFY_REAL_NOT_COMPARABLE` | FULL | A field was not compared with the real engine, e.g. a timestamp without a year while the samples' `reference_time` is in a different year than the engine's clock. |
| `VERIFY_UNKNOWN_EXPECTED_FIELD` | PARTIAL | A sample lists expected values for a field the parser does not produce (probably a typo), so it was not checked. |
