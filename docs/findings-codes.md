# Finding codes

Every translation decision that is not a faithful 1:1 conversion produces a **finding** with a
stable code. Codes never change meaning; new behaviour gets a new code. A finding's `status` is:

- **FULL**: an informational note. The element was translated faithfully.
- **PARTIAL**: output was produced but may behave differently. A human should review it.
- **UNSUPPORTED**: the element was *not* translated. Its logic is missing from the output.

A test (`tests/unit/test_docs.py`) checks that every code emitted by the source tree is listed here.

Some findings are **linked to an assumption** in the source's assumption registry (e.g. A06, A11).
Their status and text are chosen from the assumption's current status (unconfirmed, confirmed or
refuted) when the report is built, and the text ends with `[Assumption <id>: <status>]`.

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

## Source: Rosettalog IR (`*.ir.json`)

| Code | Status | Meaning |
|---|---|---|
| `IR_INVALID` | UNSUPPORTED | The file is not valid Rosettalog IR. |

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
| `DATE_TWO_DIGIT_YEAR_PIVOT` | PARTIAL / FULL | Per target: how the engine expands two-digit years, compared with QRadar's pivot. **Linked to assumption A11**, so status and text follow its confirmation status. Engines: Joda-Time default (current year −80…+19), Splunk `%y` (standard strptime, 69–99 → 19xx), Elasticsearch `uu` and KQL (2000–2099). |
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
| `SPLUNK_TIMESTAMP_FALLBACK` | PARTIAL | When `TIME_FORMAT` does not match, Splunk falls back to automatic timestamp recognition or the previous event's time, where QRadar leaves DeviceTime unset. |
| `SPLUNK_YEAR_INFERENCE` | PARTIAL | The timestamp format has no year; Splunk infers it from neighbouring events (out-of-order events can be assigned the next year and rejected by `MAX_DAYS_HENCE`). |
| `SPLUNK_VALUE_TRIMMED` | PARTIAL / FULL | Splunk trims surrounding whitespace from extracted values. **Linked to assumption A06**: it only matters if QRadar preserves the whitespace, and the text follows A06's status (FULL once refuted). |
| `SPLUNK_TIME_WINDOW` | PARTIAL | Extracted timestamps older than `MAX_DAYS_AGO` (default 2000 days) or more than `MAX_DAYS_HENCE` (default 2 days) ahead are replaced by the last acceptable event's timestamp. |
| `SPLUNK_KV_MODE_NONE` | FULL | `KV_MODE = none` disables Splunk's automatic key=value extraction for the sourcetype, so only translated fields appear. |
| `SPLUNK_APP_SCOPE` | FULL | Search-time extractions deployed inside an app only apply in that app unless its knowledge objects are exported (`export = system`). |
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

## Sigma backend (detection rules)

| Code | Status | Meaning |
|---|---|---|
| `SIGMA_TEST_DROPPED` | PARTIAL | The finding names the test (its path in the rule). A source test Sigma cannot express (rule/building-block reference, reference data, an untranslatable regex, a test the frontend did not understand) was left out. It is only left out where that makes the rule **broader** (never where it would miss events), so the Sigma rule may match more events than the source rule. |
| `SIGMA_EXCLUSION_DROPPED` | PARTIAL | The dropped test was an exclusion (under NOT): every event it excluded now matches, so the rule may alert far more often than the original. Always comes with `SIGMA_TEST_DROPPED`. |
| `SIGMA_CASE_BROADENED` | PARTIAL/FULL | A case-sensitive equals/contains test is written without `cased`, because every pinned pySigma backend refuses it (G0), so it also matches other letter cases. Linked to rule assumption R01 (FULL if QRadar turns out to be case-insensitive). Under NOT this would narrow the rule, so there the test is dropped instead (`SIGMA_TEST_DROPPED`). |
| `SIGMA_CONDITION_EMPTY` | UNSUPPORTED | Nothing of the rule's condition could be expressed, so no rule was written (it would match every event). |
| `SIGMA_REGEX_UNSUPPORTED` | UNSUPPORTED | The regex needs a construct outside the Sigma `re` subset (lookaround, backreferences, `\b`, possessive/atomic, scoped or mid-pattern flags, Unicode properties). The test is handled as in `SIGMA_TEST_DROPPED`. |
| `SIGMA_REGEX_END_ANCHOR` | PARTIAL | Java `\z` (absolute end) became `$`, which also matches before a final line break. |
| `SIGMA_LOGSOURCE_MAPPED` | FULL | A log source (type) test became the Sigma `logsource`, from the `sigma.logsource_map` you supplied. |
| `SIGMA_LOGSOURCE_UNMAPPED` | PARTIAL | No logsource could be derived. The rule uses `product: qradar`, which names the rule's origin, not a data source. Rosettalog never invents a target logsource. |
| `SIGMA_LOGSOURCE_CONDITION_KEPT` | PARTIAL | A log source (type) test is kept as a test on the pseudo-field `LogSource`/`LogSourceType`, which target events do not have unless you add or map it. |
| `SIGMA_QID_CONDITION` | PARTIAL | A QID test is kept as a test on the pseudo-field `QID`. QIDs are QRadar event identifiers. |
| `SIGMA_LEVEL_MAPPED` | FULL | The event response severity (0-10) became the Sigma `level`. This is a Rosettalog convention (0-1 informational, 2-3 low, 4-6 medium, 7-8 high, 9-10 critical), not an IBM mapping. |
| `SIGMA_LEVEL_NOT_SET` | FULL | The rule has no severity (no event response), so the Sigma rule has no `level`. |
| `SIGMA_RULE_DISABLED` | FULL | The source rule is disabled. Sigma has no enabled flag; this is recorded as `qradar.enabled: false`. |
| `SIGMA_BUILDING_BLOCK` | PARTIAL | A building block became a standalone Sigma rule. In QRadar it never alerts by itself. |
| `SIGMA_RULE_TYPE_UNSUPPORTED` | UNSUPPORTED | Offense rules test offenses, not events. |
| `SIGMA_FLOW_RULE` | PARTIAL | Flow rules need a flow data source and field mapping on the target. |
| `SIGMA_RESPONSE_NOT_REPRESENTABLE` | PARTIAL | A rule response/action (new event, email, reference-set update, ...) has no Sigma equivalent. It is listed, not translated. |
| `SIGMA_TITLE_TRUNCATED` | PARTIAL | The rule name exceeds Sigma's 256-character title limit. |
| `SIGMA_VALIDATION_ISSUE` | FULL/PARTIAL | A pySigma validator reported an issue: FULL for low/informational severity, PARTIAL otherwise. |
| `SIGMA_NOT_VALIDATED` | FULL | pySigma is not installed (extra `sigma`), so the rule was not validated. |

## pySigma conversion

Target queries come from pySigma, not from Rosettalog. These codes name the pySigma backend and
its version; a gap is a limitation of the downstream tool.

| Code | Status | Meaning |
|---|---|---|
| `PYSIGMA_CONVERTED` | FULL | The rule was converted by the named pySigma backend without a processing pipeline, so field names are the Sigma rule's. |
| `PYSIGMA_BACKEND_GAP` | UNSUPPORTED | The pySigma backend refused the rule (e.g. "Case-sensitive string matching is not supported by backend") or returned nothing. |

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
| `VERIFY_RULE_MISMATCH` | PARTIAL | Rule samples: Rosettalog's evaluation of the source rule (IR evaluator) matches different events than the expected hits. |
| `VERIFY_RULE_TARGET_MISMATCH` | PARTIAL | Rule samples: the generated rule (target emulator) or a converted query (real engine) matches different events than the source rule. With `SIGMA_TEST_DROPPED`, extra matches are expected. Missed events are a bug unless a finding explains them. |
| `VERIFY_RULE_DOWNSTREAM_GAP` | PARTIAL | Rule samples: a pySigma query on a real engine matches different events than the Sigma rule itself, so the converter or engine does not implement the Sigma semantics. |
| `VERIFY_RULE_NOT_EVALUABLE` | PARTIAL | Rule samples: a side could not be evaluated (e.g. a rule reference, missing reference data). |
| `VERIFY_UNKNOWN_EXPECTED_FIELD` | PARTIAL | A sample lists expected values for a field the parser does not produce (probably a typo), so it was not checked. |
