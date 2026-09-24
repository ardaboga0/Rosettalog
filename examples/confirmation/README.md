# QRadar CE confirmation pack

Rosettalog makes a few assumptions where IBM's LSX documentation is silent or ambiguous. Each
one is reported as a PARTIAL finding. This directory has one **minimal, synthetic** case per
assumption. You load the case into QRadar Community Edition, send its log lines, and record what
QRadar actually does.

**Until results are recorded, the assumed semantics stay unchanged.** Each case's
`samples.yaml` encodes the *current assumption* with
`ground_truth_source: "assumed: …"`. The test suite checks that the source emulator agrees with
it.

## Per case

```
NN-name/
├── extension.xml   # the LSX to upload
├── sample.log      # exactly the lines to send (RFC 3164 syslog, host rl-confirm-NN)
└── samples.yaml    # the same lines + Rosettalog's assumed result
```

## Procedure (per case)

1. **Upload the extension.** Go to *Admin > Log Source Extensions > Add*. Name it
   `rl-confirm-NN`, upload `extension.xml`, and set *Use Condition* to **Parsing Override**.
   Record any upload error exactly as shown; the error itself is a result (cases 11-13).
2. **Create a log source.** Go to *Admin > Log Sources > New*. Type: **Universal DSM**, protocol
   **Syslog**, Log Source Identifier **`rl-confirm-NN`** (the host name in the sample lines), and
   select the extension from step 1. Deploy changes.
3. **Send the lines** from any host that can reach QRadar on UDP 514:
   ```sh
   ./send.sh <qradar-host> NN-name
   ```
4. **Observe.** Use *Log Activity*, filtered to log source `rl-confirm-NN`:
   - **AQL** (*Log Activity > Advanced Search*):
     ```sql
     SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS dt, username, sourceport,
            QIDNAME(qid) AS qid_name, severity, UTF8(payload) AS payload
     FROM events WHERE LOGSOURCENAME(logsourceid) = 'rl-confirm-NN' LAST 1 HOURS
     ```
   - **EventName / EventCategory:** open an event and choose **Map Event**. The dialog shows the
     event ID and category that the extension extracted. Labels vary between versions; record
     what you see.
   - **Severity:** the event details' *Severity* (event-match cases).
5. **Record** the results in a copy of [`RESULTS-TEMPLATE.md`](RESULTS-TEMPLATE.md). Optionally,
   put the observed values into the case's `samples.yaml`, set
   `ground_truth_source: "observed on QRadar CE <version>"`, and run:
   ```sh
   rosettalog verify examples/confirmation/NN-name/extension.xml \
       -s examples/confirmation/NN-name/samples.yaml --to sentinel --to splunk
   ```
   `tests/unit/test_ground_truth.py` then fails for every assumption that turned out to be wrong.
   That failure is the signal to change the frontend and its finding.

**Caveats when reading results**

- QRadar fills some properties with defaults when the extension extracts nothing. For example,
  `sourceport` can show 0, and IP fields can show 0.0.0.0 or the log source address. Record the
  literal value; "0 / empty" is interpreted as "no value".
- For `devicetime`, note the console and user time zone. If DeviceTime is not parsed, QRadar
  falls back to another time, so compare against the payload.
- Send each case to its own log source so extensions do not interfere with each other.

## Cases

Generated from `src/rosettalog/frontends/qradar_lsx/assumptions.yaml` and each case's
`samples.yaml`. "Assumed" is what Rosettalog does today; the alternatives are the other plausible
behaviours the case can tell apart.

<!-- BEGIN GENERATED: confirmation-cases (from src/rosettalog/frontends/qradar_lsx/assumptions.yaml; regenerate with `uv run python -m rosettalog.frontends.qradar_lsx.docs_sync`) -->
| Case | Assumption | Question | Lines sent → assumed result (from `samples.yaml`) | Assumed behaviour | Alternatives to look for | Status |
|---|---|---|---|---|---|---|
| [01](01-matchgroup-selection) | A01 | With several match groups, which one applies? | 1: `evt=ALPHA user=u1 acct=a1 port=1111` → EventName=`ALPHA`, UserName=`u1`, SourcePort=(none)<br>2: `evt=BETA user=u2 acct=a2 port=2222` → EventName=`BETA`, UserName=`a2`, SourcePort=`2222`<br>3: `user=u3 acct=a3 port=3333` → EventName=(none), UserName=(none), SourcePort=(none) | The first group (by order) whose EventName pattern matches is applied (any of its patterns if it has no EventName). Only that group is applied; groups do not merge. | Groups merge (line 1 gets SourcePort 1111); the last group wins (line 1: a1); a group applies without an EventName match (line 3 extracts something). | unconfirmed |
| [02](02-single-group-without-eventname) | A02 | Does a single match group apply when its EventName pattern does not match? | 1: `user=u1` → EventName=(none), UserName=`u1`<br>2: `evt=E2 user=u2` → EventName=`E2`, UserName=`u2` | Yes. The only group is always applied, so other fields are still extracted. | Line 1 gets no UserName (EventName is a prerequisite). | unconfirmed |
| [03](03-event-match-multiple) | A03 | What does event-match-multiple do? | 1: `id=100 kind=foo` → EventName=`100`, EventCategory=`SingleCat`, EventSeverity=`2`<br>2: `kind=foo` → EventName=`foo`, EventCategory=`MultiCat`, EventSeverity=`8`<br>3: `id=200 kind=bar` → EventName=`200`, EventCategory=`MultiCat`, EventSeverity=`8`<br>4: `id=300` → EventName=`300`, EventCategory=(none), EventSeverity=(none) | EventName comes from matchers first, otherwise from the multiple's capture. The multiple's category and severity apply when its pattern matches, unless an event-match-single entry matched the EventName. | The multiple overrides EventName (line 3: bar); it applies only to its own EventName; line 1 gets MultiCat. | unconfirmed |
| [04](04-event-match-single-vs-category) | A04 | Does event-match-single take precedence over an EventCategory matcher? | 1: `id=100 cat=raw` → EventName=`100`, EventCategory=`SingleCat`<br>2: `id=200 cat=raw` → EventName=`200`, EventCategory=`raw` | Yes. It is derived from IBM's docs (EventCategory is "for any event with a category not handled by an event-match-single entity"). | The matcher wins (line 1 gets raw). | unconfirmed |
| [05](05-trim-whitespace-pattern) | A05 | Does trim-whitespace change the pattern? | 1: `evt=T1 user = alice` → EventName=`T1`, UserName=`alice`<br>2: `evt=T2 user=bob` → EventName=`T2`, UserName=(none) | No. The pattern is used exactly as written, whitespace included. | Whitespace is removed from the pattern (line 1 gets no value, line 2 gets bob). | unconfirmed |
| [06](06-trim-whitespace-value) | A06 | Does trim-whitespace (or QRadar in general) trim captured values? | 1: `evt=T3 user=  carol  ;` (contains consecutive spaces) → EventName=`T3`, UserName=`carol` | No. Captured values keep surrounding whitespace. | The value is "carol"; QRadar may also trim every value regardless of the flag. | unconfirmed |
| [07](07-empty-capture-fallback) | A07 | Does an empty capture fall back to the next matcher order? | 1: `evt=E1 u1= u2=bob` → EventName=`E1`, UserName=`bob`<br>2: `evt=E2 u1=alice u2=bob` → EventName=`E2`, UserName=`alice` | Yes. An empty capture counts as "no value", so the next order is tried. | The first matching pattern wins even when its capture is empty (line 1 is empty). | unconfirmed |
| [08](08-substitution-missing-group) | A08 | In a substitution, what does a group that did not participate produce? | 1: `evt=E1 user=alice@corp` → EventName=`E1`, UserName=`corp/alice`<br>2: `evt=E2 user=bob` → EventName=`E2`, UserName=`/bob` | An empty string. For example, the template '\2/\1' applied to "user=bob" (group 2 absent) gives "/bob". | "null/bob", "\2/bob", or no value at all. | unconfirmed |
| [09](09-devicetime-year-timezone-leniency) | A09, A10 | DeviceTime without a year or UTC offset. Which year and time zone are used?<br>How lenient is Joda parsing of ext-data formats? | 1: `evt=E1 ts=Mar 24 10:00:00` → EventName=`E1`, DeviceTime=`2026-03-24T10:00:00.000Z`<br>2: `evt=E2 ts=Mar  4 10:00:00` (contains consecutive spaces) → EventName=`E2`, DeviceTime=(none)<br>3: `evt=E3 ts=mar 24 10:00:00` → EventName=`E3`, DeviceTime=`2026-03-24T10:00:00.000Z` | The current year, interpreted as UTC.<br>Literals match exactly (so "Mar  4" with two spaces does not match "MMM d"); month names are case-insensitive. | A fixed year (1970/2000); the console or log source time zone.<br>Line 2 parses leniently; line 3 (lowercase month) fails. | unconfirmed<br>unconfirmed |
| [10](10-devicetime-two-digit-year) | A11 | How does QRadar expand two-digit years (yy) in ext-data formats? | 1: `evt=E1 d=01/02/26 10:00` → EventName=`E1`, DeviceTime=`2026-02-01T10:00:00.000Z`<br>2: `evt=E2 d=01/02/69 10:00` → EventName=`E2`, DeviceTime=`2069-02-01T10:00:00.000Z`<br>3: `evt=E3 d=01/02/50 10:00` → EventName=`E3`, DeviceTime=`2050-02-01T10:00:00.000Z` | A fixed 2000-2099 window (69 becomes 2069, 50 becomes 2050). This is NOT Joda-Time's documented default. Joda builds 'yy' with appendTwoDigitYear(<current year> - 30), a sliding window from the current year - 80 to + 19 (1946-2045 in 2026: 69 becomes 1969, 50 becomes 1950); see DateTimeFormat.java and DateTimeFormatterBuilder.appendTwoDigitYear in Joda-Time. Kept unchanged until observed on QRadar. | Joda's sliding window (69 -> 1969, 50 -> 1950) or the POSIX strptime pivot (69 -> 1969, 50 -> 2050). Line 3 (year 50) tells all three apart. | unconfirmed |
| [11](11-regex-engine-constructs) | A12 | Does QRadar's default ("Adaptive") pattern engine support possessive quantifiers, lookbehind and backreferences like java.util.regex? | 1: `evt=E1 user=alice p='4242'` → EventName=`E1`, UserName=`alice`, SourcePort=`4242` | Yes. Patterns have java.util.regex semantics regardless of use-default-pattern. | The upload is rejected, or fields are missing. If so, rerun with use-default-pattern="true" and record both results. | unconfirmed |
| [12](12-duplicate-matcher-order) | A13 | Two matchers for one field with the same order. Which wins? | 1: `evt=E1 a=alice b=bob` → EventName=`E1`, UserName=`bob` | Document order; the matcher listed first wins. | The other matcher wins, or the upload is rejected. | unconfirmed |
| [13](13-custom-matcher-field) | A14 | What happens to a matcher with an undocumented field name? | 1: `evt=E1 custom=x1` → EventName=`E1`, MyCustomField=`x1` | It is migrated as a custom field. | The upload is rejected, or the field is silently ignored. | unconfirmed |
| [14](14-substitution-literal-backslash) | A15 | Is literal text in a substitution template (including backslashes) copied verbatim? | 1: `evt=E1 x=alice@corp` → EventName=`E1`, UserName=`alice\\corp` | Yes. There is no escape processing, so '\1\\\2' gives 'alice\\corp'. | "\\" is an escaped backslash, giving alice\corp. | unconfirmed |
| [15](15-payload-includes-syslog-header) | A16 | Are patterns matched against the full payload, including the syslog header? | 1: `evt=E1` → EventName=`E1`, UserName=`rl-confirm-15` | Yes. | Patterns only see the message after the header (no value for line 1). | unconfirmed |
<!-- END GENERATED: confirmation-cases -->

## After you have results

Record them in `src/rosettalog/frontends/qradar_lsx/assumptions.yaml`. Set `status` to
`confirmed` or `refuted` and add `evidence`, then regenerate the docs:

```sh
uv run python -m rosettalog.frontends.qradar_lsx.docs_sync
```

A confirmed **global** assumption then drops out of the "Unconfirmed global assumptions" section
of every report automatically. Also update the case's `samples.yaml` with the observed values
and `ground_truth_source: "observed on QRadar CE <version>"`.
