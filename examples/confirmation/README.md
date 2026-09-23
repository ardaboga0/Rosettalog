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

The "Assumed" column is what Rosettalog does today. The alternatives are the plausible other
behaviours the case can tell apart.

| Case | Question | Lines (payload after `rltest:`) | Assumed | Alternatives to look for |
|---|---|---|---|---|
| [01](01-matchgroup-selection) | With several match groups, which applies? | 1 `evt=ALPHA user=u1 acct=a1 port=1111`<br>2 `evt=BETA user=u2 acct=a2 port=2222`<br>3 `user=u3 acct=a3 port=3333` | The first group (by order) whose EventName pattern matches is applied, and only that group. 1: UserName=u1, SourcePort none. 2: group 2 (a2, 2222). 3: nothing. | Groups merge (1 gets SourcePort 1111); the last group wins (1: a1); a group applies without an EventName match (3 extracts something). |
| [02](02-single-group-without-eventname) | Does a single group apply when EventName does not match? | 1 `user=u1`<br>2 `evt=E2 user=u2` | Yes: 1 gets UserName=u1 with no EventName. | Line 1 gets no UserName (EventName is a prerequisite). |
| [03](03-event-match-multiple) | What does `event-match-multiple` do? | 1 `id=100 kind=foo`<br>2 `kind=foo`<br>3 `id=200 kind=bar`<br>4 `id=300` | EventName comes from the matcher first, otherwise from the multiple's capture. The category and severity (MultiCat, 8) apply when its pattern matches, unless an event-match-single entry matched. 1: 100/SingleCat/2. 2: foo/MultiCat/8. 3: 200/MultiCat/8. 4: 300, no category. | The multiple overrides EventName (3: bar); the multiple applies only to its own EventName; line 1 gets MultiCat. |
| [04](04-event-match-single-vs-category) | Does event-match-single take precedence over an EventCategory matcher? | 1 `id=100 cat=raw`<br>2 `id=200 cat=raw` | 1: SingleCat; 2: raw. (Derived from IBM docs.) | The matcher wins (1: raw). |
| [05](05-trim-whitespace-pattern) | Does `trim-whitespace` affect the **pattern**? | 1 `evt=T1 user = alice`<br>2 `evt=T2 user=bob` | The pattern is used as written. 1: alice; 2: none. | Whitespace is removed from the pattern (1: none, 2: bob). |
| [06](06-trim-whitespace-value) | Does `trim-whitespace` trim the **value**? | 1 `evt=T3 user=  carol  ;` | Not trimmed: `"  carol  "`. | `carol`. QRadar may also trim every value regardless of the flag. |
| [07](07-empty-capture-fallback) | Does an empty capture fall back to the next matcher `order`? | 1 `evt=E1 u1= u2=bob`<br>2 `evt=E2 u1=alice u2=bob` | 1: bob (empty = no value, so fall back). 2: alice. | 1: empty (the first matching pattern wins even when empty). |
| [08](08-substitution-missing-group) | A substitution referencing a group that did not participate? | 1 `evt=E1 user=alice@corp`<br>2 `evt=E2 user=bob` | 1: `corp/alice`; 2: `/bob`. | 2: `null/bob`, `\2/bob`, or no value. |
| [09](09-devicetime-year-timezone-leniency) | DeviceTime with no year and no offset; is Joda parsing lenient? | 1 `ts=Mar 24 10:00:00`<br>2 `ts=Mar  4 10:00:00` (two spaces)<br>3 `ts=mar 24 10:00:00` | Current year, UTC. 1 and 3 parse (the month name is case-insensitive). 2 does **not** parse, because literals are exact. | A different year (1970/2000); the console/log source time zone is used; 2 parses leniently; 3 fails. |
| [10](10-devicetime-two-digit-year) | Two-digit year pivot | 1 `d=01/02/26 10:00`<br>2 `d=01/02/69 10:00` | 2026-02-01 and **2069**-02-01. | 1969 for line 2 (a sliding pivot). |
| [11](11-regex-engine-constructs) | Does QRadar's default ("Adaptive") pattern engine support possessive quantifiers, lookbehind and backreferences like java.util.regex? | 1 `evt=E1 user=alice p='4242'` | Java semantics: EventName E1, UserName alice, SourcePort 4242. | The upload is rejected, or fields are missing. If so, rerun with `use-default-pattern="true"` on each `<pattern>` and record both results. |
| [12](12-duplicate-matcher-order) | Two matchers for one field with the same `order` | 1 `evt=E1 a=alice b=bob` | Document order: the `b=` matcher (listed first) wins, giving bob. | alice; the upload is rejected. |
| [13](13-custom-matcher-field) | A matcher with an undocumented field name | 1 `evt=E1 custom=x1` | Migrated as a custom field (`MyCustomField=x1`). | The upload is rejected, or the field is silently ignored. Either way, record it. |
| [14](14-substitution-literal-backslash) | Literal text in a substitution template (`capture-group="\1\\\2"`) | 1 `evt=E1 x=alice@corp` | Copied verbatim, with no escape processing: `alice\\corp` (two backslashes). | `alice\corp` (`\\` is an escaped backslash). |
| [15](15-payload-includes-syslog-header) | Do patterns see the syslog header? | 1 `evt=E1` (the pattern captures the header host name) | Yes: UserName=`rl-confirm-15`. | No value (patterns only see the message after the header). |
