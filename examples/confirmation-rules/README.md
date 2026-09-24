# QRadar CE confirmation pack: rules

Rosettalog makes a few assumptions about how QRadar evaluates rules where IBM's documentation is
silent or ambiguous. They are listed in
[`assumptions.yaml`](../../src/rosettalog/frontends/qradar_rules/assumptions.yaml). This
directory has one **minimal, synthetic** case per assumption: you build the rule in QRadar
Community Edition, send the case's log lines, and record which events matched.

**Until results are recorded, the assumed semantics stay unchanged.** Each case's
`samples.yaml` encodes the *current assumption* (`ground_truth_source: "assumed: …"`); the test
suite checks that Rosettalog's rule evaluator agrees with it.

## Per case

```
NN-name/
├── README.md       # the rule(s) to build in the QRadar UI
├── rule.ir.json    # Rosettalog's reading of that rule (IR)
├── sample.log      # exactly the lines to send (RFC 3164 syslog, host rl-rules-NN);
│                   # "# sleep N" lines are pauses
└── samples.yaml    # the same events, as parsed, + the assumed hits per rule
```

## Procedure

1. **Once:** upload [`rl-rules.lsx.xml`](rl-rules.lsx.xml) (*Admin > Log Source Extensions >
   Add*, *Use Condition*: **Parsing Override**). It extracts `evt=`, `user=`, `src=` and `dport=`
   into EventName, Username, Source IP and Destination Port.
2. **Per case:** create a log source (*Admin > Log Sources > New*, **Universal DSM**, protocol
   **Syslog**, identifier **`rl-rules-NN`**) with that extension, and deploy changes.
3. Build the case's rule(s) as described in its `README.md`, and deploy.
4. **Send** the lines: `./send.sh <qradar-host> NN-name`. It sends one line per second, pauses
   at `# sleep N` lines, and replaces the placeholder syslog time (`Mar 24 10:00:00`) with the
   current time, so event times follow the pacing (cases 04-08 depend on it).
5. **Observe** which events each rule matched. In *Log Activity*, filter on the log source
   `rl-rules-NN` and add the column *Custom Rules* (or *Custom Rule Partially Matched*), or use
   AQL (the `creeventlist` field lists the rules an event matched; check the function names in
   your version's AQL reference):
   ```sql
   SELECT DATEFORMAT(starttime, 'HH:mm:ss') AS t, username, sourceip, destinationport,
          RULENAME(creeventlist) AS rules, UTF8(payload) AS payload
   FROM events WHERE LOGSOURCENAME(logsourceid) = 'rl-rules-NN' LAST 1 HOURS
   ```
   For counter and sequence cases (04-08), `samples.yaml` lists the **groups** the rule is
   assumed to alert on (e.g. `SourceIp=192.0.2.10`), and event times relative to the first line.
6. **Export** the case's rules and attach the export, e.g.
   `/opt/qradar/bin/contentManagement.pl -a export -c customrule --id <rule id>` (see IBM's
   Content Management Tool docs). This rule XML is what Rosettalog's rule parser will be built
   from (open questions Q1-Q4 in [docs/rules-support-matrix.md](../../docs/rules-support-matrix.md)).
7. Report the results in an issue, with your QRadar version: the matching events per rule,
   anything unexpected, and the export.

## Cases

<!-- BEGIN GENERATED: rule-confirmation-cases (from src/rosettalog/frontends/qradar_rules/assumptions.yaml; regenerate with `uv run python -m rosettalog.frontends.qradar_rules.docs_sync`) -->
| Case | Assumption | Question | Assumed hits (from `samples.yaml`) | Alternatives to look for | Status |
|---|---|---|---|---|---|
| [01](01-value-case) | R01 | Are event-property "equals" and "contains" tests case-sensitive? | `rl_rules_01_equals`: e1<br>`rl_rules_01_contains`: e2 | Case-insensitive: the equals rule also matches admin and ADMIN (e2, e3); the contains rule also matches Admin, ADMIN and xAdminx (e1, e3, e4). | unconfirmed |
| [02](02-regex-find) | R02 | Does a "matches regex" test match anywhere in the value, or must it match the whole value? | `rl_rules_02_regex`: e1, e2 | The whole value (only 'adm' matches; 'sysadmin' does not). | unconfirmed |
| [03](03-missing-property) | R03 | How does a test on a property the event does not have evaluate, and its negation? | `rl_rules_03_not_bob`: e2, e3 | Any test on a missing property makes the rule not match, negated or not (e3 does not match). | unconfirmed |
| [04](04-counter-window) | R04 | Is the "in N minutes" window of a counter test sliding, or fixed time buckets? | `rl_rules_04_counter`: SourceIp=192.0.2.10 | Fixed buckets (e.g. clock minutes): e1-e3 fall into two buckets when sending starts at about hh:mm:40, so the rule does not fire. | unconfirmed |
| [05](05-counter-grouping) | R05 | With "the same Source IP and Username", are events counted per combination of both properties? | `rl_rules_05_counter`: SourceIp=192.0.2.10,UserName=a | Per Source IP only, or per property separately: the rule then also fires for 192.0.2.10 as a whole (already at e2), not only for 192.0.2.10 with user a (at e4). | unconfirmed |
| [06](06-counter-firing) | R06 | Once a counter's threshold is reached, does the rule fire once, or again for every further event in the window? | `rl_rules_06_counter`: SourceIp=192.0.2.10 | The rule fires for e2, e3 and e4 (one alert or offense contribution each). | unconfirmed |
| [07](07-sequence-gaps) | R07 | In a sequence ("in the order"), may other events occur between the steps? | `rl_rules_07_sequence`: SourceIp=192.0.2.10 | No. An event in between (e2) breaks the sequence, so 192.0.2.10 does not fire. | unconfirmed |
| [08](08-sequence-window) | R08 | Is a sequence's "within N minutes" measured from the first to the last step? | `rl_rules_08_sequence`: SourceIp=192.0.2.11 | Measured between consecutive steps: 192.0.2.10 (40 s between steps, 80 s in total) fires too. | unconfirmed |
| [09](09-building-blocks) | R09 | Are building blocks evaluated per event, so that "matches any of these rules" is an OR of the building blocks' tests on that event, and "matches all" an AND on that same event? | `rl_rules_09_bb_a`: e1, e3<br>`rl_rules_09_bb_b`: e2, e3<br>`rl_rules_09_any`: e1, e2, e3<br>`rl_rules_09_all`: e3 | "All" is satisfied across different events (e.g. e1 and e2 together, so the all-rule also fires for e2), or building blocks keep state of their own. | unconfirmed |
<!-- END GENERATED: rule-confirmation-cases -->
