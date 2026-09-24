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
4. **Send** the lines: `./send.sh <qradar-host> NN-name`.
5. **Observe** which events each rule matched. In *Log Activity*, filter on the log source
   `rl-rules-NN` and add the column *Custom Rules* (or *Custom Rule Partially Matched*), or use
   AQL (the `creeventlist` field lists the rules an event matched; check the function names in
   your version's AQL reference):
   ```sql
   SELECT DATEFORMAT(starttime, 'HH:mm:ss') AS t, username, sourceip, destinationport,
          RULENAME(creeventlist) AS rules, UTF8(payload) AS payload
   FROM events WHERE LOGSOURCENAME(logsourceid) = 'rl-rules-NN' LAST 1 HOURS
   ```
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
<!-- END GENERATED: rule-confirmation-cases -->
