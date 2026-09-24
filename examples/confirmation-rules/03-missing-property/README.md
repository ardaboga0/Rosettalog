# Rule case 03: R03: tests on a property the event does not have

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-03`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-03 not bob`: *when the event matches this search filter*: Source IP **Equals** `192.0.2.10`; and, negated (*when the event does NOT match...*, or the test's 'not' toggle), Username **Equals** `bob`.

Then send `sample.log` (`../send.sh <qradar-host> 03-missing-property`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
