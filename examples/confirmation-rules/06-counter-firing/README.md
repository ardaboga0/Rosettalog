# Rule case 06: R06: how often a counter fires

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-06`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-06 counter`: *when the event matches this search filter*: Username **Equals** `c`; and *when at least **2** events are seen with the same **Source IP** in **5** minutes*. Record **which events** the rule matched (e1-e4), not only whether it fired.

Then send `sample.log` (`../send.sh <qradar-host> 06-counter-firing`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
