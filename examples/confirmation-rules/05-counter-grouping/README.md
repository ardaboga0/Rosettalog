# Rule case 05: R05: counters grouped by several properties

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-05`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-05 counter`: *when the event matches this search filter*: Event Name **Equals** `fail` (or any filter that matches all four lines); and *when at least **2** events are seen with the same **Source IP** and **Username** in **5** minutes*.

Then send `sample.log` (`../send.sh <qradar-host> 05-counter-grouping`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
