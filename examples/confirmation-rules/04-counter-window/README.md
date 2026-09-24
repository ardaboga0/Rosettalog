# Rule case 04: R04: is a counter's window sliding?

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-04`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-04 counter`: *when the event matches this search filter*: Username **Equals** `w`; and *when at least **3** events are seen with the same **Source IP** in **1** minutes*. **Start `send.sh` when the clock shows about hh:mm:40**, so that the three events (at +0 s, +10 s and +30 s) straddle a full minute.

Then send `sample.log` (`../send.sh <qradar-host> 04-counter-window`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
