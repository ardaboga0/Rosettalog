# Rule case 08: R08: how a sequence's window is measured

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-08`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-08 sequence`: first create three building blocks `rl-rules-08 A`/`B`/`C` (Username **Equals** `stepa`/`stepb`/`stepc`), each restricted to the log source. Then the rule: *when these rules match **in order**, from the same **Source IP**, within **1** minutes*: A, B, C.

Then send `sample.log` (`../send.sh <qradar-host> 08-sequence-window`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
