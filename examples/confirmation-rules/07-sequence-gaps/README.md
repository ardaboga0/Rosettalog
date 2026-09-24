# Rule case 07: R07: other events between the steps of a sequence

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-07`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-07 sequence`: first create two building blocks: `rl-rules-07 A` (Username **Equals** `stepa`) and `rl-rules-07 B` (Username **Equals** `stepb`), each also restricted to the log source. Then the rule: *when these rules match **in order**, from the same **Source IP**, within **5** minutes*: `rl-rules-07 A`, then `rl-rules-07 B`.

Then send `sample.log` (`../send.sh <qradar-host> 07-sequence-gaps`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
