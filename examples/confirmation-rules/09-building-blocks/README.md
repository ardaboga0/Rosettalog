# Rule case 09: R09: building blocks in 'any'/'all' rule tests

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-09`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-09 A`: building block: Username **Equals** `x`.
2. Rule `rl-rules-09 B`: building block: Destination Port **Equals** `443`.
3. Rule `rl-rules-09 any`: rule: *when an event matches **any** of the following rules*: `rl-rules-09 A`, `rl-rules-09 B`.
4. Rule `rl-rules-09 all`: rule: *when an event matches **all** of the following rules*: `rl-rules-09 A`, `rl-rules-09 B`.

Then send `sample.log` (`../send.sh <qradar-host> 09-building-blocks`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
