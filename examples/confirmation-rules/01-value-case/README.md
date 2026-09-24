# Rule case 01: R01: are equals/contains tests case-sensitive?

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-01`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-01 equals`: *when the event matches this search filter*: Username **Equals** `Admin`.
2. Rule `rl-rules-01 contains`: *when the event matches this search filter*: Username **Contains** `adm`.

Then send `sample.log` (`../send.sh <qradar-host> 01-value-case`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
