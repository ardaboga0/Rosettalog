# Rule case 02: R02: does a regex test match anywhere in the value?

Build these rules in the QRadar UI (*Offenses > Rules > Actions > New Event Rule*). Every rule
also gets the test *when the event(s) were detected by one or more of these log sources*:
`rl-rules-02`, so that only this case's events can match. No response is needed.

1. Rule `rl-rules-02 regex`: *when the event matches this search filter*: Username **Matches** (regular expression) `adm`.

Then send `sample.log` (`../send.sh <qradar-host> 02-regex-find`; it honours the `# sleep N` lines) and
record which events each rule matched (see ../README.md, "Observe"). Rosettalog's reading of the
rules is in `rule.ir.json`; the assumed hits are in `samples.yaml`. Please also export the rules
(see ../README.md, "Export"): the rule XML settles open questions Q1-Q4.
