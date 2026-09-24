# Cortex XSIAM confirmation pack

Rosettalog's XSIAM output is **emulator-verified only**. The emulator relies on a few XSIAM
behaviours that Palo Alto's documentation does not state; each is evidenced by Palo Alto's
shipped Parsing Rules or follows from documented functions. They are listed in
[`unknowns.yaml`](../../../src/rosettalog/backends/xsiam/unknowns.yaml), and findings that
depend on one say so and follow its status. This pack has one **minimal, synthetic** case per
unknown, which you can check with the **Simulate** view of the Parsing Rules editor.

**Until results are recorded, the assumed behaviour stays unchanged.** Each case's
`expected.yaml` holds what Rosettalog's emulator produces, with
`ground_truth_source: "assumed: …"`. The test suite checks that the emulator agrees with it.

## Per case

```
NN-name/
├── rule.xif        # the Parsing Rule to paste into the editor (vendor rosettalog, product rl_xNN)
├── sample.log      # the lines to send (at most 5: Simulate shows 5 samples per vendor/product)
├── expected.yaml   # the fields Rosettalog assumes XSIAM produces for each line
└── README.md       # what to record
```

## Procedure

Simulate runs Parsing Rules on logs that were already ingested. The logs have to arrive first
([Parsing Rules editor views](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/configure-cortex-xsiam/data-management/parsing-rules/parsing-rules-editor-views.md)).

1. **Collector.** Create a *Custom - HTTP based Collector*, Log Format **Raw**, with the
   case's vendor and product, e.g. `rosettalog` / `rl_x01`
   ([setup](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/configure-cortex-xsiam/cortex-xsiam-data-sources/vendor-specific-data-sources-and-connectors/http-log-collector/set-up-an-http-log-collector-to-receive-logs.md)).
   Note its URL and API key.
2. **Send** the lines:
   `XSIAM_COLLECTOR_KEY=<key> ./send.sh https://api-<tenant>/logs/v1/event NN-name`.
3. **Simulate.** Open *Settings > Configurations > Data Management > Parsing Rules*, add the
   content of `rule.xif` under **User Defined Rules**, and click **Simulate**. In **XQL
   Samples**, select the case's lines and run the simulation. **Logs Output** shows the
   resulting fields.
   - If the editor rejects the rule, that is a result too (case 03 may be rejected): record
     the exact error.
   - Case 05 also asks you to check the dataset `parsing_rules_errors`.
4. **Record** the values next to `expected.yaml`, and report them in an issue with your XSIAM
   version. You can deploy nothing and remove the rule and collector afterwards; the cases
   write only to their own `rosettalog_rl_xNN_raw` datasets.

## Cases

<!-- BEGIN GENERATED: xsiam-cases (from src/rosettalog/backends/xsiam/unknowns.yaml; regenerate with `uv run python -m rosettalog.backends.xsiam.docs_sync`) -->
| Case | ID | Question | Lines → assumed fields | Alternatives to look for | Status |
|---|---|---|---|---|---|
| [01](01-regexcapture-no-match) | X01 | What does regexcapture() return when the pattern does not match, and what does a named group that did not participate read as? | `rltest x01 user=alice` → matched=`yes`, user=`alice`, opt=`no match`<br>`rltest x01 nothing here` → matched=`no`, user=(none), opt=`no match`<br>`rltest x01 id=7` → matched=`no`, user=(none), opt=`null`<br>`rltest x01 id=8,x` → matched=`no`, user=(none), opt=`x` | No match returns null or raises a parsing error (matched stays null either way, but check the Errors); a non-participating group reads as "" (harmless) or is missing. | unconfirmed |
| [02](02-string-literals) | X02 | In XQL string literals, are backslashes passed through unchanged, with \" as the only escape (a double quote)? | `rltest x02 q="hello" dir=c\temp` → a=`hello`, b=`temp`, c=`say "hi" \d` | Backslash escapes are processed (\\ becomes \): 'b' is null or differs, and regexes such as \d may break. | unconfirmed |
| [03](03-inline-flags) | X03 | Does an inline flag in the middle of a pattern, e.g. (?i) after some text, work? | `rltest x03 code=ABC` → r=`ABC`<br>`rltest x03 CODE=abc` → r=(none) | The rule is rejected, or the flag is ignored ('r' is null for code=ABC). | unconfirmed |
| [04](04-timestamp-normalization) | X04 | Do format_string("%04d-%02d-%02d %02d:%02d:%02d", ...) and parse_timestamp("%Y-%m-%d %H:%M:%E*S", ..., "+03:00") together give the documented result, including fractions? | `rltest x04 ts=2026-3-5 9:07:03.120 +03:00` → _time=`2026-03-05T06:07:03.120Z` | A different _time (e.g. the fraction or the offset ignored), or null. | unconfirmed |
| [05](05-to-integer) | X05 | Does to_integer() turn "0443" into 443, and a non-numeric value into null without rejecting the event? | `rltest x05 port=0443` → port=`443`<br>`rltest x05 port=abc` → port=(none) | A non-numeric value raises an error and the event is not modeled. | unconfirmed |
<!-- END GENERATED: xsiam-cases -->
