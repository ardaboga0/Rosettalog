# Writing detection rules as Rosettalog IR (`*.ir.json`)

Until the QRadar rule-export parser exists (it waits for QRadar CE confirmation of the rule XML,
open questions Q1-Q5 in the [rules support matrix](rules-support-matrix.md)), rules reach the
Sigma backend as **Rosettalog IR**. You write one JSON file per rule set, by hand or from your
own export tooling:

```sh
rosettalog inspect my_rules.ir.json                 # validates and prints the IR
rosettalog schema --ir > rosettalog-ir.schema.json  # JSON Schema, e.g. for editor validation
rosettalog convert my_rules.ir.json --to sigma -O sigma.pysigma_targets=splunk,kusto,esql -o out/
rosettalog verify my_rules.ir.json -s my_samples.yaml --to sigma
```

The file name must end in `.ir.json`. It holds a JSON **list** of artifacts (a single object is
accepted too). Invalid IR is reported as `IR_INVALID` with the validation error. Unknown keys are
errors, not ignored. Every example below is tested (`tests/unit/test_ir_format_doc.py`).

## Artifact

```json
[
  {
    "id": "acme_admin_login",
    "name": "Acme FW: admin login from the documentation network",
    "kind": "detection",
    "source_format": "qradar-rules",
    "provenance": {"file": "my_rules.ir.json"},
    "detection": {
      "rule_id": "100101",
      "name": "Acme FW: admin login from the documentation network",
      "notes": "Why the rule exists.",
      "severity": 6,
      "condition": {
        "kind": "and",
        "items": [
          {"kind": "field", "field": "SourceIp", "op": "equals", "values": ["192.0.2.10", "192.0.2.11"]},
          {"kind": "field", "field": "UserName", "op": "contains", "values": ["adm"], "case_sensitive": false}
        ]
      }
    }
  }
]
```

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique slug; output file names and the Sigma rule `name` come from it. |
| `name` | yes | Display name. |
| `kind` | yes | `"detection"` for rules (`"parser"` is for LSX parsers). |
| `source_format` | yes | Use `"qradar-rules"` so that the QRadar rule assumptions (R01-R09) apply and are listed in reports. |
| `provenance` | yes | `{"file": "...", "line": n}`; shown in reports. |
| `detection` | yes | The rule (below). |
| `findings` | no | Findings you want carried into the report (normally empty). |

## `detection` (DetectionSpec)

| Key | Default | Meaning |
|---|---|---|
| `rule_id` | required | The source rule's id. References (`rule_ref`) can use it. |
| `uuid` | `null` | Source uuid. Also used for the deterministic Sigma `id`, and references can use it. |
| `name` | required | Rule name (Sigma `title`; references can use it). |
| `notes` | `""` | Sigma `description`. |
| `building_block` | `false` | A building block: written as its own Sigma rule (flagged `SIGMA_BUILDING_BLOCK`) and inlined/referenced where other rules use it. |
| `rule_type` | `"event"` | `event`, `flow`, `common` or `offense` (offense rules are UNSUPPORTED). |
| `enabled` | `true` | Recorded as `qradar.enabled`. |
| `condition` | required unless `stateful` | Single-event condition (below). With `stateful`, it filters the counted/sequenced events. |
| `stateful` | `null` | A counter or a sequence (below). |
| `severity`, `credibility`, `relevance` | `null` | 0-10, from the rule's event response. `severity` becomes the Sigma `level`. |
| `responses` | `[]` | `{"kind": "email", "attributes": {"to": "..."}}`; listed in the report as not representable. |

## Conditions

Every leaf may have `"path"` (e.g. `"test[2]"`) and `"line"`: findings refer to the test by its
path, and so does the "BROADER" note in generated rules, so set them.

| `kind` | Keys | Meaning |
|---|---|---|
| `and`, `or` | `items` (≥ 1 condition) | Boolean combination. |
| `not` | `item` | Negation. |
| `field` | `field`, `op` (`equals` / `contains` / `regex`), `values` (≥ 1, OR), `case_sensitive` (default `true`) | Property test. `field` is a canonical (QRadar) property name, e.g. `SourceIp`, `DestinationPort`, `UserName`, `EventName` (see `data/field_map.yaml`). `regex` values are **Java** regular expressions. |
| `log_source` | `by` (`log_source` / `log_source_type`), `values` | Log source (type) test; becomes the Sigma `logsource` only through `sigma.logsource_map`. |
| `qid` | `values` | QID test. |
| `rule_ref` | `rules` (ids, uuids or names), `mode` (`any` / `all`) | "Matches any/all of these rules": other artifacts in the same run, usually building blocks. **Do not write `resolved`**: it is filled when the files are loaded. |
| `reference` | `collection`, `collection_type` (`set` / `map` / `map_of_sets` / `table` / `unknown`), `fields` | Reference data test; not translatable to Sigma (the finding suggests the target mechanism). |
| `opaque` | `test`, `text` | A test you cannot express; kept so that it is reported, and dropped (broader) in Sigma. |

```json
{
  "id": "tessivor_auth_failure_not_ssh",
  "name": "Tessivor VPN: authentication failure outside SSH",
  "kind": "detection",
  "source_format": "qradar-rules",
  "provenance": {"file": "my_rules.ir.json"},
  "detection": {
    "rule_id": "100102",
    "name": "Tessivor VPN: authentication failure outside SSH",
    "condition": {
      "kind": "and",
      "items": [
        {"kind": "field", "field": "EventName", "op": "regex", "values": ["^auth[-_]fail(ure)?\\d*$"], "path": "test[1]"},
        {"kind": "not", "item": {"kind": "field", "field": "DestinationPort", "op": "equals", "values": ["22"], "path": "test[2]"}},
        {"kind": "reference", "collection": "Blocked hosts", "collection_type": "set", "fields": ["SourceIp"], "path": "test[3]"}
      ]
    }
  }
}
```

## Counters and sequences (`stateful`)

```json
{
  "id": "tessivor_vpn_bruteforce",
  "name": "Tessivor VPN: at least 3 failed logins from one source in 5 minutes",
  "kind": "detection",
  "source_format": "qradar-rules",
  "provenance": {"file": "my_rules.ir.json"},
  "detection": {
    "rule_id": "100201",
    "name": "Tessivor VPN: at least 3 failed logins from one source in 5 minutes",
    "condition": {"kind": "field", "field": "EventName", "op": "equals", "values": ["auth_fail"], "case_sensitive": false},
    "stateful": {"kind": "counter", "count": 3, "window_s": 300, "group_by": ["SourceIp"], "path": "test[2]"}
  }
}
```

- **Counter:** `count` (≥ 1), `window_s` (seconds), `group_by` (canonical fields; events are
  counted per combination), and optionally `distinct_field` (count different values of it
  instead of events). Becomes `event_count` / `value_count`.
- **Sequence:** `steps` (≥ 2 conditions), `ordered` (default `true`), `window_s`, `group_by`.
  Becomes `temporal_ordered` / `temporal`. A step that is exactly one `rule_ref` to a building
  block, in a rule without `condition`, makes the correlation reference that block's own Sigma
  rule by name.

## Building blocks

```json
[
  {
    "id": "bb_admin_users",
    "name": "BB: admin accounts",
    "kind": "detection",
    "source_format": "qradar-rules",
    "provenance": {"file": "my_rules.ir.json"},
    "detection": {
      "rule_id": "200001",
      "name": "BB: admin accounts",
      "building_block": true,
      "condition": {"kind": "field", "field": "UserName", "op": "equals", "values": ["admin", "root"], "case_sensitive": false}
    }
  },
  {
    "id": "admin_bruteforce",
    "name": "At least 3 admin-account events from one source in 5 minutes",
    "kind": "detection",
    "source_format": "qradar-rules",
    "provenance": {"file": "my_rules.ir.json"},
    "detection": {
      "rule_id": "200103",
      "name": "At least 3 admin-account events from one source in 5 minutes",
      "condition": {"kind": "rule_ref", "rules": ["200001"], "path": "test[1]"},
      "stateful": {"kind": "counter", "count": 3, "window_s": 300, "group_by": ["SourceIp"]}
    }
  }
]
```

References are resolved among **all files loaded in one run**, so pass the building blocks'
file together with the rules that use them. Missing, ambiguous and cyclic references are
reported (`RULE_REF_*`).

## Samples for `rosettalog verify`

A rule samples file has parsed events and the expected hits per rule: event ids for single-event
rules, and alerting groups (`Field=value,...` in `group_by` order, or `(all)`) for counters and
sequences. See [verification.md](verification.md#detection-rules) and `examples/rules*/`.

```yaml
reference_time: 2026-01-05T10:00:00Z
ground_truth_source: assumed
reference_data: {Blocked hosts: [198.51.100.7]}
events:
  - {id: e1, time: 2026-01-05T10:01:00Z, fields: {EventName: auth_fail, SourceIp: 192.0.2.20}}
expected:
  tessivor_auth_failure_not_ssh: [e1]
  tessivor_vpn_bruteforce: []
```
