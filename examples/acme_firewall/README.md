# Example: Acme Firewall (synthetic)

`acme_fw.lsx.xml` is a hand-written Log Source Extension for a fictional firewall. It contains
no vendor content. It is built to show both successful translation and honest reporting:

| Construct | Sentinel (KQL / RE2) | Splunk (PCRE) |
|---|---|---|
| Plain captures, case-insensitive pattern, NAT pair | FULL | FULL |
| `DeviceTime` with Joda format | `make_datetime()` | `TIME_PREFIX`/`TIME_FORMAT` |
| `event-match-single` category/severity table | `case()` | `case()` in EVAL |
| `UserName` fallback with a **lookbehind** | dropped → PARTIAL | FULL |
| `EventCategory` fallback with a **backreference** | dropped → PARTIAL | FULL |
| `HostName` (no ASIM/CIM equivalent) | kept, flagged | kept, flagged |

```bash
uv run rosettalog convert examples/acme_firewall/acme_fw.lsx.xml --to sentinel --to splunk \
    --sourcetype acme:firewall --samples examples/acme_firewall/samples.yaml -o out/
```

`samples.yaml` has four synthetic events. Two of them only produce a value through the
lookbehind or backreference fallbacks. Sentinel fails those two samples and Splunk passes all
four, and the report explains why.
