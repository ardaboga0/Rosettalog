# G3 (Splunk): correlations use fixed time buckets without the warning the spec asks for

**Recommendation:** new issue in SigmaHQ/pySigma-backend-splunk. No existing report found
(searched: correlation, bin, sliding, window, timespan, streamstats, temporal). The same
behaviour in the Elasticsearch ES|QL backend was reported as
[pySigma-backend-elasticsearch#182](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues/182).
The maintainer answered there that the Sigma specification tolerates it, but that backends should
warn and document it. This issue asks for the same in the Splunk backend.

---

**Title:** Correlations are bucketed with `bin _time span=<timespan>` (fixed windows) but no warning is issued

**Body:**

> The correlation templates (`event_count`, `value_count`, `temporal`) render
> `| bin _time span=<timespan> | stats ... by _time <group-by>`. That is a fixed, epoch-aligned
> window: events that fall into two neighbouring buckets are never counted together, so
> detections that straddle a boundary are missed (false negatives).
>
> The Sigma correlation specification tolerates this, but asks for a warning
> ([Compatibility](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md#compatibility)):
> "The conversion backend should issue a warning to raise the user's awareness about
> restrictions for aspects specified as 'should'. [...] Temporal relationships are only
> recognized within static time boundaries [...]. This could cause false negatives."
> The backend issues no warning, and the README does not mention it. The same was discussed for
> ES|QL in SigmaHQ/pySigma-backend-elasticsearch#182.
>
> **Versions:** pySigma 1.5.1, pySigma-backend-splunk 2.1.0, Splunk Enterprise 10.4.3
> (`splunk/splunk:10.4.3`). No processing pipeline.
>
> **Rules:**
> ```yaml
> title: failed logins
> name: bruteforce_events
> logsource: {product: test}
> detection:
>   sel:
>     EventName: auth_fail
>   condition: sel
> ---
> title: at least 3 failed logins from one source in 5 minutes
> name: bruteforce
> correlation:
>   type: event_count
>   rules: [bruteforce_events]
>   group-by: [src_ip]
>   timespan: 5m
>   condition: {gte: 3}
> ```
> **Generated:**
> ```
> EventName="auth_fail"
>
> | bin _time span=5m
> | stats count as event_count by _time src_ip
>
> | search event_count >= 3
> ```
> **Events** (`EventName=auth_fail`), `_time` from the event:
>
> | src_ip | times (UTC) |
> |---|---|
> | 192.0.2.20 | 10:01:00, 10:02:00, 10:03:00 |
> | 192.0.2.21 | 10:03:30, 10:04:30, 10:05:30 |
>
> **Expected** (Sigma: three events within any 5 minutes): both sources.
> **Actual:** 192.0.2.20 only. The events of 192.0.2.21 are 2 minutes apart but straddle
> 10:05:00, so they land in the buckets 10:00 (2 events) and 10:05 (1 event).
>
> **Suggestion:** issue the warning the specification asks for and document the restriction.
> Optionally, offer a sliding-window method (e.g. `streamstats time_window=<timespan>`) as
> another `correlation_method`.
