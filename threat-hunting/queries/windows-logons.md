# Hunt repeated Windows logon failures

**Hypothesis** — One source IP generated repeated logon failures. Establish whether the timeline fits expected retries, a shared egress address, or activity that needs investigation.

Use **Dev Tools** in OpenSearch Dashboards. Replace `REPLAY_ID` in the request with the value in `reports/replay.json`.

```http
GET soc-logs-telemetry/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {"term": {"labels.replay_id": "REPLAY_ID"}},
        {"term": {"event.dataset": "windows.security"}},
        {"term": {"event.outcome": "failure"}}
      ]
    }
  },
  "aggs": {
    "sources": {
      "terms": {"field": "source.ip", "size": 20},
      "aggs": {"accounts": {"terms": {"field": "user.name", "size": 10}}}
    }
  }
}
```

The aggregation counts the whole replay. The live rule evaluates each source within a five-minute window. Inspect the raw timeline before drawing a conclusion.

In **Discover**, switch to `soc-logs-*` and filter by `labels.replay_id` and the chosen `source.ip`. Sort by `@timestamp`. Compare failed and successful logons, then check which accounts and hosts appear. For sensor data, use the same time range and relevant source or destination IP to pivot across Zeek and Suricata records.

See the [investigation worksheet](../../docs/investigation.md) to record the final disposition.

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
