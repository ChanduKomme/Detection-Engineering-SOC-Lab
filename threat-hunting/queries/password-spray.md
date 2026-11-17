# Hunt password spraying

**Hypothesis** — One source is trying a few passwords across many accounts to stay under per-account lockout.

Replace `REPLAY_ID` with the value in `reports/replay.json`, or remove that filter to hunt the full index.

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
      "terms": {"field": "source.ip", "size": 20, "order": {"accounts": "desc"}},
      "aggs": {
        "accounts": {"cardinality": {"field": "user.name"}},
        "names": {"terms": {"field": "user.name", "size": 25}},
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}}
      }
    }
  }
}
```

Read the result: a high `accounts` count with roughly one failure per account is spraying. Many failures against one account is password guessing, which SOC-002 covers. In the replay, `password-spray` and `spray-and-brute-force` reach six accounts, while `spray-below-threshold` stops at four.

Then check whether any targeted account logged on successfully from the same source:

```http
GET soc-logs-telemetry/_search
{
  "query": {
    "bool": {
      "filter": [
        {"term": {"event.outcome": "success"}},
        {"term": {"source.ip": "SOURCE_IP"}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}]
}
```

---
*Detection Engineering SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*

