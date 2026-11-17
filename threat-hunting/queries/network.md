# Hunt across Zeek and Suricata records

**Hypothesis** — A host that triggered a network alert shows related scanning, unusual DNS, or repeated connections.

## Everything from one source

```http
GET soc-logs-telemetry/_search
{
  "size": 50,
  "query": {
    "bool": {
      "filter": [
        {"term": {"source.ip": "SOURCE_IP"}},
        {"terms": {"event.dataset": ["zeek.conn", "zeek.dns", "zeek.notice", "suricata.eve"]}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}]
}
```

## Longest DNS names (tunneling triage)

```http
GET soc-logs-telemetry/_search
{
  "size": 20,
  "query": {"bool": {"filter": [
    {"term": {"event.dataset": "zeek.dns"}},
    {"range": {"dns.question.length": {"gte": 40}}}
  ]}},
  "sort": [{"dns.question.length": "desc"}],
  "_source": ["@timestamp", "source.ip", "dns.question.name", "dns.question.length"]
}
```

## IDS alerts by signature and severity

```http
GET soc-logs-telemetry/_search
{
  "size": 0,
  "query": {"term": {"event.dataset": "suricata.eve"}},
  "aggs": {
    "severity": {
      "terms": {"field": "rule.severity"},
      "aggs": {"signatures": {"terms": {"field": "rule.name", "size": 10}}}
    }
  }
}
```

Suricata severity 1 is the highest priority. SOC-010 alerts on 1 and 2, and the `ids-low-severity` replay scenario checks that priority 3 stays quiet.

---
*Detection Engineering SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*

