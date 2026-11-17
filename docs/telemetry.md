# Telemetry inputs

## Windows Security events

Vector expects one UTF-8 JSON object per line at `POST /windows-auth`. The replay tool sets the event timestamp and sends records in this shape.

```json
{
  "@timestamp": "2026-11-17T00:00:00.125Z",
  "host": {"name": "lab-win01"},
  "winlog": {
    "event_id": 4625,
    "event_data": {
      "IpAddress": "192.0.2.20",
      "TargetUserName": "lab-analyst"
    }
  }
}
```

| Input | Indexed field |
|---|---|
| `@timestamp` | `@timestamp`, original event time |
| `winlog.event_id` | `event.code`, stored as a keyword |
| Event ID `4625` or `4624` | `event.outcome`, set to `failure` or `success` |
| `winlog.event_data.IpAddress` | `source.ip`, mapped as IP |
| `winlog.event_data.TargetUserName` | `user.name` |
| `host.name` | `host.name` |
| Collector clock | `pipeline.ingested_at` |

The Windows transform accepts logon records with a valid, specified source IP. Records with an unknown timestamp, unsupported event code, or placeholder IP such as `-` are dropped. Replay adds `event.id` for idempotent indexing and `labels.replay_id` plus `labels.scenario` for investigation pivots.

## Recorded network logs

The collector reads JSON-formatted Zeek `conn.log`, `dns.log`, and `notice.log` under `telemetry/zeek/` and Suricata `eve.json` under `telemetry/suricata/`. The `telemetry/` mount is read-only inside Vector. Its file checkpoints live in the named Vector data volume.

To try the examples on an empty telemetry directory, copy the bundled synthetic records into those paths. The samples use a fixed UTC time so select 17 November 2026 in Discover.

```bash
cp fixtures/network/zeek/*.log telemetry/zeek/
cp fixtures/network/suricata/eve.json telemetry/suricata/
```

| Dataset | Useful fields |
|---|---|
| `zeek.conn` | Source and destination IP and port, `source.bytes` and `destination.bytes`, transport, `zeek.conn_state`, `zeek.duration`, and `network.direction` from `local_orig`/`local_resp` (used by SOC-013, SOC-014, and SOC-015) |
| `zeek.dns` | Source IP, `dns.question.name`, and `dns.question.length` (used by SOC-012) |
| `zeek.notice` | Source IP and notice name in `rule.name` (used by SOC-011) |
| `suricata.eve` | EVE event type in `event.category`, endpoint IPs, `destination.port`, and signature name, ID, and severity (used by SOC-010) |

Zeek `uid` and Suricata `flow_id` become `event.id`, so an alert links back to the exact record.

Use the original Zeek timestamps and Suricata event times when investigating. Because those samples carry a fixed 2026-11-17 time, the live rules treat them as history and do not alert on them.

## Live network replay

`python3 tools/replay.py` (or `--scope network`) appends fresh, current-time records from [`fixtures/network-replay.json`](../fixtures/network-replay.json) to the files under `telemetry/`. Each record carries `labels.replay_id` and `labels.scenario`, which Vector keeps for this lab only, so the replay can prove that SOC-010, SOC-011, and SOC-012 fire on the positive scenarios and stay quiet on the near misses.

| Scenario | Stream | Expected alert |
|---|---|---|
| `port-scan` | `zeek/notice.log` | SOC-011 |
| `benign-notice` | `zeek/notice.log` | none |
| `dns-tunnel` | `zeek/dns.log` | SOC-012 |
| `dns-normal` | `zeek/dns.log` | none |
| `ids-high-severity` | `suricata/eve.json` | SOC-010 |
| `ids-low-severity` | `suricata/eve.json` | none |
| `port-scan-connections` | `zeek/conn.log` (25 records) | SOC-013 |
| `port-scan-below-threshold` | `zeek/conn.log` (15 records) | none |
| `llmnr-poisoner` | `zeek/conn.log` (3 records) | SOC-014 |
| `llmnr-two-clients` | `zeek/conn.log` (2 records) | none |
| `exfil-upload-heavy` | `zeek/conn.log` | SOC-015 |
| `exfil-download` | `zeek/conn.log` | none |

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
