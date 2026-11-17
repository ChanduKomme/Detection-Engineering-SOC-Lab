# OpenSearch Dashboards triage views

1. Start the lab and run `python3 tools/replay.py --report reports/replay.json`.
2. Open `http://127.0.0.1:5601` and sign in as `admin` with the password in the lab's `.env`.
3. In **Dashboards Management → Index patterns**, create an index pattern for `soc-logs-*` and another for `soc-alerts`. Choose `@timestamp` for both.
4. Open **Discover**, select `soc-logs-*`, and set the time picker to **Last 15 minutes** for a recent replay. Filter by the report's `labels.replay_id` and display `event.code`, `event.outcome`, `source.ip`, `user.name`, and `host.name`.
5. Switch to `soc-alerts`, filter on the same replay ID, and expand the alert to find its linked `event.id` and `rule_name`. The report contains its OpenSearch document ID.

6. For a detection overview, build a visualization on `soc-alerts` that splits by `rule_name` and `labels.scenario`. Each replay should show SOC-002 and SOC-003 on the Windows scenarios and SOC-010 to SOC-012 on the network scenarios.
7. For network triage, filter `soc-logs-*` on `event.dataset: zeek.dns` and add `dns.question.length` as a column, or on `suricata.eve` and add `rule.name` and `rule.severity`.

Capture your own telemetry and alert views with the matching replay ID visible. Recorded sensor samples use a fixed time range described in the [telemetry guide](../docs/telemetry.md).

---
*Detection Engineering SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
