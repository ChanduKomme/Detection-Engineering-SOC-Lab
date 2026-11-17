# CyberPulse detection console

## Automatic setup

`./setup.sh` imports [`cyberpulse-soc-dashboard.ndjson`](cyberpulse-soc-dashboard.ndjson) on every start. The console then opens straight on **CyberPulse SOC Lab — Detection Console**, in the dark navy + cyan theme from [`config/dashboards/`](../config/dashboards/).

To inspect one replay, type `labels.replay_id:"<id from reports/replay.json>"` in the search bar.

## Panels

| Panel | Index | Purpose |
|---|---|---|
| Header | — | Rule list, replay filter hint, and playbook pointer |
| Telemetry events, Alerts raised, Unique sources, Rules fired | both | KPI tiles for a quick health check of a run |
| Alerts by detection rule | `soc-alerts` | Donut colored per rule |
| Telemetry by scenario and source | `soc-logs-*` | Horizontal bars colored per data source |
| Alerts by rule and scenario | `soc-alerts` | Exact alert matrix with a total |
| Failed logons by account | `soc-logs-*` | Spray versus brute-force shape at a glance |
| Alert queue, Telemetry stream | both | Drill-down lists for triage |

## Change or re-import

Edit [`tools/build_dashboard.py`](../tools/build_dashboard.py), run `python3 tools/build_dashboard.py`, and re-run `./setup.sh`, or import the file from **Dashboards Management → Saved objects → Import** with overwrite allowed. `tests/test_dashboard.py` checks that the committed file matches the generator, that every reference resolves, and that no panels overlap.

## Troubleshooting the theme

- **Still the default OpenSearch look:** the theme is read at container start. Run `docker compose up -d --force-recreate dashboards`, then hard-refresh the browser (Ctrl+Shift+R).
- **Default logo but dark theme:** Dashboards checks each logo URL from inside the container on port 5601. Keep the container port at 5601. Only the host side changes with `DASHBOARDS_PORT`.
- **Dashboards will not start:** run `docker compose logs dashboards`. To fall back to the stock UI, remove the two `volumes` lines under `dashboards` in `docker-compose.yml`.

## Build the views by hand

1. Start the lab and run `python3 tools/replay.py --report reports/replay.json`.
2. Open `http://127.0.0.1:5601` and sign in as `admin` with the password in the lab's `.env`.
3. In **Dashboards Management → Index patterns**, create an index pattern for `soc-logs-*` and another for `soc-alerts`. Choose `@timestamp` for both.
4. Open **Discover**, select `soc-logs-*`, and set the time picker to **Last 15 minutes** for a recent replay. Filter by the report's `labels.replay_id` and display `event.code`, `event.outcome`, `source.ip`, `user.name`, and `host.name`.
5. Switch to `soc-alerts`, filter on the same replay ID, and expand the alert to find its linked `event.id` and `rule_name`. The report contains its OpenSearch document ID.

6. For a detection overview, build a visualization on `soc-alerts` that splits by `rule_name` and `labels.scenario`. Each replay should show SOC-002 and SOC-003 on the Windows scenarios and SOC-010 to SOC-012 on the network scenarios.
7. For network triage, filter `soc-logs-*` on `event.dataset: zeek.dns` and add `dns.question.length` as a column, or on `suricata.eve` and add `rule.name` and `rule.severity`.

Capture your own telemetry and alert views with the matching replay ID visible. Recorded sensor samples use a fixed time range described in the [telemetry guide](../docs/telemetry.md).

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
