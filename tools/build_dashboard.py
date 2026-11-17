#!/usr/bin/env python3
"""Generate the CyberPulse SOC detection dashboard as OpenSearch Dashboards saved objects.

Author: Chandu Komme
Project: CyberPulse SOC Lab

Writes dashboards/cyberpulse-soc-dashboard.ndjson. ``setup.sh`` imports it on
every start, and it can also be imported by hand from Saved objects.

The palette matches the dark navy + cyan UI theme:
    cyan   #00E5FF  Windows authentication, primary metric
    teal   #14B8A6  Zeek connections, SOC-012
    violet #8B5CF6  Zeek DNS, SOC-003
    amber  #FFB020  Zeek notices, SOC-011
    red    #FF4D6D  Suricata, failures, SOC-010
    sky    #38BDF8  SOC-013 vertical port scan
    pink   #F472B6  SOC-014 LLMNR/NBT-NS poisoner
    lime   #A3E635  SOC-015 upload-heavy exfiltration
"""

__author__ = "Chandu Komme"

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dashboards/cyberpulse-soc-dashboard.ndjson"
DASHBOARD_ID = "cyberpulse-soc-dashboard"
LOGS, ALERTS = "cyberpulse-logs", "cyberpulse-alerts"

DATASET_COLORS = {"windows.security": "#00E5FF", "zeek.conn": "#14B8A6", "zeek.dns": "#8B5CF6",
                  "zeek.notice": "#FFB020", "suricata.eve": "#FF4D6D"}
RULE_COLORS = {"SOC-002": "#00E5FF", "SOC-003": "#8B5CF6", "SOC-010": "#FF4D6D",
               "SOC-011": "#FFB020", "SOC-012": "#14B8A6", "SOC-013": "#38BDF8",
               "SOC-014": "#F472B6", "SOC-015": "#A3E635"}


def rule_names():
    names = {}
    for path in sorted((ROOT / "config/elastalert2/rules").glob("*.y*ml")):
        match = re.search(r'^name:\s*"?(?P<name>(?P<id>SOC-\d{3}) \|[^"]+?)"?\s*$',
                          path.read_text(encoding="utf-8"), re.M)
        if match:
            names[match.group("id")] = match.group("name").strip()
    return dict(sorted(names.items()))


def search_source(index_ref=True, query=""):
    source = {"query": {"query": query, "language": "kuery"}, "filter": []}
    if index_ref:
        source["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return json.dumps(source)


def index_ref(pattern_id):
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": pattern_id}]


def visualization(vis_id, title, vis_type, params, aggs, pattern_id=None, colors=None, query=""):
    state = {"title": title, "type": vis_type, "params": params, "aggs": aggs}
    attributes = {
        "title": title, "description": "", "version": 1,
        "uiStateJSON": json.dumps({"vis": {"colors": colors}} if colors else {}),
        "visState": json.dumps(state),
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(pattern_id is not None, query)},
    }
    return {"type": "visualization", "id": vis_id, "attributes": attributes,
            "references": index_ref(pattern_id) if pattern_id else []}


def metric(vis_id, title, pattern_id, agg_type="count", field=None, label=None):
    params = {"field": field} if field else {}
    if label:
        params["customLabel"] = label
    return visualization(vis_id, title, "metric", {
        "addTooltip": True, "addLegend": False, "type": "metric",
        "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                   "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 1000000}],
                   "labels": {"show": True}, "invertColors": False,
                   "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                             "subText": "", "fontSize": 44}},
    }, [{"id": "1", "enabled": True, "type": agg_type, "schema": "metric", "params": params}], pattern_id)


def terms(agg_id, schema, field, size, label, order_by="1"):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "size": size, "order": "desc", "orderBy": order_by,
                       "customLabel": label, "otherBucket": False, "missingBucket": False}}


def bar_params(horizontal, value_title, legend):
    category_position, value_position = ("left", "bottom") if horizontal else ("bottom", "left")
    return {
        "type": "histogram", "addTooltip": True, "addLegend": legend, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": category_position,
                          "show": True, "style": {}, "scale": {"type": "linear"},
                          "labels": {"show": True, "rotate": 0 if horizontal else -60,
                                     "filter": False, "truncate": 200}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                       "position": value_position, "show": True, "style": {},
                       "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                       "title": {"text": value_title}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": value_title, "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "showCircles": True}],
    }


def saved_search(search_id, title, pattern_id, columns):
    return {"type": "search", "id": search_id, "references": index_ref(pattern_id), "attributes": {
        "title": title, "description": "", "columns": columns, "sort": [["@timestamp", "desc"]],
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()}}}


def build():
    names = rule_names()
    rule_colors = {names[soc]: color for soc, color in RULE_COLORS.items() if soc in names}
    rules_line = " · ".join(f"**{soc}** {name.split(' | ')[2]}" for soc, name in names.items())
    header = (
        "## ⚡ CyberPulse SOC Lab — Detection Console\n"
        f"{rules_line}\n\n"
        "Inspect one run with `labels.replay_id:\"<id from reports/replay.json>\"` · "
        "Playbooks: `docs/playbooks.md` · Built by **Chandu Komme**"
    )

    objects = [
        {"type": "index-pattern", "id": LOGS, "references": [],
         "attributes": {"title": "soc-logs-*", "timeFieldName": "@timestamp"}},
        {"type": "index-pattern", "id": ALERTS, "references": [],
         "attributes": {"title": "soc-alerts", "timeFieldName": "@timestamp"}},
        visualization("cp-header", "CyberPulse header", "markdown",
                      {"fontSize": 12, "openLinksInNewTab": False, "markdown": header}, []),
        metric("cp-kpi-events", "Telemetry events", LOGS, label="Telemetry events"),
        metric("cp-kpi-alerts", "Alerts raised", ALERTS, label="Alerts raised"),
        metric("cp-kpi-sources", "Unique sources", LOGS, "cardinality", "source.ip", "Unique source IPs"),
        metric("cp-kpi-rules", "Rules fired", ALERTS, "cardinality", "rule_name", "Detection rules fired"),
        visualization("cp-alerts-donut", "Alerts by detection rule", "pie", {
            "type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "bottom",
            "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
        }, [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            terms("2", "segment", "rule_name", 10, "Rule")], ALERTS, rule_colors),
        visualization("cp-telemetry-bar", "Telemetry by scenario and source", "horizontal_bar",
                      bar_params(True, "Events", True),
                      [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                        "params": {"customLabel": "Events"}},
                       terms("2", "segment", "labels.scenario", 20, "Scenario"),
                       terms("3", "group", "event.dataset", 5, "Data source")],
                      LOGS, DATASET_COLORS),
        visualization("cp-alerts-table", "Alerts by rule and scenario", "table", {
            "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
            "showTotal": True, "totalFunc": "sum", "percentageCol": "",
        }, [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alerts"}},
            terms("2", "bucket", "rule_name", 10, "Rule", "_key"),
            terms("3", "bucket", "labels.scenario", 20, "Scenario", "_key")], ALERTS),
        visualization("cp-failed-accounts", "Failed logons by account", "horizontal_bar",
                      bar_params(True, "Failed logons", False),
                      [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                        "params": {"customLabel": "Failed logons"}},
                       terms("2", "segment", "user.name", 10, "Account")],
                      LOGS, {"Failed logons": "#FF4D6D"}, query="event.outcome:failure"),
        saved_search("cp-search-alerts", "Alert queue", ALERTS,
                     ["rule_name", "labels.scenario", "source.ip", "event.id"]),
        saved_search("cp-search-telemetry", "Telemetry stream", LOGS,
                     ["labels.scenario", "event.dataset", "source.ip", "user.name",
                      "event.outcome", "rule.name", "dns.question.length"]),
    ]

    layout = [  # id, type, x, y, w, h
        ("cp-header", "visualization", 0, 0, 48, 9),
        ("cp-kpi-events", "visualization", 0, 9, 12, 7),
        ("cp-kpi-alerts", "visualization", 12, 9, 12, 7),
        ("cp-kpi-sources", "visualization", 24, 9, 12, 7),
        ("cp-kpi-rules", "visualization", 36, 9, 12, 7),
        ("cp-alerts-donut", "visualization", 0, 16, 17, 17),
        ("cp-telemetry-bar", "visualization", 17, 16, 31, 17),
        ("cp-alerts-table", "visualization", 0, 33, 26, 15),
        ("cp-failed-accounts", "visualization", 26, 33, 22, 15),
        ("cp-search-alerts", "search", 0, 48, 48, 15),
        ("cp-search-telemetry", "search", 0, 63, 48, 20),
    ]
    objects.append({
        "type": "dashboard", "id": DASHBOARD_ID,
        "attributes": {
            "title": "CyberPulse SOC Lab — Detection Console",
            "description": "Live detections and replay telemetry by Chandu Komme.",
            "hits": 0, "version": 1, "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "panelsJSON": json.dumps([
                {"panelIndex": str(i + 1), "version": "2.19.5",
                 "embeddableConfig": {"hidePanelTitles": True} if object_id == "cp-header" else {},
                 "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)}, "panelRefName": f"panel_{i}"}
                for i, (object_id, _, x, y, w, h) in enumerate(layout)]),
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(False)},
        },
        "references": [{"name": f"panel_{i}", "type": kind, "id": object_id}
                       for i, (object_id, kind, *_rest) in enumerate(layout)],
    })
    return objects


def main():
    objects = build()
    OUTPUT.write_text("".join(json.dumps(o, ensure_ascii=False) + "\n" for o in objects), encoding="utf-8")
    print(f"Wrote {len(objects)} saved objects to {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
