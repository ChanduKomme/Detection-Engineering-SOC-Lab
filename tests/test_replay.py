"""Offline tests for the replay harness and case report. Author: Chandu Komme

A small Python model of the Vector transforms turns generated records into the
documents OpenSearch would hold, so verification and reporting logic can be
exercised without Docker.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import UUID

import pytest

import case_report
import replay

REPLAY_ID = UUID("12345678-1234-5678-1234-567812345678")
STAMP = datetime(2026, 11, 17, 9, 30, 0, 125000, tzinfo=timezone.utc)


def fixtures():
    windows = json.loads(replay.WINDOWS_FIXTURES.read_text())
    network = json.loads(replay.NETWORK_FIXTURES.read_text())
    return windows, network


def generate():
    windows, network = fixtures()
    next_ip = replay.address_factory(REPLAY_ID)
    return (windows, network, replay.make_events(windows, REPLAY_ID, STAMP, next_ip),
            replay.make_network_records(network, REPLAY_ID, STAMP, next_ip))


def normalize_windows(event):
    code = event["winlog"]["event_id"]
    return {"_id": event["event"]["id"], "_source": {
        "@timestamp": event["@timestamp"],
        "event": {"dataset": "windows.security", "category": "authentication", "code": str(code),
                  "outcome": "failure" if code == 4625 else "success", "id": event["event"]["id"]},
        "host": event["host"], "source": {"ip": event["winlog"]["event_data"]["IpAddress"]},
        "user": {"name": event["winlog"]["event_data"]["TargetUserName"]},
        "labels": event["labels"], "pipeline": {"ingested_at": "now"}}}


def normalize_network(stream, record, event_id):
    dataset = "suricata.eve" if stream.startswith("suricata/") else "zeek." + Path(stream).stem
    source = record.get("id.orig_h") or record.get("src") or record.get("src_ip")
    doc = {"event": {"dataset": dataset, "id": event_id}, "labels": record["labels"], "source": {"ip": source}}
    if "query" in record:
        doc["dns"] = {"question": {"name": record["query"], "length": len(record["query"])}}
    return {"_id": f"auto-{event_id}", "_source": doc}


def alerts_for(expected, indexed, rules):
    """Fabricate ElastAlert2 writeback documents that satisfy the expected matrix."""
    alerts = []
    for scenario, row in expected.items():
        source = next(h["_source"] for h in indexed if h["_source"]["labels"]["scenario"] == scenario)
        for soc_id, count in row.items():
            for n in range(count):
                alerts.append({"_id": f"{scenario}-{soc_id}-{n}", "_source": {
                    "rule_name": rules[soc_id], "alert_sent": True, "alert_time": "2026-11-17T09:31:00Z",
                    "labels": source["labels"], "event": {"id": source["event"]["id"]},
                    "source": {"ip": source.get("source", {}).get("ip")}}})
    return alerts


def test_load_rules_reads_every_live_rule():
    rules = replay.load_rules()
    assert set(rules) == {"SOC-002", "SOC-003", "SOC-010", "SOC-011", "SOC-012", "SOC-013", "SOC-014", "SOC-015"}
    assert list(rules) == sorted(rules)


def test_password_spray_events_rotate_accounts():
    windows, *_ = fixtures()
    spray = [s for s in windows if s["name"] == "password-spray"]
    events = replay.make_events(spray, REPLAY_ID, STAMP)
    assert len({e["winlog"]["event_data"]["TargetUserName"] for e in events}) == 6
    assert len({e["winlog"]["event_data"]["IpAddress"] for e in events}) == 1


def test_sources_never_share_an_address():
    _, _, events, records = generate()
    windows_ips = {(e["labels"]["scenario"], e["winlog"]["event_data"]["IpAddress"]) for e in events}
    network_ips = {r.get("src") or r.get("id.orig_h") or r.get("src_ip") for _, r, _ in records}
    assert len({ip for _, ip in windows_ips}) == len(windows_ips)
    assert not network_ips & {ip for _, ip in windows_ips}


def test_network_records_have_the_shape_vector_expects():
    *_, records = generate()
    for stream, record, event_id in records:
        if stream.startswith("zeek/"):
            assert record["uid"] == event_id and isinstance(record["ts"], float)
        else:
            assert str(record["flow_id"]) == event_id
            assert datetime.strptime(record["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") == STAMP


def test_write_network_records_appends_ndjson(tmp_path):
    *_, records = generate()
    replay.write_network_records(records, tmp_path)
    replay.write_network_records(records[:1], tmp_path)
    lines = (tmp_path / "zeek/notice.log").read_text().splitlines()
    assert len(lines) == 3 and all(json.loads(line)["labels"] for line in lines)


def test_full_report_round_trip_and_case_file():
    windows, network, events, records = generate()
    rules = replay.load_rules()
    expected = replay.expected_matrix(windows + network, rules)
    indexed = [normalize_windows(e) for e in events] + [normalize_network(*r) for r in records]
    replay.verify_windows(events, indexed)
    replay.verify_network(records, indexed)
    report = replay.build_report(REPLAY_ID, rules, expected, indexed, alerts_for(expected, indexed, rules), {})
    fired = {name: sorted(a["rule"] for a in case["alerts"]) for name, case in report["scenarios"].items()}
    assert fired["spray-and-brute-force"] == ["SOC-002", "SOC-003"]
    assert fired["dns-normal"] == [] and fired["dns-tunnel"] == ["SOC-012"]
    markdown = case_report.render(report)
    assert markdown.count("## Case ") == sum(sum(row.values()) for row in expected.values())
    assert "T1110.003" in markdown and "Chandu Komme" in markdown
    assert "`below-threshold`" in markdown


def test_unexpected_alert_fails_the_replay():
    windows, network, events, records = generate()
    rules = replay.load_rules()
    expected = replay.expected_matrix(windows + network, rules)
    indexed = [normalize_windows(e) for e in events] + [normalize_network(*r) for r in records]
    alerts = alerts_for(expected, indexed, rules)
    noisy = dict(expected, **{"below-threshold": dict(expected["below-threshold"], **{"SOC-002": 1})})
    alerts += alerts_for({"below-threshold": noisy["below-threshold"]}, indexed, rules)
    with pytest.raises(RuntimeError, match="Alert matrix differs"):
        replay.build_report(REPLAY_ID, rules, expected, indexed, alerts, {})


def test_missing_network_document_is_detected():
    *_, records = generate()
    indexed = [normalize_network(*r) for r in records[1:]]
    with pytest.raises(RuntimeError, match="was not indexed"):
        replay.verify_network(records, indexed)


def test_tampered_windows_field_is_detected():
    _, _, events, _ = generate()
    indexed = [normalize_windows(e) for e in events]
    indexed[0]["_source"]["user"]["name"] = "someone-else"
    with pytest.raises(RuntimeError, match="Unexpected normalized fields"):
        replay.verify_windows(events, indexed)


def test_case_report_cli(tmp_path, capsys):
    report = {"replay_id": "r", "telemetry_index": "t", "alert_index": "a",
              "scenarios": {"x": {"event_ids": ["e1"], "alerts": [
                  {"id": "a1", "rule": "SOC-011", "rule_name": "SOC-011 | T1046 | scan", "event_id": "e1"}]},
                  "y": {"event_ids": ["e2"], "alerts": []}}}
    source = tmp_path / "r.json"
    source.write_text(json.dumps(report))
    assert case_report.main([str(source), "-o", str(tmp_path / "case.md")]) == 0
    text = (tmp_path / "case.md").read_text()
    assert "[T1046](https://attack.mitre.org/techniques/T1046/)" in text and "`y`" in text


def test_repeated_network_records_expand_templates():
    *_, records = generate()
    scan = [r for _, r, _ in records if r["labels"]["scenario"] == "port-scan-connections"]
    assert len(scan) == 25 and len({r["id.resp_p"] for r in scan}) == 25
    assert all(isinstance(r["id.resp_p"], int) and isinstance(r["id.orig_p"], int) for r in scan)
    assert len({r["id.orig_h"] for r in scan}) == 1
    poison = [r for _, r, _ in records if r["labels"]["scenario"] == "llmnr-poisoner"]
    assert {r["id.resp_h"] for r in poison} == {"192.0.2.1", "192.0.2.2", "192.0.2.3"}
    assert all(r["id.orig_p"] == 5355 for r in poison)
    ids = [event_id for *_, event_id in records]
    assert len(ids) == len(set(ids))


def test_scenario_totals():
    windows, network, events, records = generate()
    assert (len(windows), len(network), len(events), len(records)) == (7, 12, 61, 53)
