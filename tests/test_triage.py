"""Tests for the automated triage engine. Author: Chandu Komme"""
import json

import triage


def alert(rule, ip, scenario="s", n=1):
    return {"id": f"{rule}-{n}", "rule": rule, "rule_name": rule, "event_id": f"e-{rule}-{n}",
            "source_ip": ip, "alert_time": f"2026-11-17T09:3{n}:00Z"}


def report(*scenarios):
    return {"replay_id": "r", "scenarios": {name: {"event_ids": [], "alerts": alerts} for name, alerts in scenarios}}


def test_single_alert_scores_its_severity():
    [inc] = triage.build_incidents(report(("a", [alert("SOC-011", "10.0.0.1")])))
    assert (inc["score"], inc["priority"], inc["tactics"]) == (50, "P3", ["discovery"])


def test_alerts_from_one_source_merge_and_corroborate():
    [inc] = triage.build_incidents(report(("x", [alert("SOC-002", "10.0.0.2", n=1), alert("SOC-003", "10.0.0.2", n=2)])))
    assert inc["rules"] == ["SOC-002", "SOC-003"] and inc["alert_count"] == 2
    assert inc["score"] == 78 and inc["priority"] == "P2"
    assert inc["first_seen"] < inc["last_seen"]


def test_kill_chain_progression_raises_priority():
    [inc] = triage.build_incidents(report(
        ("scan", [alert("SOC-013", "10.0.0.3", n=1)]),
        ("exfil", [alert("SOC-015", "10.0.0.3", n=2)])))
    assert inc["tactics"] == ["discovery", "exfiltration"]
    assert inc["score"] == 100 and inc["priority"] == "P1"
    assert len(inc["actions"]) == 2


def test_incidents_sorted_by_score_and_separate_per_source():
    incidents = triage.build_incidents(report(
        ("a", [alert("SOC-011", "10.0.0.1")]),
        ("b", [alert("SOC-015", "10.0.0.9")])))
    assert [i["entity"] for i in incidents] == ["10.0.0.9", "10.0.0.1"]


def test_missing_source_falls_back_to_scenario():
    a = alert("SOC-012", None)
    [inc] = triage.build_incidents(report(("dns-tunnel", [a])))
    assert inc["entity"] == "scenario:dns-tunnel"


def test_unknown_rule_scores_zero():
    assert triage.score_incident(["SOC-999"]) == 0


def test_cli_writes_markdown_and_json(tmp_path):
    source = tmp_path / "r.json"
    source.write_text(json.dumps(report(("x", [alert("SOC-014", "10.0.0.4")]), ("quiet", []))))
    assert triage.main([str(source), "-o", str(tmp_path / "q.md"), "--json", str(tmp_path / "q.json")]) == 0
    text = (tmp_path / "q.md").read_text()
    assert "INC-001" in text and "LLMNR/NBT-NS poisoner" in text and "Chandu Komme" in text
    data = json.loads((tmp_path / "q.json").read_text())
    assert data["incidents"][0]["priority"] == "P2"


def test_every_live_rule_has_triage_metadata():
    import replay
    assert set(replay.load_rules()) <= set(triage.RULES)
