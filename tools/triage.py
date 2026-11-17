#!/usr/bin/env python3
"""Automated triage: turn raw alerts into scored, prioritized incidents.

Author: Chandu Komme
Project: CyberPulse SOC Lab

Alerts that share an attacking source are one incident. Each incident is
scored from 0 to 100:

    score = highest rule severity
          + 8 for every additional distinct rule      (corroboration)
          + 10 for every additional ATT&CK tactic     (kill-chain progress)

and given a priority (P1 >= 85, P2 >= 65, otherwise P3) plus response actions
for the tactics it covers. Input is the JSON report written by
tools/replay.py. Standard library only.

Usage:
    python3 tools/triage.py reports/replay.json -o reports/incidents.md --json reports/incidents.json
"""

__author__ = "Chandu Komme"

import argparse
from collections import OrderedDict
import json
from pathlib import Path
import sys

RULES = {
    "SOC-002": {"severity": "high", "technique": "T1110.001", "tactic": "credential_access",
                "title": "Repeated Windows logon failures"},
    "SOC-003": {"severity": "high", "technique": "T1110.003", "tactic": "credential_access",
                "title": "Password spray"},
    "SOC-010": {"severity": "high", "technique": "T1071.001", "tactic": "command_and_control",
                "title": "High-severity IDS alert"},
    "SOC-011": {"severity": "medium", "technique": "T1046", "tactic": "discovery",
                "title": "Zeek port scan notice"},
    "SOC-012": {"severity": "medium", "technique": "T1071.004", "tactic": "command_and_control",
                "title": "Possible DNS tunneling"},
    "SOC-013": {"severity": "medium", "technique": "T1046", "tactic": "discovery",
                "title": "Vertical port scan"},
    "SOC-014": {"severity": "high", "technique": "T1557.001", "tactic": "credential_access",
                "title": "LLMNR/NBT-NS poisoner"},
    "SOC-015": {"severity": "critical", "technique": "T1041", "tactic": "exfiltration",
                "title": "Upload-heavy outbound session"},
}
SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 50, "low": 30}
TACTIC_ORDER = ["discovery", "credential_access", "lateral_movement", "command_and_control", "exfiltration"]
ACTIONS = {
    "discovery": "Confirm whether the source is an authorized scanner; if not, isolate it and review what it reached after the scan.",
    "credential_access": "Reset targeted accounts that logged on successfully, block the source, and look for follow-on logons.",
    "lateral_movement": "Isolate the destination hosts and collect process and logon evidence.",
    "command_and_control": "Block the destination, find the owning process on the source host, and hunt for beaconing.",
    "exfiltration": "Block the destination now, preserve flow records, and scope what data left the host.",
}


def priority(score):
    return "P1" if score >= 85 else "P2" if score >= 65 else "P3"


def score_incident(rule_ids):
    known = [RULES[r] for r in rule_ids if r in RULES]
    if not known:
        return 0
    base = max(SEVERITY_SCORE[r["severity"]] for r in known)
    tactics = {r["tactic"] for r in known}
    return min(100, base + 8 * (len(set(rule_ids)) - 1) + 10 * (len(tactics) - 1))


def build_incidents(report):
    """Group report alerts by source IP (falling back to scenario) into incidents."""
    groups = OrderedDict()
    for scenario, case in report["scenarios"].items():
        for alert in case["alerts"]:
            entity = alert.get("source_ip") or f"scenario:{scenario}"
            group = groups.setdefault(entity, {"alerts": [], "scenarios": set()})
            group["alerts"].append(alert)
            group["scenarios"].add(scenario)

    incidents = []
    for number, (entity, group) in enumerate(groups.items(), start=1):
        rule_ids = sorted({a["rule"] for a in group["alerts"]})
        tactics = sorted({RULES[r]["tactic"] for r in rule_ids if r in RULES},
                         key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        score = score_incident(rule_ids)
        times = sorted(a["alert_time"] for a in group["alerts"] if a.get("alert_time"))
        incidents.append({
            "incident": f"INC-{number:03}",
            "entity": entity,
            "score": score,
            "priority": priority(score),
            "rules": rule_ids,
            "techniques": sorted({RULES[r]["technique"] for r in rule_ids if r in RULES}),
            "tactics": tactics,
            "scenarios": sorted(group["scenarios"]),
            "alert_count": len(group["alerts"]),
            "alert_ids": [a["id"] for a in group["alerts"]],
            "evidence_event_ids": [a["event_id"] for a in group["alerts"]],
            "first_seen": times[0] if times else None,
            "last_seen": times[-1] if times else None,
            "actions": [ACTIONS[t] for t in tactics if t in ACTIONS],
        })
    incidents.sort(key=lambda i: (-i["score"], i["incident"]))
    return incidents


def render_markdown(report, incidents):
    by_priority = {p: sum(1 for i in incidents if i["priority"] == p) for p in ("P1", "P2", "P3")}
    lines = [
        f"# Triage queue — replay `{report['replay_id']}`",
        "",
        f"**{len(incidents)} incidents** from {sum(i['alert_count'] for i in incidents)} alerts · "
        f"P1: {by_priority['P1']} · P2: {by_priority['P2']} · P3: {by_priority['P3']}",
        "",
        "Score = highest rule severity + 8 per extra rule + 10 per extra ATT&CK tactic (max 100).",
        "",
        "| Incident | Priority | Score | Source | Rules | Tactics | Alerts |",
        "|---|---|---:|---|---|---|---:|",
    ]
    for i in incidents:
        lines.append(f"| {i['incident']} | **{i['priority']}** | {i['score']} | `{i['entity']}` | "
                     f"{', '.join(i['rules'])} | {', '.join(t.replace('_', ' ') for t in i['tactics'])} | {i['alert_count']} |")
    for i in incidents:
        lines += ["", f"## {i['incident']} — {i['priority']} (score {i['score']})", "",
                  f"- **Source:** `{i['entity']}`",
                  f"- **Detections:** " + "; ".join(f"{r} {RULES.get(r, {}).get('title', '')}".strip() for r in i["rules"]),
                  f"- **ATT&CK:** {', '.join(i['techniques'])}",
                  f"- **Scenarios:** {', '.join(i['scenarios'])}",
                  f"- **Evidence:** {', '.join(f'`{e}`' for e in i['evidence_event_ids'])}",
                  "", "**Recommended actions**", ""]
        lines += [f"1. {a}" for a in i["actions"]] or ["1. Review the evidence and record a disposition."]
    lines += ["", "---", "*Generated by `tools/triage.py` — CyberPulse SOC Lab by Chandu Komme*", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", type=Path, help="JSON report written by tools/replay.py")
    parser.add_argument("-o", "--output", type=Path, help="Markdown triage queue (default: stdout)")
    parser.add_argument("--json", type=Path, help="Also write incidents as JSON")
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        incidents = build_incidents(report)
    except (OSError, ValueError, KeyError) as error:
        print(f"Cannot triage: {error}", file=sys.stderr)
        return 1
    markdown = render_markdown(report, incidents)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"replay_id": report["replay_id"], "incidents": incidents}, indent=2) + "\n",
                             encoding="utf-8")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
        top = incidents[0] if incidents else None
        print(f"Triaged {len(incidents)} incident(s)"
              + (f"; top: {top['incident']} {top['priority']} score {top['score']}" if top else "")
              + f". Saved to {args.output}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
