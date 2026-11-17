#!/usr/bin/env python3
"""Turn a replay evidence report into a Markdown incident case file.

Author: Chandu Komme
Project: CyberPulse SOC Lab

Usage:
    python3 tools/case_report.py reports/replay.json -o reports/case.md

Each alert becomes a case entry with its rule, ATT&CK technique, severity,
evidence IDs, the matching triage playbook, and a disposition checklist for
the analyst. Scenarios that correctly produced no alert are listed as tuning
evidence. Standard library only.
"""

__author__ = "Chandu Komme"

import argparse
import json
from pathlib import Path
import sys

RULE_CONTEXT = {
    "SOC-002": {"severity": "High", "technique": "T1110.001", "title": "Password guessing",
                "first_checks": ["Stale service credential on the source host",
                                 "Shared NAT or VPN egress address",
                                 "Successful 4624 from the same source after the burst"]},
    "SOC-003": {"severity": "High", "technique": "T1110.003", "title": "Password spraying",
                "first_checks": ["Count of distinct accounts and whether any are privileged",
                                 "Any successful logon for a targeted account",
                                 "Whether the source is a known jump host or VDI gateway"]},
    "SOC-010": {"severity": "High", "technique": "T1071.001", "title": "High-severity IDS alert",
                "first_checks": ["Signature intent and known false-positive history",
                                 "Other flows between the same hosts",
                                 "Endpoint process that owns the connection"]},
    "SOC-011": {"severity": "Medium", "technique": "T1046", "title": "Network service discovery",
                "first_checks": ["Is the source an authorized scanner?",
                                 "Ports and hosts touched by the scan",
                                 "Connections from the scanner after the scan"]},
    "SOC-013": {"severity": "Medium", "technique": "T1046", "title": "Vertical port scan",
                "first_checks": ["Is the source an approved vulnerability scanner?",
                                 "Which ports answered, and what services run on them",
                                 "Successful connections from the source after the scan"]},
    "SOC-014": {"severity": "High", "technique": "T1557.001", "title": "LLMNR/NBT-NS poisoning",
                "first_checks": ["Is the source a legitimate name server?",
                                 "NTLM authentications from the answered clients to the source",
                                 "Whether LLMNR and NBT-NS can be disabled by policy"]},
    "SOC-015": {"severity": "Critical", "technique": "T1041", "title": "Upload-heavy exfiltration",
                "first_checks": ["Destination reputation and ownership",
                                 "Process on the source host that owns the connection",
                                 "Volume and type of data that left the host"]},
    "SOC-012": {"severity": "Medium", "technique": "T1071.004", "title": "Possible DNS tunneling",
                "first_checks": ["Query volume to the same parent domain",
                                 "Entropy and encoding of the subdomain labels",
                                 "Process on the source host issuing the queries"]},
}


def rule_technique(alert):
    parts = alert.get("rule_name", "").split(" | ")
    return parts[1] if len(parts) > 2 else "T0000"


def technique_link(technique):
    return f"[{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)"


def render(report):
    replay_id = report["replay_id"]
    scenarios = report["scenarios"]
    alerts = [(name, alert) for name, case in scenarios.items() for alert in case["alerts"]]
    quiet = [name for name, case in scenarios.items() if not case["alerts"]]
    lines = [
        f"# Incident case file — replay `{replay_id}`",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Prepared with | CyberPulse SOC Lab by Chandu Komme |",
        f"| Telemetry index | `{report['telemetry_index']}` |",
        f"| Alert index | `{report['alert_index']}` |",
        f"| Alerts raised | {len(alerts)} |",
        f"| Scenarios replayed | {len(scenarios)} ({len(quiet)} correctly silent) |",
        "",
        "## Alert summary",
        "",
        "| # | Rule | Technique | Severity | Scenario | Alert ID | Source event |",
        "|---:|---|---|---|---|---|---|",
    ]
    for number, (scenario, alert) in enumerate(alerts, start=1):
        context = RULE_CONTEXT.get(alert["rule"], {})
        technique = context.get("technique") or rule_technique(alert)
        lines.append(f"| {number} | {alert['rule']} | {technique_link(technique)} | "
                     f"{context.get('severity', 'Medium')} | {scenario} | `{alert['id']}` | `{alert['event_id']}` |")

    for number, (scenario, alert) in enumerate(alerts, start=1):
        context = RULE_CONTEXT.get(alert["rule"], {})
        evidence = scenarios[scenario]["event_ids"]
        lines += [
            "",
            f"## Case {number}: {alert.get('rule_name', alert['rule'])}",
            "",
            f"- **Scenario:** `{scenario}` — {len(evidence)} related telemetry record(s)",
            f"- **Playbook:** [{alert['rule']} triage](../docs/playbooks.md#{alert['rule'].lower()})",
            f"- **Hunting pivot:** filter `labels.replay_id: {replay_id}` and `labels.scenario: {scenario}`",
            f"- **Evidence IDs:** {', '.join(f'`{eid}`' for eid in evidence[:12])}"
            + (" …" if len(evidence) > 12 else ""),
            "",
            "**First checks**",
            "",
        ]
        lines += [f"- [ ] {check}" for check in context.get("first_checks", ["Review the linked evidence"])]
        lines += [
            "",
            "**Disposition** — [ ] True positive  [ ] Benign true positive  [ ] False positive",
            "",
            "Analyst notes:",
            "",
            "> _Record observations with evidence IDs, hypotheses separately, and any tuning change._",
        ]

    lines += ["", "## Correctly silent scenarios", "",
              "These negative cases are tuning evidence: the rules did not fire on near-miss activity.", ""]
    lines += [f"- `{name}` ({len(scenarios[name]['event_ids'])} records)" for name in quiet] or ["- none"]
    lines += ["", "---", "*Generated by `tools/case_report.py` — CyberPulse SOC Lab by Chandu Komme*", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", type=Path, help="JSON report written by tools/replay.py")
    parser.add_argument("-o", "--output", type=Path, help="Markdown file to write (default: stdout)")
    args = parser.parse_args(argv)
    try:
        markdown = render(json.loads(args.report.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError) as error:
        print(f"Cannot build case file: {error}", file=sys.stderr)
        return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
        print(f"Saved case file to {args.output}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
