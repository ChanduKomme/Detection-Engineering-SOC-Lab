"""MITRE ATT&CK coverage report and ATT&CK Navigator layer.

Author: Chandu Komme

Coverage tiers (also the Navigator score):

* 1 - Sigma reference rule with passing positive and negative unit tests.
* 2 - Live ElastAlert2 rule verified end to end by ``tools/replay.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import lint, sigma, testing

__author__ = "Chandu Komme"

TECHNIQUES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1027": "Obfuscated Files or Information",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1078": "Valid Accounts",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1557.001": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
}

# Official ATT&CK Enterprise tactic assignments for the techniques above.
TECHNIQUE_TACTICS = {
    "T1003.001": ["credential_access"],
    "T1021.002": ["lateral_movement"],
    "T1027": ["defense_evasion"],
    "T1041": ["exfiltration"],
    "T1046": ["discovery"],
    "T1047": ["execution"],
    "T1053.005": ["execution", "persistence", "privilege_escalation"],
    "T1059.001": ["execution"],
    "T1071.001": ["command_and_control"],
    "T1071.004": ["command_and_control"],
    "T1078": ["initial_access", "persistence", "privilege_escalation", "defense_evasion"],
    "T1110.001": ["credential_access"],
    "T1110.003": ["credential_access"],
    "T1547.001": ["persistence", "privilege_escalation"],
    "T1550.002": ["defense_evasion", "lateral_movement"],
    "T1557.001": ["credential_access", "collection"],
    "T1562.001": ["defense_evasion"],
}

TACTIC_ORDER = ["initial_access", "execution", "persistence", "privilege_escalation",
                "defense_evasion", "credential_access", "discovery", "lateral_movement",
                "collection", "command_and_control", "exfiltration", "impact"]

COLORS = {1: "#8ec8f0", 2: "#2f7fd1"}


def collect(root: Path, sigma_dir: Path, tests_dir: Path, rules_dir: Path) -> list[dict]:
    tested = testing.tested_rules(tests_dir, root)

    rows: dict[str, dict] = {}
    for ruleset in sigma.catalog(root / sigma_dir):
        relative = str(ruleset.rules[0].path.relative_to(root))
        cases = tested.get(relative, {"positive": 0, "negative": 0})
        for rule in ruleset.rules:
            tactics = [tag.split(".", 1)[1] for tag in rule.tags if lint.TACTIC_TAG.match(tag)]
            for tag in rule.tags:
                if not lint.ATTACK_TAG.match(tag):
                    continue
                technique = tag.split(".", 1)[1].upper()
                row = rows.setdefault(technique, {
                    "technique": technique, "name": TECHNIQUES.get(technique, technique),
                    "tactics": set(), "sigma": [], "live": [], "tests": 0,
                })
                row["tactics"].update(TECHNIQUE_TACTICS.get(technique, tactics))
                row["sigma"].append(rule.title)
                row["tests"] += cases["positive"] + cases["negative"]

    for live in lint.live_rules(root, rules_dir):
        row = rows.setdefault(live["technique"], {
            "technique": live["technique"], "name": TECHNIQUES.get(live["technique"], live["technique"]),
            "tactics": set(TECHNIQUE_TACTICS.get(live["technique"], [])), "sigma": [], "live": [], "tests": 0,
        })
        row["live"].append(live["soc_id"])

    ordered = []
    for row in rows.values():
        row["tactics"] = sorted(row["tactics"], key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        row["score"] = 2 if row["live"] else 1
        ordered.append(row)
    ordered.sort(key=lambda row: row["technique"])
    return ordered


def navigator_layer(rows: list[dict]) -> dict:
    return {
        "name": "Detection Engineering SOC Lab - Chandu Komme",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Detection coverage of the Detection Engineering SOC Lab by Chandu Komme. "
                        "Score 1: tested Sigma rule. Score 2: live ElastAlert2 rule verified by replay."),
        "techniques": [
            {
                "techniqueID": row["technique"],
                "score": row["score"],
                "color": COLORS[row["score"]],
                "comment": "; ".join(filter(None, [
                    ("Live: " + ", ".join(row["live"])) if row["live"] else "",
                    ("Sigma: " + ", ".join(row["sigma"])) if row["sigma"] else "",
                ])),
                "enabled": True,
                "showSubtechniques": True,
            }
            for row in rows
        ],
        "gradient": {"colors": [COLORS[1], COLORS[2]], "minValue": 1, "maxValue": 2},
        "legendItems": [
            {"label": "Tested Sigma rule", "color": COLORS[1]},
            {"label": "Live rule verified by replay", "color": COLORS[2]},
        ],
        "metadata": [{"name": "author", "value": "Chandu Komme"}],
    }


def markdown(rows: list[dict]) -> str:
    live = sum(1 for row in rows if row["live"])
    lines = [
        "# MITRE ATT&CK coverage",
        "",
        "<!-- Generated by `python -m detectlab coverage`. Do not edit by hand. -->",
        "",
        f"**{len(rows)} techniques** covered: **{live}** with live, replay-verified rules and "
        f"**{len(rows) - live}** with tested Sigma references. "
        "Load [`attack-navigator-layer.json`](../detection-rules/attack-navigator-layer.json) "
        "in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for the heat map.",
        "",
        "| Technique | Name | Tactics | Live rule | Sigma rules | Unit tests |",
        "|---|---|---|---|---|---:|",
    ]
    for row in rows:
        tactics = ", ".join(t.replace("_", " ") for t in row["tactics"]) or "—"
        lines.append(
            f"| [{row['technique']}](https://attack.mitre.org/techniques/{row['technique'].replace('.', '/')}/) "
            f"| {row['name']} | {tactics} | {', '.join(row['live']) or '—'} "
            f"| {'<br>'.join(row['sigma']) or '—'} | {row['tests']} |"
        )
    lines += ["", "---", "*Detection Engineering SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*", ""]
    return "\n".join(lines)


def render(root: Path, sigma_dir: Path, tests_dir: Path, rules_dir: Path) -> dict[Path, str]:
    rows = collect(root, sigma_dir, tests_dir, rules_dir)
    return {
        root / "docs/attack-coverage.md": markdown(rows),
        root / "detection-rules/attack-navigator-layer.json": json.dumps(navigator_layer(rows), indent=2) + "\n",
    }
