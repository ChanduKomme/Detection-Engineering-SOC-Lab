# Incident investigation worksheet

Use the replay report and OpenSearch evidence to produce a case another analyst can review.

| Field | What to record |
|---|---|
| Trigger | Rule name, ATT&CK technique, alert document ID, and replay ID |
| Timeline | First and last event timestamps, failures per source, and any successful logon |
| Scope | Affected host and accounts, source IP, and related telemetry |
| Assessment | Plausible explanations, supporting evidence, and evidence gaps |
| Disposition | True positive, false positive, or needs investigation, with reasoning |
| Follow-up | Additional telemetry or a tuning change, with a verification check |

## Generate the case file

After a replay, `python3 tools/case_report.py reports/replay.json -o reports/case.md` writes one case entry per alert. Each entry has the rule and technique, the evidence IDs, a link to the [triage playbook](playbooks.md), first checks, and a disposition checklist. The file also lists the scenarios that correctly stayed silent as tuning evidence.

## Example case summary

SOC-002 observed ten Windows logon failures from one synthetic address, and SOC-003 observed a single source failing against six accounts. In `spray-and-brute-force`, both rules fired for the same source, which shows how two detections can describe one actor from different angles. The near-miss scenarios illustrate below-threshold background, mixed outcomes, grouping by source, and a spray that stops at four accounts. In a real investigation, check for stale service credentials, shared egress, and a successful logon shortly after the failures before assigning a disposition.

## Analyst handoffs

| Tool | Handoff |
|---|---|
| MISP | Enrich approved real indicators and record provenance, confidence, and dates. Fixture addresses use reserved documentation ranges. |
| DFIR-IRIS | Open an investigation with the alert ID, scoped timeline, evidence references, and analyst disposition. |
| Velociraptor | With appropriate endpoint access, gather relevant Windows Security events for the scoped interval. |
| StackStorm | Model a case-creation or notification step using the reviewed alert fields. The bundled lab writes the alert and replay report locally. |

---
*Detection Engineering SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
