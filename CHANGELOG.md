# Changelog

All notable changes to the CyberPulse SOC Lab by Chandu Komme.

## 2.1.0 — 2026-11-17

### Changed
- **Renamed the project to CyberPulse SOC Lab.** The Compose project is `cyberpulse-soc-lab`.
- **New console UI.** OpenSearch Dashboards now uses a locked dark theme with navy and cyan accents, a CyberPulse logo, mark, favicon, loading animation, browser title, and a branded login page.
- **Redesigned SOC dashboard.** The new Detection Console has KPI tiles, an alerts-by-rule donut, telemetry by scenario and source, an alert matrix, failed logons by account, the alert queue, and the telemetry stream, with fixed colors per data source and per rule.

### Added
- `tools/build_dashboard.py` generates the dashboard saved objects, and `tests/test_dashboard.py` validates them.
- `setup.sh` imports the dashboard automatically and makes it the landing page.
- `tools/replay.py` reads `OPENSEARCH_PORT` and `VECTOR_PORT` from `.env` and explains TLS port mix-ups.
- A separate `evidence/` folder with screenshots, live OpenSearch results, and terminal output.

## 2.0.0 — 2026-11-17

### Added
- **Detection-as-code toolkit** (`detectlab/`): an offline Sigma evaluator with field modifiers, boolean conditions, and `event_count`, `value_count`, `temporal`, and `temporal_ordered` correlations, including chained correlations.
- **Detection unit tests** for all 16 Sigma files: 52 positive and near-miss negative cases, enforced by the linter.
- **Rule linter** for Sigma metadata, UUIDs, ATT&CK tags, false-positive guidance, correlation references, live-rule naming, and Sigma-source links.
- **ATT&CK coverage** report and Navigator layer generated from the rules and checked for staleness in CI.
- **Four new live rules**: SOC-003 password spray (cardinality), SOC-010 high-severity Suricata alert, SOC-011 Zeek port scan, and SOC-012 long DNS query.
- **Three new Sigma rules**: password spray, successful logon after brute force (chained temporal correlation), and high-severity Suricata alert.
- **Network replay**: `tools/replay.py` writes fresh Zeek and Suricata records and verifies network alerts end to end.
- **Per-rule alert matrix**: every replay scenario declares the alerts it expects from every rule, so unexpected alerts fail the run.
- **Incident case files**: `tools/case_report.py` turns replay evidence into a Markdown case with playbook links and a disposition checklist.
- **Triage playbooks** for every live rule, plus password-spray and network hunting queries.
- `Makefile`, `requirements-dev.txt`, and a pytest suite (99 tests) covering the evaluator, catalog, replay logic, and case reports.
- A two-stage CI pipeline: offline detection-as-code gates, then Vector config validation and the live SIEM replay.

### Changed
- Vector now records `dns.question.length`, `destination.port`, `source.bytes`, and Zeek/Suricata event IDs, and the index template maps them.
- The Windows replay adds three spray scenarios and verifies two rules at once.

## 1.0.0

- Compose stack with Vector, OpenSearch, OpenSearch Dashboards, and ElastAlert2.
- SOC-002 brute-force rule with four replay scenarios and CI evidence.
- Sigma reference catalog, hunting queries, investigation worksheet, and AI triage prompt.

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*

