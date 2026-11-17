# Alert matrix — replay `23803a1b-736c-4987-b8d5-963d232b4f9b`

Expected versus observed alerts for every scenario, taken from the live `soc-alerts` index.

| Scenario | Events | Expected | Observed | Result |
|---|---:|---|---|---|
| `spray-and-brute-force` | 12 | SOC-002, SOC-003 | SOC-002, SOC-003 | ✅ match |
| `at-threshold` | 10 | SOC-002 | SOC-002 | ✅ match |
| `mixed-outcomes` | 10 | none | none | ✅ match |
| `split-sources` | 10 | none | none | ✅ match |
| `below-threshold` | 9 | none | none | ✅ match |
| `password-spray` | 6 | SOC-003 | SOC-003 | ✅ match |
| `spray-below-threshold` | 4 | none | none | ✅ match |
| `benign-notice` | 1 | none | none | ✅ match |
| `dns-normal` | 1 | none | none | ✅ match |
| `dns-tunnel` | 1 | SOC-012 | SOC-012 | ✅ match |
| `ids-high-severity` | 1 | SOC-010 | SOC-010 | ✅ match |
| `ids-low-severity` | 1 | none | none | ✅ match |
| `port-scan` | 1 | SOC-011 | SOC-011 | ✅ match |

**67 events, 7 alerts, 0 missing, 0 unexpected.**

---
*Collected by Chandu Komme — CyberPulse SOC Lab*
