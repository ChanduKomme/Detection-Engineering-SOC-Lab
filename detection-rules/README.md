# Detection rules

Five ElastAlert2 rules in [`config/elastalert2/rules/`](../config/elastalert2/rules/) run live on the normalized OpenSearch fields, and the replay verifies each one end to end.

| Live rule | Type | Logic | Sigma reference |
|---|---|---|---|
| SOC-002 | frequency | 10+ failed logons per source IP in 5 minutes | [T1110_brute_force.yml](sigma/credential-access/T1110_brute_force.yml) |
| SOC-003 | cardinality | 5+ distinct accounts failing per source IP in 10 minutes | [T1110.003_password_spray.yml](sigma/credential-access/T1110.003_password_spray.yml) |
| SOC-010 | any | Suricata alert with severity 1 or 2 | [T1071.001_suricata_high_severity.yml](sigma/network/T1071.001_suricata_high_severity.yml) |
| SOC-011 | any | Zeek `Scan::Port_Scan` notice | [T1046_network_scan.yml](sigma/discovery/T1046_network_scan.yml) |
| SOC-012 | any | Zeek DNS name of 60+ characters | [T1071.004_dns_tunneling.yml](sigma/network/T1071.004_dns_tunneling.yml) |

Every one of the 16 Sigma files has positive and negative unit tests in [`tests/detections/`](../tests/detections/), run with `python -m detectlab test`. See [detection as code](../docs/detection-as-code.md) and the generated [ATT&CK coverage](../docs/attack-coverage.md). Load [`attack-navigator-layer.json`](attack-navigator-layer.json) in the ATT&CK Navigator for a heat map.

The [Sigma catalog](sigma/) contains portable rules for the original source schemas. The Windows authentication file includes a base event selector and an event-count correlation. To deploy a Sigma reference, choose a compatible backend, map each rule's native fields to that data source, and verify positive and negative examples. Some references require Sysmon, Windows Defender Operational events, or raw Zeek fields that the normalized lab index does not carry.

| Example rule | Native inputs |
|---|---|
| Windows failed-logon correlation | Windows Security event ID and source IP |
| Encoded PowerShell | Windows process image and command line |
| LSASS process access | Sysmon target image and access mask |
| Scheduled task creation | Windows Security event 4698 and its task content |
| Outbound volume | Zeek connection direction and originator bytes |
| DNS query length | Raw Zeek DNS query |
| Password spray | Windows Security event ID, source IP, and target account |
| Logon after brute force | Ordered failure burst and success from one source IP |

Run `python -m detectlab lint` to check the catalog, and validate with pySigma before converting a rule to another backend. Review the false-positive notes beside each rule. For operation of the active detection, use the [replay walkthrough](../README.md#detection-validation-and-evidence).

---
*Detection Engineering SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
