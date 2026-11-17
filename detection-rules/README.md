# Detection rules

Eight ElastAlert2 rules in [`config/elastalert2/rules/`](../config/elastalert2/rules/) run live on the normalized OpenSearch fields, and the replay verifies each one end to end.

| Live rule | Type | Logic | Sigma reference |
|---|---|---|---|
| SOC-002 | frequency | 10+ failed logons per source IP in 5 minutes | [T1110_brute_force.yml](sigma/credential-access/T1110_brute_force.yml) |
| SOC-003 | cardinality | 5+ distinct accounts failing per source IP in 10 minutes | [T1110.003_password_spray.yml](sigma/credential-access/T1110.003_password_spray.yml) |
| SOC-010 | any | Suricata alert with severity 1 or 2 | [T1071.001_suricata_high_severity.yml](sigma/network/T1071.001_suricata_high_severity.yml) |
| SOC-011 | any | Zeek `Scan::Port_Scan` notice | [T1046_network_scan.yml](sigma/discovery/T1046_network_scan.yml) |
| SOC-012 | any | Zeek DNS name of 60+ characters | [T1071.004_dns_tunneling.yml](sigma/network/T1071.004_dns_tunneling.yml) |
| SOC-013 | cardinality | 20+ distinct failed TCP ports per source in 1 minute | [T1046_network_scan.yml](sigma/discovery/T1046_network_scan.yml) |
| SOC-014 | cardinality | 3+ clients answered on LLMNR/NBT-NS ports per source in 10 minutes | [T1557_llmnr_poison.yml](sigma/credential-access/T1557_llmnr_poison.yml) |
| SOC-015 | any | Outbound session: 20 MB+ up, under 1 MB down, 30 s+ | [T1041_c2_exfil.yml](sigma/exfiltration/T1041_c2_exfil.yml) |

Every one of the 16 Sigma files has positive and negative unit tests in [`tests/detections/`](../tests/detections/), run with `python -m detectlab test`. See [detection as code](../docs/detection-as-code.md) and the generated [ATT&CK coverage](../docs/attack-coverage.md). Load [`attack-navigator-layer.json`](attack-navigator-layer.json) in the ATT&CK Navigator for a heat map.

The [Sigma catalog](sigma/) holds 16 rule files written for the native source schemas. Several use correlations (event_count, value_count, temporal_ordered), and each one documents its false positives. To deploy a rule outside the lab, convert it with a pySigma backend, map the native fields to your data source, and re-run its unit tests.

| Technique | Rule | How it decides |
|---|---|---|
| T1003.001 | LSASS memory-read handle | Sysmon 10 on lsass.exe with a memory-read access mask or a minidump call stack, excluding trusted security and system processes |
| T1021.002 | Executable written to an admin share | Event 5145 write to ADMIN$ or C$ of an .exe, .dll or script, from a remote user account |
| T1041 | Upload-heavy outbound session | Zeek connection uploading 20 MB or more while receiving under 1 MB, for at least 30 seconds |
| T1046 | Scan notice and vertical port scan | Zeek scan notice, or 20 or more distinct failed ports from one source in a minute |
| T1047 | WMI execution | WmiPrvSE spawning a shell or LOLBin, or wmic process call create against a remote node |
| T1053.005 | Suspicious scheduled task | Event 4698 whose task runs a LOLBin, a user-path binary, or is hidden |
| T1059.001 | Encoded PowerShell | Every -EncodedCommand abbreviation plus a base64 payload, including renamed PowerShell |
| T1071.001 | High-severity IDS alert | Suricata alert with priority 1 or 2 |
| T1071.004 | DNS tunneling | Query of 60 or more characters, a 40-character label, or a long TXT or NULL lookup |
| T1078 | Logon after brute force | Failure burst followed by a success from the same source (temporal_ordered) |
| T1110.001 | Repeated logon failures | 10 failures from one source in 5 minutes (event_count) |
| T1110.003 | Password spray | 5 or more distinct accounts failing from one source in 10 minutes (value_count) |
| T1547.001 | Autorun registry persistence | Run, RunOnce or Winlogon value launching a user-path binary or a script host |
| T1550.002 | Pass-the-hash logon shape | Type 9 seclogo/Negotiate, or type 3 NTLM with a zero key length, excluding anonymous and computer accounts |
| T1557.001 | LLMNR/NBT-NS poisoner | One host answering name queries for 3 or more clients in 10 minutes (value_count) |
| T1562.001 | Defender tampering | Protection disabled, or an exclusion or real-time switch-off written to the Defender configuration |

Run `python -m detectlab lint` to check the catalog, and validate with pySigma before converting a rule to another backend. Review the false-positive notes beside each rule. For operation of the active detection, use the [replay walkthrough](../README.md#detection-validation-and-evidence).

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*
