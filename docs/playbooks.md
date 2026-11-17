# Alert triage playbooks

One playbook per live rule. Each starts from the alert in `soc-alerts`, pivots into `soc-logs-telemetry`, and ends with a disposition recorded in the [investigation worksheet](investigation.md). `tools/case_report.py` links every generated case to the matching section here.

| Rule | Technique | Severity | Logic |
|---|---|---|---|
| [SOC-002](#soc-002) | T1110.001 Password Guessing | High | 10+ failed 4625 logons from one source IP in 5 minutes |
| [SOC-003](#soc-003) | T1110.003 Password Spraying | High | Failed logons against 5+ distinct accounts from one source IP in 10 minutes |
| [SOC-010](#soc-010) | T1071.001 Web Protocols | High | Suricata alert with priority 1 or 2 |
| [SOC-011](#soc-011) | T1046 Network Service Discovery | Medium | Zeek `Scan::Port_Scan` notice |
| [SOC-012](#soc-012) | T1071.004 DNS | Medium | Zeek DNS query name of 60+ characters |
| [SOC-013](#soc-013) | T1046 Network Service Discovery | Medium | 20+ distinct refused or unanswered TCP ports from one source in 1 minute |
| [SOC-014](#soc-014) | T1557.001 LLMNR/NBT-NS Poisoning | High | One host answering LLMNR or NBT-NS for 3+ clients in 10 minutes |
| [SOC-015](#soc-015) | T1041 Exfiltration Over C2 Channel | Critical | Outbound session uploading 20 MB+ while receiving under 1 MB, lasting 30 s+ |

## SOC-002

**Repeated Windows logon failures — T1110.001**

1. **Scope.** Open the alert and copy `source.ip`, `user.name`, `host.name`, and `labels.replay_id`. Run the source aggregation in [windows-logons.md](../threat-hunting/queries/windows-logons.md).
2. **Did it work?** Search for a `4624` success from the same source after the first failure. A success turns this into a possible account compromise. The Sigma chain [T1078_logon_after_bruteforce.yml](../detection-rules/sigma/initial-access/T1078_logon_after_bruteforce.yml) describes that sequence.
3. **Benign checks.** Look for a service or scheduled task with a stale password (same account, regular interval) and for a NAT or VPN egress shared by many users (many accounts, many hosts).
4. **Contain (real environment).** Block or rate-limit the source at the edge, reset the targeted account if a success followed, and review its sessions.
5. **Tune.** If a known service caused the alert, fix the credential rather than excluding the account, and record the change.

## SOC-003

**Password spray from one source — T1110.003**

1. **Scope.** Run the distinct-account query in [password-spray.md](../threat-hunting/queries/password-spray.md). Note how many accounts were tried and whether any are privileged or disabled.
2. **Did any account fall?** Check for a `4624` for any targeted account from the same source within the window. Spraying aims for one weak password, so a single success matters.
3. **Benign checks.** VDI gateways, jump hosts, and identity sync jobs can show many accounts from one IP. Confirm with the asset owner.
4. **Contain (real environment).** Block the source, force a reset for accounts that logged on successfully, and check for MFA fatigue prompts.
5. **Tune.** Exclude only confirmed gateways by address, with an owner and review date. Do not raise the threshold to hide noise.

## SOC-010

**High-severity Suricata alert — T1071.001**

1. **Scope.** Read `rule.name` and `rule.id` (signature) and the endpoints. Pull other Suricata and Zeek records between the same IPs with [network.md](../threat-hunting/queries/network.md).
2. **Intent.** Decide what the signature detects and how often it has been a false positive. Check if the destination port and protocol fit the signature.
3. **Corroborate.** Look for repeated connections at regular intervals (beaconing) and DNS lookups that resolve to the destination.
4. **Contain (real environment).** Isolate the host if C2 is likely and collect the process tree that owns the connection.
5. **Tune.** Suppress noisy signatures by signature ID and host pair, never globally.

## SOC-011

**Zeek port scan notice — T1046**

1. **Scope.** Identify the scanner (`source.ip`) and the target from the notice. List what the scanner connected to afterwards.
2. **Authorized?** Compare against the vulnerability-scanner inventory and change tickets.
3. **Follow-on activity.** Successful connections to discovered services shortly after the scan raise the priority.
4. **Contain (real environment).** Block an unauthorized internal scanner and investigate the host that ran it.
5. **Tune.** Exclude authorized scanners by address with an owner and expiry.

## SOC-012

**Unusually long DNS query — T1071.004**

1. **Scope.** Read `dns.question.name` and `dns.question.length`. Count queries from the source to the same parent domain.
2. **Encoding.** Base32/base64-looking labels, high entropy, and steady volume suggest tunneling. Vendor telemetry and CDNs also use long names.
3. **Corroborate.** Find the process issuing the queries on the source host and whether the domain is newly registered.
4. **Contain (real environment).** Sinkhole the domain and isolate the host if tunneling is confirmed.
5. **Tune.** Allow-list confirmed vendor domains by parent domain with an owner and review date.

## SOC-013

**Vertical port scan from one source — T1046**

1. **Scope.** List the ports the source probed and which ones answered (`zeek.conn_state: SF`) with the network hunt in [network.md](../threat-hunting/queries/network.md).
2. **Authorized?** Compare the source with the scanner inventory and change tickets.
3. **Follow-on activity.** Look for successful sessions to the open ports after the scan, and for SOC-014 or SOC-015 alerts from the same source. The triage engine scores that progression higher.
4. **Contain (real environment).** Isolate an unauthorized internal scanner and investigate the host that ran it.
5. **Tune.** Exclude approved scanners by address with an owner and expiry. Keep the threshold.

## SOC-014

**LLMNR or NBT-NS poisoner answering many hosts — T1557.001**

1. **Scope.** List the clients the source answered (`destination.ip`) and when.
2. **Harvested credentials.** Search for NTLM authentications from those clients to the source. Each one is a hash the attacker may now crack or relay.
3. **Benign checks.** Confirm the source is not a legacy WINS or print server.
4. **Contain (real environment).** Isolate the source and reset passwords for accounts that authenticated to it.
5. **Fix the root cause.** Disable LLMNR and NetBIOS over TCP/IP by Group Policy wherever possible.

## SOC-015

**Upload-heavy outbound session — T1041**

1. **Scope.** Record the destination, port, bytes in each direction, and duration from the alert.
2. **Ownership.** Identify the process on the source host that owned the connection, and the destination's owner and reputation.
3. **Benign checks.** Backup and file-sync agents upload large volumes. Confirm against the approved destination list.
4. **Contain (real environment).** Block the destination, preserve the flow records, and isolate the host if the transfer is not explained.
5. **Tune.** Allow-list approved backup destinations by address with an owner and review date.

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*

