# Alert triage playbooks

One playbook per live rule. Each starts from the alert in `soc-alerts`, pivots into `soc-logs-telemetry`, and ends with a disposition recorded in the [investigation worksheet](investigation.md). `tools/case_report.py` links every generated case to the matching section here.

| Rule | Technique | Severity | Logic |
|---|---|---|---|
| [SOC-002](#soc-002) | T1110.001 Password Guessing | High | 10+ failed 4625 logons from one source IP in 5 minutes |
| [SOC-003](#soc-003) | T1110.003 Password Spraying | High | Failed logons against 5+ distinct accounts from one source IP in 10 minutes |
| [SOC-010](#soc-010) | T1071.001 Web Protocols | High | Suricata alert with priority 1 or 2 |
| [SOC-011](#soc-011) | T1046 Network Service Discovery | Medium | Zeek `Scan::Port_Scan` notice |
| [SOC-012](#soc-012) | T1071.004 DNS | Medium | Zeek DNS query name of 60+ characters |

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

---
*CyberPulse SOC Lab — by [Chandu Komme](https://github.com/ChanduKomme)*

