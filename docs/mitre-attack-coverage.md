# 🗺️ MITRE ATT&CK Coverage

## Techniques Detected

| Technique ID | Technique Name | Sub-technique | Scenario | Detection Method | SOAR Response |
|-------------|---------------|---------------|----------|-----------------|---------------|
| T1046 | Network Service Discovery | — | S1 (Nmap) | Suricata SID 9000002 | Detection only |
| T1046 | Network Service Discovery | Evasion | S2 (Low & Slow) | Suricata SID 9000003 | Detection only |
| T1110 | Brute Force | T1110.001 SSH | S3 | Suricata SID 9000004 + Splunk | Auto case + Slack |
| T1046 → T1110 | Multi-stage Attack Chain | — | S4 | Splunk Correlation SPL | Auto case + Slack |
| — | Threat Intelligence Match | — | S5 | Splunk TI Lookup | Auto case + Slack |

## Coverage by Tactic

| Tactic | Covered | Techniques |
|--------|---------|-----------|
| Reconnaissance | ✅ | T1046, T1046 Evasion |
| Initial Access | ❌ | — |
| Execution | ❌ | — |
| Persistence | ❌ | — |
| Defense Evasion | ✅ Partial | Low & Slow scan |
| Discovery | ✅ | T1046 |
| Lateral Movement | ❌ | — |
| Credential Access | ✅ | T1110 SSH Brute Force |
| Collection | ❌ | — |
| Exfiltration | ❌ | — |
| Command & Control | ❌ | — |

## Suricata Rules Summary

| SID | Rule Name | Technique | Priority |
|-----|-----------|-----------|---------|
| 9000002 | SCAN Nmap Port Scan Detected | T1046 | 3 |
| 9000003 | SCAN Low and Slow Port Scan | T1046 | 3 |
| 9000004 | ATTACK SSH Brute Force Detected | T1110 | 1 |

## Splunk Alerts Summary

| Alert Name | Type | Schedule | SOAR |
|-----------|------|---------|------|
| S3 SSH Brute Force | Real-time | Per-result | ✅ |
| S4 Multi-stage Correlation | Scheduled | `*/5 * * * *` | ✅ |
| S5 Threat Intel Match | Real-time | Per-result | ✅ |

## Limitations & Future Work

**Not detected in current setup:**
- Internal lateral movement — Suricata only monitors WAN interface, internal LAN traffic bypasses pfSense
- After-hours login — requires auth log forwarding from Victim (e.g., via Wazuh agent)
- Data exfiltration — requires DLP or full packet capture
- C2 communication — requires DNS/HTTP behavioral analysis

**Potential improvements:**
- Enable Suricata on LAN interface to detect internal reconnaissance
- Add Wazuh agent on Victim to forward `auth.log` for login monitoring
- Integrate pfSense REST API for automatic IP blocking (full-auto S4 response)
- Replace static TI CSV with live AbuseIPDB API integration
- Add MITRE ATT&CK Navigator layer export
