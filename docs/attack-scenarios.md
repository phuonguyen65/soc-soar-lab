# ⚔️ Attack Scenarios

## Overview

| # | Scenario | MITRE | Tool | Splunk Alert | SOAR Response |
|---|----------|-------|------|-------------|---------------|
| S1 | Nmap Port Scan | T1046 | nmap | ❌ | Detection only |
| S2 | Low & Slow Scan | T1046 Evasion | nmap -T1 | ❌ | Detection only |
| S3 | SSH Brute Force | T1110 | hydra | ✅ | Auto case + Slack |
| S4 | Multi-stage Correlation | T1046→T1110 | nmap + hydra | ✅ | Auto case + Slack + **Block IP** |
| S5 | Threat Intel Match | TI Lookup | any | ✅ | Auto case + Slack |

---

## S1 — Nmap Port Scan

**MITRE**: T1046 Network Service Discovery  
**Purpose**: Reconnaissance — attacker scans for open ports on the target

**Kali command:**
```bash
nmap -sS 192.168.56.130
```

**Suricata Rule (SID 9000002):**
```
alert tcp any any -> $HOME_NET any (msg:"SCAN Nmap Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 20,seconds 10; classtype:network-scan; sid:9000002; rev:1;)
```

**Verify on Splunk:**
```spl
index=suricata sourcetype=syslog "Nmap Port Scan"
```

> 📸 _[Screenshot: Splunk S1 result]_

**Why no auto-block**: Too many false positives — legitimate scanners and security tools generate similar traffic patterns.

---

## S2 — Low & Slow Scan

**MITRE**: T1046 (Evasion variant)  
**Purpose**: Bypass IDS by scanning slowly — below standard detection thresholds

**Kali command:**
```bash
nmap -T1 -sS 192.168.56.130
```

**Suricata Rule (SID 9000003):**
```
alert tcp any any -> $HOME_NET any (msg:"SCAN Low and Slow Port Scan"; flags:S; threshold:type threshold,track by_src,count 5,seconds 60; classtype:network-scan; sid:9000003; rev:1;)
```

**Verify on Splunk:**
```spl
index=suricata sourcetype=syslog "Low and Slow"
```

> 📸 _[Screenshot: Splunk S2 result]_

---

## S3 — SSH Brute Force

**MITRE**: T1110 Brute Force (T1110.001 SSH)  
**Purpose**: Attack SSH service using a password wordlist

**Kali command:**
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.130 -t 4
```

**Suricata Rule (SID 9000004):**
```
alert tcp any any -> $HOME_NET 22 (msg:"ATTACK SSH Brute Force Detected"; flow:to_server; threshold:type threshold,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:9000004; rev:1;)
```

**Splunk Alert:**
- Name: `S3 SSH Brute Force`
- SPL: `index=suricata sourcetype=syslog suricata AND "SSH Brute Force"`
- Type: Real-time, Per-Result
- Action: Webhook → Shuffle

**SOAR Response**: Automatically creates TheHive case + Slack alert

> 📸 _[Screenshot: TheHive case S3]_
> 📸 _[Screenshot: Slack alert S3]_

---

## S4 — Multi-stage Correlation + Auto Block (Flagship)

**MITRE**: T1046 → T1110  
**Purpose**: Detect an attacker who scans then brute-forces from the same IP within 5 minutes — then automatically block them

**Kali command:**
```bash
nmap -sS 192.168.56.130 && hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.130 -t 4
```

**Splunk Correlation Alert:**
- Name: `S4 Multi-stage Correlation`
- Schedule: every 5 minutes (`*/5 * * * *`)
- SPL:
```spl
index=suricata sourcetype=syslog suricata earliest=-5m
| rex field=_raw "{\w+}\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as alert_count by src_ip
| where alert_count >= 2
| eval description="Multi-stage attack from ".src_ip." (".alert_count." events in 5 min)"
```

**SOAR Auto-block Flow:**
```
Splunk detects same IP in scan + brute force within 5 min
        ↓
Shuffle Tools 1: create TheHive case + Slack notify
        ↓
Shuffle Tools 2: extract IP from description → SSH into pfSense → pfctl block
```

**Shuffle Tools 2 command:**
```bash
if echo "$exec.search_name" | grep -q "S4"; then
  IP=$(echo "$exec.result.description" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -n "$IP" ]; then
    ssh -i /home/nvphuong/.ssh/pfsense_key -o StrictHostKeyChecking=no root@192.168.1.1 "pfctl -t blocklist -T add $IP"
    echo "Blocked $IP on pfSense"
  fi
fi
```

**Verify block on pfSense:**
```bash
ssh -i /home/nvphuong/.ssh/pfsense_key root@192.168.1.1 "pfctl -t blocklist -T show"
```

> 📸 _[Screenshot: Shuffle Tools 2 — Blocked 192.168.56.132]_
> 📸 _[Screenshot: Slack alert S4 with attacker IP]_
> 📸 _[Screenshot: TheHive case S4]_

**Note on pfSense block**: pfSense CE 2.8.1 does not include a REST API package. IP blocking is implemented via SSH + `pfctl` directly. The `blocklist` table must exist before the first block — it is created automatically on first use via `pfctl -t blocklist -T add`.

---

## S5 — Threat Intel Match

**MITRE**: TI-based Detection  
**Purpose**: Automatically match src_ip against a threat intelligence list

**Threat Intel Lookup Table** (`configs/splunk/threat_intel_ips.csv`):
```csv
ip,threat,description
192.168.56.132,malicious,Kali Linux attacker
10.0.0.1,suspicious,Known scanner
185.220.101.1,malicious,Tor exit node
```

**Splunk TI Alert:**
- Name: `S5 Threat Intel Match`
- Type: Real-time, Per-Result
- SPL:
```spl
index=suricata sourcetype=syslog suricata
| rex field=_raw "{\w+}\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| lookup threat_intel_ips ip as src_ip OUTPUT threat description
| where isnotnull(threat)
| table _time src_ip threat description
```

**SOAR Response**: On TI match → immediately creates case + Slack notify with threat label (malicious/suspicious)

> 📸 _[Screenshot: Splunk TI match result]_
> 📸 _[Screenshot: Slack alert S5]_
