# 🔐 SOC Lab — SIEM + SOAR Integration

> **Stack**: pfSense + Suricata + Splunk + Shuffle + TheHive  
> **Goal**: Build a fully automated threat detection and incident response system (SOAR) that requires zero manual analyst intervention

---

## 📌 Overview

This lab demonstrates a complete **SOAR (Security Orchestration, Automation and Response)** pipeline built on top of a SIEM foundation. When Kali Linux attacks the pfSense firewall, the entire chain — detection → case creation → IP block → notification — executes automatically within seconds.

### What This Lab Proves

- End-to-end automated incident response without human intervention
- Real-time threat detection using network IDS (Suricata) + SIEM correlation (Splunk)
- Automatic case management (TheHive) and alerting (Slack) via SOAR playbooks (Shuffle)
- **Automatic IP blocking on pfSense firewall** via SSH when multi-stage attack detected
- Multi-stage attack correlation across 5 MITRE ATT&CK-mapped scenarios

---

## 🎯 Results

**Full automated pipeline:**

```
Kali attacks → Suricata detects → Splunk alerts → Shuffle playbook → TheHive case + Slack notify + pfSense block IP
```

- ✅ 5 attack scenarios detected and mapped to MITRE ATT&CK
- ✅ Automatic TheHive case creation with full context (src IP, alert name, raw log)
- ✅ Real-time Slack notification
- ✅ Threat Intelligence lookup automation
- ✅ Multi-stage attack correlation (scan → brute force from same IP)
- ✅ **Automatic IP blocking on pfSense** when multi-stage attack detected (S4)
- ✅ Splunk Kill Chain Dashboard

---

## 🏗️ System Architecture

### Network Topology

```
[Kali Linux]──────WAN (192.168.56.x)──────[pfSense + Suricata]
192.168.56.132                              WAN: 192.168.56.130
                                            LAN: 192.168.1.1
                                                    │
                              ┌─────────────────────┼─────────────────────┐
                              │                     │                     │
                    [Ubuntu Victim]          [Splunk SIEM]         [SOAR Stack]
                    192.168.1.130            192.168.1.128          192.168.1.129
                    Apache + DVWA            (LAN)                  TheHive + Shuffle
```

> 📸 _[Screenshot: Network diagram]_

### VM Inventory

| VM | OS | RAM | IP | Role |
|----|----|-----|----|------|
| Kali Linux | Kali Rolling | 2GB | 192.168.56.132 | Attacker |
| pfSense | pfSense CE 2.8.1 | 1GB | WAN: .56.130 / LAN: .1.1 | Firewall + IDS |
| Ubuntu Victim | Ubuntu 22.04 | 2GB | 192.168.1.130 | Target |
| Splunk SIEM | Ubuntu 22.04 Server | 3GB | 192.168.1.128 | SIEM |
| SOAR Stack | Ubuntu 22.04 Server | 4GB | 192.168.1.129 | Shuffle + TheHive |

### Tech Stack

| Layer | Tool | Version | Role |
|-------|------|---------|------|
| Firewall | pfSense CE | 2.8.1 | Gateway, NAT, firewall rules, IP blocking |
| Network IDS | Suricata | 7.0.8 | Packet inspection, custom rules, EVE JSON |
| SIEM | Splunk Enterprise | 10.2.3 | Log aggregation, SPL queries, real-time alerting |
| SOAR | Shuffle Automation | Latest | Workflow automation, playbook engine |
| Case Management | TheHive | 5.3 | Incident tracking, case creation |
| Attacker | Kali Linux | Rolling | nmap, hydra, sqlmap |
| Target | DVWA | Latest | Vulnerable web application |

---

## 🔄 Incident Response Pipeline

| Step | Action | Tool |
|------|--------|------|
| 1 | Kali attacks pfSense WAN | Kali Linux |
| 2 | Suricata detects suspicious traffic | Suricata on pfSense |
| 3 | pfSense sends syslog to Splunk (UDP 514) | pfSense Syslog |
| 4 | Splunk analyzes logs and triggers real-time alert | Splunk Enterprise |
| 5 | Splunk sends webhook to Shuffle SOAR | Splunk Webhook Action |
| 6 | Shuffle Tools 1: create TheHive case + Slack notify | Shuffle Automation |
| 7 | Shuffle Tools 2 (S4 only): SSH into pfSense → block attacker IP | Shuffle + pfctl |
| 8 | Analyst receives Slack notification, investigates on TheHive | TheHive 5.3 |

> 📸 _[Screenshot: Shuffle workflow diagram]_

---

## ⚔️ Attack Scenarios

5 attack scenarios simulated and mapped to MITRE ATT&CK framework:

| # | Scenario | MITRE Technique | Detection | SOAR Response |
|---|----------|----------------|-----------|---------------|
| S1 | Nmap Port Scan | T1046 | Suricata rule | Detection only |
| S2 | Low & Slow Scan | T1046 Evasion | Suricata threshold | Detection only |
| S3 | SSH Brute Force | T1110 | Suricata + Splunk alert | Auto case + Slack |
| S4 | Multi-stage Correlation | T1046 → T1110 | Splunk correlation SPL | Auto case + Slack + **Block IP** |
| S5 | Threat Intel Match | TI Lookup | Splunk + TI lookup | Auto case + Slack |

### S1 — Nmap Port Scan

```bash
nmap -sS 192.168.56.130
```

**Suricata Rule:**
```
alert tcp any any -> $HOME_NET any (msg:"SCAN Nmap Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 20,seconds 10; classtype:network-scan; sid:9000002; rev:1;)
```

> 📸 _[Screenshot: Splunk S1 result]_

---

### S2 — Low & Slow Scan

```bash
nmap -T1 -sS 192.168.56.130
```

**Suricata Rule:**
```
alert tcp any any -> $HOME_NET any (msg:"SCAN Low and Slow Port Scan"; flags:S; threshold:type threshold,track by_src,count 5,seconds 60; classtype:network-scan; sid:9000003; rev:1;)
```

> 📸 _[Screenshot: Splunk S2 result]_

---

### S3 — SSH Brute Force

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.130 -t 4
```

**Suricata Rule:**
```
alert tcp any any -> $HOME_NET 22 (msg:"ATTACK SSH Brute Force Detected"; flow:to_server; threshold:type threshold,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:9000004; rev:1;)
```

**Splunk Alert SPL:**
```
index=suricata sourcetype=syslog suricata AND "SSH Brute Force"
```

> 📸 _[Screenshot: TheHive case S3 + Slack alert]_

---

### S4 — Multi-stage Correlation + Auto Block (Flagship)

```bash
nmap -sS 192.168.56.130 && hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.130 -t 4
```

**Splunk Correlation SPL:**
```spl
index=suricata sourcetype=syslog suricata earliest=-5m
| rex field=_raw "{\w+}\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as alert_count by src_ip
| where alert_count >= 2
| eval description="Multi-stage attack from ".src_ip." (".alert_count." events in 5 min)"
```

**SOAR Auto-block:**  
Shuffle extracts src_ip from description → SSH into pfSense → adds IP to `blocklist` table via `pfctl`

```bash
# Shuffle Tools 2 command
if echo "$exec.search_name" | grep -q "S4"; then
  IP=$(echo "$exec.result.description" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -n "$IP" ]; then
    ssh -i /home/nvphuong/.ssh/pfsense_key -o StrictHostKeyChecking=no root@192.168.1.1 "pfctl -t blocklist -T add $IP"
    echo "Blocked $IP on pfSense"
  fi
fi
```

> 📸 _[Screenshot: Shuffle Tools 2 — Blocked 192.168.56.132]_
> 📸 _[Screenshot: Slack alert S4 with attacker IP]_

---

### S5 — Threat Intel Match

**Threat Intel Lookup Table:**
```csv
ip,threat,description
192.168.56.132,malicious,Kali Linux attacker
10.0.0.1,suspicious,Known scanner
185.220.101.1,malicious,Tor exit node
```

**Splunk TI Lookup SPL:**
```spl
index=suricata sourcetype=syslog suricata
| rex field=_raw "{\w+}\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| lookup threat_intel_ips ip as src_ip OUTPUT threat description
| where isnotnull(threat)
| table _time src_ip threat description
```

> 📸 _[Screenshot: Splunk TI match result]_

---

## 🤖 SOAR Playbook — Shuffle Workflow

### Workflow: SOC-Alert-Response

```
Webhook trigger (from Splunk)
        ↓
Shuffle Tools 1 — Execute Bash
        ├── curl → TheHive API: create alert
        └── curl → Slack webhook: notify
        ↓
Shuffle Tools 2 — Execute Bash (S4 only)
        └── SSH → pfSense: pfctl -t blocklist -T add <src_ip>
```

> 📸 _[Screenshot: Shuffle workflow canvas with 2 nodes]_

---

## 📊 Splunk Dashboard — Kill Chain

- **Alert Timeline** — line chart showing attack spikes over time
- **Top Attacking IPs** — bar chart ranking attackers by event count
- **Alert Severity Heatmap** — column chart by Suricata priority level
- **Attack Type Breakdown** — pie chart by alert category
- **Recent Alerts** — table with src_ip, alert_msg, priority

> 📸 _[Screenshot: Full Kill Chain Dashboard]_

---

## 🛠️ Setup Guide

See detailed docs:
- [docs/architecture.md](docs/architecture.md) — Architecture and configuration
- [docs/attack-scenarios.md](docs/attack-scenarios.md) — Attack simulation guide
- [configs/suricata/custom.rules](configs/suricata/custom.rules) — Suricata custom rules
- [configs/splunk/dashboard.xml](configs/splunk/dashboard.xml) — Splunk dashboard XML
- [configs/splunk/alerts.md](configs/splunk/alerts.md) — Splunk SPL queries
- [configs/shuffle/workflow.md](configs/shuffle/workflow.md) — Shuffle workflow guide
- [scripts/suricata_forwarder.sh](scripts/suricata_forwarder.sh) — EVE JSON forwarder script

### Quick Start

**VM boot order:**
1. pfSense — wait for full boot
2. Splunk SIEM
3. SOAR Stack
4. Ubuntu Victim
5. Kali Linux

**Health check:**
```bash
# Splunk VM
sudo /opt/splunk/bin/splunk status --run-as-root

# SOAR Stack
cd /opt/thehive && sudo docker compose ps
cd /opt/Shuffle && sudo docker compose ps

# Test pfSense SSH from SOAR VM
ssh -i /home/nvphuong/.ssh/pfsense_key root@192.168.1.1 "echo ok"

# Check blocklist
ssh -i /home/nvphuong/.ssh/pfsense_key root@192.168.1.1 "pfctl -t blocklist -T show"
```

---

## 🚧 Challenges & Lessons Learned

| Challenge | Root Cause | Solution |
|-----------|-----------|---------|
| SSH from Splunk to pfSense timeout | Login Protection auto-blocked IP | Added Splunk IP to pfSense Pass List, raised threshold to 1000 |
| Suricata custom rule not loading | Category not enabled in WAN Rules | Enabled custom.rules in WAN Categories |
| Shuffle OpenSearch Out of Memory | Java heap default 3GB, VM only had 2.8GB RAM | Increased VM RAM to 4GB, reduced heap to 256MB |
| TheHive Shuffle app rejected all fields | App v1.1.0 incompatible with TheHive 5.x API | Used Execute Bash + curl to call REST API directly |
| TheHive API returned 403 | Global admin API key lacks `manageAlert` permission | Created org-admin user inside Organisation SOC |
| pfSense REST API not available | Package not in pfSense CE 2.8.1 official repo | Used SSH + pfctl to block IPs directly |
| Suricata missed internal recon | Suricata only monitors WAN interface (em0) | Known limitation — internal LAN traffic bypasses pfSense |

**Key takeaways:**
- SOAR does not mean automate everything — categorizing scenarios into full-auto, semi-auto, and detection-only reflects how real SOCs operate
- Debugging with curl directly is the fastest way to isolate issues before integrating into workflows
- Compatibility is the biggest challenge when combining multiple independent open-source systems
- When a REST API is unavailable, SSH + CLI tools are a practical alternative for firewall automation

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Technique Name | Scenario | Detection Method | SOAR Response |
|-------------|---------------|----------|-----------------|---------------|
| T1046 | Network Service Discovery | S1, S2 | Suricata IDS rules | Detection only |
| T1110 | Brute Force — SSH | S3 | Suricata + Splunk alert | Auto case + Slack |
| T1046 → T1110 | Multi-stage Attack Chain | S4 | Splunk correlation SPL | Auto case + Slack + **Block IP** |
| — | Threat Intel Match | S5 | Splunk TI lookup | Auto case + Slack |

---

## 📁 Repository Structure

```
soc-soar-lab/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── attack-scenarios.md
│   └── mitre-attack-coverage.md
├── configs/
│   ├── suricata/
│   │   └── custom.rules
│   ├── splunk/
│   │   ├── alerts.md
│   │   ├── dashboard.xml
│   │   └── threat_intel_ips.csv
│   └── shuffle/
│       └── workflow.md
├── scripts/
│   └── suricata_forwarder.sh
└── screenshots/
    ├── architecture/
    ├── splunk/
    ├── shuffle/
    ├── thehive/
    └── slack/
```

---

*Built on VMware Workstation for personal security research and learning purposes.*
