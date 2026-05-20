# Splunk Alerts — SPL Queries

## S3 — SSH Brute Force

**Alert name**: `S3 SSH Brute Force`  
**Type**: Real-time, Per-Result  
**Action**: Webhook → Shuffle

```spl
index=suricata sourcetype=syslog suricata AND "SSH Brute Force"
```

---

## S4 — Multi-stage Correlation

**Alert name**: `S4 Multi-stage Correlation`  
**Type**: Scheduled — `*/5 * * * *` (every 5 minutes)  
**Trigger**: Number of Results > 0, For each result  
**Action**: Webhook → Shuffle

```spl
index=suricata sourcetype=syslog suricata earliest=-5m
| rex field=_raw "{\w+}\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as alert_count by src_ip
| where alert_count >= 2
| eval description="Multi-stage attack from ".src_ip." (".alert_count." events in 5 min)"
```

**Logic**: If the same src_ip appears 2+ times within 5 minutes → multi-stage attack (scan + brute force from same source).

---

## S5 — Threat Intel Match

**Alert name**: `S5 Threat Intel Match`  
**Type**: Real-time, Per-Result  
**Action**: Webhook → Shuffle  
**Lookup file**: `threat_intel_ips.csv`

```spl
index=suricata sourcetype=syslog suricata
| rex field=_raw "{\w+}\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| lookup threat_intel_ips ip as src_ip OUTPUT threat description
| where isnotnull(threat)
| table _time src_ip threat description
```

---

## Threat Intel Lookup Table

File: `configs/splunk/threat_intel_ips.csv`

```csv
ip,threat,description
192.168.56.132,malicious,Kali Linux attacker
10.0.0.1,suspicious,Known scanner
185.220.101.1,malicious,Tor exit node
```

**Deploy to Splunk:**
```bash
printf "ip,threat,description\n192.168.56.132,malicious,Kali Linux attacker\n10.0.0.1,suspicious,Known scanner\n185.220.101.1,malicious,Tor exit node\n" \
  | sudo tee /opt/splunk/etc/apps/search/lookups/threat_intel_ips.csv
```

Then go to **Splunk UI → Settings → Lookups → Lookup definitions → Add new**:
- Name: `threat_intel_ips`
- Type: File-based
- File: `threat_intel_ips.csv`

---

## Verify Lookup

```spl
| inputlookup threat_intel_ips.csv
```

Expected: 3 rows with ip, threat, description columns.
