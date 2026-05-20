# 🏗️ Architecture

## Network Topology

```
[Kali Linux]──────WAN (192.168.56.x / VMnet8 NAT)──────[pfSense + Suricata]
192.168.56.132                                           WAN: 192.168.56.130
                                                         LAN: 192.168.1.1
                                                                 │
                                         ┌───────────────────────┼───────────────────────┐
                                         │                       │                       │
                               [Ubuntu Victim]            [Splunk SIEM]           [SOAR Stack]
                               192.168.1.130              192.168.1.128            192.168.1.129
                               Apache + DVWA              (VMnet3 Host-only)       TheHive + Shuffle
```

## Network Segments

| Network | VMware Adapter | Subnet | Machines |
|---------|---------------|--------|----------|
| WAN | VMnet8 (NAT) | 192.168.56.x | Kali, pfSense WAN |
| LAN | VMnet3 (Host-only) | 192.168.1.x | pfSense LAN, Victim, Splunk, SOAR |

## VM Inventory

| VM | OS | RAM | IP | Network | Role |
|----|----|-----|----|---------|------|
| Kali Linux | Kali Rolling | 2GB | 192.168.56.132 (DHCP) | VMnet8 | Attacker |
| pfSense | pfSense CE 2.8.1 | 1GB | WAN: 192.168.56.130 / LAN: 192.168.1.1 | VMnet8 + VMnet3 | Firewall + IDS |
| Ubuntu Victim | Ubuntu 22.04 Desktop | 2GB | 192.168.1.130 | VMnet3 | Attack target |
| Splunk SIEM | Ubuntu 22.04 Server | 3GB | 192.168.1.128 | VMnet3 | SIEM |
| SOAR Stack | Ubuntu 22.04 Server | 4GB | 192.168.1.129 | VMnet3 | Shuffle + TheHive |

## Running Services

### pfSense (192.168.1.1)
- Web UI: `https://192.168.1.1`
- Suricata: running on WAN interface (em0), version 7.0.8
- EVE JSON log: `/var/log/suricata/suricata_em064296/eve.json`
- Custom rules: `/usr/local/etc/suricata/suricata_64296_em0/rules/custom.rules`
- Remote syslog: sending to Splunk `192.168.1.128:514` (UDP)

### Splunk SIEM (192.168.1.128)
- Web UI: `http://192.168.1.128:8000`
- Install path: `/opt/splunk`
- Index: `suricata`
- Data inputs:
  - UDP 514: syslog from pfSense (sourcetype: syslog)
  - File: `/var/log/suricata_eve.json` (sourcetype: _json)
- Cron job: SCP copy eve.json from pfSense every minute

### SOAR Stack (192.168.1.129)

**TheHive 5.3**
- URL: `http://192.168.1.129:9000`
- Docker compose: `/opt/thehive/docker-compose.yml`
- Organisation: SOC
- SOAR user: `soar@thehive.local` (role: org-admin)

**Shuffle SOAR**
- URL: `http://192.168.1.129:3001`
- Docker compose: `/opt/Shuffle/docker-compose.yml`
- Containers: shuffle-backend, shuffle-frontend, shuffle-opensearch, shuffle-orborus
- Workflow: `SOC-Alert-Response`

## Data Flow

```
1. Kali attacks pfSense WAN interface
2. Suricata detects → writes to eve.json + sends syslog UDP 514
3. Syslog → Splunk index=suricata (real-time via UDP 514)
4. Cron SCP every minute: pfSense eve.json → /var/log/suricata_eve.json → Splunk
5. Splunk real-time alert triggers → Webhook POST → Shuffle
6. Shuffle Execute Bash node:
   ├── curl → TheHive REST API: create alert
   └── curl → Slack Incoming Webhook: send notification
```

## Startup Sequence (After Reboot)

1. **pfSense** — wait for full boot
2. **Splunk SIEM**
   ```bash
   sudo /opt/splunk/bin/splunk start --run-as-root
   ```
3. **SOAR Stack** — containers auto-start via `restart: unless-stopped`
   ```bash
   # Verify
   cd /opt/thehive && sudo docker compose ps
   cd /opt/Shuffle && sudo docker compose ps
   ```
4. **Ubuntu Victim**
5. **Kali Linux**

## Health Check Commands

```bash
# Splunk status
sudo /opt/splunk/bin/splunk status --run-as-root

# TheHive containers
cd /opt/thehive && sudo docker compose ps

# Shuffle containers
cd /opt/Shuffle && sudo docker compose ps

# Test Shuffle webhook
curl -X POST http://192.168.1.129:3001/api/v1/hooks/<WEBHOOK_ID> \
  -H "Content-Type: application/json" \
  -d '{"test":"hello"}'

# Test TheHive API
curl -X POST http://192.168.1.129:9000/api/v1/alert \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","description":"Test","type":"suricata","source":"splunk","sourceRef":"test-001","severity":2}'

# Check Suricata on pfSense
pgrep suricata
tail -5 /var/log/suricata/suricata_em064296/eve.json
```
