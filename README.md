# 🍯 Azure Honeypot + Microsoft Sentinel SIEM

> **Live brute force attack detection and geolocation mapping using Microsoft Azure and Sentinel**

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Query_Language-red?style=for-the-badge)

---

## 📋 Overview

Deployed an intentionally vulnerable Windows virtual machine on Microsoft Azure to act as a honeypot — a decoy system designed to attract and log real-world cyberattacks. Microsoft Sentinel was configured as the SIEM to ingest, query, and visualize security events including brute force login attempts from global threat actors.

**Within 24 hours of deployment, the honeypot captured 300+ real brute force attempts from 4 countries.**

---

## 🎯 Objectives

- Deploy an exposed Windows VM to attract automated internet scanners
- Configure Microsoft Sentinel to collect and analyze Windows Security Events
- Write KQL queries to identify and categorize attack patterns
- Build a live geolocation attack map to visualize threat origins
- Cross-reference attacker IPs with threat intelligence platforms

---

## 🏗️ Architecture

```
Internet          Honeypot VM        Log Analytics      Microsoft         Attack Map
Attackers    →    CORP-Admin     →   Workspace      →   Sentinel SIEM  →  Workbook
(Global)          (Exposed)          (honeypot-law)     (Threat Detection) (Live Map)
```

---

## ☁️ Resources Deployed

| Resource | Name | Details |
|----------|------|---------|
| Virtual Machine | CORP-Admin | Standard_B2ats_v2 · Windows 10 · West US 3 |
| Resource Group | honeypot-lab-rg | Container for all lab resources |
| Log Analytics Workspace | honeypot-law | Log ingestion and storage |
| SIEM | Microsoft Sentinel | Threat detection and visualization |
| Data Collection Rule | honeypot-dcr | Pipes VM logs to Sentinel |
| NSG Rule | DANGER_AllowAll | All ports open · Priority 100 |
| Workbook | BruteForceTest1 | Live attack map dashboard |

---

## ⚙️ Setup Steps

### 1. Create Resource Group
```
Portal → Resource Groups → Create
Name: honeypot-lab-rg | Region: West US 3
```

### 2. Deploy Windows VM
```
Virtual Machines → Create
Name: CORP-Admin | Size: Standard_B2ats_v2
Username: CORP-Admin | Inbound: RDP (3389)
```

### 3. Open All Ports (NSG Rule)
```
CORP-Admin-nsg → Inbound Rules → Add
Source: Any | Destination: Any | Protocol: Any
Action: Allow | Priority: 100 | Name: DANGER_AllowAll
```

### 4. Disable Windows Firewall
```powershell
# Run as Administrator inside the VM
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Verify
Get-NetFirewallProfile | Select Name, Enabled
# All three should return: Enabled: False
```

### 5. Create Log Analytics Workspace
```
Search "Log Analytics Workspaces" → Create
Name: honeypot-law | Region: West US 3
```

### 6. Enable Microsoft Sentinel
```
Search "Microsoft Sentinel" → Create
Select: honeypot-law → Add
```

### 7. Install Data Connector
```
Sentinel → Content Hub → "Windows Security Events" → Install
Sentinel → Data Connectors → Windows Security Events via AMA
Create data collection rule → honeypot-dcr
Resources: CORP-Admin | Collect: All Security Events
```

---

## 🔍 KQL Queries

### Verify Pipeline
```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count()
```

### Brute Force Attempts by IP
```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by AttackerIP = IpAddress, Account
| sort by FailedAttempts desc
```

### Attacker Geolocation
```kusto
SecurityEvent
| where EventID == 4625
| where IpAddress != "-"
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(GeoInfo.country)
| extend City = tostring(GeoInfo.city)
| extend Latitude = tostring(GeoInfo.latitude)
| extend Longitude = tostring(GeoInfo.longitude)
| summarize Attempts = count() by IpAddress, Country, City, Latitude, Longitude
| sort by Attempts desc
```

### Successful RDP Logins (Compromise Check)
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where Account !contains "SYSTEM"
| where Account !contains "ANONYMOUS"
| project TimeGenerated, Account, IpAddress
| sort by TimeGenerated desc
```

### Attack Intensity Over Time
```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
| render timechart
```

### Full Suspicious Activity Timeline
```kusto
SecurityEvent
| where EventID in (4625, 4624, 4798, 4799)
| project TimeGenerated, EventID, Account, IpAddress, Activity
| sort by TimeGenerated desc
```

---

## 📊 Windows Security Event ID Reference

| Event ID | Description | Observed | Significance |
|----------|-------------|----------|--------------|
| 4625 | Failed logon attempt | ✅ Yes | 🔴 Primary brute force indicator |
| 4624 | Successful logon | ✅ Yes | Internal Windows only — no breach |
| 4798 | User account enumeration | ✅ Yes | 🟠 Reconnaissance activity |
| 4799 | Security group enumeration | ✅ Yes | 🟠 Reconnaissance activity |
| 4672 | Special privileges assigned | ✅ Yes | Tied to own sessions |
| 4738 | User account changed | ✅ Yes | Own password reset |
| 4724 | Password reset attempt | ✅ Yes | Own action confirmed |

---

## 🌍 Live Attack Results (First 24 Hours)

| IP Address | Country | City | Attempts | VirusTotal | Intel |
|------------|---------|------|----------|------------|-------|
| 157.10.30.86 | 🇵🇰 Pakistan | Karachi | **181** | ⚠️ Suspicious | Wind Waves Broadband — SOCRadar flagged |
| 103.25.211.7 | 🇮🇩 Indonesia | — | **111** | ⚠️ Suspicious | CrowdSec: DB Bruteforce, HTTP Exploit, HTTP Crawl |
| 194.165.16.166 | 🇲🇨 Monaco | Monaco | **2** | ✅ Clean | First attacker — likely VPN/proxy |
| 45.142.154.96 | 🇭🇰 Hong Kong | — | **1** | ❓ Unknown | Joined within 24 hours |

### Summary Stats
```
Total Attempts  :  300+
Countries       :  4
Successful RDP  :  0  ← Zero breaches confirmed
Time to First Attack: ~1 hour after deployment
```

---

## 🔬 Threat Intelligence Findings

### 103.25.211.7 (Indonesia) — Most Notable
Cross-referenced on **VirusTotal** and **CrowdSec**:
- ISP: PT Transdata Sejahtera (AS132653)
- CrowdSec community history: **Database Bruteforce / HTTP Crawl / HTTP Exploit**
- This is a **known multi-target threat actor** — not an opportunistic one-off

### 157.10.30.86 (Pakistan)
- ISP: Wind Waves Broadband Private Limited (AS152296)
- **SOCRadar** flagged as Suspicious
- 1 detected file communicating with this IP (VirusTotal)
- Highest volume attacker: 181 attempts

---

## 🛡️ Attack Map Workbook

Built a live Sentinel Workbook (BruteForceTest1) combining:
- **World map** with colored pins sized by attempt volume (hot/cold heatmap)
- **IP intelligence table** — attacker IPs, countries, cities, attempt counts
- **Event ID breakdown** — full activity summary by event type
- **Auto-refresh: 5 minutes** — updates live

### Map Visualization Settings
```
Location info: Latitude/Longitude
Latitude field: Latitude
Longitude field: Longitude
Size by: Attempts
Color palette: Blue to Red (cold → hot)
Metric Label: Country
Metric Value: Attempts
```

---

## ✅ Outcomes

- [x] VM successfully exposed to internet and discovered by bots within ~1 hour
- [x] 300+ real brute force attempts captured and logged
- [x] Attackers geolocated to 4 countries using KQL + Azure geo functions
- [x] Known threat actors identified via VirusTotal and CrowdSec
- [x] Zero successful unauthorized logins confirmed
- [x] Live attack map deployed with auto-refresh
- [x] Full SOC dashboard built (map + IP table + event breakdown)

---

## 💰 Cost

| Resource | Monthly Cost |
|----------|-------------|
| Standard_B2ats_v2 VM | ~$6.86 |
| Log Analytics | Free (under 5GB/day) |
| Microsoft Sentinel | Free (first 31 days) |
| Public IP + Storage | ~$5.00 |
| **Total** | **~$12/month** |

> 💡 Azure free trial provides $200 credit — enough to run this lab for ~500 days

**To stop all charges:**
```
Azure Portal → Resource Groups → honeypot-lab-rg → Delete resource group
```

---

## 🧰 Tools & Technologies

- **Microsoft Azure** — Cloud infrastructure
- **Microsoft Sentinel** — SIEM / threat detection
- **Log Analytics Workspace** — Log ingestion and KQL querying
- **Azure Monitor Agent** — Data collection from VM
- **KQL (Kusto Query Language)** — Log analysis and threat hunting
- **VirusTotal** — IP reputation and threat intelligence
- **CrowdSec CTI** — Community threat intelligence
- **Azure Workbooks** — Dashboard and visualization

---

## 📚 What I Learned

- How automated internet scanners discover exposed systems within minutes to hours
- How to configure a cloud-native SIEM from scratch (data connectors, DCRs, workspaces)
- Writing KQL queries to detect, analyze, and visualize attack patterns
- Performing basic threat intelligence analysis against live attacker IPs
- How to correlate multiple event IDs to distinguish real attacks from Windows internals
- Building live security dashboards for threat monitoring

---

## 🚀 Future Improvements

- [ ] Create Sentinel Analytic Rules to auto-generate incidents on 10+ failed logins
- [ ] Build automated playbook to block attacker IPs and send email alerts
- [ ] Map attack TTPs to MITRE ATT&CK framework (T1110 Brute Force, T1021 Remote Services)
- [ ] Deploy Cowrie SSH honeypot on Linux VM to capture actual password attempts
- [ ] Add threat intelligence feed (AlienVault OTX) for automatic IP reputation scoring

---

*Built March 2026 — Azure Honeypot Lab*
