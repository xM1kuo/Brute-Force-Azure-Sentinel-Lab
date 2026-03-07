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





# PowerShell IT Automation + Threat Intelligence Portfolio

**Author:** Michael Martinez  
**Certifications:** CompTIA Network+ | Security+ | CySA+ | AZ-900  
**Stack:** PowerShell 7 | Python 3 | Azure | Active Directory | Microsoft Sentinel | VirusTotal API | AbuseIPDB API

---

## Overview

This repository contains 5 production-style automation scripts and a threat intelligence pipeline, all built in an Azure Windows Server 2022 lab environment with Active Directory. Each script solves a real IT problem encountered in help desk, sysadmin, and SOC analyst roles.

The lab was deployed entirely via Azure Cloud Shell — no GUI, no wizards. A Windows Server 2022 VM was provisioned, promoted to a Domain Controller for `lab.local`, and used as the target environment for all scripts.

The threat intelligence pipeline was built to enrich real attacker IPs captured by an Azure Sentinel honeypot — confirming known threat actors with 100/100 abuse scores and hundreds of prior victims worldwide.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Cloud Provider | Microsoft Azure (West US 3) |
| OS | Windows Server 2022 Datacenter |
| Domain | lab.local |
| Role | Active Directory Domain Controller |
| SIEM | Microsoft Sentinel (honeypot lab) |
| Threat Intel | VirusTotal API + AbuseIPDB API |

---

## Project 1: PowerShell IT Automation Scripts

### 1. `New-ADUserOnboard.ps1` — AD User Provisioning

**Problem:** New hire onboarding in AD is done manually — clicking through ADUC for every user wastes time and introduces human error.

**Solution:** Automates the full onboarding workflow: creates the OU if it doesn't exist, provisions the user account with correct attributes, places them in the right OU, and verifies the account is active.

**Key concepts:** `New-ADUser`, `New-ADOrganizationalUnit`, `Get-ADUser`, secure string handling

**Resume impact:** Sysadmin and Help Desk roles — demonstrates AD administration depth beyond basic ticket work.

---

### 2. `Failed-LoginMonitor.ps1` — Brute Force Detection & Auto-Response

**Problem:** Manual log review for failed logins is slow. By the time a Tier 1 analyst escalates, an attacker may have already succeeded.

**Solution:** Queries Windows Security Event Log for EventID 4625 (failed logins) in a configurable time window. Groups attempts by username, flags accounts that exceed a threshold, auto-disables them via AD, and writes an incident log with timestamp.

**Key concepts:** `Get-WinEvent`, EventID 4625, XML event parsing, `Disable-ADAccount`, incident logging

**Resume impact:** SOC Analyst roles — directly mirrors Tier 1 detection and automated response workflows. Ties into the Azure Sentinel honeypot project (same EventID, same detection logic).

---

### 3. `M365-LicenseAudit.ps1` — Microsoft 365 License Audit

**Problem:** Companies waste money on M365 licenses assigned to inactive or disabled users. Auditing manually across hundreds of accounts is error-prone.

**Solution:** Pulls all users, evaluates license assignment, last sign-in activity, and account status. Flags accounts as UNLICENSED, INACTIVE 90+ DAYS, or DISABLED. Exports a full CSV report.

**Key concepts:** Microsoft Graph API (`Get-MgUser`), license audit logic, CSV export, conditional flagging

**Resume impact:** Help Desk and Sysadmin roles — every M365 tenant needs this. Shows ability to produce reports that directly save the company money.

---

### 4. `SystemHealth-Report.ps1` — Daily System Health Report

**Problem:** Without proactive monitoring, disk space issues and memory pressure go unnoticed until systems fail.

**Solution:** Checks disk usage, CPU load, and memory consumption on the local machine. Applies green/yellow/red status thresholds. Outputs a styled HTML dashboard saved with a datestamp — ready to be scheduled as a daily task.

**Key concepts:** `Get-WmiObject`, threshold logic, HTML generation via here-strings, scheduled task integration

**Resume impact:** Sysadmin roles — shows initiative beyond reactive support. The HTML output is something a manager can actually open and read.

---

### 5. `log_parser.py` — Windows Security Log Parser (Python)

**Problem:** Raw Windows Security Event logs are noisy and difficult to parse manually at scale.

**Solution:** Python script that ingests Security Event log data, detects brute force patterns (threshold-based), flags after-hours logins, and outputs a clean summary report.

**Key concepts:** `re` (regex), `defaultdict`, datetime parsing, threshold detection, after-hours logic, file output

**Resume impact:** SOC Analyst roles — demonstrates cross-language capability (PowerShell + Python) and log analysis skills directly applicable to SIEM work.

---

## Project 2: Automated Threat Intelligence Pipeline

### `threat_pipeline.py` — Real Attacker IP Enrichment

**Problem:** Capturing attacker IPs in a SIEM is only half the job. Knowing *who* those attackers are — their reputation, ISP, prior victims, and threat score — is what turns raw data into actionable intelligence.

**Solution:** Python pipeline that takes attacker IPs captured from the Azure Sentinel honeypot, queries VirusTotal and AbuseIPDB in real time, calculates a composite threat level, and outputs a ranked threat report.

**Key concepts:** REST API integration (VirusTotal v3, AbuseIPDB v2), composite threat scoring, sorted reporting, file output

**Real data from the honeypot (March 2026):**

| IP | Country | VT Detections | Abuse Score | Reports | ISP | Level |
|----|---------|--------------|-------------|---------|-----|-------|
| 80.94.95.83 | Romania 🇷🇴 | 10 | 100/100 | 1,346 | UNMANAGED LTD | 🔴 HIGH |
| 109.205.211.14 | Azerbaijan 🇦🇿 | 9 | 100/100 | 432 | ColocationX | 🔴 HIGH |
| 84.8.107.159 | Saudi Arabia 🇸🇦 | 8 | 100/100 | 217 | Oracle Svenska AB | 🔴 HIGH |
| 103.25.211.7 | Indonesia 🇮🇩 | 0 | 14/100 | 2 | PT Transdata Sejahtera | 🟠 LOW |
| 157.10.30.86 | Pakistan 🇵🇰 | 0 | 3/100 | 1 | Wind Waves Broadband | 🟢 CLEAN |

**Resume impact:** Demonstrates a complete SOC workflow — honeypot captures real attackers, pipeline confirms known threat actors with verifiable external data. The Romanian IP alone had 1,346 prior abuse reports from other victims worldwide.

---

## Complete SOC Workflow

```
Azure Honeypot VM (exposed)
        ↓ captures attacker IPs
Microsoft Sentinel SIEM
        ↓ live geolocation attack map
threat_pipeline.py
        ↓ queries VirusTotal + AbuseIPDB
Threat Report
        ↓ confirmed threat actors, abuse scores, ISP data
Incident Response (Failed-LoginMonitor.ps1)
        ↓ auto-disables accounts, logs incidents
```

---

## Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| Active Directory administration | Scripts 1, 2 |
| Security event detection & response | Scripts 2, 5 |
| Threat intelligence enrichment | threat_pipeline.py |
| REST API integration | VirusTotal v3, AbuseIPDB v2, Microsoft Graph |
| Microsoft 365 administration | Script 3 |
| System monitoring & reporting | Script 4 |
| Python scripting | Scripts 5, threat_pipeline.py |
| Azure VM deployment (Cloud Shell) | All |
| Incident logging & documentation | Scripts 2, 5 |
| SIEM operations (Microsoft Sentinel) | Honeypot lab |

---

## How to Run

All PowerShell scripts require Windows Server with AD DS, PowerShell 5.1+, run as Administrator.

```powershell
# AD user provisioning
.\New-ADUserOnboard.ps1

# Brute force monitor
.\Failed-LoginMonitor.ps1

# Python log parser
python log_parser.py

# Threat intel pipeline (requires VirusTotal + AbuseIPDB API keys)
python threat_pipeline.py
```

---

## Related Project: Azure Honeypot + Sentinel SIEM Lab

Deployed an exposed Windows VM honeypot on Azure. Configured Microsoft Sentinel end-to-end with KQL detection rules. Captured 7,400+ real brute force attempts from Romania alone, plus Indonesia, Azerbaijan, Saudi Arabia, Pakistan and Morocco. Built a live geolocation attack map. Cross-referenced attacker IPs via VirusTotal and AbuseIPDB — identified known multi-target threat actors with 100/100 abuse scores.

→ [View Project](https://github.com/xM1kuo)

---

## Contact

Michael Martinez — [LinkedIn](https://linkedin.com/in/michael-martinez-31479b2a5) | [GitHub](https://github.com/xM1kuo)
