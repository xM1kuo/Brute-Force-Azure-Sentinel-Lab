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
