# 📡 SOC Threat Detection Monitor

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)](test_soc.py)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_Aligned-red?style=flat-square)](https://attack.mitre.org/)
[![Role](https://img.shields.io/badge/Role-SOC_Analyst_•_SIEM_Analyst-blue?style=flat-square)]()

> **Portfolio Security Tool** — Demonstrating SOC Analyst Workflow Skills

---

## 📌 Project Overview

This project simulates the **core analytical workflow of a Tier-1 SOC Analyst**:
parsing authentication logs, correlating events against detection rules, and generating
prioritized, MITRE ATT&CK-mapped security alerts for analyst review.

Built to demonstrate skills directly relevant to:
- **SOC Analyst (L1/L2)** — log analysis, alert triage, escalation decisions
- **SIEM Analyst** — rule-based correlation, detection logic, alert enrichment
- **Incident Response Analyst** — identifying attack stages, recommending containment
- **Security Monitoring Analyst** — continuous monitoring, pattern recognition

---

## 🏗️ Architecture

```
AUTH LOG FILE                   DETECTION ENGINE
(syslog format)                 (SIGMA-inspired rules)
      │                                │
      ▼                                ▼
┌─────────────┐              ┌────────────────────┐
│ Log Parser  │──LogEvents──▶│  State Accumulators│
│             │              │  - failed_by_ip    │
│  • Regex    │              │  - users_by_ip     │
│  • IP/User  │              │  - refused_by_ip   │
│    extract  │              │  - sudo_events     │
└─────────────┘              └────────────────────┘
                                       │
                              Threshold Evaluation
                                       │
                                       ▼
                             ┌──────────────────────┐
                             │   Alert Generator    │
                             │  • Severity scoring  │
                             │  • MITRE ATT&CK map  │
                             │  • Remediation steps │
                             └──────────────────────┘
                                       │
                             ┌─────────▼──────────┐
                             │  Report Output      │
                             │  • Console (color)  │
                             │  • JSON export      │
                             └────────────────────┘
```

---

## 🎯 Detection Rules

| Rule | Severity | MITRE Technique | Trigger Condition |
|:---|:---|:---|:---|
| **SSH Brute Force** | 🟠 HIGH | T1110.001 | ≥5 failed logins from same IP |
| **Password Spray** | 🟠 HIGH | T1110.003 | ≥3 unique usernames targeted from same IP |
| **Account Compromise** | 🔴 CRITICAL | T1078 | Successful login from previously brute-forced IP |
| **Port Scan** | 🟡 MEDIUM | T1046 | ≥8 refused connections from same IP |
| **Privilege Escalation** | 🟡 MEDIUM | T1548 | ≥3 sudo commands by same user |

All thresholds are configurable via `rules.json`.

---

## 📂 File Structure

```
soc-threat-monitor/
├── soc_monitor.py    # Core parser + detection engine + reporting
├── rules.json        # Configurable SIGMA-inspired detection rules
├── test_soc.py       # 15+ pytest unit tests
└── README.md         # This file
```

---

## 🚀 Quick Start

```bash
# Run with built-in demo (recommended first try)
python soc_monitor.py --demo

# Analyze a real auth.log
python soc_monitor.py --log /var/log/auth.log

# Export alerts to JSON for SIEM ingestion
python soc_monitor.py --log /var/log/auth.log --output alerts.json

# Use custom detection rules
python soc_monitor.py --log auth.log --rules custom_rules.json

# Run all tests
pytest test_soc.py -v
```

### Sample Output

```
======================================================================
           SOC THREAT DETECTION REPORT
           Generated: 2026-05-26 08:00:00
======================================================================
  Events Analyzed : 28
  Alerts Generated: 5
  Breakdown: CRITICAL=1 | HIGH=2 | MEDIUM=2

  🔴 [CRITICAL] SUCCESSFUL_LOGIN_AFTER_BRUTE_FORCE — ALERT-0003
     Description : Successful login from 10.0.0.99 as 'testuser' AFTER
                   multiple failed attempts. Possible account compromise!
     MITRE ATT&CK: T1078 - Valid Accounts
     Action      : IMMEDIATE: Isolate session. Reset account credentials.
```

---

## 📚 SOC Analyst Relevance

| SOC Skill | Demonstrated Here |
|:---|:---|
| **Log Parsing** | Regex-based syslog parser for auth.log format |
| **Event Correlation** | State-machine accumulation across multiple events |
| **Alert Triage** | Severity-ordered output with CRITICAL first |
| **MITRE ATT&CK** | Every alert maps to a specific tactic and technique |
| **Escalation Logic** | Compound rule: brute-force + success = CRITICAL |
| **Documentation** | Recommended remediation steps per alert |
| **Automation** | JSON export for SIEM integration or ticket creation |

---

## 🔗 Extension Ideas (Phase 2)

- **Elasticsearch/Kibana integration**: Push alerts to an ELK stack
- **Slack/Teams webhook**: Real-time alert notifications
- **GeoIP enrichment**: Map source IPs to countries
- **Threat Feed lookup**: Check IPs against OTX/AbuseIPDB
- **VirusTotal hash queries**: Enrich with malware reputation data
