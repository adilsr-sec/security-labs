# 🕵️ Threat Intelligence Feed Aggregator

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)](test_threat_intel.py)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_Aligned-red?style=flat-square)](https://attack.mitre.org/)
[![Role](https://img.shields.io/badge/Role-Threat_Intel_Analyst-purple?style=flat-square)]()

> **Portfolio Security Tool** — Demonstrating Threat Intelligence Analysis Skills

---

## 📌 Project Overview

This tool demonstrates the workflow of a **Threat Intelligence Analyst**:
aggregating Indicators of Compromise (IOCs), checking their reputation against
threat databases, and producing MITRE ATT&CK-enriched reports.

In real SOC environments, threat intel analysts use tools like:
- **AbuseIPDB** — IP reputation scoring
- **VirusTotal** — Multi-engine file analysis and URL scanning
- **AlienVault OTX** — Open Threat Exchange feed aggregation
- **MISP** — Malware Information Sharing Platform
- **Shodan** — Internet-facing asset intelligence

This portfolio tool simulates these workflows **offline** with a built-in
IOC knowledge base, enabling full demonstration without API keys.

---

## 🎯 Supported IOC Types

| IOC Type | Example | Check Includes |
|:---|:---|:---|
| **IPv4 Address** | `91.108.4.11` | Reputation, category, C2/botnet/scanner flags |
| **Domain** | `malware-c2.ru` | Phishing, C2, malware delivery flags |
| **File Hash** | `3395856ce...` | MD5/SHA-1/SHA-256 malware signatures |

---

## 📊 Threat Categories & MITRE Mapping

| Category | MITRE Tactic | Example Technique |
|:---|:---|:---|
| **C2 Server** | Command and Control | T1071.001 - Web Protocols |
| **Botnet Node** | Impact | T1498 - Network Denial of Service |
| **Phishing Domain** | Credential Access | T1557 - Adversary-in-the-Middle |
| **Port Scanner** | Discovery | T1046 - Network Service Discovery |
| **Ransomware** | Impact | T1486 - Data Encrypted for Impact |
| **Tor Exit Node** | Defense Evasion | T1090.003 - Multi-hop Proxy |

---

## 📂 File Structure

```
threat-intel-aggregator/
├── threat_intel.py       # Core IOC checker + simulated threat DB
├── test_threat_intel.py  # 20+ pytest unit tests
└── README.md             # This file
```

---

## 🚀 Quick Start

```bash
# Run full demonstration
python threat_intel.py --demo

# Check a specific IP
python threat_intel.py --check-ip 91.108.4.11

# Check a domain
python threat_intel.py --check-domain malware-c2.ru

# Check a file hash
python threat_intel.py --check-hash 3395856ce81f2b7382dee72602f798b642f14c0

# Output as JSON (for SIEM integration)
python threat_intel.py --check-ip 185.220.101.45 --json

# Run all tests
pytest test_threat_intel.py -v
```

### Sample Output

```
  🔴 IOC Check Result
  ──────────────────────────────────────────────────
  Type       : IP
  Value      : 91.108.4.11
  Risk Level : CRITICAL
  Malicious  : YES ⚠️
  Confidence : 95%
  Category   : c2
  Description: Active C2 server for Agent Tesla keylogger campaign.
  MITRE      : Command and Control / T1071.001 - Application Layer Protocol
  Sources    : OTX, MISP, AbuseIPDB
  Tags       : c2, agent_tesla, keylogger, malware
  First Seen : 2025-11-01  |  Last Seen: 2026-05-25
```

---

## 🔗 Real-World API Integration (Phase 2)

To extend this tool with live data, add these API integrations:

```python
# Example: AbuseIPDB integration
import requests

def check_ip_abuseipdb(ip: str, api_key: str) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers, params=params
    )
    return response.json()["data"]
```

> ⚠️ **Security Note:** Never hardcode API keys. Use environment variables:
> `export ABUSEIPDB_API_KEY="your_key_here"`

---

## 📚 Threat Intelligence Resources

| Resource | URL | Use Case |
|:---|:---|:---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) | Tactic/technique mapping |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) | IP reputation |
| VirusTotal | [virustotal.com](https://www.virustotal.com) | File/URL analysis |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com) | Open threat feeds |
| MalwareBazaar | [bazaar.abuse.ch](https://bazaar.abuse.ch) | Malware hash database |
| PhishTank | [phishtank.com](https://www.phishtank.com) | Phishing URL database |
