<div align="center">

# 🛡️ Cybersecurity Engineering Portfolio

### *Aspiring SOC Analyst | Digital Forensics | Incident Response | Blue Team*

[![CI Status](https://github.com/adilsr-sec/security-labs/actions/workflows/ci.yml/badge.svg)](https://github.com/adilsr-sec/security-labs/actions)
[![Security: Bandit](https://img.shields.io/badge/Security_Scan-Bandit-orange?style=flat-square&logo=python)](https://bandit.readthedocs.io/)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Active-red?style=flat-square&logo=tryhackme)](https://tryhackme.com/p/adilsr-sec)
[![HackTheBox](https://img.shields.io/badge/HackTheBox-Active-9fef00?style=flat-square&logo=hackthebox&logoColor=white)](https://app.hackthebox.com/profile/adilsr-sec)
[![OffSec](https://img.shields.io/badge/OffSec-Learning_Path-blue?style=flat-square)](https://www.offsec.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Portfolio](https://img.shields.io/badge/Portfolio-Live-brightgreen?style=flat-square&logo=github)](https://adilsr-sec.github.io/security-labs)

</div>

---

<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3000&pause=800&color=00D4FF&center=true&vCenter=true&multiline=true&width=700&height=80&lines=Protecting+systems+%7C+Hunting+threats+%7C+Building+defenses;SOC+%7C+Forensics+%7C+Incident+Response+%7C+Blue+Team" alt="Typing SVG" />
</div>

---

## 👤 About Me

I am a **Cybersecurity Engineering graduate** with a strong foundation in ethical hacking, cryptography, steganography, digital forensics, and network security. My academic journey, hands-on lab experience, and personal projects have prepared me to contribute meaningfully to **Security Operations Centers (SOC)**, **Incident Response teams**, and **Digital Forensics investigations**.

> *"Security is not a product, but a process."* — Bruce Schneier

I am actively building skills aligned with **Blue Team** operations — monitoring, detecting, analyzing, and responding to threats — while maintaining a working understanding of offensive techniques to think like an attacker.

**Target Roles:** SOC Analyst • Junior Security Analyst • Digital Forensics Analyst • Incident Response Analyst • Vulnerability Assessment Analyst • Threat Intelligence Analyst • SIEM Analyst • Malware Analysis Intern

---

## 🎯 Career Objective

Passionate and detail-oriented cybersecurity graduate seeking an entry-level position in **Security Operations** or **Digital Forensics**. I bring hands-on experience with industry-standard security tooling (Nmap, Wireshark, Burp Suite, Autopsy, FTK Imager), academic project delivery in blockchain security and steganographic data hiding, and a commitment to continuous learning through platforms like TryHackMe, HackTheBox, and OffSec.

---

## 🛠️ Technical Skills Matrix

| Category | Technologies & Tools |
|:---|:---|
| **Security Operations & Monitoring** | SIEM Concepts (Splunk/ELK Stack) • Log Analysis • Threat Detection • Alert Triage • Security Dashboards |
| **Network Security & Reconnaissance** | Nmap • Wireshark • Packet Analysis • Port Scanning • Firewall Configuration • TCP/IP Protocols |
| **Ethical Hacking & Pentesting** | Burp Suite • Recon-ng • OWASP Top 10 • Web App Security • Vulnerability Assessment |
| **Digital Forensics & Incident Response** | FTK Imager • Autopsy • Metadata Extraction • Chain of Custody • Incident Response Lifecycle |
| **Cryptography & Steganography** | Symmetric/Asymmetric Encryption • Hashing Algorithms • LSB Steganography • ARSS Algorithm • Digital Watermarking |
| **Threat Intelligence** | IOC Analysis • MITRE ATT&CK Framework • Threat Feed Processing • IP/Domain/Hash Analysis |
| **Biometric & Mobile Security** | Biometric Authentication Concepts • Mobile Computing Security • Android Security Model |
| **Programming & Scripting** | Python 3 • Bash/Shell Scripting • C • Java • SQL • Regular Expressions |
| **Operating Systems** | Linux (Kali, Ubuntu, Debian) • Windows Server • Virtualization (VirtualBox/VMware) |
| **Platforms & Training** | TryHackMe • HackTheBox • OffSec Learning • OWASP WebGoat |

---

## 📁 Repository Structure

```text
cybersecurity-portfolio/
├── .github/
│   ├── workflows/
│   │   └── ci.yml                        # Multi-job CI: lint, test, bandit security scan
│   ├── SECURITY.md                       # Responsible disclosure policy
│   └── CONTRIBUTING.md
│
├── projects/
│   ├── secured-voting-blockchain/        # 🗳️ Academic Project: Blockchain Voting Machine
│   │   ├── blockchain.py                 #    Core blockchain implementation
│   │   ├── voting_cli.py                 #    CLI voting interface
│   │   ├── test_blockchain.py            #    Unit tests
│   │   └── README.md
│   │
│   ├── audio-steganography-arss/         # 🔊 Academic Project: Arjuna's Astra (ARSS)
│   │   ├── arss_steg.py                  #    ARSS encode/decode engine
│   │   ├── test_arss.py                  #    Unit tests
│   │   └── README.md
│   │
│   ├── network_scanner/                  # 🔍 Tool: Multi-threaded Network Port Scanner
│   │   ├── scanner.py                    #    Threaded scanner with banner grabbing
│   │   ├── test_scanner.py               #    Unit tests
│   │   └── README.md
│   │
│   ├── auth_log_analyzer/                # 🛡️ Tool: SSH Authentication Log Analyzer
│   │   ├── analyzer.py                   #    Log parser + brute-force detector
│   │   ├── sample_auth.log               #    Sample log for testing
│   │   ├── test_analyzer.py              #    Unit tests
│   │   └── README.md
│   │
│   ├── soc-threat-monitor/               # 📡 Tool: SOC Threat Detection Dashboard
│   │   ├── soc_monitor.py                #    Real-time log correlation + alerting
│   │   ├── rules.json                    #    SIGMA-inspired detection rules
│   │   ├── test_soc.py                   #    Unit tests
│   │   └── README.md
│   │
│   └── threat-intel-aggregator/          # 🕵️ Tool: Threat Intelligence Feed Aggregator
│       ├── threat_intel.py               #    IOC feed parser and checker
│       ├── ioc_checker.py                #    IP/Domain/Hash reputation checker
│       ├── test_threat_intel.py          #    Unit tests
│       └── README.md
│
├── labs/
│   ├── ctf-writeups/
│   │   ├── 01-basic-sqli-ctf.md          # CTF Write-up: SQL Injection Challenge
│   │   └── 02-steganography-ctf.md       # CTF Write-up: Hidden in Plain Sight
│   ├── forensics/
│   │   └── ir_playbook.md                # Incident Response Playbook
│   ├── forensics/
│   │   └── forensic_triage.sh            # Bash: First-responder triage script
│   └── README.md
│
├── certifications/
│   └── README.md                         # Coursework, certs, and learning roadmap
│
├── docs/                                 # GitHub Pages portfolio site
│   ├── index.html                        # Main portfolio page
│   ├── style.css
│   └── script.js
│
├── .gitignore
├── LICENSE
├── requirements.txt
└── README.md                             # This file
```

---

## 🚀 Featured Projects

<table>
<tr>
<td width="50%" valign="top">

### 🗳️ Secured Voting Machine — Blockchain
**Domain:** Cryptography • Distributed Ledger • Consensus

A decentralized electronic voting system built on a custom **Python blockchain**. Each vote is cryptographically hashed (SHA-256), chained to a tamper-evident ledger, and validated by a Proof-of-Work consensus mechanism to prevent double-voting and unauthorized modification.

**Key Concepts:** Immutability • Hash Chaining • Voter Anonymization • Merkle-like Verification

[![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)](projects/secured-voting-blockchain/)
[![Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square)](projects/secured-voting-blockchain/)

[📄 View Project →](projects/secured-voting-blockchain/README.md)

</td>
<td width="50%" valign="top">

### 🔊 Arjuna's Astra — ARSS Steganography
**Domain:** Steganography • Signal Processing • Data Hiding

A custom audio-in-image steganography engine implementing the **ARSS (Arjuna's Astra Robust Steganography Scheme)** algorithm. Encodes audio waveform data into the least-significant bits of image pixels, producing visually imperceptible modifications with mathematically verifiable payload integrity.

**Key Concepts:** LSB Embedding • Spectral Encoding • PSNR Measurement • Steganalysis Resistance

[![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)](projects/audio-steganography-arss/)
[![Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square)](projects/audio-steganography-arss/)

[📄 View Project →](projects/audio-steganography-arss/README.md)

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📡 SOC Threat Detection Monitor
**Domain:** Security Operations • SIEM • Incident Triage

A Python-based **Security Operations Center (SOC) log monitor** that ingests multi-source logs, applies SIGMA-inspired correlation rules, and generates prioritized alerts for analyst review. Supports brute-force detection, port scan signatures, privilege escalation patterns, and anomaly scoring.

**Key Concepts:** Log Correlation • Alert Triage • Threat Scoring • SOC Workflows

[![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)](projects/soc-threat-monitor/)
[![Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square)](projects/soc-threat-monitor/)

[📄 View Project →](projects/soc-threat-monitor/README.md)

</td>
<td width="50%" valign="top">

### 🕵️ Threat Intelligence Aggregator
**Domain:** Threat Intel • IOC Analysis • MITRE ATT&CK

A lightweight **Threat Intelligence Feed Aggregator** that parses open-source IOC feeds, checks IPs, domains, and file hashes against known threat databases, and produces structured reports for analyst consumption. Maps findings to MITRE ATT&CK techniques.

**Key Concepts:** IOC Enrichment • Feed Parsing • ATT&CK Mapping • Reputation Scoring

[![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)](projects/threat-intel-aggregator/)
[![Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square)](projects/threat-intel-aggregator/)

[📄 View Project →](projects/threat-intel-aggregator/README.md)

</td>
</tr>
</table>

---

## 🔬 Lab Experience & Hands-On Training

| Lab Domain | Activities & Tools Used |
|:---|:---|
| **Network Security Lab** | Packet capture analysis (Wireshark), firewall rule configuration, port scanning (Nmap), vulnerability mapping |
| **Ethical Hacking Lab** | Web application pentesting (Burp Suite), reconnaissance (Recon-ng), exploitation fundamentals |
| **Cyber Forensics Lab** | Disk imaging (FTK Imager), artifact recovery (Autopsy), file metadata analysis, chain of custody documentation |
| **Cryptography Lab** | Symmetric encryption (AES, DES) in C/Java, asymmetric (RSA), hashing (SHA-256, MD5), key generation |
| **System & Network Security Lab** | IDS/IPS configuration, Snort rule writing, network hardening checklists |
| **OS & DBMS Lab** | Linux administration, SQL injection defense, user privilege management, audit logging |
| **Scripting for Security** | Python automation for scanning, log parsing, and report generation; Bash scripting for system triage |

📁 [Detailed Lab Write-ups and Reports →](labs/README.md)

---

## 🏆 CTF & Platform Activity

| Platform | Profile | Activity |
|:---|:---|:---|
| **TryHackMe** | [adilsr-sec](https://tryhackme.com/p/adilsr-sec) | Active — SOC Analyst, Jr. Penetration Tester paths |
| **HackTheBox** | [adilsr-sec](https://app.hackthebox.com/profile/adilsr-sec) | Active — Starting Point machines |
| **OffSec** | [Learning Path](https://www.offsec.com/) | PEN-100 / SOC-100 fundamentals |
| **Hack.me / PortSwigger** | Web Security Academy | OWASP Top 10 labs |

📁 [CTF Write-ups →](labs/ctf-writeups/)

---

## 🎓 Academic Background & Coursework

**B.E. / B.Tech in Computer Science (Cybersecurity Specialization)**

| Semester | Core Subjects |
|:---|:---|
| **Theory Courses** | Ethical Hacking • Cryptography • Steganography & Digital Watermarking • Systems & Network Security • Cyber Forensics • Biometric Security • Storage Management & Security • Intrusion Detection & Prevention Systems • Mathematical Foundations for Security • Mobile Computing Security • Web Programming |
| **Lab Courses** | C Programming Lab • Data Structures Lab • Java Programming Lab • Scripting Languages for Security • OS & DBMS Lab • Cryptography Lab • System & Network Security Lab • Cyber Forensics Lab • Ethical Hacking Lab |
| **Capstone Projects** | Secured Voting Machine using Blockchain Technology • Audio-in-Image Steganography using ARSS Algorithm (Arjuna's Astra) |

📁 [Certifications & Learning Roadmap →](certifications/README.md)

---

## 🔒 Security-Conscious Practices

This repository demonstrates security awareness at the code and process level:

| Practice | Implementation |
|:---|:---|
| **Zero Secret Leakage** | No API keys, passwords, tokens, or real credentials in code. Environment variables documented; `.gitignore` configured |
| **Static Analysis** | All Python code scanned with `bandit` in CI pipeline for common security anti-patterns |
| **Safe Tooling Scope** | All active reconnaissance tools (scanner, analyzer) explicitly scoped to authorized targets only |
| **Dependency Auditing** | `pip-audit` and `safety` check for known CVEs in dependencies on every push |
| **Responsible Disclosure** | [SECURITY.md](.github/SECURITY.md) documents our vulnerability disclosure policy |
| **Defensive Coding** | Input validation, exception handling, and output sanitization throughout all scripts |

---

## 📊 GitHub Stats

<div align="center">

![GitHub Stats](https://github-readme-stats.vercel.app/api?username=adilsr-sec&show_icons=true&theme=dark&hide_border=true&bg_color=0d1117&title_color=00d4ff&icon_color=00d4ff&text_color=ffffff)
![Top Languages](https://github-readme-stats.vercel.app/api/top-langs/?username=adilsr-sec&layout=compact&theme=dark&hide_border=true&bg_color=0d1117&title_color=00d4ff&text_color=ffffff)

</div>

---

## 🚀 Quick Start — Run Projects Locally

```bash
# 1. Clone the repository
git clone https://github.com/adilsr-sec/security-labs.git
cd cybersecurity-portfolio

# 2. Create and activate a virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run all tests
pytest --tb=short -v

# 5. Run security scan (bandit)
bandit -r projects/ -ll

# 6. Try a project — example: Network Scanner
python projects/network_scanner/scanner.py --host localhost --ports 20-1024

# 7. Try log analysis
python projects/auth_log_analyzer/analyzer.py --log projects/auth_log_analyzer/sample_auth.log

# 8. Try blockchain voting
python projects/secured-voting-blockchain/voting_cli.py
```

---

## 📧 Contact & Profiles

<div align="center">

| Platform | Link |
|:---:|:---:|
| 📧 Email | [adilsr33@gmail.com](mailto:adilsr33@gmail.com) |
| 💼 LinkedIn | [linkedin.com/in/adilsr33](https://linkedin.com/in/adilsr33) |
| 🎯 TryHackMe | [tryhackme.com/p/adilsr-sec](https://tryhackme.com/p/adilsr-sec) |
| 💻 HackTheBox | [app.hackthebox.com/profile/adilsr-sec](https://app.hackthebox.com/profile/adilsr-sec) |
| 🌐 Portfolio | [adilsr-sec.github.io/security-labs](https://adilsr-sec.github.io/security-labs) |

</div>

---

<div align="center">

*⚠️ All tools in this repository are for educational and authorized testing purposes only.*
*Unauthorized use of security tools against systems you do not own is illegal and unethical.*

**Made with 🛡️ and passion for cybersecurity**

</div>
