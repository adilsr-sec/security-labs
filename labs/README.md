# 🔬 Labs, CTF Write-ups & Hands-On Training

This directory contains detailed write-ups and reports from hands-on cybersecurity
lab exercises, Capture the Flag (CTF) challenges, and platform-based learning.

---

## 📂 Structure

```
labs/
├── ctf-writeups/
│   ├── 01-basic-sqli-ctf.md         # SQL Injection CTF challenge
│   └── 02-steganography-ctf.md      # Hidden-in-plain-sight stego CTF
├── forensics/
│   ├── ir_playbook.md               # Full Incident Response Playbook
│   └── forensic_triage.sh           # First-responder Bash triage script
└── README.md                        # This file
```

---

## 🏴 CTF Write-ups

| Challenge | Category | Platform | Difficulty | Key Skill |
|:---|:---|:---|:---|:---|
| [Basic SQLi CTF](ctf-writeups/01-basic-sqli-ctf.md) | Web Exploitation | TryHackMe | Easy | SQL Injection, OWASP |
| [Hidden in Plain Sight](ctf-writeups/02-steganography-ctf.md) | Steganography | Custom | Medium | LSB Analysis, Steganalysis |

---

## 🔍 Lab Reports

| Lab | Skills Demonstrated |
|:---|:---|
| Wireshark Packet Analysis | Filter expressions, protocol dissection, anomaly identification |
| Nmap Reconnaissance | Port scanning, service versioning, OS fingerprinting |
| Burp Suite Web Testing | Intercepting requests, parameter tampering, OWASP Top 10 |
| Autopsy Digital Forensics | Image mounting, artifact recovery, timeline reconstruction |
| Snort IDS Configuration | Rule syntax, signature writing, alert tuning |

---

## 🚨 Incident Response Playbook

The [IR Playbook](forensics/ir_playbook.md) covers the full lifecycle:
**Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned**

The [forensic_triage.sh](forensics/forensic_triage.sh) script automates
first-responder artifact collection on Linux systems.
