# Cybersecurity Engineering Portfolio

[![CI Build](https://img.shields.io/badge/CI-Passing-success?style=flat-square&logo=github-actions)](https://github.com/)
[![Security: Compliant](https://img.shields.io/badge/Security-Compliant-brightgreen?style=flat-square&logo=gitbook)](https://github.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Active-red?style=flat-square&logo=tryhackme)](https://tryhackme.com/)

Welcome to my cybersecurity portfolio. This repository showcases my technical skills, lab experience, academic projects, and security tools. As an aspiring Cybersecurity Engineer / SOC Analyst, I focus on building secure systems, analyzing network events, and automating threat detection.

---

## 🎯 Career Objective & Focus

Passionate and detail-oriented cybersecurity graduate seeking to leverage hands-on lab experience and solid theoretical foundations in security engineering, cryptology, and digital forensics. Committed to applying security-first coding practices, automating repetitive operations, and contributing to incident response strategies.

---

## 🛠️ Technical Skills Matrix

| Category | Skills & Domain Knowledge |
| :--- | :--- |
| **Core Security Domains** | Ethical Hacking • Cryptography • Steganography & Digital Watermarking • Systems & Network Security • Intrusion Detection & Prevention Systems (IDPS) • Cyber Forensics • Biometric Security • Storage Security |
| **Tools & Platforms** | Nmap • Wireshark • Burp Suite • Recon-ng • FTK Imager • Autopsy • TryHackMe Labs • Hackathon environments |
| **Programming & Lab Foundations** | Python (Security Tooling) • Bash Scripting • C Programming • Java • Operating Systems (Linux, Windows) • Database Management Systems (DBMS) |
| **Academic Focus** | Mathematical Foundations for Security Systems • Mobile Computing Security • Distributed Ledger Technology |

---

## 📁 Repository Structure

```text
├── .github/workflows/       # GitHub Actions automated checks (flake8, pytest)
├── projects/                # Core portfolio projects
│   ├── secured-voting-blockchain/   # Academic Project 1: Blockchain Voting Machine
│   ├── audio-steganography-arss/    # Academic Project 2: Audio Steganography (ARSS)
│   ├── 01-network-scanner/          # Tooling 1: Multi-threaded Python Port Scanner
│   └── 02-auth-log-analyzer/        # Tooling 2: Authentication Log Analyzer
├── labs/                    # Write-ups & logs for hands-on labs (OS, DBMS, Forensics)
├── certifications/          # Coursework and professional certifications
├── requirements.txt         # Dev dependencies for testing/linting
└── README.md                # This document
```

---

## 🚀 Featured Projects

### 🗳️ 1. Secured Voting Machine using Blockchain
* **Focus:** Distributed Ledger Technology, Consensus, Cryptography, Immutability.
* **Overview:** A decentralized voting model leveraging blockchain to prevent double-voting, secure records against unauthorized alteration, and enforce voter anonymity.
* [Go to Project Write-up & Architecture](projects/secured-voting-blockchain/README.md)

### 🔊 2. Audio in Image Steganography using ARSS Algorithm (Arjuna's Astra)
* **Focus:** Data Hiding, Steganalysis, Cryptographic Hashing, Signal Hiding.
* **Overview:** A custom steganography tool leveraging the **ARSS (Arjuna's Astra)** algorithm to embed audio payload signals within cover image files with low distortion and high security.
* [Go to Project Write-up & Methodology](projects/audio-steganography-arss/README.md)

### 🔍 3. Multi-Threaded Network Port Scanner
* **Focus:** Network Security, Active Reconnaissance, Python Scripting, Banner Grabbing.
* **Overview:** A multi-threaded TCP scanner written in Python that resolves domains, checks IP validation, identifies open ports, and grabs banner services.
* [Go to Code & Instructions](projects/01-network-scanner/README.md)

### 🛡️ 4. SSH Authentication Log Analyzer
* **Focus:** Incident Response, Log Parsing, Threat Intelligence, Pattern Matching.
* **Overview:** A security tool that parses system authentication logs (syslog format) to flag brute-force attacks and highlight suspicious activity.
* [Go to Code & Instructions](projects/02-auth-log-analyzer/README.md)

---

## 🔬 Lab Experience & Training

* **Systems & Network Security Lab:** Configured firewalls, analyzed packet captures using **Wireshark**, and conducted vulnerability assessments using **Nmap** and **Burp Suite**.
* **Cyber Forensics Lab:** Conducted host forensics, extracted file metadata, and recovered deleted items using **Autopsy** and **FTK Imager**.
* **Cryptography & Ethical Hacking Labs:** Practical implementation of symmetric/asymmetric algorithms in C/Java, as well as password cracking and scanning configurations.
* *Detailed lab reports and write-ups can be found in the [Labs Directory](labs/README.md).*

---

## 🔒 Security-Conscious Practices & Disclosure

This repository adheres to standard security-conscious practices:
1. **Zero Secret Leakage:** No API keys, passwords, private keys, or actual system credentials are hardcoded. Mock secrets are labeled clearly, and real config values are managed via `.gitignore`.
2. **Defensive Programming:** Scripts utilize strict input validation, exception handling, and bound limits to prevent injection or crashes.
3. **Safe Scanning:** Reconnaissance tools (like the network scanner) are intended for authorized scanning only (e.g., `localhost` or owned subnets).

---

## 📧 Contact & Professional Profiles

* **Email:** [your.email@example.com](mailto:your.email@example.com)
* **LinkedIn:** [linkedin.com/in/yourprofile](https://linkedin.com/in/yourprofile)
* **TryHackMe:** [tryhackme.com/p/yourusername](https://tryhackme.com/p/yourusername)
