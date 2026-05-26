# Academic & Practical Labs Index

This section summarizes my practical hands-on labs, detailing the objectives, tools, and technical competencies exercised in each curriculum area.

---

## 🛠️ Security & Specialized Labs

### 🔍 Cyber Forensics Lab
* **Focus:** Data recovery, disk imaging, forensic analysis, file extraction.
* **Tools:** Autopsy, FTK Imager, ExifTool.
* **Key Exercises:**
  - Acquired raw forensic disk images (`.dd` / `.E01`) from flash media.
  - Performed **file carving** using signatures to retrieve deleted JPEG and PDF files.
  - Analyzed registry hives and metadata to establish user activity timelines.

### 🛡️ Systems & Network Security Lab
* **Focus:** Packet analysis, traffic auditing, firewall configurations, vulnerability assessment.
* **Tools:** Wireshark, Nmap, Burp Suite, iptables.
* **Key Exercises:**
  - Analyzed TCP dump files to identify active network scans and anomalies.
  - Constructed custom firewall rules to block unauthorized connections and rate-limit incoming TCP Syn requests.
  - Performed local vulnerability assessments to detect outdated web services.

### 🔑 Cryptography Lab
* **Focus:** Implementation and analysis of classical and modern cryptographic standards.
* **Languages:** C, Java.
* **Key Exercises:**
  - C implementations of classical ciphers (Playfair, Vigenere, Hill Cipher).
  - Programmed secure hashing (SHA-256) and symmetric key generation (AES-128/256).
  - Implemented RSA public/private key exchanges in Java.

### 🏴 Ethical Hacking Lab
* **Focus:** OWASP Top 10, target scanning, exploitation concepts.
* **Platforms:** TryHackMe, local capture-the-flag (CTF) environments.
* **Key Exercises:**
  - Mapped target attack surfaces using `Recon-ng` and standard Nmap sweeps.
  - Audited local web apps for SQL Injection (SQLi) and Cross-Site Scripting (XSS) using Burp Suite proxy intercept.
  - Completed security challenges spanning web vulnerabilities, privilege escalation, and network enumeration.

---

## 💻 Core Engineering & Development Labs

### 🐍 Scripting Languages for Security
* **Focus:** Security automation, custom scripting.
* **Languages:** Python, Bash.
* **Key Exercises:**
  - Wrote Bash scripts to parse syslog feeds and send alerts for unauthorized sudo command usages.
  - Automated network sweeps and file integrity monitoring (MD5/SHA256 audits).
  - Developed custom parsing tools for raw threat intelligence feeds.

### 💾 OS & DBMS Lab
* **Focus:** Operating system configurations, file system structures, relational database security.
* **Databases:** MySQL, PostgreSQL.
* **Key Exercises:**
  - Configured Linux system permissions (chmod, chown) and set up user privilege groups.
  - Built custom database tables with constraints, stored procedures, and triggers.
  - Implemented Role-Based Access Control (RBAC) to enforce Least Privilege access to relational databases.

### ☕ Data Structures & OOP Lab (C / Java)
* **Focus:** Efficient algorithms, robust design patterns, secure programming.
* **Key Exercises:**
  - Built basic data structures (linked lists, trees, graphs, heaps) in C, emphasizing pointer safety.
  - Implemented Object-Oriented patterns in Java to secure API parameters and prevent logic flows.
