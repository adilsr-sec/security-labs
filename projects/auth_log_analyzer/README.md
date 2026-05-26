# SSH Authentication Log Analyzer

A Python-based command-line security tool designed to parse Linux system authentication logs (`auth.log`), detect failed logins, audit successful logins, and flag potential brute-force attempts.

---

## 🎯 Project Objective

Monitoring system access logs is a critical task for Security Operations Center (SOC) analysts and systems administrators. This project serves to:
1. **Automate Log Auditing:** Replace manual parsing of log files with efficient regular expression extraction.
2. **Detect SSH Brute-Force Attacks:** Track failed attempts per source IP and alert when they cross security thresholds.
3. **Audit Successful Access:** Log active administrative sessions and check their origin IP addresses against unauthorized subnet pools.

---

## 🔍 Threat Analysis Context

During an incident investigation, an analyst might notice a spike in traffic on port 22. Using this log analyzer:
* **Brute-Force Pattern:** You can immediately group how many times a single IP address (e.g., `192.168.1.100`) attempts to login using different usernames within minutes.
* **Credential Stuffing:** High volumes of failed attempts across various user lists (like `support`, `ubnt`, `test`) denote automated credential stuffing.
* **Unusual Access Times/Subnets:** Correlating successful publickey or password-based log entries with external subnets helps flag compromised accounts.

---

## 🛠️ Usage Instructions

### Run the Analyzer on the Sample Log
We provide a simulated log (`sample_auth.log`) containing standard and malicious log patterns.

To run the parser with default settings (brute force threshold of 5 failures):
```bash
python analyzer.py sample_auth.log
```

### Options
* **`-t` or `--threshold`**: Adjust the failure count trigger (default: 5). For a strict review:
  ```bash
  python analyzer.py sample_auth.log -t 3
  ```
* **`-j` or `--json`**: Export results as a JSON structure to pipe into other tools or SIEM pipelines:
  ```bash
  python analyzer.py sample_auth.log --json
  ```

---

## 📊 Sample Output (Console Report)

```text
============================================================
                AUTHENTICATION LOG ANALYSIS REPORT            
============================================================
Total Successful Logins: 2
Total Failed Attempts:   9
------------------------------------------------------------

[+] Successful Logins by IP:
  - 192.168.1.20    : 1 times
  - 192.168.1.15    : 1 times

[+] Top Targeted Usernames:
  - root            : 4 failures
  - support         : 2 failures
  - ubnt            : 2 failures
  - admin           : 1 failures

[!] Potential Brute-Force Activity:
  - [WARNING] IP 192.168.1.100 triggered 6 login failures.
============================================================
```

---

## 🛡️ Recommended Security Mitigations

When brute-force triggers are tripped, security teams should implement:
1. **Disable Password Authentication:** Force key-based logins (`ssh-copy-id`) and disable password authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`).
2. **Rate Limiting / Fail2ban:** Install service watchdogs like `fail2ban` to automatically update local iptables/firewall rules to drop traffic from offending IPs.
3. **Change Default Ports:** Relocate SSH to a non-standard high port to mitigate scanning noise.
4. **Enforce Multi-Factor Authentication (MFA):** Set up Google Authenticator PAM modules to require dynamic second-factor validation.
