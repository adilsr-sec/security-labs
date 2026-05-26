# Incident Response Playbook — SSH Brute Force & Account Compromise

**Document Version:** 1.0
**Classification:** Portfolio / Educational
**Applicable Standards:** NIST SP 800-61r2, SANS IR Process

---

## 📋 Overview

This playbook defines the step-by-step incident response procedure for handling
a **SSH brute-force attack followed by confirmed account compromise**.

This scenario is directly relevant to:
- SOC Analyst (Alert triage → Escalation)
- Incident Response Analyst (Containment → Recovery)
- Digital Forensics Analyst (Evidence collection → Timeline)

---

## 🔄 IR Lifecycle (NIST SP 800-61r2)

```
PREPARATION → IDENTIFICATION → CONTAINMENT → ERADICATION → RECOVERY → LESSONS LEARNED
     ↑                                                                        │
     └────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: PREPARATION

### Pre-Incident Requirements
- [ ] SIEM configured and ingesting auth logs (e.g., Splunk, ELK)
- [ ] Baseline established for normal SSH login behavior
- [ ] Incident response contact list current
- [ ] Forensic workstation available with Autopsy, FTK Imager, Volatility
- [ ] Network isolation capability (firewall API or manual procedure)
- [ ] Log retention policy: minimum 90 days

### Detection Triggers (SIEM Alerts)
| Alert | Threshold | Severity |
|:---|:---|:---|
| SSH failed logins | > 5/minute from single IP | HIGH |
| Login success after failures | After > 3 failures | CRITICAL |
| New root session | Any time outside business hours | HIGH |
| Suspicious sudo activity | > 3 privilege commands in 10 min | MEDIUM |

---

## Phase 2: IDENTIFICATION

### 2.1 Initial Triage (First 15 minutes)

**Analyst Actions:**
```bash
# Confirm alert: count failed logins from suspected IP
grep "Failed password" /var/log/auth.log | grep "192.168.1.50" | wc -l

# Check for successful login from same IP
grep "Accepted" /var/log/auth.log | grep "192.168.1.50"

# Check what sessions are currently active
who -a
last -20

# Identify compromised account
grep "Accepted password for" /var/log/auth.log | tail -20
```

**Confirmation Criteria:**
- [ ] ≥5 failed logins from single source IP
- [ ] Successful authentication confirmed from same IP
- [ ] Session is currently active OR recently active

**Severity Classification:** CRITICAL (Account Compromise Confirmed)

### 2.2 Scope Assessment

```bash
# What commands did the attacker run?
cat /home/<user>/.bash_history
cat /root/.bash_history

# Check for new accounts created
grep "useradd\|adduser" /var/log/auth.log

# Check for privilege escalation
grep "sudo" /var/log/auth.log | grep <compromised_user>

# Network connections from compromised session
ss -tnp | grep ESTABLISHED
netstat -antp
```

---

## Phase 3: CONTAINMENT

### 3.1 Short-Term Containment (Immediate)

```bash
# 1. Block attacker IP at firewall
sudo iptables -I INPUT -s 192.168.1.50 -j DROP
sudo iptables -I OUTPUT -d 192.168.1.50 -j DROP

# 2. Kill active compromised session
# Find session PID:
who -a
# Kill it:
sudo pkill -9 -u <compromised_user>  # Terminate all processes for user

# 3. Lock the compromised account
sudo passwd -l <compromised_user>   # Lock password
sudo usermod -L <compromised_user>  # Also lock account flag
```

### 3.2 Forensic Evidence Preservation (Before Eradication!)

```bash
# Create forensic copy of relevant logs (evidence preservation)
cp /var/log/auth.log /forensics/evidence/auth.log.$(date +%Y%m%d_%H%M%S)
cp /var/log/syslog   /forensics/evidence/syslog.$(date +%Y%m%d_%H%M%S)

# Capture current network state
ss -tnp > /forensics/evidence/network_connections.txt
ps auxf  > /forensics/evidence/process_list.txt

# Capture bash history before it is cleared
cp /home/<user>/.bash_history /forensics/evidence/bash_history_<user>.txt
cp /root/.bash_history         /forensics/evidence/bash_history_root.txt

# Hash all evidence files (chain of custody)
sha256sum /forensics/evidence/* > /forensics/evidence/CHECKSUMS.txt
```

---

## Phase 4: ERADICATION

### 4.1 Remove Attacker Persistence

```bash
# Check for cron jobs added by attacker
crontab -l -u <compromised_user>
cat /etc/cron.d/*
cat /var/spool/cron/*

# Check for SSH authorized keys added
cat /home/<compromised_user>/.ssh/authorized_keys
cat /root/.ssh/authorized_keys

# Check for new/modified SUID binaries
find / -perm -4000 -newer /var/log/auth.log 2>/dev/null

# Check running processes for malicious binaries
ps auxf | grep -v "\[" | awk '{print $11}' | sort -u
```

### 4.2 Clean and Rebuild

- Reset compromised user's password (strong, unique)
- Revoke and regenerate SSH keys for affected user
- Audit and remove any backdoors or persistence mechanisms
- Patch SSH configuration:

```bash
# /etc/ssh/sshd_config hardening
PermitRootLogin no
PasswordAuthentication no          # Key-based auth only
MaxAuthTries 3
LoginGraceTime 60
AllowUsers specific_user_only
```

---

## Phase 5: RECOVERY

```bash
# Re-enable account after cleanup is confirmed
sudo passwd -u <compromised_user>
sudo usermod -U <compromised_user>

# Restart SSH service
sudo systemctl restart sshd

# Monitor for 24 hours post-recovery
tail -f /var/log/auth.log | grep "192.168.1.50"

# Re-test firewall block
nc -z 192.168.1.50 22 && echo "OPEN" || echo "BLOCKED"
```

---

## Phase 6: LESSONS LEARNED

### Post-Incident Report Template

| Field | Content |
|:---|:---|
| **Incident ID** | IR-2026-001 |
| **Date/Time Detected** | 2026-05-26 08:01 UTC |
| **Date/Time Contained** | 2026-05-26 08:15 UTC |
| **MTTR (Mean Time to Respond)** | 14 minutes |
| **Attack Vector** | SSH brute-force → credential compromise |
| **Attacker IP** | 192.168.1.50 |
| **Compromised Account** | testuser |
| **Data Exfiltration** | None confirmed |
| **Root Cause** | Weak password + no fail2ban |
| **Recommendations** | Deploy fail2ban, enforce MFA, key-only SSH |

### Hardening Recommendations

1. **Deploy fail2ban** — automatically block IPs after N failures
2. **Enforce SSH key authentication** — disable password auth
3. **Implement MFA** — even for SSH (Google Authenticator PAM)
4. **Network segmentation** — restrict SSH to management VLAN only
5. **Privileged Access Workstation (PAW)** — require jump server for SSH
6. **SIEM tuning** — lower brute-force threshold to 3 failures
7. **User training** — password hygiene and phishing awareness

---

## 📚 References

- NIST SP 800-61r2: Computer Security Incident Handling Guide
- SANS Incident Handler's Handbook
- MITRE ATT&CK: T1110.001 (Brute Force), T1078 (Valid Accounts)
