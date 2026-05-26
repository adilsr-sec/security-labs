#!/usr/bin/env python3
"""
Threat Intelligence Feed Aggregator & IOC Checker
===================================================
Portfolio Project — Cybersecurity Engineering

A lightweight threat intelligence tool that:
  1. Aggregates Indicators of Compromise (IOCs) from open-source feeds.
  2. Checks IPs, domains, and file hashes against known threat data.
  3. Scores IOC reputation and maps findings to MITRE ATT&CK.
  4. Generates structured threat intelligence reports.

Simulated feeds (offline demo — no real API calls required):
  - Simulated OSINT IOC dataset (malicious IPs, domains, hashes)
  - Mock AbuseIPDB-style reputation scores
  - Mock VirusTotal-style file hash results

Usage:
    python threat_intel.py --demo
    python threat_intel.py --check-ip 1.2.3.4
    python threat_intel.py --check-domain malware.example.com
    python threat_intel.py --check-hash abc123...

Author: Adil S R
Role Alignment: Threat Intelligence Analyst, SOC Analyst, Security Analyst
"""

import hashlib
import json
import re
import sys
import argparse
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# IOC Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IOCResult:
    """Result of an IOC reputation check."""
    ioc_type: str           # "ip", "domain", "hash"
    ioc_value: str
    is_malicious: bool
    confidence: int         # 0–100
    threat_category: str    # "botnet", "malware", "phishing", "c2", "scanner", "clean"
    sources: list[str]
    mitre_tactic: str
    mitre_technique: str
    description: str
    first_seen: str
    last_seen: str
    tags: list[str]

    def to_dict(self) -> dict:
        return asdict(self)

    def risk_level(self) -> str:
        if self.confidence >= 80:
            return "CRITICAL"
        elif self.confidence >= 60:
            return "HIGH"
        elif self.confidence >= 40:
            return "MEDIUM"
        elif self.confidence > 0:
            return "LOW"
        return "CLEAN"


# ─────────────────────────────────────────────────────────────────────────────
# Simulated Threat Intelligence Database
# In a real implementation, these would be fetched from:
#   - AbuseIPDB API (IP reputation)
#   - VirusTotal API (file hash analysis)
#   - OTX (Open Threat Exchange) by AlienVault
#   - Shodan (internet-facing device intelligence)
#   - MISP (Malware Information Sharing Platform)
# ─────────────────────────────────────────────────────────────────────────────

SIMULATED_MALICIOUS_IPS: dict[str, dict] = {
    "185.220.101.45": {
        "category": "tor_exit_node",
        "confidence": 90,
        "description": "Known Tor exit node used in anonymous attack traffic.",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1090.003 - Proxy: Multi-hop Proxy",
        "tags": ["tor", "anonymizer", "high_volume"],
        "first_seen": "2024-01-15",
        "last_seen": "2026-05-20",
        "sources": ["AbuseIPDB", "Tor Project Exit List"],
    },
    "45.33.32.156": {
        "category": "scanner",
        "confidence": 75,
        "description": "Shodan Honeypot Scanner - mass scanning activity detected.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "tags": ["scanner", "mass_scan", "shodan"],
        "first_seen": "2023-06-01",
        "last_seen": "2026-04-30",
        "sources": ["Shodan", "GreyNoise"],
    },
    "91.108.4.11": {
        "category": "c2",
        "confidence": 95,
        "description": "Active C2 server for Agent Tesla keylogger campaign.",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.001 - Application Layer Protocol: Web Protocols",
        "tags": ["c2", "agent_tesla", "keylogger", "malware"],
        "first_seen": "2025-11-01",
        "last_seen": "2026-05-25",
        "sources": ["OTX", "MISP", "AbuseIPDB"],
    },
    "103.102.166.240": {
        "category": "botnet",
        "confidence": 85,
        "description": "Mirai botnet node - IoT device compromise and DDoS participation.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 - Network Denial of Service",
        "tags": ["botnet", "mirai", "ddos", "iot"],
        "first_seen": "2025-08-14",
        "last_seen": "2026-05-22",
        "sources": ["Spamhaus", "OTX"],
    },
    "192.42.116.41": {
        "category": "phishing",
        "confidence": 70,
        "description": "Associated with credential phishing campaigns targeting financial sector.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1566.001 - Phishing: Spearphishing Attachment",
        "tags": ["phishing", "credential_harvest", "financial"],
        "first_seen": "2026-02-10",
        "last_seen": "2026-05-15",
        "sources": ["PhishTank", "OpenPhish"],
    },
}

SIMULATED_MALICIOUS_DOMAINS: dict[str, dict] = {
    "malware-c2.ru": {
        "category": "c2",
        "confidence": 95,
        "description": "C2 domain for Emotet banking trojan variant.",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1568.001 - Dynamic Resolution: Fast Flux DNS",
        "tags": ["emotet", "banking_trojan", "c2", "fast_flux"],
        "first_seen": "2025-09-01",
        "last_seen": "2026-05-24",
        "sources": ["MISP", "FeodoTracker"],
    },
    "phish-bank-login.xyz": {
        "category": "phishing",
        "confidence": 92,
        "description": "Phishing domain impersonating major bank login page.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1557 - Adversary-in-the-Middle",
        "tags": ["phishing", "bank", "credential_theft"],
        "first_seen": "2026-03-15",
        "last_seen": "2026-05-20",
        "sources": ["PhishTank", "Google Safe Browsing"],
    },
    "ransomware-drop.onion.to": {
        "category": "ransomware",
        "confidence": 98,
        "description": "Ransomware payload delivery and payment portal relay.",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1204.002 - User Execution: Malicious File",
        "tags": ["ransomware", "payload_delivery", "tor_relay"],
        "first_seen": "2026-01-01",
        "last_seen": "2026-05-26",
        "sources": ["OTX", "VirusTotal", "MISP"],
    },
}

SIMULATED_MALICIOUS_HASHES: dict[str, dict] = {
    "d41d8cd98f00b204e9800998ecf8427e": {
        "category": "malware",
        "confidence": 0,
        "description": "MD5 hash of empty file — not malicious.",
        "mitre_tactic": "",
        "mitre_technique": "",
        "tags": ["benign", "empty_file"],
        "first_seen": "",
        "last_seen": "",
        "sources": [],
    },
    "3395856ce81f2b7382dee72602f798b642f14c0": {
        "category": "trojan",
        "confidence": 90,
        "description": "Known Agent Tesla trojan sample — keylogger + credential stealer.",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1056.001 - Input Capture: Keylogging",
        "tags": ["agent_tesla", "keylogger", "trojan", "credential_stealer"],
        "first_seen": "2025-10-15",
        "last_seen": "2026-05-18",
        "sources": ["VirusTotal (58/72)", "MalwareBazaar"],
    },
    "aec070645fe53ee3b3763059376134f058cc337": {
        "category": "ransomware",
        "confidence": 97,
        "description": "LockBit 3.0 ransomware binary — encrypts and exfiltrates data.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
        "tags": ["lockbit", "ransomware", "encryption", "double_extortion"],
        "first_seen": "2025-12-01",
        "last_seen": "2026-05-20",
        "sources": ["VirusTotal (65/72)", "MalwareBazaar", "MISP"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# IOC Checker
# ─────────────────────────────────────────────────────────────────────────────

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$")
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32,64}$")


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    if not IP_REGEX.match(ip):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    return bool(DOMAIN_REGEX.match(domain))


def validate_hash(h: str) -> bool:
    """Validate MD5/SHA-1/SHA-256 hash format."""
    return bool(HASH_REGEX.match(h))


def check_ip(ip: str) -> IOCResult:
    """Check IP against threat intelligence database."""
    if not validate_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    if ip in SIMULATED_MALICIOUS_IPS:
        data = SIMULATED_MALICIOUS_IPS[ip]
        return IOCResult(
            ioc_type="ip",
            ioc_value=ip,
            is_malicious=data["confidence"] > 0,
            confidence=data["confidence"],
            threat_category=data["category"],
            sources=data["sources"],
            mitre_tactic=data["mitre_tactic"],
            mitre_technique=data["mitre_technique"],
            description=data["description"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            tags=data["tags"],
        )

    return IOCResult(
        ioc_type="ip",
        ioc_value=ip,
        is_malicious=False,
        confidence=0,
        threat_category="clean",
        sources=["Checked against local threat DB"],
        mitre_tactic="",
        mitre_technique="",
        description="No known threat intelligence found for this IP.",
        first_seen="",
        last_seen="",
        tags=["clean"],
    )


def check_domain(domain: str) -> IOCResult:
    """Check domain against threat intelligence database."""
    if not validate_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")

    domain_lower = domain.lower()
    if domain_lower in SIMULATED_MALICIOUS_DOMAINS:
        data = SIMULATED_MALICIOUS_DOMAINS[domain_lower]
        return IOCResult(
            ioc_type="domain",
            ioc_value=domain,
            is_malicious=data["confidence"] > 0,
            confidence=data["confidence"],
            threat_category=data["category"],
            sources=data["sources"],
            mitre_tactic=data["mitre_tactic"],
            mitre_technique=data["mitre_technique"],
            description=data["description"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            tags=data["tags"],
        )

    return IOCResult(
        ioc_type="domain",
        ioc_value=domain,
        is_malicious=False,
        confidence=0,
        threat_category="clean",
        sources=["Checked against local threat DB"],
        mitre_tactic="",
        mitre_technique="",
        description="No known threat intelligence found for this domain.",
        first_seen="",
        last_seen="",
        tags=["clean"],
    )


def check_hash(file_hash: str) -> IOCResult:
    """Check file hash against threat intelligence database."""
    if not validate_hash(file_hash):
        raise ValueError(f"Invalid hash format: {file_hash}")

    hash_lower = file_hash.lower()
    if hash_lower in SIMULATED_MALICIOUS_HASHES:
        data = SIMULATED_MALICIOUS_HASHES[hash_lower]
        return IOCResult(
            ioc_type="hash",
            ioc_value=file_hash,
            is_malicious=data["confidence"] > 0,
            confidence=data["confidence"],
            threat_category=data["category"],
            sources=data["sources"],
            mitre_tactic=data["mitre_tactic"],
            mitre_technique=data["mitre_technique"],
            description=data["description"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            tags=data["tags"],
        )

    return IOCResult(
        ioc_type="hash",
        ioc_value=file_hash,
        is_malicious=False,
        confidence=0,
        threat_category="clean",
        sources=["Checked against local threat DB"],
        mitre_tactic="",
        mitre_technique="",
        description="No known threat intelligence found for this hash.",
        first_seen="",
        last_seen="",
        tags=["clean"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

RISK_ICONS = {"CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[!  ]", "LOW": "[LOW]", "CLEAN": "[OK ]"}


def print_ioc_result(result: IOCResult) -> None:
    """Pretty-print a single IOC check result."""
    risk = result.risk_level()
    icon = RISK_ICONS.get(risk, "[ ? ]")

    print(f"\n  {icon} IOC Check Result")
    print(f"  {'-'*50}")
    print(f"  Type       : {result.ioc_type.upper()}")
    print(f"  Value      : {result.ioc_value}")
    print(f"  Risk Level : {risk}")
    print(f"  Malicious  : {'YES [!!]' if result.is_malicious else 'No'}")
    print(f"  Confidence : {result.confidence}%")
    print(f"  Category   : {result.threat_category}")
    if result.description:
        print(f"  Description: {result.description}")
    if result.mitre_technique:
        print(f"  MITRE      : {result.mitre_tactic} / {result.mitre_technique}")
    if result.sources:
        print(f"  Sources    : {', '.join(result.sources)}")
    if result.tags:
        print(f"  Tags       : {', '.join(result.tags)}")
    if result.first_seen:
        print(f"  First Seen : {result.first_seen}  |  Last Seen: {result.last_seen}")


def run_demo() -> None:
    """Run a demonstration with all IOC types."""
    print("\n" + "=" * 60)
    print("   THREAT INTELLIGENCE AGGREGATOR — DEMO")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    print("\n[+] Checking IPs...")
    for ip in ["91.108.4.11", "45.33.32.156", "8.8.8.8", "103.102.166.240"]:
        result = check_ip(ip)
        print_ioc_result(result)

    print("\n[+] Checking Domains...")
    for domain in ["malware-c2.ru", "phish-bank-login.xyz", "google.com"]:
        result = check_domain(domain)
        print_ioc_result(result)

    print("\n[+] Checking File Hashes...")
    for h in [
        "3395856ce81f2b7382dee72602f798b642f14c0",
        "aec070645fe53ee3b3763059376134f058cc337",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1 of empty string
    ]:
        result = check_hash(h)
        print_ioc_result(result)

    print("\n" + "=" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator & IOC Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threat_intel.py --demo
  python threat_intel.py --check-ip 91.108.4.11
  python threat_intel.py --check-domain malware-c2.ru
  python threat_intel.py --check-hash 3395856ce81f2b7382dee72602f798b642f14c0
        """,
    )
    parser.add_argument("--demo", action="store_true", help="Run full demonstration")
    parser.add_argument("--check-ip", metavar="IP", help="Check an IP address")
    parser.add_argument("--check-domain", metavar="DOMAIN", help="Check a domain")
    parser.add_argument("--check-hash", metavar="HASH", help="Check a file hash (MD5/SHA-1/SHA-256)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    result = None
    try:
        if args.check_ip:
            result = check_ip(args.check_ip)
        elif args.check_domain:
            result = check_domain(args.check_domain)
        elif args.check_hash:
            result = check_hash(args.check_hash)
        else:
            parser.print_help()
            return
    except ValueError as e:
        print(f"[!] Input Error: {e}")
        sys.exit(1)

    if result:
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print_ioc_result(result)


if __name__ == "__main__":
    main()
