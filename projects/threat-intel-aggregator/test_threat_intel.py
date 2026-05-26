"""
Unit Tests — Threat Intelligence Aggregator
============================================
Tests cover:
  - Input validation (IP, domain, hash)
  - Known malicious IOC lookup returns correct results
  - Unknown IOC returns clean result
  - Risk level calculation
  - IOC result serialization
"""

import pytest
from threat_intel import (
    check_ip,
    check_domain,
    check_hash,
    validate_ip,
    validate_domain,
    validate_hash,
    IOCResult,
)


# ─────────────────────────────────────────────────────────────────────────────
# Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestValidation:
    def test_valid_ips(self):
        for ip in ["1.2.3.4", "192.168.0.1", "255.255.255.255", "0.0.0.0"]:
            assert validate_ip(ip) is True, f"Expected valid: {ip}"

    def test_invalid_ips(self):
        for ip in ["999.1.2.3", "not_an_ip", "1.2.3", "1.2.3.4.5", "", "256.0.0.1"]:
            assert validate_ip(ip) is False, f"Expected invalid: {ip}"

    def test_valid_domains(self):
        for domain in ["google.com", "malware.ru", "sub.example.co.uk", "test-site.xyz"]:
            assert validate_domain(domain) is True, f"Expected valid: {domain}"

    def test_invalid_domains(self):
        for domain in ["not a domain", "", "localhost", "..bad.."]:
            assert validate_domain(domain) is False, f"Expected invalid: {domain}"

    def test_valid_hashes(self):
        for h in [
            "d41d8cd98f00b204e9800998ecf8427e",           # MD5 (32 chars)
            "3395856ce81f2b7382dee72602f798b642f14c0",     # SHA-1 (40 chars)
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256
        ]:
            assert validate_hash(h) is True

    def test_invalid_hashes(self):
        for h in ["not_a_hash", "ZZZZZZ", "", "12345"]:
            assert validate_hash(h) is False


# ─────────────────────────────────────────────────────────────────────────────
# IP Check Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIPCheck:
    def test_known_malicious_ip(self):
        result = check_ip("91.108.4.11")
        assert result.is_malicious is True
        assert result.confidence > 0
        assert result.ioc_type == "ip"
        assert result.ioc_value == "91.108.4.11"

    def test_malicious_ip_has_mitre(self):
        result = check_ip("91.108.4.11")
        assert result.mitre_tactic != ""
        assert result.mitre_technique != ""

    def test_malicious_ip_has_sources(self):
        result = check_ip("91.108.4.11")
        assert len(result.sources) > 0

    def test_clean_ip_not_malicious(self):
        result = check_ip("8.8.8.8")
        assert result.is_malicious is False
        assert result.confidence == 0
        assert result.threat_category == "clean"

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError):
            check_ip("999.0.0.1")
        with pytest.raises(ValueError):
            check_ip("not_an_ip")

    def test_all_known_ips_are_malicious(self):
        """All IPs in the simulated database should be flagged."""
        malicious_ips = [
            "185.220.101.45", "45.33.32.156", "91.108.4.11",
            "103.102.166.240", "192.42.116.41",
        ]
        for ip in malicious_ips:
            result = check_ip(ip)
            assert result.is_malicious is True, f"Expected {ip} to be malicious"


# ─────────────────────────────────────────────────────────────────────────────
# Domain Check Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainCheck:
    def test_known_malicious_domain(self):
        result = check_domain("malware-c2.ru")
        assert result.is_malicious is True
        assert result.ioc_type == "domain"
        assert "c2" in result.threat_category

    def test_clean_domain(self):
        result = check_domain("google.com")
        assert result.is_malicious is False
        assert result.confidence == 0

    def test_domain_case_insensitive(self):
        """Domain lookup should be case-insensitive."""
        r1 = check_domain("MALWARE-C2.RU")
        r2 = check_domain("malware-c2.ru")
        assert r1.is_malicious == r2.is_malicious

    def test_invalid_domain_raises(self):
        with pytest.raises(ValueError):
            check_domain("not a domain!")


# ─────────────────────────────────────────────────────────────────────────────
# Hash Check Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHashCheck:
    def test_known_malicious_hash(self):
        result = check_hash("3395856ce81f2b7382dee72602f798b642f14c0")
        assert result.is_malicious is True
        assert result.ioc_type == "hash"

    def test_ransomware_hash_critical(self):
        result = check_hash("aec070645fe53ee3b3763059376134f058cc337")
        assert result.is_malicious is True
        assert result.confidence >= 90
        assert result.risk_level() in ("CRITICAL", "HIGH")

    def test_unknown_hash_clean(self):
        result = check_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert result.is_malicious is False

    def test_invalid_hash_raises(self):
        with pytest.raises(ValueError):
            check_hash("not_valid_hash")


# ─────────────────────────────────────────────────────────────────────────────
# IOCResult Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCResult:
    def test_risk_level_critical(self):
        result = check_ip("91.108.4.11")
        assert result.risk_level() in ("CRITICAL", "HIGH")

    def test_risk_level_clean(self):
        result = check_ip("8.8.8.8")
        assert result.risk_level() == "CLEAN"

    def test_to_dict_serializable(self):
        import json
        result = check_ip("91.108.4.11")
        d = result.to_dict()
        json.dumps(d)  # Should not raise
        assert "ioc_type" in d
        assert "confidence" in d
        assert "mitre_technique" in d

    def test_tags_is_list(self):
        result = check_ip("91.108.4.11")
        assert isinstance(result.tags, list)

    def test_sources_is_list(self):
        result = check_domain("malware-c2.ru")
        assert isinstance(result.sources, list)
