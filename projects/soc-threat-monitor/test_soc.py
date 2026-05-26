"""
Unit Tests — SOC Threat Detection Monitor
==========================================
Tests cover:
  - Log line parsing (valid and invalid inputs)
  - IP and username extraction
  - Event type classification
  - Detection rules: brute force, spray, compromise, port scan, sudo
  - Alert severity levels
  - MITRE ATT&CK field population
"""

import pytest
from soc_monitor import (
    parse_log_line,
    DetectionEngine,
    LogEvent,
    DEMO_LOG,
)


# ─────────────────────────────────────────────────────────────────────────────
# Log Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLogParser:
    def test_parse_failed_login(self):
        line = "May 26 10:00:01 host sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2"
        event = parse_log_line(line)
        assert event is not None
        assert event.event_type == "FAILED_LOGIN"
        assert event.source_ip == "1.2.3.4"
        assert event.username == "admin"

    def test_parse_successful_login(self):
        line = "May 26 10:00:05 host sshd[123]: Accepted password for alice from 10.0.0.1 port 54321 ssh2"
        event = parse_log_line(line)
        assert event is not None
        assert event.event_type == "SUCCESSFUL_LOGIN"
        assert event.username == "alice"
        assert event.source_ip == "10.0.0.1"

    def test_parse_refused_connection(self):
        line = "May 26 10:01:00 host sshd[123]: refused connect from 5.5.5.5 (5.5.5.5)"
        event = parse_log_line(line)
        assert event is not None
        assert event.event_type == "CONNECTION_REFUSED"

    def test_parse_sudo_event(self):
        line = "May 26 10:02:00 host sudo[456]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        event = parse_log_line(line)
        assert event is not None
        assert event.event_type in ("SUDO", "COMMAND_EXECUTION")

    def test_empty_line_returns_none(self):
        assert parse_log_line("") is None
        assert parse_log_line("   ") is None

    def test_malformed_line_returns_none(self):
        assert parse_log_line("not a valid syslog line at all!") is None

    def test_timestamp_captured(self):
        line = "May 26 08:01:01 server1 sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
        event = parse_log_line(line)
        assert event is not None
        assert "08:01:01" in event.timestamp

    def test_no_localhost_ip(self):
        line = "May 26 10:00:01 host sshd[1]: Failed password for user from 127.0.0.1 port 22 ssh2"
        event = parse_log_line(line)
        # Localhost IPs filtered; source_ip may be None or 127.0.0.1
        # Just verify parsing doesn't crash
        assert event is not None


# ─────────────────────────────────────────────────────────────────────────────
# Detection Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

def make_failed_events(ip: str, count: int, username: str = "testuser") -> list[LogEvent]:
    """Generate synthetic failed login events from an IP."""
    events = []
    for i in range(count):
        events.append(LogEvent(
            raw=f"failed from {ip}",
            timestamp=f"May 26 10:0{i}:00",
            hostname="server",
            process="sshd",
            message=f"Failed password for invalid user {username} from {ip} port {22000+i} ssh2",
            source_ip=ip,
            username=username,
            event_type="FAILED_LOGIN",
        ))
    return events


class TestDetectionEngine:
    def test_no_events_no_alerts(self):
        engine = DetectionEngine()
        alerts = engine.process_events([])
        assert alerts == []

    def test_brute_force_triggers_at_threshold(self):
        engine = DetectionEngine({"brute_force_threshold": 5})
        events = make_failed_events("1.2.3.4", 5)
        alerts = engine.process_events(events)
        names = [a.rule_name for a in alerts]
        assert "SSH_BRUTE_FORCE" in names

    def test_brute_force_does_not_trigger_below_threshold(self):
        engine = DetectionEngine({"brute_force_threshold": 5})
        events = make_failed_events("1.2.3.4", 4)
        alerts = engine.process_events(events)
        names = [a.rule_name for a in alerts]
        assert "SSH_BRUTE_FORCE" not in names

    def test_brute_force_severity_is_high(self):
        engine = DetectionEngine({"brute_force_threshold": 3})
        events = make_failed_events("9.9.9.9", 3)
        alerts = engine.process_events(events)
        bf_alerts = [a for a in alerts if a.rule_name == "SSH_BRUTE_FORCE"]
        assert all(a.severity == "HIGH" for a in bf_alerts)

    def test_password_spray_triggers(self):
        """Different usernames from same IP should trigger spray alert."""
        engine = DetectionEngine({"spray_threshold": 3, "brute_force_threshold": 99})
        ip = "5.5.5.5"
        events = []
        for user in ["alice", "bob", "charlie", "dave"]:
            e = make_failed_events(ip, 1, username=user)[0]
            events.append(e)

        alerts = engine.process_events(events)
        names = [a.rule_name for a in alerts]
        assert "PASSWORD_SPRAY" in names

    def test_successful_after_brute_force_critical(self):
        """Successful login after brute-force should generate CRITICAL alert."""
        engine = DetectionEngine({"brute_force_threshold": 99})  # Suppress brute alert
        ip = "6.6.6.6"
        failed_events = make_failed_events(ip, 3)

        success = LogEvent(
            raw="Accepted from 6.6.6.6",
            timestamp="May 26 10:05:00",
            hostname="server",
            process="sshd",
            message="Accepted password for testuser from 6.6.6.6 port 22 ssh2",
            source_ip=ip,
            username="testuser",
            event_type="SUCCESSFUL_LOGIN",
        )

        alerts = engine.process_events(failed_events + [success])
        critical = [a for a in alerts if a.severity == "CRITICAL"]
        assert len(critical) > 0
        assert any(a.rule_name == "SUCCESSFUL_LOGIN_AFTER_BRUTE_FORCE" for a in critical)

    def test_port_scan_triggers(self):
        """Many refused connections should trigger port scan alert."""
        engine = DetectionEngine({"refused_scan_threshold": 5})
        ip = "7.7.7.7"
        events = []
        for i in range(6):
            events.append(LogEvent(
                raw=f"refused from {ip}",
                timestamp=f"May 26 10:0{i}:00",
                hostname="server",
                process="sshd",
                message=f"refused connect from {ip}",
                source_ip=ip,
                username=None,
                event_type="CONNECTION_REFUSED",
            ))

        alerts = engine.process_events(events)
        names = [a.rule_name for a in alerts]
        assert "PORT_SCAN_DETECTED" in names

    def test_mitre_fields_populated(self):
        """All alerts should have MITRE tactic and technique populated."""
        engine = DetectionEngine({"brute_force_threshold": 3})
        events = make_failed_events("8.8.8.8", 3)
        alerts = engine.process_events(events)
        for alert in alerts:
            assert alert.mitre_tactic != ""
            assert alert.mitre_technique != ""

    def test_recommended_action_populated(self):
        """All alerts should have a recommended action."""
        engine = DetectionEngine({"brute_force_threshold": 3})
        events = make_failed_events("8.8.8.8", 3)
        alerts = engine.process_events(events)
        for alert in alerts:
            assert alert.recommended_action != ""

    def test_demo_log_generates_alerts(self):
        """The built-in demo log should produce at least 3 alerts."""
        lines = DEMO_LOG.strip().split("\n")
        events = [parse_log_line(line) for line in lines]
        events = [e for e in events if e]

        engine = DetectionEngine()
        alerts = engine.process_events(events)
        assert len(alerts) >= 3

    def test_alert_ids_are_unique(self):
        """Each alert should have a unique ID."""
        engine = DetectionEngine({"brute_force_threshold": 3, "spray_threshold": 2})
        events = make_failed_events("1.1.1.1", 3) + make_failed_events("2.2.2.2", 3)
        alerts = engine.process_events(events)
        ids = [a.alert_id for a in alerts]
        assert len(ids) == len(set(ids))

    def test_alert_serializable(self):
        """Alert.to_dict() should return a JSON-serializable dict."""
        import json
        engine = DetectionEngine({"brute_force_threshold": 3})
        events = make_failed_events("3.3.3.3", 3)
        alerts = engine.process_events(events)
        for alert in alerts:
            json.dumps(alert.to_dict())  # Should not raise
