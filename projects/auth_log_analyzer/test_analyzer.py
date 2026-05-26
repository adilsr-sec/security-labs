import unittest
import sys
import os
from unittest.mock import patch, mock_open

# Append current directory to path so that 'analyzer' can be imported directly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from analyzer import parse_log_line, analyze_log_file  # noqa: E402


class TestLogAnalyzer(unittest.TestCase):

    def test_parse_log_line_failed(self):
        line = (
            "May 26 10:02:15 server sshd[12350]: Failed password for root "
            "from 192.168.1.100 port 50201 ssh2"
        )
        res = parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["event_type"], "Failed Password")
        self.assertEqual(res["user"], "root")
        self.assertEqual(res["ip"], "192.168.1.100")

    def test_parse_log_line_accepted(self):
        line = (
            "May 26 10:01:05 server sshd[12345]: Accepted publickey for "
            "admin from 192.168.1.20 port 49232 ssh2: RSA"
        )
        res = parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["event_type"], "Successful Login")
        self.assertEqual(res["user"], "admin")
        self.assertEqual(res["ip"], "192.168.1.20")
        self.assertEqual(res["method"], "publickey")

    def test_parse_log_line_invalid_user(self):
        line = (
            "May 26 10:03:00 server sshd[12362]: Invalid user support from "
            "10.0.0.50 port 38221 ssh2"
        )
        res = parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["event_type"], "Invalid Username")
        self.assertEqual(res["user"], "support")
        self.assertEqual(res["ip"], "10.0.0.50")

    def test_parse_log_line_irrelevant(self):
        line = (
            "May 26 10:04:10 server sshd[12345]: pam_unix(sshd:session): "
            "session closed for user admin"
        )
        res = parse_log_line(line)
        self.assertIsNone(res)

    def test_analyze_log_file_computations(self):
        mock_log_data = (
            "May 26 10:02:15 server sshd[12350]: Failed password for root "
            "from 192.168.1.100 port 50201 ssh2\n"
            "May 26 10:02:16 server sshd[12350]: Failed password for root "
            "from 192.168.1.100 port 50202 ssh2\n"
            "May 26 10:01:05 server sshd[12345]: Accepted publickey for "
            "admin from 192.168.1.20 port 49232 ssh2\n"
            "May 26 10:03:00 server sshd[12362]: Invalid user support "
            "from 10.0.0.50 port 38221 ssh2\n"
        )

        with patch("builtins.open", mock_open(read_data=mock_log_data)):
            metrics = analyze_log_file(
                "fake_path.log", brute_force_threshold=2
            )

            self.assertIsNotNone(metrics)
            # 2 failures + 1 invalid user failure = 3 total failed attempts
            self.assertEqual(metrics["total_failed_attempts"], 3)
            self.assertEqual(metrics["total_successful_logins"], 1)
            self.assertEqual(metrics["failures_by_ip"]["192.168.1.100"], 2)
            self.assertEqual(metrics["failures_by_ip"]["10.0.0.50"], 1)
            self.assertEqual(
                metrics["successful_logins_by_ip"]["192.168.1.20"], 1
            )

            # Brute-force threshold is 2, so 192.168.1.100 should warn
            warnings = metrics["brute_force_warnings"]
            self.assertEqual(len(warnings), 1)
            self.assertEqual(warnings[0]["ip"], "192.168.1.100")


if __name__ == "__main__":
    unittest.main()
