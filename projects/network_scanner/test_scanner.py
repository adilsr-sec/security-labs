import unittest
from unittest.mock import patch, MagicMock
import socket
import sys
import os

# Append current directory to path so that 'scanner' can be imported directly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scanner import (  # noqa: E402
    validate_target,
    parse_port_range,
    scan_port
)


class TestNetworkScanner(unittest.TestCase):

    def test_validate_target_valid_ip(self):
        # Valid IPv4 address should return target as is
        self.assertEqual(validate_target("192.168.1.1"), "192.168.1.1")
        # Valid IPv6 address
        self.assertEqual(validate_target("::1"), "::1")

    @patch("socket.gethostbyname")
    def test_validate_target_valid_hostname(self, mock_gethostbyname):
        # Mock successful name resolution
        mock_gethostbyname.return_value = "93.184.216.34"
        self.assertEqual(validate_target("example.com"), "93.184.216.34")

    @patch("socket.gethostbyname")
    def test_validate_target_invalid_hostname(self, mock_gethostbyname):
        # Mock failed hostname resolution
        mock_gethostbyname.side_effect = socket.gaierror
        self.assertIsNone(validate_target("invalid-hostname-xyz.local"))

    def test_parse_port_range_single(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_parse_port_range_comma(self):
        self.assertEqual(parse_port_range("80,443,8080"), [80, 443, 8080])

    def test_parse_port_range_hyphen(self):
        self.assertEqual(parse_port_range("21-25"), [21, 22, 23, 24, 25])

    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket_class):
        # Configure socket to simulate closed port (connect_ex returns 111)
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.return_value = 111
        mock_socket_class.return_value.__enter__.return_value = (
            mock_socket_instance
        )

        result = scan_port("127.0.0.1", 80)
        self.assertIsNone(result)

    @patch("socket.socket")
    def test_scan_port_open_no_banner(self, mock_socket_class):
        # Configure socket to simulate open port, recv raises timeout
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.return_value = 0
        mock_socket_instance.recv.side_effect = socket.timeout
        mock_socket_class.return_value.__enter__.return_value = (
            mock_socket_instance
        )

        result = scan_port("127.0.0.1", 22)
        self.assertIsNotNone(result)
        self.assertEqual(result["port"], 22)
        self.assertEqual(result["status"], "Open")
        self.assertEqual(result["service"], "SSH")
        self.assertIsNone(result["banner"])


if __name__ == "__main__":
    unittest.main()
