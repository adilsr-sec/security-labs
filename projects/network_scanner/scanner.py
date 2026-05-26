#!/usr/bin/env python3
"""
Multi-Threaded Network Port Scanner
Author: entry-level cybersecurity engineer
Description: A security-oriented TCP port scanner that resolves hostnames,
             validates inputs, uses multi-threading, and grabs banners.
"""

import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress


# Predefined dictionary mapping common ports to their typical services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}


def validate_target(target):
    """
    Validates if the target is a valid IP address or hostname.
    Returns the resolved IP address, or None if invalid.
    """
    # Check if target is a valid IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Check if target is a valid hostname and resolve it
    try:
        resolved_ip = socket.gethostbyname(target)
        return resolved_ip
    except socket.gaierror:
        return None


def grab_banner(s):
    """
    Attempts to read a service banner from the open socket.
    Returns the banner string or None.
    """
    try:
        # Set a short timeout for banner grabbing to keep scan fast
        s.settimeout(1.5)
        # Send a generic probe (useful for HTTP/SMTP, or receiving SSH banners)
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner:
            return banner
    except Exception:
        pass
    return None


def scan_port(target_ip, port):
    """
    Scans a single port on the target IP.
    Returns a dict with status details if open, or None if closed.
    """
    try:
        # Create a standard TCP IPv4 socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            # Establish the 3-way handshake connection
            result = s.connect_ex((target_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown Service")
                banner = grab_banner(s)
                return {
                    "port": port,
                    "status": "Open",
                    "service": service,
                    "banner": banner
                }
    except Exception:
        # Graceful handling of network socket exceptions
        pass
    return None


def run_scanner(target, ports, threads):
    """
    Orchestrates the scanning process using a ThreadPoolExecutor.
    """
    print(f"[*] Initializing scan on target: {target}")
    target_ip = validate_target(target)

    if not target_ip:
        print(f"[!] Error: Could not resolve target: '{target}'")
        return []

    print(f"[*] Target resolved to IP: {target_ip}")
    print(f"[*] Scanning {len(ports)} ports using {threads} threads...\n")
    print(f"{'PORT':<8}{'STATUS':<10}{'SERVICE':<18}{'BANNER/INFO'}")
    print("-" * 60)

    open_ports_results = []

    # Using ThreadPoolExecutor to run tasks in parallel
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Map scan_port tasks
        futures = {
            executor.submit(scan_port, target_ip, port): port
            for port in ports
        }
        for future in futures:
            res = future.result()
            if res:
                open_ports_results.append(res)
                banner_str = res['banner'] if res['banner'] else "N/A"
                # Limit banner length in output
                if len(banner_str) > 30:
                    banner_display = banner_str[:30] + '...'
                else:
                    banner_display = banner_str
                print(
                    f"{res['port']:<8}"
                    f"{res['status']:<10}"
                    f"{res['service']:<18}"
                    f"{banner_display}"
                )

    print("\n[*] Scan completed.")
    return open_ports_results


def parse_port_range(port_str):
    """
    Parses a string input of ports. Can be comma-separated or hyphenated.
    Examples: '80,443' or '20-100' or '22'
    """
    ports = []
    try:
        if '-' in port_str:
            start, end = map(int, port_str.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_str:
            ports = [int(p.strip()) for p in port_str.split(',')]
        else:
            ports = [int(port_str)]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Invalid port format. Use '80,443' or '20-100'."
        )

    # Filter out port bounds
    ports = [p for p in ports if 1 <= p <= 65535]
    if not ports:
        raise argparse.ArgumentTypeError("Ports must be in the range 1-65535.")
    return ports


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Threaded TCP Port Scanner with Banner Grabbing"
    )
    parser.add_argument(
        "target",
        help="Target IP address or Hostname (e.g. 127.0.0.1 or localhost)"
    )
    parser.add_argument(
        "-p", "--ports", type=parse_port_range,
        help="Port(s) to scan. Format: '80,443' or '20-100'."
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10,
        help="Number of threads (default: 10)"
    )

    args = parser.parse_args()

    # Default to scanning common ports if none specified
    scan_ports = args.ports if args.ports else sorted(COMMON_PORTS.keys())

    try:
        run_scanner(args.target, scan_ports, args.threads)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user (KeyboardInterrupt). Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()
