#!/usr/bin/env python3
"""
Authentication Log Analyzer
Author: entry-level cybersecurity engineer
Description: Parses auth.log files to extract SSH successes, failures,
             and identify brute-force attacks from specific source IPs.
"""

import re
import sys
import json
import argparse
from collections import defaultdict

# Regex patterns for SSH logins
FAILED_REGEX = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"
)
ACCEPTED_REGEX = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"
)
INVALID_USER_REGEX = re.compile(
    r"Invalid user (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+"
)


def parse_log_line(line):
    """
    Parses a single log line.
    Returns a dict containing event_type, user, ip, and details, or None.
    """
    # Check for failed password attempt
    match = FAILED_REGEX.search(line)
    if match:
        return {
            "event_type": "Failed Password",
            "user": match.group("user"),
            "ip": match.group("ip")
        }

    # Check for accepted connection
    match = ACCEPTED_REGEX.search(line)
    if match:
        return {
            "event_type": "Successful Login",
            "user": match.group("user"),
            "ip": match.group("ip"),
            "method": match.group("method")
        }

    # Check for invalid user attempt
    match = INVALID_USER_REGEX.search(line)
    if match:
        return {
            "event_type": "Invalid Username",
            "user": match.group("user"),
            "ip": match.group("ip")
        }

    return None


def analyze_log_file(filepath, brute_force_threshold=5):
    """
    Reads the file line-by-line and compiles security metrics.
    """
    metrics = {
        "total_failed_attempts": 0,
        "total_successful_logins": 0,
        "invalid_users_targeted": defaultdict(int),
        "failures_by_ip": defaultdict(int),
        "failures_by_user": defaultdict(int),
        "successful_logins_by_ip": defaultdict(int),
        "brute_force_warnings": []
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = parse_log_line(line)
                if not parsed:
                    continue

                event = parsed["event_type"]
                ip = parsed["ip"]
                user = parsed["user"]

                if event == "Failed Password":
                    metrics["total_failed_attempts"] += 1
                    metrics["failures_by_ip"][ip] += 1
                    metrics["failures_by_user"][user] += 1

                elif event == "Successful Login":
                    metrics["total_successful_logins"] += 1
                    metrics["successful_logins_by_ip"][ip] += 1

                elif event == "Invalid Username":
                    metrics["invalid_users_targeted"][user] += 1
                    metrics["failures_by_ip"][ip] += 1
                    metrics["failures_by_user"][user] += 1
                    metrics["total_failed_attempts"] += 1

    except FileNotFoundError:
        print(f"[!] Error: File not found: {filepath}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] Exception error reading file: {e}", file=sys.stderr)
        return None

    # Identify potential brute-force sources based on thresholds
    for ip, count in metrics["failures_by_ip"].items():
        if count >= brute_force_threshold:
            impacted = [
                u for u, c in metrics["failures_by_user"].items() if count > 0
            ]
            metrics["brute_force_warnings"].append({
                "ip": ip,
                "failed_count": count,
                "impacted_users": impacted
            })

    # Convert defaultdicts to regular dicts for compatibility/JSON export
    metrics["invalid_users_targeted"] = dict(
        metrics["invalid_users_targeted"]
    )
    metrics["failures_by_ip"] = dict(metrics["failures_by_ip"])
    metrics["failures_by_user"] = dict(metrics["failures_by_user"])
    metrics["successful_logins_by_ip"] = dict(
        metrics["successful_logins_by_ip"]
    )

    return metrics


def print_report(metrics, threshold):
    """
    Renders the metrics nicely in the CLI terminal.
    """
    if not metrics:
        return

    print("=" * 60)
    print("                AUTHENTICATION LOG ANALYSIS REPORT            ")
    print("=" * 60)
    print(f"Total Successful Logins: {metrics['total_successful_logins']}")
    print(f"Total Failed Attempts:   {metrics['total_failed_attempts']}")
    print("-" * 60)

    print("\n[+] Successful Logins by IP:")
    for ip, count in metrics["successful_logins_by_ip"].items():
        print(f"  - {ip:<15} : {count} times")

    print("\n[+] Top Targeted Usernames:")
    sorted_users = sorted(
        metrics["failures_by_user"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]
    for user, count in sorted_users:
        print(f"  - {user:<15} : {count} failures")

    print("\n[!] Potential Brute-Force Activity:")
    warnings = metrics["brute_force_warnings"]
    if not warnings:
        print(f"  - No IPs exceeded the failure threshold of {threshold}.")
    else:
        for warn in warnings:
            print(
                f"  - [WARNING] IP {warn['ip']} triggered "
                f"{warn['failed_count']} login failures."
            )

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="SSH Auth Log Parser and Brute Force Detector"
    )
    parser.add_argument(
        "logfile",
        help="Path to the authentication log file (e.g. auth.log)"
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=5,
        help="Threshold for alerting brute force attempts (default: 5)"
    )
    parser.add_argument(
        "-j", "--json", action="store_true",
        help="Output analysis metrics in JSON format"
    )

    args = parser.parse_args()

    metrics = analyze_log_file(args.logfile, args.threshold)

    if not metrics:
        sys.exit(1)

    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        print_report(metrics, args.threshold)


if __name__ == "__main__":
    main()
