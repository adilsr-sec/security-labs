#!/usr/bin/env python3
"""
Secured Voting Machine — Interactive CLI
=========================================
Academic Project — Cybersecurity Engineering Portfolio

An interactive command-line interface for the blockchain voting system.
Demonstrates practical application of the Blockchain and VotingSystem classes.

Usage:
    python voting_cli.py
    python voting_cli.py --demo      # Run automated demo with sample data

Author: Adil S R
"""

import argparse
import sys
from blockchain import VotingSystem


def run_demo() -> None:
    """
    Run a fully automated demonstration of the voting system.
    This simulates an election with preset voters and votes.
    """
    print("\n" + "=" * 60)
    print("   BLOCKCHAIN VOTING SYSTEM — AUTOMATED DEMO")
    print("=" * 60)

    # Initialize with custom candidates
    print("\n[+] Initializing voting system...")
    vs = VotingSystem(candidates=["Alice (Party A)", "Bob (Party B)", "Carol (Independent)"])
    print("    Candidates registered:")
    for c in vs.candidates:
        print(f"      • {c}")

    # Register voters
    print("\n[+] Registering voters...")
    voters = [
        "voter_ID_2401", "voter_ID_2402", "voter_ID_2403",
        "voter_ID_2404", "voter_ID_2405", "voter_ID_2406",
        "voter_ID_2407", "voter_ID_2408",
    ]
    for vid in voters:
        ok = vs.register_voter(vid)
        print(f"    Voter {vid}: {'[OK] Registered' if ok else '[!!] Already exists'}")

    # Cast votes
    print("\n[+] Casting votes...")
    vote_data = [
        ("voter_ID_2401", "Alice (Party A)"),
        ("voter_ID_2402", "Bob (Party B)"),
        ("voter_ID_2403", "Alice (Party A)"),
        ("voter_ID_2404", "Carol (Independent)"),
        ("voter_ID_2405", "Alice (Party A)"),
        ("voter_ID_2406", "Bob (Party B)"),
        ("voter_ID_2407", "Carol (Independent)"),
        # Double-vote attempt:
        ("voter_ID_2401", "Bob (Party B)"),
        # Unregistered voter attempt:
        ("voter_ID_9999", "Alice (Party A)"),
    ]

    for voter_id, candidate in vote_data:
        result = vs.cast_vote(voter_id, candidate)
        if result["status"] == "success":
            print(f"    [OK] {voter_id[:16]}... -> {candidate} | Block #{result['block_index']}")
        else:
            print(f"    [!!] {voter_id[:16]}... -> REJECTED: {result['message']}")

    # Show blockchain structure
    print("\n[+] Blockchain ledger (last 3 blocks):")
    for block in vs.blockchain.chain[-3:]:
        print(f"    Block #{block.index} | Hash: {block.hash[:32]}... | Nonce: {block.nonce}")

    # Verify chain integrity
    print(f"\n[+] Chain validation: {'[INTACT]' if vs.blockchain.is_chain_valid() else '[CORRUPTED!]'}")

    # Print results
    vs.print_results()


def run_interactive() -> None:
    """Run the interactive CLI voting session."""
    print("\n" + "=" * 60)
    print("   SECURED VOTING MACHINE — BLOCKCHAIN POWERED")
    print("=" * 60)
    print("   Security: SHA-256 hash chaining + Proof-of-Work")
    print("   Anonymity: Voter IDs stored as cryptographic hashes")
    print("=" * 60)

    # Get candidate list
    print("\n[Setup] Enter candidate names (comma-separated):")
    print("        Press Enter for defaults: A, B, C")
    raw = input("Candidates: ").strip()
    if raw:
        candidates = [c.strip() for c in raw.split(",") if c.strip()]
    else:
        candidates = ["Candidate A", "Candidate B", "Candidate C"]

    vs = VotingSystem(candidates=candidates)
    print(f"[+] Voting system initialized with {len(candidates)} candidates.")

    while True:
        print("\n" + "-" * 40)
        print("  MENU")
        print("  [1] Register a voter")
        print("  [2] Cast a vote")
        print("  [3] View live results")
        print("  [4] Verify chain integrity")
        print("  [5] Export blockchain ledger")
        print("  [Q] Quit")
        print("-" * 40)

        choice = input("Select option: ").strip().upper()

        if choice == "1":
            voter_id = input("Enter voter ID to register: ").strip()
            try:
                ok = vs.register_voter(voter_id)
                if ok:
                    print(f"  [OK] Voter registered successfully (ID hashed & stored).")
                else:
                    print(f"  [!!] Voter already registered.")
            except ValueError as e:
                print(f"  [!!] Error: {e}")

        elif choice == "2":
            voter_id = input("Enter your voter ID: ").strip()
            print("  Available candidates:")
            for i, c in enumerate(vs.candidates, 1):
                print(f"    [{i}] {c}")
            choice_c = input("  Enter candidate number or name: ").strip()
            try:
                if choice_c.isdigit():
                    idx = int(choice_c) - 1
                    if 0 <= idx < len(vs.candidates):
                        candidate = vs.candidates[idx]
                    else:
                        print("  [!!] Invalid number.")
                        continue
                else:
                    candidate = choice_c

                result = vs.cast_vote(voter_id, candidate)
                if result["status"] == "success":
                    print(f"  [OK] {result['message']}")
                    print(f"     Block #{result['block_index']} | Hash: {result['block_hash'][:32]}...")
                else:
                    print(f"  [!!] Vote rejected: {result['message']}")
            except ValueError as e:
                print(f"  [!!] Error: {e}")

        elif choice == "3":
            vs.print_results()

        elif choice == "4":
            valid = vs.blockchain.is_chain_valid()
            print(f"\n  Chain Integrity: {'[VALID]' if valid else '[TAMPERED!]'}")
            print(f"  Total blocks in chain: {len(vs.blockchain)}")

        elif choice == "5":
            import json
            ledger = vs.blockchain.export_chain()
            print(f"\n  Blockchain ledger ({len(ledger)} blocks):")
            print(json.dumps(ledger, indent=2))

        elif choice == "Q":
            print("\n[+] Closing voting session. Final results:")
            vs.print_results()
            print("    Goodbye!\n")
            sys.exit(0)

        else:
            print("  [!!] Invalid option. Please try again.")


def main():
    parser = argparse.ArgumentParser(
        description="Secured Voting Machine — Blockchain-powered CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python voting_cli.py           # Interactive mode
  python voting_cli.py --demo    # Automated demo with sample data
        """,
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run automated demonstration with pre-set data",
    )
    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        run_interactive()


if __name__ == "__main__":
    main()
