# 🗳️ Secured Voting Machine using Blockchain Technology

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)](test_blockchain.py)
[![Domain](https://img.shields.io/badge/Domain-Cryptography_•_Distributed_Ledger-blueviolet?style=flat-square)]()

> **Academic Capstone Project** — Cybersecurity Engineering

---

## 📌 Project Overview

This project implements a **decentralized electronic voting system** backed by a custom blockchain. Traditional centralized voting systems are vulnerable to single-point-of-failure attacks, insider threats, and record tampering. By distributing vote records across a cryptographically chained ledger, this system achieves:

- **Immutability**: Once recorded, no vote can be altered without invalidating the entire chain.
- **Voter Anonymity**: Voter IDs are hashed (SHA-256) before storage; the ledger never holds raw identity.
- **Double-Vote Prevention**: A cryptographic voter registry prevents repeated voting.
- **Tamper Evidence**: Any modification to any block is instantly detected via hash mismatch.

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────┐
│                    VotingSystem (App Layer)             │
│  ┌──────────────────┐   ┌──────────────────────────┐   │
│  │  Voter Registry  │   │    Candidate Whitelist   │   │
│  │  (hash → voted)  │   │  ["Alice", "Bob", ...]   │   │
│  └──────────────────┘   └──────────────────────────┘   │
└────────────────────────────────────────────────────────┘
               │ cast_vote()
               ▼
┌────────────────────────────────────────────────────────┐
│                  Blockchain (Ledger Layer)              │
│                                                        │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐           │
│  │ Block #0 │──▶│ Block #1 │──▶│ Block #2 │──▶ ...    │
│  │ GENESIS  │   │  VOTE    │   │  VOTE    │           │
│  │ H:0x000  │   │ prev:... │   │ prev:... │           │
│  └──────────┘   └──────────┘   └──────────┘           │
│                                                        │
│  Each block: SHA-256(index + timestamp + data +        │
│              previous_hash + nonce)                    │
│  Proof-of-Work: hash must start with "000..."          │
└────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Properties

| Property | Implementation | Security Guarantee |
|:---|:---|:---|
| **Immutability** | SHA-256 hash chaining | Any modification changes all subsequent hashes |
| **Proof-of-Work** | Nonce mining (difficulty=3) | Retroactive tampering requires immense computation |
| **Voter Anonymity** | SHA-256(voter_id) stored | Raw voter identity never persists in the ledger |
| **Double-Vote Prevention** | In-memory hash registry | Each voter hash can vote exactly once |
| **Candidate Validation** | Whitelist check | No votes for non-existent candidates accepted |
| **Input Sanitization** | `strip()` + empty checks | Prevents injection and empty-string attacks |

---

## 📂 File Structure

```
secured-voting-blockchain/
├── blockchain.py        # Core blockchain + VotingSystem classes
├── voting_cli.py        # Interactive CLI + automated demo
├── test_blockchain.py   # 15+ pytest unit tests
└── README.md            # This file
```

---

## 🚀 Quick Start

```bash
# Run the automated demo (recommended first try)
python voting_cli.py --demo

# Run the interactive CLI
python voting_cli.py

# Run all unit tests
pytest test_blockchain.py -v

# Example output:
# PASSED test_block_creation
# PASSED test_chain_valid_after_multiple_blocks
# PASSED test_double_vote_prevented
# PASSED test_voter_hash_not_stored_in_ledger
# ...
```

---

## 🔬 How the ARSS Algorithm Relates (Cross-Project Link)

The hash functions used here (SHA-256) are the same cryptographic primitives used in the **Arjuna's Astra steganography project** for payload integrity verification. This cross-project consistency demonstrates an understanding of how one core concept (cryptographic hashing) applies across both ledger security and data-hiding domains.

---

## 📚 Academic References

- Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System.*
- Haber, S., & Stornetta, W. S. (1991). *How to time-stamp a digital document.*
- NIST FIPS 180-4: Secure Hash Standard (SHS) — SHA-256 specification.

---

## ⚠️ Security Disclosure

This is a **demonstration implementation** for academic and portfolio purposes. A production-grade blockchain voting system would additionally require:
- Hardware Security Modules (HSMs) for key management
- Zero-Knowledge Proofs for advanced anonymity
- Formal security audits and penetration testing
- Distributed consensus across multiple independent nodes
- Secure key exchange and voter authentication mechanisms
