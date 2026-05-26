#!/usr/bin/env python3
"""
Secured Voting Machine using Blockchain Technology
====================================================
Academic Project — Cybersecurity Engineering Portfolio

This module implements a custom blockchain-based voting system:
  - SHA-256 hash chaining for immutability
  - Proof-of-Work consensus to prevent tampering
  - Voter anonymization via hashed voter IDs
  - Double-vote prevention with a voter registry

Usage:
    from blockchain import Blockchain, VotingSystem
    vs = VotingSystem()
    vs.register_voter("voter_001")
    vs.cast_vote("voter_001", "Candidate A")
    vs.print_results()

Author: Adil S R
Course: Secured Voting Systems / Capstone Project
Security Note: This is a demonstration implementation.
               Production systems require hardware security modules (HSMs),
               secure key management, and rigorous penetration testing.
"""

import hashlib
import json
import time
import re
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Block — Single chain element
# ─────────────────────────────────────────────────────────────────────────────

class Block:
    """
    Represents a single block in the voting blockchain.

    Each block contains:
      - index:         Position in the chain
      - timestamp:     UNIX epoch of creation
      - data:          Vote payload (candidate, anonymized voter hash)
      - previous_hash: SHA-256 hash of the previous block (chain link)
      - nonce:         Proof-of-Work counter
      - hash:          This block's computed SHA-256 hash
    """

    def __init__(self, index: int, data: dict, previous_hash: str):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of the block's canonical content."""
        block_content = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_content.encode()).hexdigest()

    def mine_block(self, difficulty: int) -> None:
        """
        Proof-of-Work: increment nonce until hash starts with
        `difficulty` leading zeros.

        This makes retroactive tampering computationally expensive —
        an adversary must redo PoW for every subsequent block.
        """
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self._compute_hash()

    def to_dict(self) -> dict:
        """Serialize block to dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, hash={self.hash[:16]}..., "
            f"nonce={self.nonce}, data={self.data})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Blockchain — Immutable ledger
# ─────────────────────────────────────────────────────────────────────────────

class Blockchain:
    """
    Manages the chain of vote blocks.

    Security properties:
      - Hash linking: Changing any block invalidates all subsequent hashes.
      - PoW mining: Tampering requires immense computation.
      - Genesis block: A fixed origin anchors the entire chain.
    """

    DIFFICULTY = 3  # Leading zeros required in PoW hash

    def __init__(self):
        self.chain: list[Block] = []
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        """Create the immutable first block (genesis) with hardcoded origin data."""
        genesis = Block(
            index=0,
            data={"type": "GENESIS", "message": "Voting system initialized"},
            previous_hash="0" * 64,
        )
        genesis.mine_block(self.DIFFICULTY)
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        """Return the most recent block."""
        return self.chain[-1]

    def add_block(self, data: dict) -> Block:
        """
        Mine and append a new vote block to the chain.

        Args:
            data: Vote payload dictionary.

        Returns:
            The newly added Block.
        """
        block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=self.last_block.hash,
        )
        block.mine_block(self.DIFFICULTY)
        self.chain.append(block)
        return block

    def is_chain_valid(self) -> bool:
        """
        Validate the entire chain integrity.

        Checks:
          1. Each block's stored hash matches its recomputed hash.
          2. Each block's previous_hash matches the prior block's hash.
          3. Each block satisfies the Proof-of-Work difficulty.

        Returns:
            True if the chain is intact; False if tampered.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Recompute hash to detect data tampering
            if current.hash != current._compute_hash():
                return False

            # Verify chain linkage
            if current.previous_hash != previous.hash:
                return False

            # Verify Proof-of-Work
            target = "0" * self.DIFFICULTY
            if not current.hash.startswith(target):
                return False

        return True

    def export_chain(self) -> list[dict]:
        """Export all blocks as serializable dictionaries."""
        return [block.to_dict() for block in self.chain]

    def __len__(self) -> int:
        return len(self.chain)


# ─────────────────────────────────────────────────────────────────────────────
# VotingSystem — Application layer
# ─────────────────────────────────────────────────────────────────────────────

class VotingSystem:
    """
    High-level voting application built on top of the Blockchain.

    Security features:
      - Voter IDs are hashed (SHA-256) before storage — the chain never
        stores raw voter identity (voter anonymization).
      - A separate in-memory registry tracks who has voted to prevent
        double-voting, keyed by voter hash.
      - Candidates are validated against a predefined whitelist.
    """

    def __init__(self, candidates: Optional[list[str]] = None):
        self.blockchain = Blockchain()
        self.candidates = candidates or ["Candidate A", "Candidate B", "Candidate C"]
        # Maps voter_hash -> True (has voted)
        self._voted_registry: dict[str, bool] = {}
        self._vote_counts: dict[str, int] = {c: 0 for c in self.candidates}
        self._total_registered = 0

    # ── Voter Management ────────────────────────────────────────────────────

    def _hash_voter_id(self, voter_id: str) -> str:
        """Return anonymized SHA-256 hash of a voter's ID."""
        return hashlib.sha256(voter_id.strip().encode()).hexdigest()

    def register_voter(self, voter_id: str) -> bool:
        """
        Register a new voter.

        Args:
            voter_id: Raw voter identifier (e.g., national ID, student ID).

        Returns:
            True if registration succeeded; False if already registered.
        """
        if not voter_id or not voter_id.strip():
            raise ValueError("Voter ID cannot be empty.")

        voter_hash = self._hash_voter_id(voter_id)
        if voter_hash in self._voted_registry:
            return False  # Already registered

        self._voted_registry[voter_hash] = False  # Registered, not yet voted
        self._total_registered += 1
        return True

    # ── Voting ───────────────────────────────────────────────────────────────

    def cast_vote(self, voter_id: str, candidate: str) -> dict:
        """
        Record a vote on the blockchain.

        Args:
            voter_id:  Raw voter identifier.
            candidate: Selected candidate name.

        Returns:
            Result dictionary with status and block hash.

        Raises:
            ValueError: For invalid voter ID or candidate.
        """
        if not voter_id or not voter_id.strip():
            raise ValueError("Voter ID cannot be empty.")

        candidate = candidate.strip()
        if candidate not in self.candidates:
            raise ValueError(
                f"Invalid candidate '{candidate}'. "
                f"Valid options: {self.candidates}"
            )

        voter_hash = self._hash_voter_id(voter_id)

        # Check registration
        if voter_hash not in self._voted_registry:
            return {"status": "error", "message": "Voter not registered."}

        # Prevent double-voting
        if self._voted_registry[voter_hash]:
            return {"status": "error", "message": "This voter has already voted."}

        # Record vote on blockchain (store only anonymized hash)
        vote_payload = {
            "type": "VOTE",
            "voter_hash": voter_hash[:16] + "...",  # Partial hash in ledger
            "candidate": candidate,
            "timestamp": time.time(),
        }
        block = self.blockchain.add_block(vote_payload)

        # Mark voter as having voted
        self._voted_registry[voter_hash] = True
        self._vote_counts[candidate] += 1

        return {
            "status": "success",
            "message": f"Vote for '{candidate}' recorded.",
            "block_index": block.index,
            "block_hash": block.hash,
        }

    # ── Results & Verification ────────────────────────────────────────────────

    def get_results(self) -> dict:
        """
        Tally and return verified election results.

        Returns:
            Dictionary with results, winner, and chain validity status.
        """
        total_votes = sum(self._vote_counts.values())
        winner = max(self._vote_counts, key=self._vote_counts.get) if total_votes > 0 else None
        chain_valid = self.blockchain.is_chain_valid()

        return {
            "chain_valid": chain_valid,
            "total_registered": self._total_registered,
            "total_votes": total_votes,
            "turnout_pct": round((total_votes / self._total_registered * 100), 2)
            if self._total_registered > 0 else 0.0,
            "results": self._vote_counts.copy(),
            "winner": winner,
            "chain_length": len(self.blockchain),
        }

    def print_results(self) -> None:
        """Pretty-print election results to stdout."""
        res = self.get_results()
        print("\n" + "=" * 50)
        print("       ELECTION RESULTS — BLOCKCHAIN VERIFIED")
        print("=" * 50)
        print(f"  Chain Integrity : {'[VALID]' if res['chain_valid'] else '[TAMPERED!]'}")
        print(f"  Total Registered: {res['total_registered']}")
        print(f"  Total Votes Cast: {res['total_votes']}")
        print(f"  Voter Turnout   : {res['turnout_pct']}%")
        print("-" * 50)
        for candidate, votes in sorted(
            res["results"].items(), key=lambda x: x[1], reverse=True
        ):
            bar = "|" * votes
            pct = round(votes / res["total_votes"] * 100, 1) if res["total_votes"] > 0 else 0
            print(f"  {candidate:<20} {bar:<20} {votes} votes ({pct}%)")
        print("-" * 50)
        if res["winner"]:
            print(f"  [WINNER] {res['winner']}")
        print("=" * 50)
