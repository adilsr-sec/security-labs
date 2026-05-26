"""
Unit Tests — Secured Voting Machine (Blockchain)
==================================================
Tests cover:
  - Block creation and hash computation
  - Proof-of-Work mining difficulty
  - Chain integrity validation
  - Tamper detection
  - Voter registration and duplicate prevention
  - Vote casting and double-vote prevention
  - Results tallying and winner determination
"""

import pytest
import time
from blockchain import Block, Blockchain, VotingSystem


# ─────────────────────────────────────────────────────────────────────────────
# Block Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBlock:
    def test_block_creation(self):
        """Block initializes with correct fields."""
        block = Block(index=1, data={"test": "data"}, previous_hash="abc123")
        assert block.index == 1
        assert block.data == {"test": "data"}
        assert block.previous_hash == "abc123"
        assert block.nonce == 0
        assert len(block.hash) == 64  # SHA-256 is always 64 hex chars

    def test_hash_is_deterministic(self):
        """Same block content produces the same hash when recomputed."""
        block = Block(index=0, data={"vote": "A"}, previous_hash="0" * 64)
        original_hash = block.hash
        recomputed = block._compute_hash()
        assert original_hash == recomputed

    def test_data_change_invalidates_hash(self):
        """Modifying block data causes hash mismatch (tamper detection basis)."""
        block = Block(index=1, data={"vote": "A"}, previous_hash="0" * 64)
        original_hash = block.hash
        block.data["vote"] = "B"  # Simulate tampering
        recomputed = block._compute_hash()
        assert original_hash != recomputed

    def test_mining_satisfies_difficulty(self):
        """Mined block hash starts with the correct number of leading zeros."""
        difficulty = 2
        block = Block(index=1, data={"test": True}, previous_hash="0" * 64)
        block.mine_block(difficulty)
        assert block.hash.startswith("0" * difficulty)

    def test_to_dict_contains_required_fields(self):
        """Block serialization includes all required fields."""
        block = Block(index=1, data={"candidate": "A"}, previous_hash="abc")
        d = block.to_dict()
        for key in ("index", "timestamp", "data", "previous_hash", "nonce", "hash"):
            assert key in d


# ─────────────────────────────────────────────────────────────────────────────
# Blockchain Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBlockchain:
    def setup_method(self):
        """Fresh blockchain for each test."""
        self.bc = Blockchain()

    def test_genesis_block_exists(self):
        """Chain initializes with exactly one genesis block."""
        assert len(self.bc) == 1
        assert self.bc.chain[0].index == 0
        assert self.bc.chain[0].previous_hash == "0" * 64

    def test_genesis_block_mines_correctly(self):
        """Genesis block satisfies Proof-of-Work difficulty."""
        assert self.bc.chain[0].hash.startswith("0" * Blockchain.DIFFICULTY)

    def test_add_block_increases_chain_length(self):
        """Adding a block increments chain length."""
        self.bc.add_block({"vote": "A"})
        assert len(self.bc) == 2

    def test_added_block_links_to_previous(self):
        """New block's previous_hash equals the last block's hash."""
        self.bc.add_block({"vote": "A"})
        assert self.bc.chain[1].previous_hash == self.bc.chain[0].hash

    def test_chain_valid_after_multiple_blocks(self):
        """Chain remains valid after adding several blocks."""
        for i in range(3):
            self.bc.add_block({"vote": str(i)})
        assert self.bc.is_chain_valid() is True

    def test_tampered_data_detected(self):
        """Chain validation fails if a block's data is mutated."""
        self.bc.add_block({"vote": "A"})
        self.bc.chain[1].data["vote"] = "B"  # Tamper!
        assert self.bc.is_chain_valid() is False

    def test_tampered_hash_detected(self):
        """Chain validation fails if a block's stored hash is modified."""
        self.bc.add_block({"vote": "A"})
        self.bc.chain[1].hash = "0" * 64  # Tamper!
        assert self.bc.is_chain_valid() is False

    def test_export_chain_returns_list_of_dicts(self):
        """export_chain returns a list of block dictionaries."""
        self.bc.add_block({"test": True})
        exported = self.bc.export_chain()
        assert isinstance(exported, list)
        assert len(exported) == 2
        assert isinstance(exported[0], dict)


# ─────────────────────────────────────────────────────────────────────────────
# VotingSystem Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVotingSystem:
    def setup_method(self):
        """Fresh voting system with default candidates."""
        self.vs = VotingSystem(candidates=["Alpha", "Beta", "Gamma"])

    def test_voter_registration_succeeds(self):
        """New voter is registered successfully."""
        assert self.vs.register_voter("voter_001") is True

    def test_duplicate_voter_registration_fails(self):
        """Registering the same voter twice returns False."""
        self.vs.register_voter("voter_001")
        assert self.vs.register_voter("voter_001") is False

    def test_empty_voter_id_raises(self):
        """Empty voter ID raises ValueError."""
        with pytest.raises(ValueError):
            self.vs.register_voter("")

    def test_cast_vote_success(self):
        """Registered voter can cast one vote successfully."""
        self.vs.register_voter("voter_001")
        result = self.vs.cast_vote("voter_001", "Alpha")
        assert result["status"] == "success"
        assert "block_index" in result

    def test_double_vote_prevented(self):
        """Same voter cannot vote twice."""
        self.vs.register_voter("voter_001")
        self.vs.cast_vote("voter_001", "Alpha")
        result = self.vs.cast_vote("voter_001", "Beta")
        assert result["status"] == "error"
        assert "already voted" in result["message"].lower()

    def test_unregistered_voter_rejected(self):
        """Unregistered voter is rejected at vote time."""
        result = self.vs.cast_vote("voter_ghost", "Alpha")
        assert result["status"] == "error"

    def test_invalid_candidate_raises(self):
        """Vote for non-existent candidate raises ValueError."""
        self.vs.register_voter("voter_001")
        with pytest.raises(ValueError, match="Invalid candidate"):
            self.vs.cast_vote("voter_001", "Unknown Party")

    def test_results_count_votes_correctly(self):
        """Vote counts match actual votes cast."""
        for i in range(4):
            self.vs.register_voter(f"voter_{i:03d}")
        self.vs.cast_vote("voter_000", "Alpha")
        self.vs.cast_vote("voter_001", "Alpha")
        self.vs.cast_vote("voter_002", "Beta")
        self.vs.cast_vote("voter_003", "Gamma")

        results = self.vs.get_results()
        assert results["results"]["Alpha"] == 2
        assert results["results"]["Beta"] == 1
        assert results["results"]["Gamma"] == 1
        assert results["total_votes"] == 4
        assert results["winner"] == "Alpha"

    def test_chain_valid_after_voting(self):
        """Blockchain remains valid after a full voting session."""
        for i in range(3):
            self.vs.register_voter(f"voter_{i}")
            self.vs.cast_vote(f"voter_{i}", self.vs.candidates[i % 3])

        results = self.vs.get_results()
        assert results["chain_valid"] is True

    def test_voter_hash_not_stored_in_ledger(self):
        """Voter's raw ID is never stored in the blockchain data."""
        self.vs.register_voter("secret_voter_ID")
        self.vs.cast_vote("secret_voter_ID", "Alpha")

        for block in self.vs.blockchain.chain:
            assert "secret_voter_ID" not in str(block.data)
