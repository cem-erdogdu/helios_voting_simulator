"""
Bulletin Board for Cryptographic Voting

The bulletin board is the single source of truth for the election.
It stores all posted ballots with their zero-knowledge proofs,
validates proofs, prevents duplicate voting, and produces the
homomorphic combination for tallying.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional
from crypto import Ciphertext, combine_many_ciphertexts, p, g
from zkp import BallotProof, verify_ballot_proof
from voter_registry import VoterRegistry


@dataclass(frozen=True)
class BallotEntry:
    """
    A single entry on the bulletin board.
    
    Attributes:
        voter_id: Unique identifier for the voter
        ciphertext: The encrypted ballot
        proof: Zero-knowledge proof of ballot validity
        receipt: Unique receipt for individual verifiability
    """
    voter_id: str
    ciphertext: Ciphertext
    proof: BallotProof
    receipt: str
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "voter_id": self.voter_id,
            "ciphertext": self.ciphertext.to_dict(),
            "proof": self.proof.to_dict(),
            "receipt": self.receipt
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "BallotEntry":
        """Deserialize from dictionary."""
        return cls(
            voter_id=d["voter_id"],
            ciphertext=Ciphertext.from_dict(d["ciphertext"]),
            proof=BallotProof.from_dict(d["proof"]),
            receipt=d["receipt"]
        )


@dataclass(frozen=True)
class BallotReceipt:
    """
    Receipt given to a voter after casting their ballot.
    
    This receipt allows the voter to verify their ballot was
    counted in the final tally without revealing their vote.
    
    Attributes:
        receipt_id: Unique identifier for this ballot
        voter_id: The voter who cast the ballot
        timestamp: Receipt timestamp (for ordering)
    """
    receipt_id: str
    voter_id: str
    timestamp: str
    
    def to_verification_string(self) -> str:
        """Convert receipt to a string for verification."""
        return f"{self.receipt_id}:{self.voter_id}:{self.timestamp}"
    
    @classmethod
    def from_verification_string(cls, s: str) -> "BallotReceipt":
        """Parse a receipt from a verification string."""
        parts = s.split(":")
        return cls(
            receipt_id=parts[0],
            voter_id=parts[1],
            timestamp=parts[2]
        )


@dataclass
class BulletinBoard:
    """
    Public bulletin board for the election.
    
    The board stores all valid ballots and provides:
    - Voter registration verification (voter must be registered)
    - Proof validation on submission
    - Duplicate voter detection
    - Homomorphic combination of all ballots
    - Full election verification
    - Individual verifiability via ballot receipts
    
    Attributes:
        public_key: The election public key (for proof verification)
        entries: List of accepted ballot entries
        _voter_ids: Set of voter IDs who have already voted
        _receipts: Dictionary mapping receipt_id to entry index
        registry: Optional voter registry for authentication
    """
    public_key: int
    entries: list[BallotEntry] = field(default_factory=list)
    _voter_ids: set[str] = field(default_factory=set)
    _receipts: dict[str, int] = field(default_factory=dict)
    registry: Optional[VoterRegistry] = None
    
    def set_registry(self, registry: VoterRegistry) -> None:
        """
        Set the voter registry for authentication.
        
        Args:
            registry: The voter registry to use
        """
        self.registry = registry
    
    def _generate_receipt(self, ciphertext: Ciphertext, proof: BallotProof) -> str:
        """
        Compute a deterministic receipt tied to ballot contents.

        The receipt is a fingerprint of the posted ciphertext and proof,
        allowing auditors to detect any post-submission ballot tampering.

        Args:
            ciphertext: The ballot ciphertext
            proof: The ballot validity proof

        Returns:
            32-hex-character ballot fingerprint
        """
        components = [
            ciphertext.c1,
            ciphertext.c2,
            proof.a0_g,
            proof.a0_y,
            proof.a1_g,
            proof.a1_y,
            proof.e0,
            proof.e1,
            proof.z0,
            proof.z1,
        ]
        data = ":".join(str(component) for component in components)
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def post_ballot(
        self,
        voter_id: str,
        ciphertext: Ciphertext,
        proof: BallotProof
    ) -> tuple[bool, str, Optional[str]]:
        """
        Post a ballot to the bulletin board.
        
        The ballot is only accepted if:
        1. The voter is registered (if registry is set)
        2. The voter hasn't voted before (no duplicates)
        3. The ZK proof is valid
        
        Args:
            voter_id: Unique identifier for the voter
            ciphertext: The encrypted ballot
            proof: ZK proof of ballot validity
            
        Returns:
            Tuple of (success: bool, message: str, receipt: Optional[str])
        """
        voter_id = voter_id.strip().lower()
        
        # Check if voter is registered (if registry is set)
        if self.registry is not None:
            if not self.registry.is_registered(voter_id):
                return False, f"Voter '{voter_id}' is not registered", None
        
        # Check for duplicate voter
        if voter_id in self._voter_ids:
            return False, f"Voter '{voter_id}' has already cast a ballot", None
        
        # Verify the ZK proof
        if not verify_ballot_proof(ciphertext, proof, self.public_key):
            return False, f"Invalid ZK proof for voter '{voter_id}'", None
        
        # Derive receipt from ballot content so later audits can recompute it.
        receipt = self._generate_receipt(ciphertext, proof)
        
        # Accept the ballot
        entry = BallotEntry(
            voter_id=voter_id,
            ciphertext=ciphertext,
            proof=proof,
            receipt=receipt
        )
        entry_index = len(self.entries)
        self.entries.append(entry)
        self._voter_ids.add(voter_id)
        self._receipts[receipt] = entry_index
        
        return True, f"Ballot from '{voter_id}' accepted", receipt
    
    def verify_ballot_by_receipt(self, receipt: str) -> tuple[bool, str]:
        """
        Verify that a ballot with the given receipt was counted.
        
        This provides individual verifiability - voters can check
        that their ballot was included in the final tally.
        
        Args:
            receipt: The receipt string provided when the ballot was cast
            
        Returns:
            Tuple of (found: bool, message: str)
        """
        if receipt in self._receipts:
            entry_index = self._receipts[receipt]
            entry = self.entries[entry_index]
            return True, (
                f"✓ Ballot verified on bulletin board\n"
                f"  Voter: {entry.voter_id}\n"
                f"  Position: {entry_index + 1} of {len(self.entries)}\n"
                f"  Receipt: {receipt}"
            )
        return False, "✗ Receipt not found - ballot may not have been counted"
    
    def get_ballot_by_receipt(self, receipt: str) -> Optional[BallotEntry]:
        """
        Get a ballot entry by its receipt.
        
        Args:
            receipt: The receipt string
            
        Returns:
            The BallotEntry if found, None otherwise
        """
        if receipt in self._receipts:
            return self.entries[self._receipts[receipt]]
        return None
    
    def get_combined_ciphertext(self) -> Optional[Ciphertext]:
        """
        Produce the homomorphic combination of all accepted ballots.
        
        Returns:
            Combined ciphertext, or None if no ballots have been posted
        """
        if not self.entries:
            return None
        
        ciphertexts = [entry.ciphertext for entry in self.entries]
        return combine_many_ciphertexts(ciphertexts)
    
    def verify_election(self) -> tuple[bool, str]:
        """
        Verify the integrity of the entire election.
        
        Checks:
        1. All entries have valid ZK proofs
        2. The combined ciphertext matches the product of individual ballots
        3. No duplicate voters
        4. All voters are registered (if registry is set)
        
        Returns:
            Tuple of (is_valid: bool, report: str)
        """
        if not self.entries:
            return False, "No ballots posted"
        
        report_lines = ["Election Verification Report", "=" * 40]
        
        # Check 1: Verify all voters are registered (if registry is set)
        if self.registry is not None:
            unregistered = []
            for entry in self.entries:
                if not self.registry.is_registered(entry.voter_id):
                    unregistered.append(entry.voter_id)
            
            if unregistered:
                report_lines.append(f"✗ FAILED: Unregistered voters found: {', '.join(unregistered)}")
                return False, "\n".join(report_lines)
            
            report_lines.append(f"✓ All {len(self.entries)} voters are registered")
        
        # Check 2: Verify all proofs
        invalid_proofs = []
        for entry in self.entries:
            if not verify_ballot_proof(entry.ciphertext, entry.proof, self.public_key):
                invalid_proofs.append(entry.voter_id)
        
        if invalid_proofs:
            report_lines.append(f"✗ FAILED: Invalid proofs found for: {', '.join(invalid_proofs)}")
            return False, "\n".join(report_lines)
        
        report_lines.append(f"✓ All {len(self.entries)} ballots have valid proofs")
        
        # Check 3: Verify no duplicate voters
        voter_ids = [entry.voter_id for entry in self.entries]
        if len(voter_ids) != len(set(voter_ids)):
            report_lines.append("✗ FAILED: Duplicate voters detected")
            return False, "\n".join(report_lines)
        
        report_lines.append("✓ No duplicate voters")
        
        # Check 4: Verify combined ciphertext integrity
        combined = self.get_combined_ciphertext()
        
        # Recompute the combination manually to verify
        manual_combined = self.entries[0].ciphertext
        for entry in self.entries[1:]:
            manual_combined = Ciphertext(
                c1=(manual_combined.c1 * entry.ciphertext.c1) % p,
                c2=(manual_combined.c2 * entry.ciphertext.c2) % p
            )
        
        if combined.c1 != manual_combined.c1 or combined.c2 != manual_combined.c2:
            report_lines.append("✗ FAILED: Combined ciphertext mismatch")
            return False, "\n".join(report_lines)
        
        report_lines.append("✓ Combined ciphertext integrity verified")
        report_lines.append("=" * 40)
        report_lines.append("Election is VALID")
        
        return True, "\n".join(report_lines)
    
    def get_voter_count(self) -> int:
        """Return the number of ballots posted."""
        return len(self.entries)
    
    def get_entries(self) -> list[BallotEntry]:
        """Return a copy of all entries (for audit)."""
        return list(self.entries)
    
    def has_voted(self, voter_id: str) -> bool:
        """Check if a voter has already cast a ballot."""
        return voter_id.strip().lower() in self._voter_ids
    
    def get_receipts(self) -> list[str]:
        """Get all receipt IDs (for public audit)."""
        return list(self._receipts.keys())
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "public_key": str(self.public_key),
            "entries": [entry.to_dict() for entry in self.entries],
            "voter_ids": list(self._voter_ids),
            "receipts": self._receipts
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "BulletinBoard":
        """Deserialize from dictionary."""
        board = cls(public_key=int(d["public_key"]))
        for entry_data in d.get("entries", []):
            entry = BallotEntry.from_dict(entry_data)
            board.entries.append(entry)
        board._voter_ids = set(d.get("voter_ids", []))
        board._receipts = d.get("receipts", {})
        return board


def create_board(public_key: int, registry: Optional[VoterRegistry] = None) -> BulletinBoard:
    """
    Create a new bulletin board for an election.
    
    Args:
        public_key: The election public key
        registry: Optional voter registry for authentication
        
    Returns:
        New BulletinBoard instance
    """
    board = BulletinBoard(public_key=public_key)
    if registry is not None:
        board.set_registry(registry)
    return board
