"""
Bulletin Board for Cryptographic Voting

The bulletin board is the single source of truth for the election.
It stores all posted ballots with their zero-knowledge proofs,
validates proofs, prevents duplicate voting, and produces the
homomorphic combination for tallying.
"""

from dataclasses import dataclass, field
from typing import Optional
from crypto import Ciphertext, combine_many_ciphertexts, p, g
from zkp import BallotProof, verify_ballot_proof


@dataclass(frozen=True)
class BallotEntry:
    """
    A single entry on the bulletin board.
    
    Attributes:
        voter_id: Unique identifier for the voter
        ciphertext: The encrypted ballot
        proof: Zero-knowledge proof of ballot validity
    """
    voter_id: str
    ciphertext: Ciphertext
    proof: BallotProof


@dataclass
class BulletinBoard:
    """
    Public bulletin board for the election.
    
    The board stores all valid ballots and provides:
    - Proof validation on submission
    - Duplicate voter detection
    - Homomorphic combination of all ballots
    - Full election verification
    
    Attributes:
        public_key: The election public key (for proof verification)
        entries: List of accepted ballot entries
        _voter_ids: Set of voter IDs who have already voted
    """
    public_key: int
    entries: list[BallotEntry] = field(default_factory=list)
    _voter_ids: set[str] = field(default_factory=set)
    
    def post_ballot(
        self,
        voter_id: str,
        ciphertext: Ciphertext,
        proof: BallotProof
    ) -> tuple[bool, str]:
        """
        Post a ballot to the bulletin board.
        
        The ballot is only accepted if:
        1. The voter hasn't voted before (no duplicates)
        2. The ZK proof is valid
        
        Args:
            voter_id: Unique identifier for the voter
            ciphertext: The encrypted ballot
            proof: ZK proof of ballot validity
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Check for duplicate voter
        if voter_id in self._voter_ids:
            return False, f"Voter '{voter_id}' has already cast a ballot"
        
        # Verify the ZK proof
        if not verify_ballot_proof(ciphertext, proof, self.public_key):
            return False, f"Invalid ZK proof for voter '{voter_id}'"
        
        # Accept the ballot
        entry = BallotEntry(voter_id=voter_id, ciphertext=ciphertext, proof=proof)
        self.entries.append(entry)
        self._voter_ids.add(voter_id)
        
        return True, f"Ballot from '{voter_id}' accepted"
    
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
        
        Returns:
            Tuple of (is_valid: bool, report: str)
        """
        if not self.entries:
            return False, "No ballots posted"
        
        report_lines = ["Election Verification Report", "=" * 40]
        
        # Check 1: Verify all proofs
        invalid_proofs = []
        for entry in self.entries:
            if not verify_ballot_proof(entry.ciphertext, entry.proof, self.public_key):
                invalid_proofs.append(entry.voter_id)
        
        if invalid_proofs:
            report_lines.append(f"✗ FAILED: Invalid proofs found for: {', '.join(invalid_proofs)}")
            return False, "\n".join(report_lines)
        
        report_lines.append(f"✓ All {len(self.entries)} ballots have valid proofs")
        
        # Check 2: Verify no duplicate voters
        voter_ids = [entry.voter_id for entry in self.entries]
        if len(voter_ids) != len(set(voter_ids)):
            report_lines.append("✗ FAILED: Duplicate voters detected")
            return False, "\n".join(report_lines)
        
        report_lines.append("✓ No duplicate voters")
        
        # Check 3: Verify combined ciphertext integrity
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
        return voter_id in self._voter_ids


def create_board(public_key: int) -> BulletinBoard:
    """
    Create a new bulletin board for an election.
    
    Args:
        public_key: The election public key
        
    Returns:
        New BulletinBoard instance
    """
    return BulletinBoard(public_key=public_key)
