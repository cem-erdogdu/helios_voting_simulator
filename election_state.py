"""
Election State Manager

This module handles saving and loading the full election state
to/from JSON files for persistence.
"""

import json
import os
from typing import Optional
from dataclasses import dataclass, field

from crypto import Keypair, Ciphertext, p, g
from voter_registry import VoterRegistry
from bulletin_board import BulletinBoard
from trustees import Trustee


# Default filename for election state
DEFAULT_ELECTION_FILE = "election.json"


@dataclass
class ElectionState:
    """
    Complete state of an election for serialization.
    
    Attributes:
        election_name: Name of the election
        keypair: The election keypair (contains private key)
        registry: Voter registry with registered voters
        board: Bulletin board with all ballots
        trustees: List of trustees
        threshold: Number of trustees needed for decryption
        num_trustees: Total number of trustees
        voter_receipts: Map of voter_id to receipt (for convenience)
    """
    election_name: str = "Election"
    keypair: Optional[Keypair] = None
    registry: Optional[VoterRegistry] = None
    board: Optional[BulletinBoard] = None
    trustees: list[Trustee] = field(default_factory=list)
    threshold: int = 3
    num_trustees: int = 5
    voter_receipts: dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize the entire election state to a dictionary."""
        return {
            "election_name": self.election_name,
            "keypair": self.keypair.to_dict() if self.keypair else None,
            "registry": self.registry.to_dict() if self.registry else None,
            "board": self.board.to_dict() if self.board else None,
            "trustees": [t.to_dict() for t in self.trustees],
            "threshold": self.threshold,
            "num_trustees": self.num_trustees,
            "voter_receipts": self.voter_receipts,
            "public_params": {
                "p": str(p),
                "g": str(g)
            }
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "ElectionState":
        """Deserialize election state from a dictionary."""
        state = cls()
        state.election_name = d.get("election_name", "Election")
        
        if d.get("keypair"):
            state.keypair = Keypair.from_dict(d["keypair"])
        
        if d.get("registry"):
            state.registry = VoterRegistry.from_dict(d["registry"])
        
        if d.get("board"):
            state.board = BulletinBoard.from_dict(d["board"])
            # Re-link registry if both exist
            if state.registry:
                state.board.set_registry(state.registry)
        
        state.trustees = [Trustee.from_dict(t) for t in d.get("trustees", [])]
        state.threshold = d.get("threshold", 3)
        state.num_trustees = d.get("num_trustees", 5)
        state.voter_receipts = d.get("voter_receipts", {})
        
        return state
    
    def save(self, filepath: str = DEFAULT_ELECTION_FILE) -> bool:
        """
        Save the election state to a JSON file.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            with open(filepath, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving election state: {e}")
            return False
    
    @classmethod
    def load(cls, filepath: str = DEFAULT_ELECTION_FILE) -> Optional["ElectionState"]:
        """
        Load the election state from a JSON file.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            ElectionState if loaded successfully, None otherwise
        """
        try:
            if not os.path.exists(filepath):
                return None
            with open(filepath, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            print(f"Error loading election state: {e}")
            return None
    
    def is_setup(self) -> bool:
        """Check if the election has been set up."""
        return (self.keypair is not None and 
                self.registry is not None and 
                self.board is not None)
    
    def get_stats(self) -> dict:
        """Get election statistics."""
        return {
            "election_name": self.election_name,
            "registered_voters": self.registry.get_voter_count() if self.registry else 0,
            "ballots_cast": self.board.get_voter_count() if self.board else 0,
            "trustees": len(self.trustees),
            "threshold": self.threshold
        }


def save_election(state: ElectionState, filepath: str = DEFAULT_ELECTION_FILE) -> bool:
    """
    Convenience function to save election state.
    
    Args:
        state: The election state to save
        filepath: Path to the JSON file
        
    Returns:
        True if saved successfully, False otherwise
    """
    return state.save(filepath)


def load_election(filepath: str = DEFAULT_ELECTION_FILE) -> Optional[ElectionState]:
    """
    Convenience function to load election state.
    
    Args:
        filepath: Path to the JSON file
        
    Returns:
        ElectionState if loaded successfully, None otherwise
    """
    return ElectionState.load(filepath)


def election_exists(filepath: str = DEFAULT_ELECTION_FILE) -> bool:
    """Check if an election file exists."""
    return os.path.exists(filepath)
