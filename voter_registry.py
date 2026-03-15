"""
Voter Registry with PIN Authentication

This module implements a voter registration system where voters must
register with a unique ID and PIN before they can vote. The PIN is
securely hashed using PBKDF2 for storage.
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional


# Constants for PIN hashing
SALT_LENGTH = 32  # bytes
ITERATIONS = 100000  # PBKDF2 iterations


@dataclass
class RegisteredVoter:
    """
    A registered voter with secure PIN storage.
    
    Attributes:
        voter_id: Unique identifier for the voter
        salt: Random salt for PIN hashing
        pin_hash: Hash of the PIN with salt
    """
    voter_id: str
    salt: bytes
    pin_hash: bytes
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "voter_id": self.voter_id,
            "salt": self.salt.hex(),
            "pin_hash": self.pin_hash.hex()
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "RegisteredVoter":
        """Deserialize from dictionary."""
        return cls(
            voter_id=d["voter_id"],
            salt=bytes.fromhex(d["salt"]),
            pin_hash=bytes.fromhex(d["pin_hash"])
        )


@dataclass
class VoterRegistry:
    """
    Registry of eligible voters with PIN authentication.
    
    The registry stores registered voters and their hashed PINs.
    Only registered voters can cast ballots on the bulletin board.
    
    Attributes:
        _voters: Dictionary mapping voter_id to RegisteredVoter
    """
    _voters: dict[str, RegisteredVoter] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "voters": {k: v.to_dict() for k, v in self._voters.items()}
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "VoterRegistry":
        """Deserialize from dictionary."""
        registry = cls()
        for voter_id, voter_data in d.get("voters", {}).items():
            registry._voters[voter_id] = RegisteredVoter.from_dict(voter_data)
        return registry
    
    def _hash_pin(self, pin: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """
        Hash a PIN using PBKDF2 with a random salt.
        
        Args:
            pin: The PIN to hash (4-6 digit string)
            salt: Optional salt (if None, generates new salt)
            
        Returns:
            Tuple of (salt, hash)
        """
        if salt is None:
            salt = secrets.token_bytes(SALT_LENGTH)
        
        pin_hash = hashlib.pbkdf2_hmac(
            'sha256',
            pin.encode('utf-8'),
            salt,
            ITERATIONS
        )
        return salt, pin_hash
    
    def _verify_pin(self, voter: RegisteredVoter, pin: str) -> bool:
        """
        Verify a PIN against the stored hash.
        
        Args:
            voter: The registered voter to check against
            pin: The PIN to verify
            
        Returns:
            True if PIN matches, False otherwise
        """
        _, pin_hash = self._hash_pin(pin, voter.salt)
        return secrets.compare_digest(pin_hash, voter.pin_hash)
    
    def register_voter(self, voter_id: str, pin: str) -> tuple[bool, str]:
        """
        Register a new voter with a PIN.
        
        Args:
            voter_id: Unique identifier for the voter
            pin: The voter's PIN (4-6 digit string)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Validate voter_id
        voter_id = voter_id.strip().lower()
        if not voter_id:
            return False, "Voter ID cannot be empty"
        
        if len(voter_id) < 3:
            return False, "Voter ID must be at least 3 characters"
        
        # Check if already registered
        if voter_id in self._voters:
            return False, f"Voter '{voter_id}' is already registered"
        
        # Validate PIN
        if not pin.isdigit():
            return False, "PIN must contain only digits"
        
        if len(pin) < 4 or len(pin) > 6:
            return False, "PIN must be 4-6 digits"
        
        # Hash PIN and store
        salt, pin_hash = self._hash_pin(pin)
        voter = RegisteredVoter(
            voter_id=voter_id,
            salt=salt,
            pin_hash=pin_hash
        )
        self._voters[voter_id] = voter
        
        return True, f"Voter '{voter_id}' registered successfully"
    
    def authenticate_voter(self, voter_id: str, pin: str) -> tuple[bool, str]:
        """
        Authenticate a voter with their PIN.
        
        Args:
            voter_id: The voter's ID
            pin: The voter's PIN
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        voter_id = voter_id.strip().lower()
        
        if voter_id not in self._voters:
            return False, "Invalid voter ID or PIN"
        
        voter = self._voters[voter_id]
        
        if not self._verify_pin(voter, pin):
            return False, "Invalid voter ID or PIN"
        
        return True, f"Voter '{voter_id}' authenticated successfully"
    
    def is_registered(self, voter_id: str) -> bool:
        """
        Check if a voter is registered.
        
        Args:
            voter_id: The voter ID to check
            
        Returns:
            True if registered, False otherwise
        """
        return voter_id.strip().lower() in self._voters
    
    def get_registered_voters(self) -> list[str]:
        """
        Get a list of all registered voter IDs.
        
        Returns:
            List of voter IDs
        """
        return list(self._voters.keys())
    
    def get_voter_count(self) -> int:
        """
        Get the number of registered voters.
        
        Returns:
            Number of registered voters
        """
        return len(self._voters)
    
    def remove_voter(self, voter_id: str) -> tuple[bool, str]:
        """
        Remove a voter from the registry (admin function).
        
        Args:
            voter_id: The voter ID to remove
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        voter_id = voter_id.strip().lower()
        
        if voter_id not in self._voters:
            return False, f"Voter '{voter_id}' is not registered"
        
        del self._voters[voter_id]
        return True, f"Voter '{voter_id}' removed from registry"


def create_registry() -> VoterRegistry:
    """
    Create a new empty voter registry.
    
    Returns:
        New VoterRegistry instance
    """
    return VoterRegistry()
