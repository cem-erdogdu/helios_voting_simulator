"""
Zero-Knowledge Proofs for Ballot Validity

This module implements non-interactive zero-knowledge proofs that
a ciphertext encrypts either 0 or 1 (a valid vote) without revealing
which value was encrypted.

The proof uses the disjunctive OR technique on Schnorr proofs of
equality of discrete logarithms.
"""

import hashlib
import secrets
from dataclasses import dataclass
from crypto import p, g, Ciphertext


@dataclass(frozen=True)
class BallotProof:
    """
    Zero-knowledge proof that a ciphertext encrypts 0 or 1.
    
    This is a disjunctive OR proof showing that either:
    - Case 0: log_g(c1) = log_y(c2)  [encrypts 0]
    - Case 1: log_g(c1) = log_y(c2/g) [encrypts 1]
    
    The proof contains commitments and responses for both cases,
    with one case being "real" and the other "simulated".
    
    Attributes:
        a0: Commitment for case 0 (g^w0, y^w0)
        a1: Commitment for case 1 (g^w1, y^w1)
        e0: Challenge for case 0
        e1: Challenge for case 1
        z0: Response for case 0
        z1: Response for case 1
    """
    a0_g: int  # First component of commitment for case 0
    a0_y: int  # Second component of commitment for case 0
    a1_g: int  # First component of commitment for case 1
    a1_y: int  # Second component of commitment for case 1
    e0: int    # Challenge for case 0
    e1: int    # Challenge for case 1
    z0: int    # Response for case 0
    z1: int    # Response for case 1
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "a0_g": str(self.a0_g),
            "a0_y": str(self.a0_y),
            "a1_g": str(self.a1_g),
            "a1_y": str(self.a1_y),
            "e0": str(self.e0),
            "e1": str(self.e1),
            "z0": str(self.z0),
            "z1": str(self.z1)
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "BallotProof":
        """Deserialize from dictionary."""
        return cls(
            a0_g=int(d["a0_g"]),
            a0_y=int(d["a0_y"]),
            a1_g=int(d["a1_g"]),
            a1_y=int(d["a1_y"]),
            e0=int(d["e0"]),
            e1=int(d["e1"]),
            z0=int(d["z0"]),
            z1=int(d["z1"])
        )


def _hash_to_challenge(*values: int) -> int:
    """
    Hash a sequence of integers to produce a challenge.
    
    This implements the Fiat-Shamir transform, making the proof
    non-interactive by deriving the challenge from the commitments.
    
    Args:
        *values: Integers to hash (commitments, public key, ciphertext, etc.)
        
    Returns:
        Challenge as an integer modulo (p-1)
    """
    # Concatenate all values as bytes
    data = b""
    for v in values:
        # Use variable-length encoding with length prefix
        v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big') if v > 0 else b'\x00'
        data += len(v_bytes).to_bytes(4, byteorder='big') + v_bytes
    
    # Hash with SHA-256
    hash_bytes = hashlib.sha256(data).digest()
    
    # Convert to integer and take modulo (p-1)
    challenge = int.from_bytes(hash_bytes, byteorder='big')
    return challenge % (p - 1)


def generate_ballot_proof(
    ciphertext: Ciphertext,
    vote: int,
    randomness: int,
    public_key: int
) -> BallotProof:
    """
    Generate a zero-knowledge proof that the ciphertext encrypts a valid vote (0 or 1).
    
    The proof shows that either:
    - Case 0: The ciphertext encrypts 0, i.e., log_g(c1) = log_y(c2)
    - Case 1: The ciphertext encrypts 1, i.e., log_g(c1) = log_y(c2/g)
    
    Without revealing which case is true.
    
    Args:
        ciphertext: The ciphertext (c1, c2) to prove valid
        vote: The actual vote value (0 or 1) - determines which case is real
        randomness: The randomness r used in encryption (c1 = g^r)
        public_key: The public key y
        
    Returns:
        BallotProof that can be verified by anyone
        
    Raises:
        ValueError: If vote is not 0 or 1
    """
    if vote not in (0, 1):
        raise ValueError("Vote must be 0 or 1 to generate a valid proof")
    
    c1, c2 = ciphertext.c1, ciphertext.c2
    r = randomness
    y = public_key
    
    # q = (p-1)/2 is the order of the subgroup
    q = (p - 1) // 2
    
    # Case 0 proves: log_g(c1) = log_y(c2)
    # Case 1 proves: log_g(c1) = log_y(c2/g)
    
    # The real case is the one matching the actual vote
    real_case = vote  # 0 or 1
    fake_case = 1 - vote  # The other case
    
    # For the fake case: pick random challenge and response, derive commitment
    e_fake = secrets.randbelow(q)
    z_fake = secrets.randbelow(q)
    
    if fake_case == 0:
        # Fake case 0: derive a0 from e_fake and z_fake
        # We need: g^z0 = a0_g * c1^e0 and y^z0 = a0_y * c2^e0
        # So: a0_g = g^z0 / c1^e0 and a0_y = y^z0 / c2^e0
        c1_e = pow(c1, e_fake, p)
        c2_e = pow(c2, e_fake, p)
        a0_g = (pow(g, z_fake, p) * pow(c1_e, p - 2, p)) % p
        a0_y = (pow(y, z_fake, p) * pow(c2_e, p - 2, p)) % p
        
        # For case 1 (real): generate commitment properly
        w1 = secrets.randbelow(q)
        a1_g = pow(g, w1, p)
        a1_y = pow(y, w1, p)
        
    else:
        # Fake case 1: derive a1 from e_fake and z_fake
        # We need: g^z1 = a1_g * c1^e1 and y^z1 = a1_y * (c2/g)^e1
        # So: a1_g = g^z1 / c1^e1 and a1_y = y^z1 / (c2/g)^e1
        c2_div_g = (c2 * pow(g, p - 2, p)) % p  # c2 / g
        c1_e = pow(c1, e_fake, p)
        c2g_e = pow(c2_div_g, e_fake, p)
        a1_g = (pow(g, z_fake, p) * pow(c1_e, p - 2, p)) % p
        a1_y = (pow(y, z_fake, p) * pow(c2g_e, p - 2, p)) % p
        
        # For case 0 (real): generate commitment properly
        w0 = secrets.randbelow(q)
        a0_g = pow(g, w0, p)
        a0_y = pow(y, w0, p)
    
    # Compute overall challenge using Fiat-Shamir
    e_total = _hash_to_challenge(c1, c2, y, a0_g, a0_y, a1_g, a1_y)
    
    # Real challenge = total - fake challenge
    if real_case == 0:
        e0 = (e_total - e_fake) % q
        e1 = e_fake
        # Compute real response: z0 = w0 + e0 * r
        z0 = (w0 + e0 * r) % q
        z1 = z_fake
    else:
        e0 = e_fake
        e1 = (e_total - e_fake) % q
        z0 = z_fake
        # Compute real response: z1 = w1 + e1 * r
        z1 = (w1 + e1 * r) % q
    
    return BallotProof(
        a0_g=a0_g, a0_y=a0_y,
        a1_g=a1_g, a1_y=a1_y,
        e0=e0, e1=e1,
        z0=z0, z1=z1
    )


def verify_ballot_proof(
    ciphertext: Ciphertext,
    proof: BallotProof,
    public_key: int
) -> bool:
    """
    Verify a zero-knowledge proof that a ciphertext encrypts a valid vote.
    
    The verification checks:
    1. For case 0: g^z0 = a0_g * c1^e0 AND y^z0 = a0_y * c2^e0
    2. For case 1: g^z1 = a1_g * c1^e1 AND y^z1 = a1_y * (c2/g)^e1
    3. e0 + e1 = hash(c1, c2, y, a0_g, a0_y, a1_g, a1_y) mod q
    
    Args:
        ciphertext: The ciphertext (c1, c2) to verify
        proof: The BallotProof to verify
        public_key: The public key y
        
    Returns:
        True if the proof is valid, False otherwise
    """
    c1, c2 = ciphertext.c1, ciphertext.c2
    y = public_key
    q = (p - 1) // 2
    
    # Recompute total challenge
    e_total_expected = _hash_to_challenge(c1, c2, y, proof.a0_g, proof.a0_y, proof.a1_g, proof.a1_y)
    
    # Check that challenges sum correctly
    if (proof.e0 + proof.e1) % q != e_total_expected % q:
        return False
    
    # Verify case 0: encrypts 0, so log_g(c1) = log_y(c2)
    # Check: g^z0 = a0_g * c1^e0
    lhs_0g = pow(g, proof.z0, p)
    rhs_0g = (proof.a0_g * pow(c1, proof.e0, p)) % p
    if lhs_0g != rhs_0g:
        return False
    
    # Check: y^z0 = a0_y * c2^e0
    lhs_0y = pow(y, proof.z0, p)
    rhs_0y = (proof.a0_y * pow(c2, proof.e0, p)) % p
    if lhs_0y != rhs_0y:
        return False
    
    # Verify case 1: encrypts 1, so log_g(c1) = log_y(c2/g)
    c2_div_g = (c2 * pow(g, p - 2, p)) % p
    
    # Check: g^z1 = a1_g * c1^e1
    lhs_1g = pow(g, proof.z1, p)
    rhs_1g = (proof.a1_g * pow(c1, proof.e1, p)) % p
    if lhs_1g != rhs_1g:
        return False
    
    # Check: y^z1 = a1_y * (c2/g)^e1
    lhs_1y = pow(y, proof.z1, p)
    rhs_1y = (proof.a1_y * pow(c2_div_g, proof.e1, p)) % p
    if lhs_1y != rhs_1y:
        return False
    
    return True


def encrypt_with_proof(vote: int, public_key: int) -> tuple[Ciphertext, BallotProof, int]:
    """
    Encrypt a vote and generate a validity proof.
    
    Args:
        vote: The vote value (0 or 1)
        public_key: The public key to encrypt under
        
    Returns:
        Tuple of (ciphertext, proof, randomness_used)
    """
    from crypto import encrypt
    
    if vote not in (0, 1):
        raise ValueError("Vote must be 0 or 1")
    
    # Generate randomness
    q = (p - 1) // 2
    r = secrets.randbelow(q)
    
    # Create ciphertext manually to capture randomness
    c1 = pow(g, r, p)
    m = 1 if vote == 0 else g
    c2 = (pow(public_key, r, p) * m) % p
    ciphertext = Ciphertext(c1=c1, c2=c2)
    
    # Generate proof
    proof = generate_ballot_proof(ciphertext, vote, r, public_key)
    
    return ciphertext, proof, r
