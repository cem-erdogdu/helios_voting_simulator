"""
Trustee Key Sharing using Shamir's Secret Sharing.

This module implements threshold cryptography for the voting system.
The private key is split into n shares such that any t shares can
reconstruct the secret or produce a decryption, but fewer than t
shares reveal nothing about the secret.
"""

import secrets
from dataclasses import dataclass
from crypto import p, g, Ciphertext


@dataclass(frozen=True)
class Share:
    """
    A share of the secret held by a single trustee.
    
    Attributes:
        index: The trustee's index (1-based, used as x-coordinate in polynomial)
        value: The share value f(index) where f is the secret polynomial
    """
    index: int
    value: int
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "index": self.index,
            "value": str(self.value)
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "Share":
        """Deserialize from dictionary."""
        return cls(index=d["index"], value=int(d["value"]))


@dataclass(frozen=True)
class PartialDecryption:
    """
    A partial decryption produced by a single trustee.
    
    Each trustee computes c1^{share} mod p, which contributes to
    reconstructing c1^{private_key} for full decryption.
    
    Attributes:
        trustee_index: The index of the trustee who produced this
        value: c1^{share_value} mod p
    """
    trustee_index: int
    value: int
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "trustee_index": self.trustee_index,
            "value": str(self.value)
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "PartialDecryption":
        """Deserialize from dictionary."""
        return cls(trustee_index=d["trustee_index"], value=int(d["value"]))


def _mod_inverse(a: int, mod: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        if b == 0:
            return a, 1, 0
        g, x1, y1 = extended_gcd(b, a % b)
        return g, y1, x1 - (a // b) * y1
    
    _, x, _ = extended_gcd(a % mod, mod)
    return (x % mod + mod) % mod


def split_secret(secret: int, threshold: int, num_shares: int, prime: int) -> list[Share]:
    """
    Split a secret into n shares using Shamir's Secret Sharing.
    
    Creates a random polynomial of degree (threshold-1) with the secret
    as the constant term. Evaluates this polynomial at n distinct points
    to generate shares. Any threshold shares can reconstruct the secret.
    
    Args:
        secret: The secret integer to split (the private key)
        threshold: Minimum number of shares needed to reconstruct (t)
        num_shares: Total number of shares to generate (n)
        prime: Prime modulus for field arithmetic (the subgroup order q)
        
    Returns:
        List of n Share objects, one for each trustee
        
    Raises:
        ValueError: If threshold > num_shares or threshold < 2
    """
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed number of shares")
    if not 0 <= secret < prime:
        raise ValueError(f"Secret must be in range [0, {prime})")
    
    # Generate random coefficients for polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    coefficients = [secret]  # a_0 = secret
    for _ in range(threshold - 1):
        coeff = secrets.randbelow(prime)
        coefficients.append(coeff)
    
    # Evaluate polynomial at points 1, 2, ..., n to generate shares
    shares = []
    for i in range(1, num_shares + 1):
        # Compute f(i) = sum(a_k * i^k) mod prime
        value = 0
        power = 1  # i^0 = 1
        for coeff in coefficients:
            value = (value + coeff * power) % prime
            power = (power * i) % prime
        shares.append(Share(index=i, value=value))
    
    return shares


def reconstruct_secret(shares: list[Share], prime: int) -> int:
    """
    Reconstruct the secret from any t shares using Lagrange interpolation.
    
    Uses Lagrange interpolation to evaluate the polynomial at x=0,
    which yields the constant term (the secret).
    
    Args:
        shares: List of at least threshold shares
        prime: Prime modulus for field arithmetic
        
    Returns:
        The reconstructed secret
        
    Raises:
        ValueError: If shares list is empty or contains duplicate indices
    """
    if not shares:
        raise ValueError("At least one share is required")
    
    # Check for duplicate indices
    indices = [s.index for s in shares]
    if len(indices) != len(set(indices)):
        raise ValueError("Duplicate trustee indices in shares")
    
    # Lagrange interpolation at x=0
    # secret = sum(y_i * lagrange_coefficient_i) mod prime
    # where lagrange_coefficient_i = product(j != i) [x_j / (x_j - x_i)]
    # At x=0: lagrange_coefficient_i = product(j != i) [x_j / (x_j - x_i)]
    
    secret = 0
    for i, share_i in enumerate(shares):
        # Compute Lagrange basis polynomial evaluated at 0
        numerator = 1
        denominator = 1
        
        for j, share_j in enumerate(shares):
            if i != j:
                # For x=0: term is x_j / (x_j - x_i)
                numerator = (numerator * share_j.index) % prime
                diff = (share_j.index - share_i.index) % prime
                denominator = (denominator * diff) % prime
        
        lagrange_coeff = (numerator * _mod_inverse(denominator, prime)) % prime
        secret = (secret + share_i.value * lagrange_coeff) % prime
    
    return secret


def partial_decrypt(ciphertext: Ciphertext, share: Share, prime: int) -> PartialDecryption:
    """
    Produce a partial decryption using a single trustee's share.
    
    The trustee computes c1^{share_value} mod p without ever seeing
    the full private key. This partial decryption will be combined
    with others to reconstruct c1^{private_key} for full decryption.
    
    Args:
        ciphertext: The ciphertext to partially decrypt
        share: This trustee's share of the private key
        prime: Prime modulus (the subgroup order q)
        
    Returns:
        PartialDecryption containing c1^{share_value} mod p
    """
    # Compute c1^{share} mod p
    value = pow(ciphertext.c1, share.value, p)
    return PartialDecryption(trustee_index=share.index, value=value)


def combine_partial_decryptions(
    ciphertext: Ciphertext,
    partials: list[PartialDecryption],
    prime: int
) -> int:
    """
    Combine partial decryptions to recover the tally.
    
    Uses Lagrange interpolation to reconstruct c1^{private_key} from
    the partial decryptions, then completes the ElGamal decryption.
    
    The math:
    - Full decryption: m = c2 / (c1^x) where x is the private key
    - Each trustee provides: c1^{x_i} where x_i is their share
    - We combine: c1^x = product of (c1^{x_i})^{lambda_i} where lambda_i are Lagrange coefficients
    - Then: m = c2 / c1^x mod p
    
    Args:
        ciphertext: The ciphertext (combined homomorphic ciphertext)
        partials: List of partial decryptions from at least t trustees
        prime: Prime modulus for field arithmetic (subgroup order q)
        
    Returns:
        The decrypted tally (sum of votes)
        
    Raises:
        ValueError: If partials list is empty or has duplicate indices
    """
    if not partials:
        raise ValueError("At least one partial decryption is required")
    
    # Check for duplicate indices
    indices = [p.trustee_index for p in partials]
    if len(indices) != len(set(indices)):
        raise ValueError("Duplicate trustee indices in partial decryptions")
    
    # Combine partial decryptions using Lagrange interpolation
    # We want to compute: c1^x = product of (c1^{x_i})^{lambda_i}
    # where lambda_i are Lagrange coefficients for reconstruction at x=0
    
    c1_to_x = 1
    for i, partial_i in enumerate(partials):
        # Compute Lagrange coefficient for this trustee
        numerator = 1
        denominator = 1
        
        for j, partial_j in enumerate(partials):
            if i != j:
                numerator = (numerator * partial_j.trustee_index) % prime
                diff = (partial_j.trustee_index - partial_i.trustee_index) % prime
                denominator = (denominator * diff) % prime
        
        lagrange_coeff = (numerator * _mod_inverse(denominator, prime)) % prime
        
        # Raise partial decryption to the Lagrange coefficient power
        # (c1^{x_i})^{lambda_i} = c1^{x_i * lambda_i}
        contribution = pow(partial_i.value, lagrange_coeff, p)
        c1_to_x = (c1_to_x * contribution) % p
    
    # Complete the decryption: m = c2 / c1^x mod p
    c1_to_x_inv = pow(c1_to_x, p - 2, p)  # Fermat's little theorem
    m = (ciphertext.c2 * c1_to_x_inv) % p
    
    # Solve discrete log to find the tally (brute force since votes are small)
    # We limit search to a reasonable max (e.g., 1000 votes) since this is a demo
    MAX_VOTES = 1000
    current = 1
    for tally in range(MAX_VOTES):
        if current == m:
            return tally
        current = (current * g) % p
    
    raise ValueError(f"Could not decrypt: result {m} not found in first {MAX_VOTES} powers of g")


class Trustee:
    """
    Represents a single trustee in the threshold cryptosystem.
    
    Each trustee holds one share of the private key and can produce
    partial decryptions without ever seeing the full private key.
    """
    
    def __init__(self, index: int, share: Share):
        """
        Initialize a trustee with their share.
        
        Args:
            index: The trustee's 1-based index
            share: The trustee's share of the private key
        """
        self.index = index
        self.share = share
    
    def decrypt_partial(self, ciphertext: Ciphertext, prime: int) -> PartialDecryption:
        """
        Produce a partial decryption of the ciphertext.
        
        Args:
            ciphertext: The ciphertext to partially decrypt
            prime: Prime modulus for field arithmetic
            
        Returns:
            PartialDecryption that can be combined with others
        """
        return partial_decrypt(ciphertext, self.share, prime)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON encoding."""
        return {
            "index": self.index,
            "share": self.share.to_dict()
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> "Trustee":
        """Deserialize from dictionary."""
        return cls(index=d["index"], share=Share.from_dict(d["share"]))


def create_trustees(secret: int, threshold: int, num_trustees: int, prime: int) -> list[Trustee]:
    """
    Create a set of trustees by splitting a secret.
    
    Args:
        secret: The secret to split (private key)
        threshold: Minimum trustees needed for decryption
        num_trustees: Total number of trustees
        prime: Prime modulus for field arithmetic
        
    Returns:
        List of Trustee objects, each holding one share
    """
    shares = split_secret(secret, threshold, num_trustees, prime)
    return [Trustee(index=i+1, share=share) for i, share in enumerate(shares)]
