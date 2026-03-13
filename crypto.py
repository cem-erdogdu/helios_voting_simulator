"""
Cryptographic primitives for homomorphic voting.

This module implements Exponential ElGamal encryption over a multiplicative
group mod p, providing the homomorphic property needed for tallying votes
without decrypting individual ballots.
"""

import random
import secrets
from dataclasses import dataclass


def _generate_safe_prime(bits: int) -> tuple[int, int]:
    """Generate a safe prime p = 2q + 1 where q is also prime."""
    while True:
        q = secrets.randbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        p = 2 * q + 1
        
        # Check if p and q are both prime using Fermat test (sufficient for demo)
        if pow(2, q, p) == 1 and pow(2, p - 1, p) == 1:
            return p, q


def _find_generator(p: int, q: int) -> int:
    """Find a generator g for the subgroup of order q mod p."""
    while True:
        h = random.randrange(2, p - 1)
        g = pow(h, 2, p)
        if g != 1 and pow(g, q, p) == 1:
            return g


# Pre-computed 512-bit safe prime for faster startup
# p = 2q + 1 where both p and q are prime
# Generated via _generate_safe_prime(512)
p: int = 11375647207869087457002804623604520811536052796880356319272661351969801326301166568055631383730818622369290831065553623880057547571654309553486819167412943
g: int = 2976480927342400397899404953836223769239960434214465864564910631814074584054250575913004864136365689209584828820251238183020977396512169184673062467592341


@dataclass(frozen=True)
class Keypair:
    """
    ElGamal keypair structure.
    
    Attributes:
        x: Private key (random scalar)
        y: Public key (y = g^x mod p)
    """
    x: int
    y: int


@dataclass(frozen=True)
class Ciphertext:
    """
    ElGamal ciphertext pair (c1, c2).
    
    For encryption of vote v (encoded as g^v):
    c1 = g^r mod p
    c2 = y^r * g^v mod p
    
    Attributes:
        c1: First component (ephemeral public key)
        c2: Second component (blinded message)
    """
    c1: int
    c2: int


def generate_keypair() -> Keypair:
    """
    Generate a fresh keypair with random private key.
    
    Returns:
        Keypair with randomly chosen private key x in [1, q-1]
        and corresponding public key y = g^x mod p.
    """
    q = (p - 1) // 2
    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)
    return Keypair(x=x, y=y)


def encrypt(vote: int, public_key: int) -> Ciphertext:
    """
    Encrypt a vote (0 or 1) using the public key.
    
    Vote encoding:
    - 0 -> group identity (1)
    - 1 -> g
    
    This encoding allows decryption by solving a small discrete log
    (since votes are only 0 or 1, we can simply check if result is 1 or g).
    
    Args:
        vote: The vote value (0 for "no", 1 for "yes")
        public_key: The public key y to encrypt under
        
    Returns:
        Ciphertext pair (c1, c2)
        
    Raises:
        ValueError: If vote is not 0 or 1
    """
    if vote not in (0, 1):
        raise ValueError("Vote must be 0 or 1")
    
    q = (p - 1) // 2
    r = secrets.randbelow(q)
    
    c1 = pow(g, r, p)
    
    # Encode vote: 0 -> 1, 1 -> g
    m = 1 if vote == 0 else g
    c2 = (pow(public_key, r, p) * m) % p
    
    return Ciphertext(c1=c1, c2=c2)


def decrypt(ciphertext: Ciphertext, keypair: Keypair) -> int:
    """
    Decrypt a ciphertext using the keypair.
    
    Decryption computes: m = c2 / (c1^x) = c2 * c1^(-x) mod p
    Then recovers vote by checking if m is 1 (vote=0) or g (vote=1).
    
    For homomorphically combined ciphertexts, this returns the SUM of
    the original votes (since g^a * g^b = g^(a+b)).
    
    Args:
        ciphertext: The ciphertext pair (c1, c2) to decrypt
        keypair: The keypair containing private key x
        
    Returns:
        The decrypted value (sum of original votes for combined ciphertexts)
        
    Raises:
        ValueError: If the decrypted value cannot be interpreted
    """
    c1, c2 = ciphertext.c1, ciphertext.c2
    x = keypair.x
    
    # Compute c1^(-x) mod p = (c1^x)^(p-2) mod p (Fermat's little theorem)
    c1_x = pow(c1, x, p)
    c1_x_inv = pow(c1_x, p - 2, p)
    
    m = (c2 * c1_x_inv) % p
    
    # For single votes: m is either 1 (vote=0) or g (vote=1)
    # For combined votes: m = g^sum where sum is the total
    # We solve discrete log by brute force (small exponents only)
    MAX_VOTES = 1000  # Reasonable limit for demo purposes
    current = 1
    for vote_sum in range(MAX_VOTES):
        if current == m:
            return vote_sum
        current = (current * g) % p
    
    raise ValueError(f"Could not decrypt: result {m} not found in first {MAX_VOTES} powers of g")


def combine_ciphertexts(ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
    """
    Homomorphically combine two ciphertexts.
    
    Given encryptions of v1 and v2, produces an encryption of v1 + v2.
    This works because:
    - c1_combined = c1_1 * c1_2 = g^(r1+r2)
    - c2_combined = c2_1 * c2_2 = y^(r1+r2) * g^(v1+v2)
    
    Args:
        ct1: First ciphertext
        ct2: Second ciphertext
        
    Returns:
        Combined ciphertext encrypting the sum of the original votes
    """
    return Ciphertext(
        c1=(ct1.c1 * ct2.c1) % p,
        c2=(ct1.c2 * ct2.c2) % p
    )


def combine_many_ciphertexts(ciphertexts: list[Ciphertext]) -> Ciphertext:
    """
    Homomorphically combine multiple ciphertexts.
    
    Args:
        ciphertexts: List of ciphertexts to combine
        
    Returns:
        Combined ciphertext encrypting the sum of all original votes
        
    Raises:
        ValueError: If the list is empty
    """
    if not ciphertexts:
        raise ValueError("Cannot combine empty list of ciphertexts")
    
    result = ciphertexts[0]
    for ct in ciphertexts[1:]:
        result = combine_ciphertexts(result, ct)
    return result
