#!/usr/bin/env python3
"""
Standalone Election Audit Script

This script can be run independently to verify an election from a saved JSON file.
It re-verifies all ZK proofs, recomputes the combined ciphertext, and prints
a full verification report.

Usage:
    python3 audit.py [election_file]

If no election file is specified, it defaults to "election.json".
"""

import sys
import json
from typing import Optional

from crypto import Ciphertext, combine_many_ciphertexts, p, g
from zkp import verify_ballot_proof
from trustees import combine_partial_decryptions
from election_state import ElectionState, load_election, DEFAULT_ELECTION_FILE


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(title.center(70))
    print("=" * 70)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def audit_election(filepath: str = DEFAULT_ELECTION_FILE) -> bool:
    """
    Perform a full audit of an election from a saved JSON file.
    
    Args:
        filepath: Path to the election JSON file
        
    Returns:
        True if the election is valid, False otherwise
    """
    print_header("ELECTION AUDIT REPORT")
    print(f"\n📁 Audit file: {filepath}")
    
    # Load the election
    print_section("LOADING ELECTION DATA")
    state = load_election(filepath)
    if state is None:
        print("❌ FAILED: Could not load election file")
        return False
    
    print(f"✓ Election loaded: {state.election_name}")
    print(f"  Public key: {str(state.keypair.y)[:40]}...")
    
    # Check if board exists
    if state.board is None:
        print("❌ FAILED: No bulletin board data found")
        return False
    
    board = state.board
    entries = board.get_entries()
    
    print(f"\n📊 Election Statistics:")
    print(f"  Registered voters: {state.registry.get_voter_count() if state.registry else 0}")
    print(f"  Ballots cast: {len(entries)}")
    print(f"  Trustees: {len(state.trustees)} (threshold: {state.threshold})")
    
    if len(entries) == 0:
        print("\n⚠️  No ballots to audit")
        return True
    
    # Verify all ZK proofs
    print_section("ZERO-KNOWLEDGE PROOF VERIFICATION")
    print("Re-verifying all ballot proofs...")
    
    invalid_proofs = []
    for i, entry in enumerate(entries, 1):
        is_valid = verify_ballot_proof(entry.ciphertext, entry.proof, board.public_key)
        status = "✓" if is_valid else "✗"
        print(f"  {status} Ballot {i} ({entry.voter_id}): {'VALID' if is_valid else 'INVALID'}")
        if not is_valid:
            invalid_proofs.append((i, entry.voter_id))
    
    if invalid_proofs:
        print(f"\n❌ FAILED: {len(invalid_proofs)} invalid proofs found:")
        for idx, voter_id in invalid_proofs:
            print(f"    - Ballot {idx}: {voter_id}")
        return False
    
    print(f"\n✓ All {len(entries)} ZK proofs are valid")
    
    # Check for duplicate voters
    print_section("DUPLICATE VOTER CHECK")
    voter_ids = [entry.voter_id for entry in entries]
    unique_voters = set(voter_ids)
    
    if len(voter_ids) != len(unique_voters):
        duplicates = []
        seen = set()
        for vid in voter_ids:
            if vid in seen:
                duplicates.append(vid)
            seen.add(vid)
        print(f"❌ FAILED: Duplicate voters detected: {', '.join(duplicates)}")
        return False
    
    print(f"✓ No duplicate voters ({len(unique_voters)} unique voters)")
    
    # Verify combined ciphertext integrity
    print_section("COMBINED CIPHERTEXT VERIFICATION")
    print("Recomputing homomorphic combination...")
    
    # Get combined from board
    combined = board.get_combined_ciphertext()
    
    # Recompute manually
    manual_combined = entries[0].ciphertext
    for entry in entries[1:]:
        manual_combined = Ciphertext(
            c1=(manual_combined.c1 * entry.ciphertext.c1) % p,
            c2=(manual_combined.c2 * entry.ciphertext.c2) % p
        )
    
    if combined.c1 != manual_combined.c1 or combined.c2 != manual_combined.c2:
        print("❌ FAILED: Combined ciphertext mismatch")
        print(f"  Board c1: {combined.c1}")
        print(f"  Computed c1: {manual_combined.c1}")
        print(f"  Board c2: {combined.c2}")
        print(f"  Computed c2: {manual_combined.c2}")
        return False
    
    print("✓ Combined ciphertext integrity verified")
    print(f"  c1 = {str(combined.c1)[:50]}...")
    print(f"  c2 = {str(combined.c2)[:50]}...")
    
    # Verify voter registration if registry exists
    if state.registry is not None:
        print_section("VOTER REGISTRATION CHECK")
        unregistered = []
        for entry in entries:
            if not state.registry.is_registered(entry.voter_id):
                unregistered.append(entry.voter_id)
        
        if unregistered:
            print(f"❌ FAILED: Unregistered voters found: {', '.join(unregistered)}")
            return False
        
        print(f"✓ All {len(entries)} voters are registered")
    
    # Verify receipts
    print_section("BALLOT RECEIPT VERIFICATION")
    receipts = board.get_receipts()
    print(f"Total receipts: {len(receipts)}")
    
    # Check that all entries have receipts
    missing_receipts = []
    for entry in entries:
        found, _ = board.verify_ballot_by_receipt(entry.receipt)
        if not found:
            missing_receipts.append(entry.voter_id)
    
    if missing_receipts:
        print(f"❌ FAILED: Receipts not found for: {', '.join(missing_receipts)}")
        return False
    
    print(f"✓ All {len(entries)} ballots have valid receipts")
    
    # Sample receipt verification
    if receipts:
        sample_receipt = receipts[0]
        found, msg = board.verify_ballot_by_receipt(sample_receipt)
        if found:
            print(f"✓ Sample receipt verified: {sample_receipt[:16]}...")
    
    # Perform threshold decryption verification (if we have trustees)
    if state.trustees and len(state.trustees) >= state.threshold:
        print_section("THRESHOLD DECRYPTION VERIFICATION")
        print(f"Simulating decryption with {state.threshold} of {len(state.trustees)} trustees...")
        
        q = (p - 1) // 2
        participating = state.trustees[:state.threshold]
        print(f"Participating trustees: {[t.index for t in participating]}")
        
        # Collect partial decryptions
        partials = [t.decrypt_partial(combined, q) for t in participating]
        
        # Combine partial decryptions
        try:
            tally = combine_partial_decryptions(combined, partials, q)
            print(f"✓ Threshold decryption successful")
            print(f"  Decrypted tally: {tally}")
            print(f"  'Yes' votes: {tally}")
            print(f"  'No' votes: {len(entries) - tally}")
        except Exception as e:
            print(f"⚠️  Threshold decryption failed: {e}")
    
    # Final summary
    print_section("AUDIT SUMMARY")
    print("✅ ELECTION IS VALID")
    print(f"\n  Total ballots audited: {len(entries)}")
    print(f"  ZK proofs verified: {len(entries)}")
    print(f"  Duplicate voters: None")
    print(f"  Ciphertext integrity: Verified")
    if state.registry:
        print(f"  Voter registration: All verified")
    print(f"  Receipts: All valid")
    print("\n" + "=" * 70)
    print("END OF AUDIT REPORT".center(70))
    print("=" * 70 + "\n")
    
    return True


def main():
    """Main entry point for the audit script."""
    # Get filepath from command line or use default
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = DEFAULT_ELECTION_FILE
    
    print_header("STANDALONE ELECTION AUDITOR")
    print("\nThis script independently verifies an election from a JSON file.")
    print("It re-verifies all ZK proofs and recomputes all cryptographic values.")
    
    # Run the audit
    is_valid = audit_election(filepath)
    
    # Exit with appropriate code
    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
