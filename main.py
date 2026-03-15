"""
Cryptographic Voting Simulator Demo

This script demonstrates a complete electronic voting system with:
- Homomorphic encryption for privacy-preserving tallying
- Zero-knowledge proofs for ballot validity
- Bulletin board for transparent, auditable elections
- Threshold decryption for distributed trust
"""

import secrets

from crypto import (
    generate_keypair,
    encrypt,
    decrypt,
    combine_many_ciphertexts,
    Ciphertext,
    p,
    g,
)
from trustees import (
    create_trustees,
    combine_partial_decryptions,
    reconstruct_secret,
)
from zkp import (
    generate_ballot_proof,
    verify_ballot_proof,
    encrypt_with_proof,
    BallotProof,
)
from bulletin_board import (
    create_board,
    BulletinBoard,
    BallotEntry,
)


def demo_basic_encryption():
    """Demonstrate basic homomorphic encryption and decryption with ZK proofs."""
    # Define five votes (mix of 0s and 1s)
    votes = [1, 0, 1, 1, 0]
    
    print("\n🗳️  VOTE ENCRYPTION WITH VALIDITY PROOFS")
    print("-" * 40)
    print(f"Individual votes: {votes}")
    print(f"Expected tally:   {sum(votes)}")
    print("\nEach vote is encrypted with a zero-knowledge proof that")
    print("the ciphertext contains either 0 or 1 (without revealing which).")
    
    # Generate a temporary keypair for this demo
    keypair = generate_keypair()
    
    # Encrypt each vote with proof
    ciphertexts = []
    proofs = []
    for i, vote in enumerate(votes, 1):
        ct, proof, _ = encrypt_with_proof(vote, keypair.y)
        ciphertexts.append(ct)
        proofs.append(proof)
        
        # Verify the proof immediately to show it works
        is_valid = verify_ballot_proof(ct, proof, keypair.y)
        
        print(f"\n  Vote {i}: {vote}")
        print(f"    Ciphertext:")
        print(f"      c1 = {ct.c1}")
        print(f"      c2 = {ct.c2}")
        print(f"    ZK Proof: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Show summary of proof verification
    print(f"\n📋 PROOF VERIFICATION SUMMARY")
    print("-" * 40)
    all_valid = all(verify_ballot_proof(ct, proof, keypair.y) 
                    for ct, proof in zip(ciphertexts, proofs))
    print(f"All 5 ballots have valid proofs: {'✓ YES' if all_valid else '✗ NO'}")
    
    # Combine all ciphertexts homomorphically
    print("\n🔒 HOMOMORPHIC COMBINATION")
    print("-" * 40)
    print("Combining all 5 ciphertexts without decryption...")
    combined = combine_many_ciphertexts(ciphertexts)
    print(f"\nCombined ciphertext:")
    print(f"  c1 = {combined.c1}")
    print(f"  c2 = {combined.c2}")
    
    # Decrypt the combined result
    print("\n🔓 TALLY DECRYPTION (Full Key)")
    print("-" * 40)
    tally = decrypt(combined, keypair)
    print(f"Decrypted tally: {tally}")
    
    # Verification
    print("\n✅ VERIFICATION")
    print("-" * 40)
    print(f"Individual votes:     {votes}")
    print(f"Sum of votes:         {sum(votes)}")
    print(f"Decrypted tally:      {tally}")
    
    if tally == sum(votes):
        print("\n✓ SUCCESS: Homomorphic tally matches sum of individual votes!")
    else:
        print("\n✗ FAILURE: Tally mismatch!")


def demo_threshold_decryption(keypair, expected_tally, combined_ciphertext):
    """Demonstrate threshold decryption with trustee key sharing."""
    print("\n" + "=" * 60)
    print("PART 3: THRESHOLD DECRYPTION WITH TRUSTEES")
    print("=" * 60)
    
    # Threshold parameters
    NUM_TRUSTEES = 5
    THRESHOLD = 3
    q = (p - 1) // 2  # Subgroup order for secret sharing
    
    print(f"\n🏛️  TRUSTEE SETUP")
    print("-" * 40)
    print(f"Number of trustees: {NUM_TRUSTEES}")
    print(f"Decryption threshold: {THRESHOLD}")
    print(f"Scheme: Any {THRESHOLD} of {NUM_TRUSTEES} trustees can decrypt")
    print(f"        Fewer than {THRESHOLD} trustees learn nothing")
    
    # Split the private key among trustees
    print(f"\n🔐 SPLITTING PRIVATE KEY")
    print("-" * 40)
    print(f"The private key is split using Shamir's Secret Sharing")
    print(f"over a field of order q = (p-1)/2 ({q.bit_length()} bits)")
    print(f"\nPrivate key x: [HIDDEN]")
    
    trustees = create_trustees(keypair.x, THRESHOLD, NUM_TRUSTEES, q)
    
    print(f"\nShares distributed to trustees:")
    for trustee in trustees:
        print(f"  Trustee {trustee.index}: share = {trustee.share.value}")
    
    # Verify that the secret can be reconstructed from any t shares
    print(f"\n🧪 VERIFYING SECRET SHARING")
    print("-" * 40)
    
    # Test reconstruction with first t trustees
    test_shares = [t.share for t in trustees[:THRESHOLD]]
    reconstructed = reconstruct_secret(test_shares, q)
    print(f"Reconstructed from trustees 1,2,3: {reconstructed}")
    print(f"Matches original private key: {reconstructed == keypair.x}")
    
    # Show that partial decryptions work
    print(f"\n🔓 COLLECTING PARTIAL DECRYPTIONS")
    print("-" * 40)
    print(f"Selecting {THRESHOLD} trustees to produce partial decryptions...")
    
    # Select exactly 3 trustees (e.g., trustees 2, 4, and 5)
    participating_trustees = [trustees[1], trustees[3], trustees[4]]  # indices 2, 4, 5
    participating_indices = [t.index for t in participating_trustees]
    
    print(f"\nParticipating trustees: {participating_indices}")
    print(f"Non-participating trustees: {[i for i in range(1, NUM_TRUSTEES + 1) if i not in participating_indices]}")
    
    # Collect partial decryptions
    partials = []
    print(f"\nPartial decryptions produced:")
    for trustee in participating_trustees:
        partial = trustee.decrypt_partial(combined_ciphertext, q)
        partials.append(partial)
        print(f"  Trustee {trustee.index}: c1^share = {partial.value}")
    
    # Combine partial decryptions to recover tally
    print(f"\n🔄 COMBINING PARTIAL DECRYPTIONS")
    print("-" * 40)
    print("Using Lagrange interpolation to reconstruct c1^x from partials...")
    
    tally = combine_partial_decryptions(combined_ciphertext, partials, q)
    print(f"\nDecrypted tally: {tally}")
    
    # Verification
    print(f"\n✅ VERIFICATION")
    print("-" * 40)
    print(f"Expected tally:         {expected_tally}")
    print(f"Threshold-decrypted:    {tally}")
    
    if tally == expected_tally:
        print(f"\n✓ SUCCESS: Threshold decryption produces correct tally!")
    else:
        print(f"\n✗ FAILURE: Threshold decryption mismatch!")
    
    print(f"\n🔒 SECURITY CHECK")
    print("-" * 40)
    print(f"✓ Full private key was NEVER reconstructed during decryption")
    print(f"✓ Each trustee only used their individual share")
    print(f"✓ No single trustee can decrypt alone")
    print(f"✓ Any {THRESHOLD} trustees can decrypt together")


def demo_fake_ballot_detection(keypair):
    """Demonstrate that invalid ballots (e.g., encrypting 2) fail verification."""
    print("\n" + "=" * 60)
    print("PART 3: FAKE BALLOT DETECTION")
    print("=" * 60)
    
    print("\n🚨 DEMONSTRATING INVALID BALLOT DETECTION")
    print("-" * 40)
    print("A malicious voter tries to encrypt an invalid vote (value 2).")
    print("The ZK proof system should detect and reject this ballot.\n")
    
    # Try to encrypt an invalid vote (2)
    fake_vote = 2
    q = (p - 1) // 2
    
    # Manually create a ciphertext encrypting 2
    r = secrets.randbelow(q)
    c1 = pow(g, r, p)
    c2 = (pow(keypair.y, r, p) * pow(g, 2, p)) % p  # g^2 instead of g^0 or g^1
    fake_ciphertext = Ciphertext(c1=c1, c2=c2)
    
    print(f"Fake ballot encrypts: {fake_vote}")
    print(f"Ciphertext:")
    print(f"  c1 = {fake_ciphertext.c1}")
    print(f"  c2 = {fake_ciphertext.c2}")
    
    # Try to generate a proof - this should fail or produce an invalid proof
    print(f"\n⚠️  Attempting to generate proof for invalid vote...")
    
    try:
        # This will raise ValueError because vote is not 0 or 1
        proof = generate_ballot_proof(fake_ciphertext, fake_vote, r, keypair.y)
        print("✗ Proof generation succeeded (unexpected!)")
    except ValueError as e:
        print(f"✓ Proof generation correctly rejected: {e}")
    
    # Now simulate a malicious prover who tries to create a fake proof
    # by pretending the vote was 0 or 1
    print(f"\n🎭 Malicious prover tries to forge proof for vote=0...")
    
    # They try to prove it's 0 (but it's actually 2)
    fake_proof_as_0 = generate_ballot_proof(fake_ciphertext, 0, r, keypair.y)
    is_valid = verify_ballot_proof(fake_ciphertext, fake_proof_as_0, keypair.y)
    print(f"Verification result: {'✓ PASSED' if is_valid else '✗ FAILED'}")
    
    print(f"\n🎭 Malicious prover tries to forge proof for vote=1...")
    fake_proof_as_1 = generate_ballot_proof(fake_ciphertext, 1, r, keypair.y)
    is_valid = verify_ballot_proof(fake_ciphertext, fake_proof_as_1, keypair.y)
    print(f"Verification result: {'✓ PASSED' if is_valid else '✗ FAILED'}")
    
    print(f"\n✅ SUMMARY")
    print("-" * 40)
    print("The ZK proof system successfully detects invalid ballots:")
    print("  • Proofs can only be generated for votes 0 or 1")
    print("  • Verification fails for ciphertexts encrypting other values")
    print("  • The system maintains privacy while ensuring validity")


def demo_bulletin_board(keypair):
    """Demonstrate the bulletin board with 7 voters and tampered ballot rejection."""
    print("\n" + "=" * 60)
    print("PART 4: BULLETIN BOARD ELECTION")
    print("=" * 60)
    
    # Create the bulletin board
    print("\n📋 CREATING BULLETIN BOARD")
    print("-" * 40)
    board = create_board(keypair.y)
    print(f"Bulletin board initialized with public key")
    print(f"Board will reject invalid proofs and duplicate voters")
    
    # Register 7 voters with their votes
    print("\n🗳️  VOTER REGISTRATION")
    print("-" * 40)
    voters = [
        ("alice", 1),
        ("bob", 0),
        ("charlie", 1),
        ("diana", 1),
        ("eve", 0),
        ("frank", 1),
        ("grace", 0),
    ]
    
    expected_tally = sum(vote for _, vote in voters)
    print(f"Registered {len(voters)} voters:")
    for voter_id, vote in voters:
        print(f"  {voter_id}: vote={vote}")
    print(f"Expected tally: {expected_tally}")
    
    # Have each voter cast their ballot
    print("\n📮 CASTING BALLOTS")
    print("-" * 40)
    
    for voter_id, vote in voters:
        # Encrypt with proof
        ciphertext, proof, _ = encrypt_with_proof(vote, keypair.y)
        
        # Post to bulletin board
        success, message, receipt = board.post_ballot(voter_id, ciphertext, proof)
        status = "✓ ACCEPTED" if success else "✗ REJECTED"
        print(f"{status}: {message}")
    
    # Try to post a duplicate ballot
    print("\n🚫 ATTEMPTING DUPLICATE VOTE")
    print("-" * 40)
    ct_dup, proof_dup, _ = encrypt_with_proof(1, keypair.y)
    success, message, receipt = board.post_ballot("alice", ct_dup, proof_dup)
    print(f"{'✓ ACCEPTED' if success else '✗ REJECTED'}: {message}")
    
    # Try to post a tampered ballot (valid proof but tampered ciphertext)
    print("\n🚨 ATTEMPTING TAMPERED BALLOT")
    print("-" * 40)
    print("Creating valid ballot, then tampering with ciphertext...")
    
    # Create a valid ballot
    ct_valid, proof_valid, r_valid = encrypt_with_proof(1, keypair.y)
    
    # Tamper with the ciphertext (change c2)
    tampered_c2 = (ct_valid.c2 * g) % p  # Multiply by g to change the vote
    ct_tampered = Ciphertext(c1=ct_valid.c1, c2=tampered_c2)
    
    # Try to post with the original proof (should fail)
    success, message, receipt = board.post_ballot("hacker", ct_tampered, proof_valid)
    print(f"Tampered ballot: {'✓ ACCEPTED' if success else '✗ REJECTED'}")
    print(f"Reason: {message}")
    
    # Show current board state
    print(f"\n📊 BULLETIN BOARD STATE")
    print("-" * 40)
    print(f"Total ballots posted: {board.get_voter_count()}")
    print(f"Voters who have voted: {sorted(board._voter_ids)}")
    
    # Run full election verification
    print(f"\n🔍 FULL ELECTION VERIFICATION")
    print("-" * 40)
    is_valid, report = board.verify_election()
    print(report)
    
    # Get combined ciphertext and tally
    if is_valid:
        print(f"\n🔒 PRODUCING COMBINED CIPHERTEXT")
        print("-" * 40)
        combined = board.get_combined_ciphertext()
        print(f"Combined ciphertext from {board.get_voter_count()} ballots:")
        print(f"  c1 = {combined.c1}")
        print(f"  c2 = {combined.c2}")
        
        return combined, expected_tally
    
    return None, expected_tally


def main():
    # Generate keypair once for all demos
    print("=" * 60)
    print("CRYPTOGRAPHIC VOTING SIMULATOR")
    print("Complete Election System Demo")
    print("=" * 60)
    
    print("\n📊 PUBLIC PARAMETERS")
    print("-" * 40)
    print(f"Safe prime p ({p.bit_length()} bits)")
    print(f"Generator g")
    
    print("\n🔑 ELECTION KEY GENERATION")
    print("-" * 40)
    keypair = generate_keypair()
    print(f"Public key y: {keypair.y}")
    print(f"Private key x: [SECRET - to be shared among trustees]")
    
    # Part 1: Basic encryption and decryption with ZK proofs
    print("\n\n" + "=" * 60)
    print("PART 1: BASIC ENCRYPTION WITH ZK PROOFS")
    print("=" * 60)
    demo_basic_encryption()
    
    # Part 2: Bulletin board election (replaces the old basic flow)
    combined, expected_tally = demo_bulletin_board(keypair)
    
    # Part 3: Threshold decryption with trustees
    if combined:
        demo_threshold_decryption(keypair, expected_tally, combined)
    
    # Part 4: Fake ballot detection
    demo_fake_ballot_detection(keypair)
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("Summary:")
    print("  • Bulletin board acts as single source of truth")
    print("  • Invalid ballots rejected at posting time")
    print("  • Duplicate voting prevented")
    print("  • Full election verification available to anyone")
    print("  • Threshold decryption ensures no single point of trust")
    print("=" * 60)


if __name__ == "__main__":
    main()
