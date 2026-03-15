# Cryptographic Voting Simulator - TODO List

## ✅ Completed

- [x] Core cryptographic primitives (Exponential ElGamal)
  - [x] 512-bit safe prime `p` and generator `g`
  - [x] Keypair generation with private key `x` and public key `y = g^x mod p`
  - [x] Vote encryption (0→1, 1→g encoding)
  - [x] Vote decryption with small discrete log solving
  - [x] Homomorphic ciphertext combination
- [x] Basic voting simulation demo
  - [x] Generate keypair
  - [x] Encrypt 5 votes
  - [x] Combine ciphertexts
  - [x] Decrypt tally
  - [x] Verify correctness
- [x] Trustee Key Sharing (Threshold Cryptography)
  - [x] Shamir's Secret Sharing implementation
  - [x] Split private key into n shares with threshold t
  - [x] Partial decryption using individual shares
  - [x] Combine partial decryptions using Lagrange interpolation
  - [x] 5 trustees with threshold 3 demonstrated
- [x] Zero-Knowledge Ballot Proofs
  - [x] Disjunctive OR proof for ballot validity (0 or 1)
  - [x] Schnorr-type proofs of knowledge of randomness
  - [x] Fiat-Shamir transform for non-interactive proofs
  - [x] Verification without decryption
  - [x] Fake ballot (value 2) detection demonstrated
- [x] Bulletin Board
  - [x] Append-only log for all encrypted ballots
  - [x] Ballot validation with ZK proof verification
  - [x] Duplicate voter detection
  - [x] Homomorphic combination of all ballots
  - [x] Full election verification interface
  - [x] 7 voters with tampered ballot rejection demonstrated

## 🚧 Planned Features

### 1. Full Election Orchestration
- [x] Election setup (voter registration, candidate/question definition)
- [x] Ballot casting with voter authentication
- [x] Tallying phase with trustee collaboration
- [x] Result publication with proof of correctness

### 2. Verifiability Checks
- [x] Individual verifiability (voters can verify their ballot was counted)
- [x] Universal verifiability (anyone can verify tally correctness)
- [x] End-to-end verifiability proofs
- [x] Audit procedures and dispute resolution

### 3. Interactive CLI ✅ COMPLETED
- [x] Menu-driven interface for election management
- [x] Voter registration with PIN authentication
- [x] Secure ballot casting
- [x] Receipt-based ballot verification
- [x] Election tallying with threshold decryption
- [x] Public audit functionality

## 📝 Notes

- All components run locally (no web servers, databases, or external APIs)
- Focus on cryptographic correctness and educational clarity
- Keep simulation-sized parameters (512-bit primes) for reasonable performance
