# Helios Voting Simulator

This project is a self‑contained, educational simulator of a modern end‑to‑end verifiable electronic voting system, inspired by systems like Helios. It is written as a single Python console demo that walks you through an entire election, from casting encrypted ballots all the way to a publicly verifiable tally.

At a high level, the simulator shows how you can:

- **Encrypt individual votes with homomorphic ElGamal encryption** so that each ballot is secret, but all ballots can be added together without decrypting them one by one.
- **Attach zero‑knowledge proofs (ZKPs) to each ballot** so that anyone can check that a ciphertext really encodes a valid vote (0 or 1) without learning which one.
- **Use a public bulletin board** as the single source of truth for the election, where all encrypted ballots and proofs are posted for anyone to audit.
- **Split the decryption key across multiple trustees** using Shamir secret sharing so that no single party can decrypt the tally on their own; only a threshold of trustees working together can do it.
- **Detect cheating attempts**, such as invalid ballots, tampered ciphertexts, or duplicate voters, and reject them automatically.

Concretely, the code demonstrates:

- **`crypto.py`**: Exponential ElGamal over a safe prime group, including key generation, vote encryption, homomorphic combination of ciphertexts, and decryption that returns the sum of all encrypted votes.
- **`zkp.py`**: Non‑interactive zero‑knowledge “valid ballot” proofs (via a disjunctive OR Schnorr construction) that a ciphertext encrypts either 0 or 1.
- **`bulletin_board.py`**: A simple, auditable bulletin board abstraction that stores ballots plus proofs, enforces one‑voter‑one‑ballot, verifies proofs on submission, and produces the combined ciphertext for tallying.
- **`trustees.py`**: Threshold cryptography using Shamir’s Secret Sharing, where a private key is split among trustees; any quorum of trustees can jointly decrypt the final tally without ever reconstructing the full key in one place.
- **`main.py`**: The orchestrated end‑to‑end demo that ties everything together into several narrative “parts”: basic homomorphic tallying, a bulletin‑board‑based election with multiple named voters, threshold decryption by trustees, and explicit demonstrations of fake/invalid ballots being rejected.

The goal of this repository is **not** to be production‑ready election software, but to serve as a **readable, executable explanation** of how the core building blocks of a Helios‑style cryptographic voting system fit together:

- How we can keep **each vote private** while still allowing a **publicly verifiable tally**.
- How a bulletin board plus ZKPs can make the whole election **auditable by anyone**.
- How **distributed trust** via trustees removes any single point of failure for decryption.

Running `main.py` will print a step‑by‑step walkthrough of the election, with intermediate values, verification checks, and success/failure messages, so you can see exactly what is happening at each phase and experiment with or extend the design.

## New Features

### Voter Registry with PIN Authentication (`voter_registry.py`)

Voters must register with a unique ID and secure PIN before they can vote. PINs are hashed using PBKDF2 with random salts for security.

```python
from voter_registry import create_registry

registry = create_registry()
registry.register_voter("alice", "1234")
registry.authenticate_voter("alice", "1234")  # Returns (True, message)
```

### Individual Verifiability

Each voter receives a unique receipt when they cast their ballot. They can use this receipt to verify their ballot was included in the final tally.

```python
from bulletin_board import create_board

board = create_board(public_key, registry)
success, message, receipt = board.post_ballot(voter_id, ciphertext, proof)
# receipt can be used later to verify the ballot was counted
found, msg = board.verify_ballot_by_receipt(receipt)
```

### Interactive CLI (`cli.py`)

Run `python3 cli.py` for an interactive election experience:

1. **Setup Election** - Generate keys and configure trustees
2. **Register Voters** - Add voters with PIN authentication
3. **Cast Ballot** - Authenticated voters cast encrypted ballots
4. **Verify My Ballot** - Check your ballot was counted using your receipt
5. **Tally Election** - Trustees collaborate to decrypt results
6. **Audit Election** - Public verification of all ballots

## Module Reference

- **`voter_registry.py`**: Voter registration with secure PIN hashing
- **`cli.py`**: Interactive command-line interface for elections
- **`election_state.py`**: Election persistence (save/load to JSON)
- **`audit.py`**: Standalone audit script for independent verification

## Election Persistence

The CLI automatically saves the election state to `election.json` after each action. When you restart the CLI, it will offer to load the saved election.

You can also programmatically save/load elections:

```python
from election_state import ElectionState, save_election, load_election

# Save election
state = ElectionState()
# ... configure election ...
state.save("my_election.json")

# Load election
loaded_state = ElectionState.load("my_election.json")
```

## Standalone Audit

Anyone can audit an election using the standalone `audit.py` script:

```bash
# Audit the default election.json file
python3 audit.py

# Audit a specific file
python3 audit.py my_election.json
```

The audit script independently:
- Loads the election from JSON
- Re-verifies all ZK proofs
- Recomputes the combined ciphertext
- Checks for duplicate voters
- Verifies voter registration
- Validates ballot receipts
- Performs threshold decryption
- Prints a full verification report

This ensures the election integrity can be verified without running the CLI.