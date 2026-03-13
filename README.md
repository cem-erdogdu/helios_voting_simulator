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