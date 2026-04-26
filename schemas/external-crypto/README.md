# External Crypto Server Contract

These schemas define the active crypto boundary for SauronID agent binding and bounded authorization.

The crypto server is not a KYC service. It should only handle agent-bound cryptographic operations:

- bind an owner, agent checksum, policy hash, and PoP key
- verify that an A-JWT/PoP presentation matches a binding
- evaluate a bounded action against a versioned policy digest
- verify ZK proofs and return versioned receipts
- encrypt sensitive audit metadata without returning plaintext

Every response should include a deterministic receipt identifier that can be logged by core without storing sensitive material.
