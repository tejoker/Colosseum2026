# Transparent production proofs

This directory replaces the production Groth16 path with a native RISC Zero
STARK. It has no per-circuit trusted setup and no ceremony participant. The
prover is untrusted; the receipt is independently verifiable against the
published guest image ID.

The reviewed stats guest proves all of the following in one statement:

- every private action envelope hashes to the `action_hash` in its signed
  receipt;
- every receipt is in the same tenant, optional agent scope, and reporting
  period;
- the complete ordered receipt list reconstructs the server-finalized v2
  action-anchor root and exact tree size;
- `success_rate`, `error_rate`, `tool_call_count`, or USD `cost_total` is
  computed by the guest rather than supplied by the prover;
- the journal binds tenant, checkpoint, action anchor, root, size, scope,
  metric, value, and period.

## Build and publish the image ID

Install the version-pinned RISC Zero 3.0 toolchain, then build:

```sh
rzup install rust 1.97.0
rzup install cargo-risczero 3.0.6
cargo build --locked --release --manifest-path transparent-zk/Cargo.toml
cargo run --locked --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --image-ids
```

The generated `SAURON_STATS_GUEST_ID` is the cryptographic identity of the
compiled guest. Publish the source, reproducible build instructions and image
ID. Configure production with both reviewed program IDs:

```json
{
  "sauron-stats-v1": "dd4bf48ed1cc4d62d51b153075a438048d03e832c3a8d50fdf4db9c0240a8060",
  "sauron-action-policy-v1": "4e7ad7997c31f4a4a9e870e40f5a059306803fca724e14d2e3fa7bf90cdd9aa5"
}
```

The build metadata and lock-file digests are committed in `image-ids.json`.
Rebuild and compare rather than trusting the manifest. Both IDs are generated
from source in this directory. The action-policy guest
supports complete-batch action allowlists, total-amount bounds, count ranges,
presence/absence checks, and time windows.

## Generate a real proof

```sh
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- private-input.json
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --action-policy private-input.json
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --self-test transparent-zk/fixtures/stats-one-record.json
cargo run --release --manifest-path transparent-zk/Cargo.toml --bin sauron-transparent-prover -- --self-test-action transparent-zk/fixtures/action-policy-one-record.json
```

The binary has RISC Zero dev mode compiled out and explicitly asks for a
`Succinct` STARK receipt. The core accepts only that native receipt form;
`Composite`, `Groth16`, `Fake`, and unknown future variants fail closed.

Clients verify the receipt; they do not run the SauronID test suite or trust a
server boolean:

```sh
cargo run --locked --release --manifest-path transparent-zk/verifier/Cargo.toml \
  -- proof-output.json
```

That minimal verifier pins the published guest IDs, rejects non-STARK receipt
types, runs the RISC Zero verifier locally, and prints only the
cryptographically committed public journal. It is a separate crate so customer
verification does not inherit the prover, guest-build, or `rzup` toolchain
dependencies. RISC Zero's current universal receipt crate still compiles its
Groth16/Arkworks verifier branch; SauronID rejects that enum variant before
verification, so it is dependency attack surface but not a trusted setup or an
accepted proof path.

## Prover-only upstream advisory

RISC Zero 3.0.5 is the current upstream release. Its `prove` feature
unconditionally compiles `risc0-groth16`/Arkworks even when this prover requests
only native `Succinct` STARK receipts. That branch pins
`tracing-subscriber 0.2.25`, reported by RUSTSEC-2025-0055 for ANSI terminal-log
injection. Sauron's prover installs no tracing subscriber and never logs the
private witness; the affected formatter is therefore unreachable here. The
exception is explicit in `.cargo/audit.toml` and must be removed on the first
patched RISC Zero/Arkworks release. The production core and separate client
verifier compile RISC Zero without `std`/`prove` and have no known RustSec
vulnerability in the current advisory database. They still inherit the
upstream Groth16 verifier branch described above plus `derivative` and `paste`
maintenance notices; the narrow maintenance exceptions are documented in each
crate's `.cargo/audit.toml`, while every unexcepted warning remains
release-blocking.

The same prover feature also pulls `rsa` through RISC Zero's `rzup` toolchain
download client. RUSTSEC-2023-0071 concerns network-observable timing of RSA
*private-key* operations; Sauron's prover performs no RSA private-key operation.
That narrow, prover-only exception is recorded beside the tracing exception.
The prover additionally inherits maintenance-only notices for
`atomic-polyfill` and `bincode` from RISC Zero's build/prover graph; they are
recorded in the same file and are not part of Sauron's proof statement.

Run proof generation as an offline build job, not as a public network service.
