# Contributing to SauronID

## Prerequisites

- Rust 1.88+ (stable toolchain with `rustfmt` and `clippy`)
- Node.js 20+
- Python 3.12+ recommended for development (the Python SDK itself supports >=3.9)

## Build and test

Everything routes through the root `Makefile` (`make help` lists all targets):

```bash
make build           # Rust core (release) + TS clients (redteam, agentic)
make test            # cargo test for the Rust workspace
make python-setup    # .venv at repo root + Python SDK install
make python-test     # Python SDK and adapter tests
make sdk-test        # agentic + ZKP SDK test suites
make dashboard-test  # Next.js dashboard unit tests
make demo            # quickstart: build + start + invariants (advisory mode)
make verify          # full release gate: fmt + clippy + tests + empirical suite
```

Before opening a PR, run `make verify`. It is the same bar CI applies.

## Pull requests

- CI's release gate runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and
  `cargo audit --deny warnings`. A PR that fails any of these will not merge.
- Add or update tests for behavior changes.
- Update docs when behavior changes. Design docs live in `docs/design/`;
  security-relevant changes should be checked against `docs/threat-model.md`.

## Contribution model

No CLA, no DCO sign-off: submitting a PR means you license your contribution
under the repository's Apache-2.0 license (see `LICENSE`, section 5).
