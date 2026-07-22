#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

audit_lock() {
  local dir="$1"
  printf '[rustsec] %s\n' "$dir"
  (cd "$ROOT/$dir" && cargo audit --deny warnings)
}

# These are separate dependency/security boundaries. The core and customer
# verifier do not inherit the prover-only toolchain and witness-generation
# dependencies.
audit_lock core
audit_lock transparent-zk/verifier
audit_lock transparent-zk
