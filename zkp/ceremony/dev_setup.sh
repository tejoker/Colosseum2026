#!/usr/bin/env bash
#
# dev_setup.sh — generates DEV Groth16 keys locally. DO NOT use in production.
#
# Produces, for each action-log circuit:
#   zkp/circuits/build/<circuit>/<circuit>_final.dev.zkey   (proving key)
#   zkp/circuits/build/<circuit>/<circuit>.dev.vkey.json    (verification key)
#
# The DEV keys are also copied to zkp/circuits/build/keys/ so the SDK + Rust
# verifier can locate them via the default lookup paths.
#
# Requires:
#   - circom 2.x on $PATH
#   - snarkjs on $PATH
#   - powersOfTau28_hez_final_15.ptau in zkp/circuits/build/ptau/
#     (small ptau — sufficient for circuits with ≤ 2^15 constraints).
#
# WARNING: This is a single-party setup. The toxic waste lives in this
# machine's memory until the script exits; an attacker with read access to
# this machine during the run can forge proofs. NEVER use the resulting keys
# for production.

set -euo pipefail

CIRCUITS=(
    "SignedLogEntry"
    "ActionRangeProof"
    "ActionSumBound"
    "ActionSetMembership"
    "ActionSetNonMembership"
    "ActionTimeWindow"
    "ActionCountInRange"
)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CIRC_DIR="${ROOT}/circuits"
BUILD_DIR="${CIRC_DIR}/build"
PTAU="${BUILD_DIR}/ptau/powersOfTau28_hez_final_15.ptau"
KEYS_OUT="${BUILD_DIR}/keys"

mkdir -p "${KEYS_OUT}" "${BUILD_DIR}/ptau"

if [[ ! -f "${PTAU}" ]]; then
    cat <<EOF >&2
[ERROR] Missing ptau file: ${PTAU}

Download it once:
    curl -L -o "${PTAU}" \\
        https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau

(For larger circuits, swap _15 for _16 or _17.)
EOF
    exit 1
fi

for C in "${CIRCUITS[@]}"; do
    echo "═══ DEV setup: ${C} ═══"
    OUT="${BUILD_DIR}/${C}"
    mkdir -p "${OUT}"

    R1CS="${OUT}/${C}.r1cs"
    if [[ ! -f "${R1CS}" ]]; then
        echo "  -> compiling ${C}.circom"
        circom "${CIRC_DIR}/${C}.circom" \
            --r1cs --wasm \
            -o "${OUT}" \
            -l "${ROOT}/node_modules"
    fi

    PRE_ZKEY="${OUT}/${C}_pre.dev.zkey"
    FINAL_ZKEY="${OUT}/${C}_final.dev.zkey"
    VKEY="${OUT}/${C}.dev.vkey.json"

    echo "  -> snarkjs groth16 setup (single-party DEV)"
    snarkjs groth16 setup "${R1CS}" "${PTAU}" "${PRE_ZKEY}"

    echo "  -> snarkjs zkey contribute (DEV self-contribution)"
    snarkjs zkey contribute "${PRE_ZKEY}" "${FINAL_ZKEY}" \
        --name="dev-local" -v \
        -e="$(head -c 64 /dev/urandom | base64)"

    echo "  -> export verification key"
    snarkjs zkey export verificationkey "${FINAL_ZKEY}" "${VKEY}"

    cp "${FINAL_ZKEY}" "${KEYS_OUT}/${C}_final.dev.zkey"
    cp "${VKEY}" "${KEYS_OUT}/${C}.dev.vkey.json"

    rm -f "${PRE_ZKEY}"
done

echo
echo "════════════════════════════════════════════════════════════════════"
echo "  DEV setup complete."
echo "  Keys: ${KEYS_OUT}"
echo
echo "  WARNING: these keys come from a single-party local setup and are"
echo "  NOT suitable for production. Run a real multi-party ceremony before"
echo "  shipping — see zkp/ceremony/README.md."
echo "════════════════════════════════════════════════════════════════════"
