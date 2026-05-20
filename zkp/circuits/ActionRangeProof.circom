pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionRangeProof — proves that a numeric field X of a committed log entry
 * satisfies a ≤ X ≤ b without revealing the rest of the entry.
 *
 * Each log entry is modeled as a fixed-arity vector of `entryFields` field
 * elements; the prover supplies the whole entry privately and points to the
 * scalar of interest via `fieldOffset` (a one-hot selector). The entry's
 * Poseidon hash (taken as Poseidon(entry[0..N])) must Merkle-verify against
 * the public root.
 *
 * Public inputs:
 *   - root        : Merkle root of the action-log tree
 *   - a, b        : range bounds (a ≤ X ≤ b)
 *   - entryIndex  : index of the entry (committed; consumers can correlate it
 *                   with off-chain metadata such as the period start)
 *
 * Private inputs:
 *   - entry[entryFields]        : the full log entry (Poseidon hashed for leaf)
 *   - pathElements[levels]      : Merkle sibling hashes
 *   - pathIndices[levels]       : left/right indicators
 *   - fieldSelector[entryFields]: one-hot vector picking the field X
 *
 * Bounds: 32-bit comparators are used → field X must fit in 2^32 (good for
 * `amount_minor` in cents up to ~42 BTC equivalents). Depth ≤ 20 in the
 * default `main` instantiation.
 */
template ActionRangeProof(levels, entryFields) {
    // Public inputs
    signal input root;
    signal input a;
    signal input b;
    signal input entryIndex;

    // Private inputs
    signal input entry[entryFields];
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input fieldSelector[entryFields];

    // Public output
    signal output valid;

    // Step 1: pick X using the one-hot selector
    // Each selector bit must be 0 or 1 and they must sum to 1.
    signal selectorSum[entryFields + 1];
    selectorSum[0] <== 0;
    for (var i = 0; i < entryFields; i++) {
        fieldSelector[i] * (1 - fieldSelector[i]) === 0;
        selectorSum[i + 1] <== selectorSum[i] + fieldSelector[i];
    }
    selectorSum[entryFields] === 1;

    signal partial[entryFields + 1];
    partial[0] <== 0;
    for (var j = 0; j < entryFields; j++) {
        partial[j + 1] <== partial[j] + fieldSelector[j] * entry[j];
    }
    signal X;
    X <== partial[entryFields];

    // Step 2: a ≤ X ≤ b (range bound, 32-bit)
    component geA = GreaterEqThan(32);
    geA.in[0] <== X;
    geA.in[1] <== a;
    geA.out === 1;

    component leB = LessEqThan(32);
    leB.in[0] <== X;
    leB.in[1] <== b;
    leB.out === 1;

    // Step 3: compute leaf = Poseidon(entry[0..entryFields])
    component leafHasher = Poseidon(entryFields);
    for (var k = 0; k < entryFields; k++) {
        leafHasher.inputs[k] <== entry[k];
    }
    signal leaf;
    leaf <== leafHasher.out;

    // Step 4: Merkle verify (entryIndex is the unsigned integer
    // formed by concatenating pathIndices from LSB to MSB).
    component idxBits = Num2Bits(levels);
    idxBits.in <== entryIndex;

    component hashers[levels];
    component mux[levels];
    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // pathIndices must equal the bits of entryIndex
        pathIndices[i] === idxBits.out[i];

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].out;
    }

    component rootCheck = IsEqual();
    rootCheck.in[0] <== levelHashes[levels];
    rootCheck.in[1] <== root;
    rootCheck.out === 1;

    valid <== 1;
}

component main {public [root, a, b, entryIndex]} = ActionRangeProof(20, 6);
