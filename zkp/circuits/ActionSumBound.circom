pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * ActionSumBound — proves that Σ amount(entry_i) ≤ budget over a public
 * contiguous range of N entry indices.
 *
 * Each entry is committed as Poseidon(entry[0..entryFields]). The amount lies
 * at a fixed offset `amountOffset` (compile-time parameter via fieldSelector
 * supplied privately — but constrained to be the same selector for every
 * entry).
 *
 * Public inputs:
 *   - root        : Merkle root of the action-log tree
 *   - budget      : upper bound on the sum (32-bit)
 *   - iLo, iHi    : inclusive range of entry indices (iHi = iLo + N - 1)
 *
 * Private inputs:
 *   - entries[N][entryFields]      : the entries
 *   - pathElements[N][levels]      : Merkle sibling hashes per entry
 *   - pathIndices[N][levels]       : left/right indicators per entry
 *   - amountSelector[entryFields]  : one-hot selector for the amount field
 *
 * Bound: 64-bit sum comparator (allows summing many 32-bit amounts safely).
 *
 * Depth ≤ 20 levels; entries fixed at N = 4 in `main` (operators recompile
 * for larger windows). See zkp/ceremony/circuits-list.json.
 */
template ActionSumBound(levels, entryFields, N) {
    // Public inputs
    signal input root;
    signal input budget;
    signal input iLo;
    signal input iHi;

    // Private inputs
    signal input entries[N][entryFields];
    signal input pathElements[N][levels];
    signal input pathIndices[N][levels];
    signal input amountSelector[entryFields];

    // Public output
    signal output valid;

    // Selector validity: one-hot
    signal selectorSum[entryFields + 1];
    selectorSum[0] <== 0;
    for (var f = 0; f < entryFields; f++) {
        amountSelector[f] * (1 - amountSelector[f]) === 0;
        selectorSum[f + 1] <== selectorSum[f] + amountSelector[f];
    }
    selectorSum[entryFields] === 1;

    // iHi == iLo + N - 1
    iHi === iLo + (N - 1);

    // Per-entry: extract amount, hash leaf, verify Merkle path at index iLo+k
    component leafHasher[N];
    component idxBits[N];
    component hashers[N][levels];
    component mux[N][levels];
    component rootCheck[N];

    signal extracted[N];
    signal partials[N][entryFields + 1];
    signal pathLevels[N][levels + 1];

    for (var k = 0; k < N; k++) {
        // Extract amount via the shared selector.
        partials[k][0] <== 0;
        for (var f = 0; f < entryFields; f++) {
            partials[k][f + 1] <== partials[k][f] + amountSelector[f] * entries[k][f];
        }
        extracted[k] <== partials[k][entryFields];

        // Hash the leaf.
        leafHasher[k] = Poseidon(entryFields);
        for (var f = 0; f < entryFields; f++) {
            leafHasher[k].inputs[f] <== entries[k][f];
        }

        // Decompose (iLo + k) into bits, constrain pathIndices to match.
        idxBits[k] = Num2Bits(levels);
        idxBits[k].in <== iLo + k;

        pathLevels[k][0] <== leafHasher[k].out;
        for (var i = 0; i < levels; i++) {
            pathIndices[k][i] === idxBits[k].out[i];

            mux[k][i] = MultiMux1(2);
            mux[k][i].c[0][0] <== pathLevels[k][i];
            mux[k][i].c[0][1] <== pathElements[k][i];
            mux[k][i].c[1][0] <== pathElements[k][i];
            mux[k][i].c[1][1] <== pathLevels[k][i];
            mux[k][i].s <== pathIndices[k][i];

            hashers[k][i] = Poseidon(2);
            hashers[k][i].inputs[0] <== mux[k][i].out[0];
            hashers[k][i].inputs[1] <== mux[k][i].out[1];
            pathLevels[k][i + 1] <== hashers[k][i].out;
        }

        rootCheck[k] = IsEqual();
        rootCheck[k].in[0] <== pathLevels[k][levels];
        rootCheck[k].in[1] <== root;
        rootCheck[k].out === 1;
    }

    // Sum: accumulator + comparator
    signal sums[N + 1];
    sums[0] <== 0;
    for (var k = 0; k < N; k++) {
        sums[k + 1] <== sums[k] + extracted[k];
    }
    signal total;
    total <== sums[N];

    component le = LessEqThan(64);
    le.in[0] <== total;
    le.in[1] <== budget;
    le.out === 1;

    valid <== 1;
}

component main {public [root, budget, iLo, iHi]} = ActionSumBound(20, 6, 4);
