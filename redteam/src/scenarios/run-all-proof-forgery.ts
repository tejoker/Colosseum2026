/**
 * S12 redteam — meta-runner for proof-forgery category.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "proof-replay",
    "proof-wrong-vk",
    "proof-tampered-root",
    "proof-cross-tenant",
    "proof-stale-period",
];

if (require.main === module) {
    void runCategory("proof-forgery", SCENARIOS);
}
