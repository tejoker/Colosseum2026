/**
 * S12 redteam — meta-runner for binding-bypass category.
 * Spawns each binding-*.ts as a subprocess and aggregates JSON results.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "binding-direct-tool-call",
    "binding-stale-cache",
    "binding-bumped-budget",
    "binding-classifier-lie",
    "binding-revoke-replay",
];

if (require.main === module) {
    void runCategory("binding-bypass", SCENARIOS);
}
