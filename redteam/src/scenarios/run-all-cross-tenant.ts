/**
 * S12 redteam — meta-runner for cross-tenant category.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "tenant-list-leak",
    "tenant-spend-leak",
    "tenant-rate-limit-cross",
];

if (require.main === module) {
    void runCategory("cross-tenant", SCENARIOS);
}
