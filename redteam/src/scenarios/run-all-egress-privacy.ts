/**
 * S12 redteam — meta-runner for egress + privacy category.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = [
    "dp-cohort-deanonymize",
    "egress-leak-claim",
    "tee-revoke",
];

if (require.main === module) {
    void runCategory("egress-privacy", SCENARIOS);
}
