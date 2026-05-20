/**
 * S12 redteam — replay-consent-token (covers A11).
 *
 * Threat-model citation: docs/threat-model.md "In scope" → "Concurrent
 * double-spend on single-use tokens" → atomic `UPDATE WHERE
 * token_used=0` pattern on consent tokens. Concurrent burst of
 * /kyc/retrieve with the same token: 1 wins, the rest 409.
 *
 * Implementation note: this scenario REQUIRES an externally-provided
 * consent_token (the issuance ceremony is exercised by the full redteam
 * runner). When `SAURON_TEST_CONSENT_TOKEN` + `SAURON_TEST_SITE_NAME`
 * are set, this runs the concurrent burst and asserts 1 winner. When
 * unset, it degrades to skipped.
 */

import {
    BASE_URL,
    ScenarioResult,
    pingServer,
    runScenario,
    skipped,
} from "./_s12_lib";

async function main(): Promise<ScenarioResult> {
    const id = "R3";
    const name = "replay-consent-token";
    const serverUp = await pingServer();
    if (!serverUp) {
        return skipped(id, name, `server ${BASE_URL} unreachable`);
    }

    const token = process.env.SAURON_TEST_CONSENT_TOKEN;
    const siteName = process.env.SAURON_TEST_SITE_NAME;
    if (!token || !siteName) {
        return skipped(
            id,
            name,
            "needs SAURON_TEST_CONSENT_TOKEN + SAURON_TEST_SITE_NAME (issuance ceremony out of scope here; covered by full redteam runner)",
        );
    }

    const body = JSON.stringify({ consent_token: token, site_name: siteName });
    const burst = 10;
    const resps = await Promise.all(
        Array.from({ length: burst }, () =>
            fetch(`${BASE_URL}/kyc/retrieve`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body,
            }),
        ),
    );

    const winners = resps.filter((r) => r.status >= 200 && r.status < 300).length;
    const conflicts = resps.filter((r) => r.status === 409).length;

    return {
        id,
        name,
        pass: winners === 1 && conflicts === burst - 1,
        note:
            "Concurrent /kyc/retrieve burst on same consent_token: exactly 1 winner, " +
            "rest 409. Enforced by atomic UPDATE WHERE token_used=0 in Repo::" +
            "consume_consent_token. Any winner-count != 1 is a TOCTOU leak.",
        evidence: {
            burst,
            winners,
            conflicts,
            other: burst - winners - conflicts,
        },
    };
}

if (require.main === module) {
    void runScenario(main);
}
