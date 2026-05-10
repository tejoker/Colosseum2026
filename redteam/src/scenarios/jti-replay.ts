import { CoreApi, createPopKeyPair, randSuffix, signPopJws } from "../core-api";

/** Second /agent/kyc/consent with the same A-JWT must fail (server JTI store). */
export async function scenarioJtiReplay(
    api: CoreApi,
    bankSite: string,
    label: string
): Promise<void> {
    const sfx = `${label}-${randSuffix()}`;
    const retail = `redteam-zkp-${sfx}`;
    await api.ensureClient(bankSite, "BANK");
    await api.ensureClient(retail, "ZKP_ONLY");
    await api.devBuyTokens(retail, 5);

    const email = `jti_${sfx}@sauron.local`;
    const password = `Passw0rd!${sfx}`;
    await api.devRegisterUser({
        site_name: bankSite,
        email,
        password,
        first_name: "Jti",
        last_name: "Redteam",
        date_of_birth: "1990-01-01",
        nationality: "FRA",
    });
    const { session, key_image } = await api.userAuth(email, password);
    const keys = api.agentActionKeygen();
    const pop = createPopKeyPair();

    const reg = await api.agentRegister(session, {
        human_key_image: key_image,
        agent_checksum: `sha256:jti-${sfx}`,
        intent_json: JSON.stringify({ scope: ["kyc_consent"] }),
        public_key_hex: keys.public_key_hex,
        ring_key_image_hex: keys.ring_key_image_hex,
        pop_jkt: `redteam-pop-${sfx}`,
        pop_public_key_b64u: pop.publicKeyB64u,
        ttl_secs: 3600,
    });
    if (reg.status !== 200) throw new Error(`agent/register ${reg.status}: ${reg.raw}`);
    const ajwt = reg.data.ajwt as string;
    if (!ajwt) throw new Error("missing ajwt");

    const agentId = reg.data.agent_id as string;
    if (!agentId) throw new Error("missing agent_id");

    const req1 = await api.kycRequest(retail, ["age_over_threshold", "age_threshold"]);
    const pop1 = await api.agentPopChallenge(session, agentId);
    const action1 = await api.buildAgentActionProof({
        secretHex: keys.secret_hex,
        agentId,
        humanKeyImage: key_image,
        ajwt,
        action: "kyc_consent",
        resource: `kyc_consent:${req1}`,
        merchantId: retail,
    });
    const c1 = await api.agentKycConsent({
        ajwt,
        site_name: retail,
        request_id: req1,
        pop_challenge_id: pop1.pop_challenge_id,
        pop_jws: signPopJws(pop1.challenge, pop.privateKey),
        agent_action: action1,
    });
    if (c1.status !== 200) throw new Error(`first consent expected 200, got ${c1.status}: ${c1.raw}`);

    const req2 = await api.kycRequest(retail, ["age_over_threshold", "age_threshold"]);
    const pop2 = await api.agentPopChallenge(session, agentId);
    const action2 = await api.buildAgentActionProof({
        secretHex: keys.secret_hex,
        agentId,
        humanKeyImage: key_image,
        ajwt,
        action: "kyc_consent",
        resource: `kyc_consent:${req2}`,
        merchantId: retail,
    });
    const c2 = await api.agentKycConsent({
        ajwt,
        site_name: retail,
        request_id: req2,
        pop_challenge_id: pop2.pop_challenge_id,
        pop_jws: signPopJws(pop2.challenge, pop.privateKey),
        agent_action: action2,
    });
    if (c2.status === 200) {
        throw new Error("second consent with same A-JWT must not succeed (JTI replay)");
    }
}
