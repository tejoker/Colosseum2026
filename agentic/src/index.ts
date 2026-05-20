export {
    computeChecksum,
    verifyChecksum,
    computeComponentChecksums,
    AgentConfig,
    AgentTool,
    LLMConfig,
} from "./checksum";

export {
    generatePopKeyPair,
    signPopChallenge,
    verifyPopChallenge,
    PopKeyPair,
} from "./pop-keys";

export {
    forgeAgentToken,
    verifyAgentToken,
    verifyAgentSession,
    createDelegationToken,
    validateDelegationChain,
    initializeIdPKeys,
    effectiveScopesForIntent,
    assertNarrowedDelegation,
    buildStrictPaymentIntent,
    assertStrictPaymentIntent,
    AgentIntent,
    StrictPaymentIntentInput,
    StrictPaymentRequest,
    AJWTPayload,
    DelegationLink,
    ForgeConfig,
    VerifyAgentTokenOptions,
    ValidateDelegationChainOptions,
    JtiReplayGuard,
} from "./ajwt";

export {
    WorkflowTracker,
    buildWorkflow,
    WorkflowDefinition,
    WorkflowStep,
    WorkflowViolation,
    TelemetryEvent,
} from "./workflow-tracker";

export {
    AgentShimClient,
    IdPClientConfig,
    AgentActionEnvelope,
    AgentActionProof,
    AgentActionChallengeInput,
} from "./idp-client";

// Sprint 3 — runtime policy enforcement (additive; opt-in via `bind()`).
export * from "./enforcement";

// Sprint 7 — customer stat aggregation + ZK integrity (cross-customer benchmarks).
export {
    METRICS,
    METRIC_IDS,
    METRIC_ID_INDEX,
    FIXED_POINT_SCALE,
    toFixedPoint,
    fromFixedPoint,
    type MetricId,
    type MetricDefinition,
    type MetricType,
} from "./stats/metric-catalog";
export {
    LocalAggregator,
    percentileNearestRank,
    type ReceiptLike,
    type MetricValue,
} from "./stats/local-aggregate";
export {
    StatsProver,
    NotProvableError,
    MAX_RECEIPTS_PER_PROOF,
    receiptToFields,
    type MerkleProof,
    type ProofObject,
    type StatsHonestProof,
    type StatsProverOptions,
    type ProofRunner,
    type ProofRunnerInput,
} from "./stats/integrity-proof";
export {
    WeeklyStatsScheduler,
    createWeeklyScheduler,
    submitWeeklyStats,
    type WeeklyStatsSchedulerOptions,
    type MerkleBundle,
    type SubmitResponse,
} from "./scheduler";

// Sprint 13-14 Tier 2 — Paillier homomorphic-encryption client (thin wrapper).
// NEEDS_CRYPTO_REVIEW: see `src/he-encrypt.ts` for the full disclaimer.
export {
    encrypt as paillierEncrypt,
    add as paillierAdd,
    mul_scalar as paillierMulScalar,
    rerandomize as paillierRerandomize,
    modPow as paillierModPow,
    ciphertextToB64,
    ciphertextFromB64,
    type PaillierPublicKey,
    type Ciphertext,
} from "./he-encrypt";
