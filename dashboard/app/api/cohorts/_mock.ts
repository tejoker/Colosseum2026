/**
 * !!! MOCK DATA — Sprint 9 !!!
 *
 * The real DP-published cohort endpoint (`/v1/cohort/published`) is part of
 * Sprint 8 (`core/src/dp/publish.rs`) and has NOT yet been wired. Until it
 * ships, this module returns plausible-shaped cohort data so the dashboard
 * UI can be developed end-to-end. EVERY object returned from here carries a
 * top-level `mock: true` flag and the proxy routes also emit that flag in
 * their response body.
 *
 * REMOVE / GATE this once `publish.rs` lands. Search for `MOCK_COHORTS` and
 * `mock: true` to find the cleanup sites.
 */

import type {
  CohortDetail,
  CohortMetric,
  CohortRank,
  CohortSummary,
} from "@/lib/api";

// ── Deterministic PRNG so snapshots and tests stay stable ────────────────
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function quartiles(rnd: () => number, base: number, spread: number) {
  // Build a plausible quartile fan around `base`. p95 wider than p75 wider
  // than p50 wider than p25. Clamp non-negative.
  const p25 = Math.max(0, base * (0.6 + rnd() * 0.1));
  const p50 = Math.max(p25, base * (0.85 + rnd() * 0.1));
  const p75 = Math.max(p50, base * (1.05 + rnd() * 0.15));
  const p95 = Math.max(p75, base * (1.25 + rnd() * 0.2 + spread * 0.1));
  return {
    value_p25: round3(p25),
    value_p50: round3(p50),
    value_p75: round3(p75),
    value_p95: round3(p95),
  };
}

function round3(x: number): number {
  return Math.round(x * 1000) / 1000;
}

const METRIC_BASES: Record<string, number> = {
  success_rate: 0.92,
  latency_p95_ms: 410,
  budget_burn_usd_per_call: 0.018,
  tool_diversity: 4.6,
};

const PRIVACY_NOTICE =
  "Cohort statistics are released under (ε, δ)-differential privacy. " +
  "Each metric carries Gaussian noise calibrated to ε=1.0, δ=1e-6, and " +
  "is suppressed when fewer than k=5 tenants contributed to the bucket.";

const NOW = 1731974400; // 2024-11-18T00:00:00Z — stable epoch for snapshots
const ONE_WEEK = 7 * 24 * 3600;

interface MockCohortSeed {
  cohort_id: string;
  label: string;
  vendor: string;
  sector: string;
  n_tenants: number;
}

const SEEDS: MockCohortSeed[] = [
  { cohort_id: "coh_openai_banking", label: "OpenAI · Banking",       vendor: "openai",    sector: "banking",   n_tenants: 24 },
  { cohort_id: "coh_anthropic_bank", label: "Anthropic · Banking",    vendor: "anthropic", sector: "banking",   n_tenants: 18 },
  { cohort_id: "coh_openai_health",  label: "OpenAI · Healthcare",    vendor: "openai",    sector: "healthcare", n_tenants: 11 },
  { cohort_id: "coh_mistral_telco",  label: "Mistral · Telco",        vendor: "mistral",   sector: "telco",     n_tenants: 7 },
  { cohort_id: "coh_anthropic_legal", label: "Anthropic · Legal",     vendor: "anthropic", sector: "legal",     n_tenants: 9 },
  { cohort_id: "coh_mistral_retail", label: "Mistral · Retail",       vendor: "mistral",   sector: "retail",    n_tenants: 3 }, // suppressed
];

function seedToSummary(s: MockCohortSeed, weekOffset = 0): CohortSummary {
  return {
    cohort_id: s.cohort_id,
    label: s.label,
    vendor: s.vendor,
    sector: s.sector,
    n_tenants: s.n_tenants,
    period_start: NOW - ONE_WEEK * (weekOffset + 1),
    period_end: NOW - ONE_WEEK * weekOffset,
  };
}

function buildMetrics(s: MockCohortSeed): CohortMetric[] {
  const suppressed = s.n_tenants < 5;
  const rnd = mulberry32(hashStr(s.cohort_id));
  return Object.entries(METRIC_BASES).map(([metric_id, base], idx) => {
    if (suppressed) {
      return {
        metric_id,
        value_p25: 0,
        value_p50: 0,
        value_p75: 0,
        value_p95: 0,
        noise_eps: 1.0,
        suppressed: true,
      };
    }
    const q = quartiles(rnd, base, idx);
    return {
      metric_id,
      ...q,
      noise_eps: 1.0,
      suppressed: false,
    };
  });
}

function hashStr(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function listMockCohorts(): CohortSummary[] {
  return SEEDS.map((s) => seedToSummary(s));
}

export function mockCohortDetail(id: string): CohortDetail | null {
  const seed = SEEDS.find((s) => s.cohort_id === id);
  if (!seed) return null;
  return {
    ...seedToSummary(seed),
    metrics: buildMetrics(seed),
    privacy_notice: PRIVACY_NOTICE,
  };
}

/**
 * Mock tenant rank for the home-page widget. Returns null when the tenant
 * has no qualifying cohort yet (use to render the "submit weekly stats"
 * empty state).
 */
export function mockTenantRank(metric: string): CohortRank | null {
  // Pretend the calling tenant lives in the OpenAI/Banking cohort and ranks
  // somewhere in the top half for the chosen metric.
  if (!Object.prototype.hasOwnProperty.call(METRIC_BASES, metric)) return null;
  const rnd = mulberry32(hashStr(metric + ":tenant"));
  const pct = Math.round(40 + rnd() * 55); // p40..p95
  return {
    cohort_id: "coh_openai_banking",
    tenant_rank_percentile: pct,
    metric,
  };
}

export const MOCK_NOTICE =
  "MOCK DATA — Sprint 8 publish.rs not yet wired. Replace with real " +
  "/v1/cohort/published proxy when available.";
