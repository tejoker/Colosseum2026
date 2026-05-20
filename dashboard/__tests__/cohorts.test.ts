import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { RankBadge } from "../components/cohorts/RankBadge";
import {
  listMockCohorts,
  mockCohortDetail,
  mockTenantRank,
} from "../app/api/cohorts/_mock";
import type { CohortRank } from "../lib/api";

// Shared envelope helper — matches what the /api/cohorts/* routes return.
function envelope<T>(data: T, opts: { mock?: boolean; error?: string } = {}) {
  return {
    ok: !opts.error,
    status: opts.error ? 500 : 200,
    json: async () => ({
      mock: opts.mock ?? true,
      notice: "MOCK DATA",
      data,
      ...(opts.error ? { error: opts.error } : {}),
    }),
    text: async () =>
      JSON.stringify({ mock: true, notice: "MOCK DATA", data }),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── 1. fetchCohorts: happy path unwraps envelope ──────────────────────

describe("fetchCohorts", () => {
  beforeEach(() => vi.resetModules());

  it("unwraps the mock envelope and returns the cohort list", async () => {
    vi.stubGlobal("fetch", async () =>
      envelope([
        {
          cohort_id: "coh_a",
          label: "A",
          vendor: "openai",
          sector: "banking",
          n_tenants: 12,
          period_start: 1,
          period_end: 2,
        },
      ])
    );
    const { fetchCohorts } = await import("../lib/api");
    const r = await fetchCohorts();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data).toHaveLength(1);
      expect(r.data[0].cohort_id).toBe("coh_a");
    }
  });
});

// ── 2. fetchCohort: error path on non-2xx ─────────────────────────────

describe("fetchCohort error", () => {
  beforeEach(() => vi.resetModules());

  it("returns ok:false when the server responds non-2xx", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: false,
      status: 404,
      json: async () => ({}),
    }));
    const { fetchCohort } = await import("../lib/api");
    const r = await fetchCohort("coh_missing");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("404");
  });
});

// ── 3. RankBadge renders the percentile + label ───────────────────────

describe("RankBadge", () => {
  it("renders 'p{N}' for a mid-cohort tenant", () => {
    const rank: CohortRank = {
      cohort_id: "coh_x",
      tenant_rank_percentile: 72,
      metric: "success_rate",
    };
    const html = renderToStaticMarkup(
      createElement(RankBadge, { rank, label: "OpenAI / Banking" })
    );
    expect(html).toContain('data-testid="rank-badge"');
    expect(html).toContain("p72");
    expect(html).toContain("in OpenAI / Banking");
  });

  it("clamps percentile to 0..100", () => {
    const rank: CohortRank = {
      cohort_id: "coh_y",
      tenant_rank_percentile: 150,
      metric: "latency_p95_ms",
    };
    const html = renderToStaticMarkup(createElement(RankBadge, { rank }));
    expect(html).toContain("p100");
  });
});

// ── 4. Suppressed cohorts: detail reports `suppressed: true` ──────────

describe("mock data suppression", () => {
  it("marks small cohorts (< k=5) as suppressed in every metric", () => {
    // coh_mistral_retail seed has n_tenants=3 — below k=5 threshold.
    const detail = mockCohortDetail("coh_mistral_retail");
    expect(detail).not.toBeNull();
    expect(detail!.metrics.length).toBeGreaterThan(0);
    for (const m of detail!.metrics) {
      expect(m.suppressed).toBe(true);
      expect(m.value_p50).toBe(0);
    }
  });

  it("publishes quartiles for cohorts that clear the k threshold", () => {
    const detail = mockCohortDetail("coh_openai_banking");
    expect(detail).not.toBeNull();
    const success = detail!.metrics.find((m) => m.metric_id === "success_rate");
    expect(success?.suppressed).toBe(false);
    expect(success!.value_p75).toBeGreaterThanOrEqual(success!.value_p50);
    expect(success!.value_p95).toBeGreaterThanOrEqual(success!.value_p75);
  });
});

// ── 5. Filter URL persistence (logic-only — no router) ────────────────

describe("CohortFilter URL persistence", () => {
  it("encodes vendor/sector into the query string and drops 'all'", () => {
    // Mirror what the component does without spinning up a router. This
    // keeps the test deterministic and avoids depending on jsdom's
    // history shim.
    function buildNext(
      current: URLSearchParams,
      key: string,
      value: string
    ): string {
      const next = new URLSearchParams(current.toString());
      if (value === "all" || value === "latest") next.delete(key);
      else next.set(key, value);
      const qs = next.toString();
      return qs ? `?${qs}` : "?";
    }

    let qs = new URLSearchParams();
    let url = buildNext(qs, "vendor", "openai");
    expect(url).toBe("?vendor=openai");
    qs = new URLSearchParams("vendor=openai");
    url = buildNext(qs, "sector", "banking");
    expect(url).toContain("vendor=openai");
    expect(url).toContain("sector=banking");
    // Resetting to "all" removes the key.
    qs = new URLSearchParams("vendor=openai&sector=banking");
    url = buildNext(qs, "vendor", "all");
    expect(url).not.toContain("vendor=");
    expect(url).toContain("sector=banking");
  });
});

// ── 6. mockTenantRank: known metric vs unknown ────────────────────────

describe("mockTenantRank", () => {
  it("returns a percentile for the default success_rate metric", () => {
    const r = mockTenantRank("success_rate");
    expect(r).not.toBeNull();
    expect(r!.tenant_rank_percentile).toBeGreaterThanOrEqual(0);
    expect(r!.tenant_rank_percentile).toBeLessThanOrEqual(100);
    expect(r!.cohort_id).toMatch(/^coh_/);
  });

  it("returns null for an unknown metric", () => {
    const r = mockTenantRank("not_a_real_metric");
    expect(r).toBeNull();
  });
});

// ── 7. listMockCohorts: stable shape + seed count ─────────────────────

describe("listMockCohorts", () => {
  it("returns the seeded cohort fixtures", () => {
    const cohorts = listMockCohorts();
    expect(cohorts.length).toBeGreaterThan(0);
    for (const c of cohorts) {
      expect(c.cohort_id).toMatch(/^coh_/);
      expect(c.period_end).toBeGreaterThan(c.period_start);
    }
  });
});

// ── 8. Sprint 8: published proxy no longer falls back to mock ─────────
//
// The route handler MUST NOT call the `_mock` listMockCohorts shim when
// `mode=published`. It either returns a `{data: [...]}` envelope from the
// real /v1/cohort endpoint or surfaces the upstream failure. We assert the
// happy path here — empty data is a valid response when the operator has
// not defined any cohorts yet, and the UI surfaces a dedicated empty state.

describe("fetchCohorts: empty cohort list", () => {
  beforeEach(() => vi.resetModules());

  it("returns ok with an empty array when the operator has no cohorts", async () => {
    // Real proxy returns `{ data: [] }` (no `mock: true`, no notice).
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      status: 200,
      json: async () => ({ data: [] }),
    }));
    const { fetchCohorts } = await import("../lib/api");
    const r = await fetchCohorts();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Array.isArray(r.data)).toBe(true);
      expect(r.data).toHaveLength(0);
    }
  });
});

describe("fetchCohorts: live published envelope without mock flag", () => {
  beforeEach(() => vi.resetModules());

  it("unwraps the real /v1/cohort envelope (no mock: true) into the summary list", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: [
          {
            cohort_id: "coh_openai_banking",
            label: "OpenAI · Banking",
            vendor: "openai",
            sector: "banking",
            n_tenants: 24,
            period_start: 1_700_000_000,
            period_end: 1_700_604_800,
          },
        ],
      }),
    }));
    const { fetchCohorts } = await import("../lib/api");
    const r = await fetchCohorts();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data).toHaveLength(1);
      expect(r.data[0].cohort_id).toBe("coh_openai_banking");
      expect(r.data[0].n_tenants).toBe(24);
    }
  });
});
