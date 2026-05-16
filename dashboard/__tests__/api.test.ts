import { describe, it, expect, vi, beforeEach } from "vitest";

// Minimal test: fetch wrapper returns ok:false on HTTP error
describe("get helper (via fetchOverview)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", async () => ({
      ok: false,
      status: 503,
      json: async () => ({}),
    }));
  });

  it("returns ok:false when fetch returns non-ok status", async () => {
    const { fetchOverview } = await import("../lib/api");
    const result = await fetchOverview();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("503");
    }
  });
});

describe("get helper — network failure", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", async () => { throw new Error("ECONNREFUSED"); });
  });

  it("returns ok:false with error message on network failure", async () => {
    vi.resetModules();
    const { fetchOverview } = await import("../lib/api");
    const result = await fetchOverview();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("ECONNREFUSED");
    }
  });
});
