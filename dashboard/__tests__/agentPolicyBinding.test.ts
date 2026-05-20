import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Sprint 10 — dashboard tests for the server-backed agent → policy binding
// fetchers. The proxy lives at `/api/agents/:id/policy_binding`; these
// tests assert the wrapper turns each HTTP shape into the expected
// `{ok, ...}` envelope and falls back to localStorage on network errors.

function mockResponse<T>(body: T, ok = true, status = 200) {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (typeof window !== "undefined") {
    window.localStorage.clear();
  }
});

describe("fetchAgentBinding (server-backed)", () => {
  beforeEach(() => vi.resetModules());

  it("returns the binding record on 200", async () => {
    vi.stubGlobal("fetch", async () =>
      mockResponse({ agent_id: "agt-1", policy_id: "pol_x", bound_at: 1234 })
    );
    const { fetchAgentBinding } = await import("../lib/api");
    const r = await fetchAgentBinding("agt-1");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.policy_id).toBe("pol_x");
      expect(r.data.bound_at).toBe(1234);
    }
  });

  it("returns ok:false with 404 error string when unbound", async () => {
    vi.stubGlobal("fetch", async () => mockResponse({}, false, 404));
    const { fetchAgentBinding } = await import("../lib/api");
    const r = await fetchAgentBinding("agt-missing");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("404");
  });
});

describe("bindAgentPolicy + unbindAgentPolicy", () => {
  beforeEach(() => vi.resetModules());

  it("POST returns the persisted record", async () => {
    vi.stubGlobal("fetch", async () =>
      mockResponse({ agent_id: "agt-2", policy_id: "pol_y", bound_at: 5555 })
    );
    const { bindAgentPolicy } = await import("../lib/api");
    const r = await bindAgentPolicy("agt-2", "pol_y");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.policy_id).toBe("pol_y");
    }
  });

  it("DELETE returns {unbound:true} on success", async () => {
    vi.stubGlobal("fetch", async () => mockResponse({ unbound: true }));
    const { unbindAgentPolicy } = await import("../lib/api");
    const r = await unbindAgentPolicy("agt-2");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.unbound).toBe(true);
  });
});

describe("fetchAgentBindingPolicyId offline fallback", () => {
  beforeEach(() => vi.resetModules());

  it("falls back to localStorage when fetch throws", async () => {
    // Seed the legacy cache so the fallback has something to return.
    if (typeof window !== "undefined") {
      window.localStorage.setItem(
        "sauron:agent-policy-binding",
        JSON.stringify({ "agt-offline": { policyId: "pol_cached", boundAt: 1 } })
      );
    }
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED");
    });
    const { fetchAgentBindingPolicyId } = await import(
      "../lib/agentPolicyBinding"
    );
    const got = await fetchAgentBindingPolicyId("agt-offline");
    expect(got).toBe("pol_cached");
  });
});
