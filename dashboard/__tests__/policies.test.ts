import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { POLICY_TEMPLATES } from "../components/policies/PolicyTemplates";
import { validatePolicyText } from "../components/policies/PolicyValidator";

// Helpers ────────────────────────────────────────────────────────────

function mockJsonResponse<T>(body: T, ok = true, status = 200) {
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
});

// ── fetchPolicies happy / error path ────────────────────────────────

describe("fetchPolicies", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("returns the list when the server responds OK", async () => {
    vi.stubGlobal("fetch", async () =>
      mockJsonResponse([
        { policy_id: "pol_abc", agent: "a", version: "1", updated_at: 1000 },
      ])
    );
    const { fetchPolicies } = await import("../lib/api");
    const r = await fetchPolicies();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data).toHaveLength(1);
      expect(r.data[0].policy_id).toBe("pol_abc");
    }
  });

  it("returns ok:false on non-2xx", async () => {
    vi.stubGlobal("fetch", async () => mockJsonResponse({}, false, 500));
    const { fetchPolicies } = await import("../lib/api");
    const r = await fetchPolicies();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain("500");
    }
  });
});

// ── fetchPolicy + deletePolicy ──────────────────────────────────────

describe("fetchPolicy / deletePolicy", () => {
  beforeEach(() => vi.resetModules());

  it("fetchPolicy returns the parsed Policy on 200", async () => {
    vi.stubGlobal("fetch", async () =>
      mockJsonResponse({
        version: "1",
        agent: "a",
        binding: {},
        invariants: [],
      })
    );
    const { fetchPolicy } = await import("../lib/api");
    const r = await fetchPolicy("pol_x");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.agent).toBe("a");
  });

  it("deletePolicy returns {deleted:true} on success", async () => {
    vi.stubGlobal("fetch", async () => mockJsonResponse({}, true, 204));
    const { deletePolicy } = await import("../lib/api");
    const r = await deletePolicy("pol_x");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.deleted).toBe(true);
  });
});

// ── uploadPolicy: content-type + body shape ─────────────────────────

describe("uploadPolicy", () => {
  beforeEach(() => vi.resetModules());

  it("sends raw YAML body when contentType is application/yaml", async () => {
    let captured: { url?: string; init?: RequestInit } = {};
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      captured = { url, init };
      return mockJsonResponse({ policy_id: "pol_x", agent: "a", checks: [] });
    });
    const { uploadPolicy } = await import("../lib/api");
    const r = await uploadPolicy("version: \"1\"\nagent: a\n", "application/yaml");
    expect(r.ok).toBe(true);
    expect(captured.init?.method).toBe("POST");
    expect(captured.init?.body).toBe("version: \"1\"\nagent: a\n");
    const headers = captured.init?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/yaml");
  });

  it("wraps YAML in JSON envelope when contentType is application/json", async () => {
    let captured: { init?: RequestInit } = {};
    vi.stubGlobal("fetch", async (_u: string, init?: RequestInit) => {
      captured = { init };
      return mockJsonResponse({ policy_id: "pol_x", agent: "a", checks: [] });
    });
    const { uploadPolicy } = await import("../lib/api");
    await uploadPolicy("version: \"1\"\nagent: a\n", "application/json");
    const parsed = JSON.parse(captured.init?.body as string);
    expect(parsed.raw_yaml).toBe("version: \"1\"\nagent: a\n");
  });
});

// ── evaluatePolicy: passes body through, handles verdict ───────────

describe("evaluatePolicy", () => {
  beforeEach(() => vi.resetModules());

  it("returns a deny verdict when the server denies", async () => {
    const denyResp = {
      verdict: { kind: "deny", check: "budget_cap", reason: "over budget" },
      trace: [
        { check: "budget_cap", verdict: { kind: "deny", check: "budget_cap", reason: "over budget" } },
      ],
      spend_total_usd: 500.0,
      simulator: true,
      simulator_warning: "no agent_id supplied",
    };
    vi.stubGlobal("fetch", async () => mockJsonResponse(denyResp));
    const { evaluatePolicy } = await import("../lib/api");
    const r = await evaluatePolicy("pol_x", {
      action: { action_id: "a1", tool: "x", timestamp: 0 },
      context_overrides: { spend_total_usd: 500 },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.verdict.kind).toBe("deny");
      expect(r.data.simulator).toBe(true);
      expect(r.data.trace).toHaveLength(1);
    }
  });
});

// ── Template loader sanity ──────────────────────────────────────────

describe("POLICY_TEMPLATES", () => {
  it("has 10 templates covering the fixture set", () => {
    expect(POLICY_TEMPLATES).toHaveLength(10);
    const ids = POLICY_TEMPLATES.map((t) => t.id);
    expect(ids).toContain("minimal");
    expect(ids).toContain("banking_payment");
    expect(ids).toContain("treasury_ops");
  });

  it("every template parses through the client-side validator", () => {
    for (const tpl of POLICY_TEMPLATES) {
      const r = validatePolicyText(tpl.yaml);
      // No errors. (Warnings would be OK, but fixtures should be clean.)
      const errs = r.issues.filter((i) => i.severity === "error");
      expect(errs, `${tpl.id} produced errors: ${errs.map((e) => e.message).join("; ")}`).toEqual([]);
    }
  });
});

// ── Validator: missing required field ───────────────────────────────

describe("validatePolicyText", () => {
  it("flags missing version + agent", () => {
    const r = validatePolicyText("description: nope\n");
    const msgs = r.issues.map((i) => i.message).join("\n");
    expect(msgs).toContain('version');
    expect(msgs).toContain('agent');
  });

  it("flags wrong version constant", () => {
    const r = validatePolicyText('version: "2"\nagent: a\n');
    const msgs = r.issues.map((i) => i.message).join("\n");
    expect(msgs).toMatch(/version.*"1"/);
  });
});
