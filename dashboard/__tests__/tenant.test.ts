import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// jsdom provides `document`, `window`, `localStorage`, and `CustomEvent`. We
// reset cookies + storage between tests so each scenario is hermetic.
function clearCookies() {
  if (typeof document === "undefined") return;
  const all = document.cookie.split(";").map((s) => s.trim()).filter(Boolean);
  for (const piece of all) {
    const k = piece.split("=")[0];
    document.cookie = `${k}=; Path=/; Max-Age=0`;
  }
}

beforeEach(() => {
  vi.resetModules();
  clearCookies();
  try {
    localStorage.clear();
  } catch {
    // jsdom localStorage may not be available in edge cases
  }
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("currentTenant()", () => {
  it('returns "default" when no cookie + no localStorage entry', async () => {
    const { currentTenant, DEFAULT_TENANT } = await import("../lib/tenant");
    expect(currentTenant()).toBe(DEFAULT_TENANT);
    expect(DEFAULT_TENANT).toBe("default");
  });

  it("returns the cookie value when the tenant cookie is set", async () => {
    document.cookie = `sauron_tenant_id=acme; Path=/`;
    const { currentTenant } = await import("../lib/tenant");
    expect(currentTenant()).toBe("acme");
  });
});

describe("setCurrentTenant()", () => {
  it("writes the cookie and mirrors the value into localStorage", async () => {
    const { setCurrentTenant, currentTenant } = await import("../lib/tenant");
    setCurrentTenant("tenant-x");
    expect(document.cookie).toContain("sauron_tenant_id=tenant-x");
    expect(localStorage.getItem("sauron_tenant_id")).toBe("tenant-x");
    // Re-resolution picks up the new value.
    expect(currentTenant()).toBe("tenant-x");
  });

  it("dispatches a sauron:tenant-changed event on change", async () => {
    const { setCurrentTenant, TENANT_CHANGED_EVENT } = await import(
      "../lib/tenant"
    );
    const handler = vi.fn();
    window.addEventListener(TENANT_CHANGED_EVENT, handler);
    setCurrentTenant("event-tenant");
    expect(handler).toHaveBeenCalledTimes(1);
    const evt = handler.mock.calls[0][0] as CustomEvent<{ tenantId: string }>;
    expect(evt.detail.tenantId).toBe("event-tenant");
    window.removeEventListener(TENANT_CHANGED_EVENT, handler);
  });
});

describe("availableTenants()", () => {
  it("fetches /api/tenants and merges the response with DEFAULT_TENANT", async () => {
    const fetchMock = vi.fn(async (..._args: unknown[]) => ({
      ok: true,
      status: 200,
      json: async () => ({ tenants: ["acme", "globex"] }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const { availableTenants } = await import("../lib/tenant");
    const list = await availableTenants();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const callArgs = fetchMock.mock.calls[0];
    expect(callArgs?.[0]).toBe("/api/tenants");
    expect(list).toContain("default");
    expect(list).toContain("acme");
    expect(list).toContain("globex");
  });
});
