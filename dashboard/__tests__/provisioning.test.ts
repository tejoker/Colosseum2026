// Self-serve provisioning routes.
//
// The operator generator must produce a record that `lib/session.ts
// authenticate()` accepts verbatim once pasted into
// SAURON_DASHBOARD_OPERATORS — that round trip is the whole contract.

import { afterEach, describe, expect, it } from "vitest";
import { POST as generateOperator } from "@/app/api/operators/generate/route";
import { POST as issueKey } from "@/app/api/keys/issue/route";
import { POST as registerTenant } from "@/app/api/tenants/route";
import { authenticate } from "@/lib/session";

function post(url: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

const OPERATORS_ENV = "SAURON_DASHBOARD_OPERATORS";

describe("POST /api/operators/generate", () => {
  afterEach(() => {
    delete process.env[OPERATORS_ENV];
  });

  it("generates a record that authenticate() verifies", async () => {
    const res = await generateOperator(
      post("http://dash/api/operators/generate", {
        name: "alice",
        password: "correct-horse-battery",
        tenants: ["acme", "globex"],
        super: false,
      })
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      ok: boolean;
      name: string;
      record: { password_scrypt: string; tenants: string[]; super: boolean };
      fragment: string;
    };
    expect(data.ok).toBe(true);
    expect(data.record.password_scrypt).toMatch(/^[^:]+:[^:]+$/);
    expect(JSON.parse(data.fragment)).toEqual({ alice: data.record });

    // Paste the fragment into the env var — the login path must accept it.
    process.env[OPERATORS_ENV] = data.fragment;
    const grant = authenticate("alice", "correct-horse-battery");
    expect(grant).toEqual({ tenants: ["acme", "globex"], super: false });
    // And reject a wrong password.
    expect(authenticate("alice", "wrong-password-here")).toBeNull();
  });

  it("rejects short passwords, bad names, and tenant-less non-super", async () => {
    const short = await generateOperator(
      post("http://dash/api/operators/generate", {
        name: "bob",
        password: "tiny",
        tenants: ["t1"],
      })
    );
    expect(short.status).toBe(400);

    const badName = await generateOperator(
      post("http://dash/api/operators/generate", {
        name: "bad name!",
        password: "long-enough-password",
        tenants: ["t1"],
      })
    );
    expect(badName.status).toBe(400);

    const noTenants = await generateOperator(
      post("http://dash/api/operators/generate", {
        name: "carol",
        password: "long-enough-password",
        tenants: [],
        super: false,
      })
    );
    expect(noTenants.status).toBe(400);
  });
});

describe("POST /api/keys/issue", () => {
  it("refuses non-super sessions before touching the core", async () => {
    const res = await issueKey(
      post("http://dash/api/keys/issue", {
        scopes: ["admin:read"],
        tenants: ["t1"],
        ttl_secs: 3600,
      })
      // no x-sauron-admin-super header (middleware only sets it for supers)
    );
    expect(res.status).toBe(403);
  });
});

describe("POST /api/tenants", () => {
  it("refuses non-super and malformed names, registers valid ones", async () => {
    const forbidden = await registerTenant(
      post("http://dash/api/tenants", { name: "acme" })
    );
    expect(forbidden.status).toBe(403);

    const bad = await registerTenant(
      post("http://dash/api/tenants", { name: "../etc" }, { "x-sauron-admin-super": "1" })
    );
    expect(bad.status).toBe(400);

    const ok = await registerTenant(
      post("http://dash/api/tenants", { name: "acme" }, { "x-sauron-admin-super": "1" })
    );
    expect(ok.status).toBe(200);
    const cookie = ok.headers.get("set-cookie") ?? "";
    expect(cookie).toContain("sauron_known_tenants=");
    const body = (await ok.json()) as { ok: boolean; tenants: string[] };
    expect(body.tenants).toContain("acme");
    expect(body.tenants).toContain("default");
  });
});
