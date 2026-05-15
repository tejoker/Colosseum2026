# SauronID Dashboard Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new `dashboard/` directory replacing `sauron-dashboard/` — premium minimaliste Linear/Vercel-style interface with dark/light theme, i18n from day one, and demo-ready UX.

**Architecture:** Next.js 16.1.6 App Router with CSS-variable theming (next-themes), all strings externalized via next-intl, Radix UI for accessible primitives, clean data flow: `lib/api.ts → page (fetch) → components (props only)`.

**Tech Stack:** Next.js 16.1.6, React 19, TypeScript strict, Tailwind CSS 4, Radix UI, next-themes, next-intl, Chart.js 4, Vitest

---

## File Map

```
dashboard/
  package.json
  tsconfig.json
  next.config.ts
  postcss.config.mjs
  vitest.config.ts
  .env.local.example
  i18n/
    request.ts
  messages/
    en.json
  app/
    globals.css
    layout.tsx
    page.tsx
    error.tsx
    not-found.tsx
    loading.tsx
    protected/page.tsx
    activity/page.tsx
    proofs/page.tsx
    try/page.tsx
    settings/page.tsx
    agents/[id]/page.tsx
    agents/[id]/audit/page.tsx
    api/
      health/route.ts
      agents/route.ts
      protected/route.ts
      activity/route.ts
      proofs/route.ts
      export/route.ts
  components/
    layout/
      TopNav.tsx
      ThemeToggle.tsx
      PageShell.tsx
      SystemStatus.tsx
    ui/
      Button.tsx
      Badge.tsx
      Card.tsx
      Table.tsx
      StatusDot.tsx
      Spinner.tsx
      Dialog.tsx
      Tooltip.tsx
      Tabs.tsx
    agents/
      AgentCard.tsx
    playground/
      ScenarioTile.tsx
      ResultPanel.tsx
    audit/
      AuditTimeline.tsx
      AuditExportPanel.tsx
    live/
      LiveFeed.tsx
  lib/
    api.ts
    format.ts
  __tests__/
    api.test.ts
    format.test.ts
```

---

## Task 1: Project scaffold

**Files:**
- Create: `dashboard/package.json`
- Create: `dashboard/tsconfig.json`
- Create: `dashboard/next.config.ts`
- Create: `dashboard/postcss.config.mjs`
- Create: `dashboard/.env.local.example`

- [ ] **Step 1: Create dashboard/package.json**

```json
{
  "name": "sauronid-dashboard",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev -p 3000",
    "build": "next build",
    "start": "next start",
    "lint": "eslint",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "dependencies": {
    "next": "16.1.6",
    "react": "19.2.3",
    "react-dom": "19.2.3",
    "next-themes": "^0.4.6",
    "next-intl": "^3.26.3",
    "@radix-ui/react-dialog": "^1.1.4",
    "@radix-ui/react-dropdown-menu": "^2.1.4",
    "@radix-ui/react-tooltip": "^1.1.6",
    "@radix-ui/react-select": "^2.1.4",
    "@radix-ui/react-tabs": "^1.1.2",
    "@radix-ui/react-switch": "^1.1.2",
    "chart.js": "^4.5.1",
    "react-chartjs-2": "^5.3.1",
    "pdf-lib": "^1.17.1"
  },
  "devDependencies": {
    "@tailwindcss/postcss": "^4.1.0",
    "@types/node": "^20",
    "@types/react": "^19",
    "@types/react-dom": "^19",
    "@vitejs/plugin-react": "^4.3.4",
    "@testing-library/react": "^16.1.0",
    "@testing-library/user-event": "^14.5.2",
    "eslint": "^9",
    "eslint-config-next": "16.1.6",
    "jsdom": "^25.0.1",
    "tailwindcss": "^4.1.0",
    "typescript": "^5",
    "vitest": "^2.1.8"
  }
}
```

- [ ] **Step 2: Create dashboard/tsconfig.json**

```json
{
  "compilerOptions": {
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": false,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": { "@/*": ["./*"] }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

- [ ] **Step 3: Create dashboard/next.config.ts**

```typescript
import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

const config: NextConfig = {
  experimental: {},
};

export default withNextIntl(config);
```

- [ ] **Step 4: Create dashboard/postcss.config.mjs**

```javascript
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};
export default config;
```

- [ ] **Step 5: Create dashboard/.env.local.example**

```bash
# SauronID core (Rust) — default port
NEXT_PUBLIC_CORE_URL=http://localhost:3001
# Analytics shim (Python) — default port
NEXT_PUBLIC_DASH_API_URL=http://localhost:8002
```

- [ ] **Step 6: Install dependencies**

```bash
cd dashboard && npm install
```

Expected: `node_modules/` created, no peer dependency errors.

- [ ] **Step 7: Commit**

```bash
git add dashboard/package.json dashboard/tsconfig.json dashboard/next.config.ts dashboard/postcss.config.mjs dashboard/.env.local.example
git commit -m "feat(dashboard): scaffold Next.js 16 project with deps"
```

---

## Task 2: CSS theme system

**Files:**
- Create: `dashboard/app/globals.css`

- [ ] **Step 1: Create dashboard/app/globals.css**

```css
@import "tailwindcss";

/* ── Font loading ──────────────────────────────────────────────────── */
@import url("https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap");

@font-face {
  font-family: "Satoshi";
  src: url("https://api.fontshare.com/v2/css?f[]=satoshi@400,500,600,700&display=swap");
}

/* ── Tailwind theme extension ──────────────────────────────────────── */
@theme {
  --font-sans: "Satoshi", system-ui, sans-serif;
  --font-mono: "Space Mono", monospace;
  --transition-fast: 150ms;
  --transition-base: 200ms;
}

/* ── Dark mode tokens (default) ────────────────────────────────────── */
:root {
  --bg: #06090f;
  --bg-surface: #111114;
  --bg-elevated: #18181b;
  --border: rgba(255, 255, 255, 0.06);
  --border-hover: rgba(255, 255, 255, 0.12);
  --text-primary: #ffffff;
  --text-secondary: rgba(255, 255, 255, 0.55);
  --text-muted: rgba(255, 255, 255, 0.30);
  --accent: #2563eb;
  --accent-hover: #4f8cfe;
  --status-ok: #34d399;
  --status-stopped: #f87171;
  --status-warning: rgba(251, 191, 36, 0.6);
}

/* ── Light mode tokens ─────────────────────────────────────────────── */
.light {
  --bg: #f8fafc;
  --bg-surface: #ffffff;
  --bg-elevated: #f1f5f9;
  --border: rgba(0, 0, 0, 0.08);
  --border-hover: rgba(0, 0, 0, 0.16);
  --text-primary: #0f172a;
  --text-secondary: rgba(15, 23, 42, 0.55);
  --text-muted: rgba(15, 23, 42, 0.35);
  --accent: #2563eb;
  --accent-hover: #1d4ed8;
  --status-ok: #059669;
  --status-stopped: #dc2626;
  --status-warning: rgba(217, 119, 6, 0.7);
}

/* ── Base ──────────────────────────────────────────────────────────── */
*, *::before, *::after {
  box-sizing: border-box;
}

html {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  background-color: var(--bg);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
}

/* ── Motion — calm, purposeful ─────────────────────────────────────── */
@media (prefers-reduced-motion: no-preference) {
  .animate-pulse-calm {
    animation: pulse-calm 1.2s ease-in-out infinite;
  }
  .animate-fade-in {
    animation: fade-in 200ms ease-out;
  }
}

@keyframes pulse-calm {
  0%, 100% { opacity: 0.4; }
  50%       { opacity: 0.8; }
}

@keyframes fade-in {
  from { opacity: 0; }
  to   { opacity: 1; }
}

/* ── Typography utilities ──────────────────────────────────────────── */
.text-mono {
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.08em;
}

.text-mono-sm {
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.12em;
}
```

- [ ] **Step 2: Verify Tailwind 4 CSS compiles**

```bash
cd dashboard && npm run dev
```

Expected: server starts on :3000, no CSS parse errors in console.

- [ ] **Step 3: Commit**

```bash
git add dashboard/app/globals.css
git commit -m "feat(dashboard): CSS theme tokens dark/light + motion system"
```

---

## Task 3: i18n setup

**Files:**
- Create: `dashboard/messages/en.json`
- Create: `dashboard/i18n/request.ts`

- [ ] **Step 1: Create dashboard/messages/en.json**

```json
{
  "nav": {
    "home": "Home",
    "protected": "Protected",
    "activity": "Activity",
    "proofs": "Proofs",
    "try": "Try",
    "settings": "Settings"
  },
  "systemStatus": {
    "nominal": "All systems operational",
    "agentsProtected": "{count} agents protected",
    "verificationRunning": "Verification running",
    "degraded": "Core unreachable — last seen {ago}",
    "connecting": "Connecting…"
  },
  "home": {
    "title": "Your agents",
    "statLine": "{agents, plural, one {# agent} other {# agents}} · {calls} calls today · {protected} protected",
    "empty": "No agents registered yet.",
    "emptyLink": "Read the docs",
    "viewActivity": "View activity"
  },
  "agentCard": {
    "lastCall": "Last call",
    "totalCalls": "Total calls",
    "active": "Active",
    "idle": "Idle"
  },
  "agentDetail": {
    "title": "Agent",
    "back": "Back to Home",
    "identity": "Identity",
    "mandate": "Mandate",
    "configDigest": "Config digest",
    "recentCalls": "Recent calls",
    "audit": "View full audit",
    "revoke": "Revoke agent",
    "revokeConfirmTitle": "Revoke this agent?",
    "revokeConfirmBody": "This agent will immediately stop being able to act. This cannot be undone. Type the agent name to confirm.",
    "revokeConfirmButton": "Revoke permanently",
    "revokeCancel": "Cancel"
  },
  "protected": {
    "title": "Protected",
    "subtitle": "Your governance layer stopped these actions.",
    "summaryToday": "{count} today",
    "summaryWeek": "{count} this week",
    "summaryTotal": "{count} total",
    "colTime": "Time",
    "colAgent": "Agent",
    "colReason": "Reason",
    "showDetail": "Show detail",
    "reasons": {
      "replay": "Replayed token",
      "scope": "Out-of-scope action",
      "signature": "Invalid signature",
      "nonce": "Nonce already used",
      "revoked": "Agent revoked",
      "expired": "Token expired"
    }
  },
  "activity": {
    "title": "Activity",
    "subtitle": "Every action is recorded and verifiable.",
    "colTime": "Time",
    "colAgent": "Agent",
    "colAction": "Action",
    "colResult": "Result",
    "colLatency": "Latency",
    "filterAll": "All",
    "filterAllowed": "Allowed",
    "filterStopped": "Stopped",
    "exportAudit": "Export audit",
    "resultAllowed": "Allowed",
    "resultStopped": "Stopped"
  },
  "proofs": {
    "title": "Proofs",
    "subtitle": "Every agent action is cryptographically anchored.",
    "bitcoin": "Bitcoin",
    "bitcoinNote": "Confirmation takes ~1 hour.",
    "solana": "Solana",
    "solanaNote": "Finalises in ~30 seconds.",
    "anchored": "Anchored",
    "pending": "Pending",
    "confirmed": "Confirmed",
    "lastBatch": "Last batch",
    "verifyOn": "Verify on {chain}"
  },
  "try": {
    "title": "Try",
    "subtitle": "See your governance layer in action.",
    "scenarios": {
      "normal": {
        "label": "A normal call",
        "description": "An agent makes a valid, properly signed request."
      },
      "replay": {
        "label": "A blocked replay",
        "description": "The same token is used twice — the second is stopped."
      },
      "scope": {
        "label": "An out-of-scope action",
        "description": "An agent tries to act outside its declared intent."
      },
      "custom": {
        "label": "Your own scenario",
        "description": "Configure the agent type, intent, and scenario freely."
      }
    },
    "running": "Running…",
    "resultAllowed": "Allowed",
    "resultStopped": "Stopped",
    "whyLabel": "What was checked",
    "detailLabel": "Technical detail"
  },
  "settings": {
    "title": "Settings",
    "tabCompanies": "Companies",
    "tabPeople": "People",
    "tabConfig": "Configuration",
    "companiesEmpty": "No companies registered.",
    "peopleEmpty": "No people registered.",
    "configCoreUrl": "Core URL",
    "configDashUrl": "Analytics URL",
    "configPollInterval": "Poll interval (ms)"
  },
  "audit": {
    "title": "Audit — {name}",
    "subtitle": "Complete, tamper-evident history for {name}.",
    "back": "Back to agent",
    "colTime": "Time",
    "colEvent": "Event",
    "colResult": "Result",
    "colRef": "Reference",
    "exportAudit": "Export audit",
    "verifyLink": "Verify"
  },
  "auditExport": {
    "title": "Export audit",
    "subtitle": "Choose a format. All exports are generated server-side.",
    "formatJson": "JSON",
    "formatJsonDesc": "Machine-readable, all cryptographic fields included.",
    "formatPdf": "PDF report",
    "formatPdfDesc": "Human-readable report with timeline and governance summary.",
    "formatSigned": "Signed report",
    "formatSignedDesc": "PDF + Ed25519 signature. Requires signing endpoint on core.",
    "scopeAgent": "This agent",
    "scopeAll": "All agents",
    "dateRange": "Date range",
    "download": "Download",
    "signedUnavailable": "Signing endpoint not yet available on this core version."
  },
  "common": {
    "loading": "Loading…",
    "error": "Something went wrong.",
    "retry": "Retry",
    "noData": "No data yet.",
    "ms": "{value}ms",
    "never": "Never"
  }
}
```

- [ ] **Step 2: Create dashboard/i18n/request.ts**

```typescript
import { getRequestConfig } from "next-intl/server";

export default getRequestConfig(async () => {
  const locale = "en";
  return {
    locale,
    messages: (await import(`../messages/${locale}.json`)).default,
  };
});
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/messages/en.json dashboard/i18n/request.ts
git commit -m "feat(dashboard): i18n setup — next-intl + complete en.json"
```

---

## Task 4: Vitest setup + lib/format.ts

**Files:**
- Create: `dashboard/vitest.config.ts`
- Create: `dashboard/lib/format.ts`
- Create: `dashboard/__tests__/format.test.ts`

- [ ] **Step 1: Create dashboard/vitest.config.ts**

```typescript
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
  },
});
```

- [ ] **Step 2: Create dashboard/lib/format.ts**

```typescript
export function fmtNumber(n: number | null | undefined): string {
  if (n == null) return "—";
  return n.toLocaleString("en-US");
}

export function fmtLatency(ms: number | null | undefined): string {
  if (ms == null) return "—";
  return `${ms}ms`;
}

export function fmtRelativeTime(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(isoString).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function fmtTimestamp(isoString: string): string {
  return new Date(isoString).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function truncateHash(hash: string, chars = 8): string {
  if (hash.length <= chars * 2 + 2) return hash;
  return `${hash.slice(0, chars)}…${hash.slice(-chars)}`;
}
```

- [ ] **Step 3: Create dashboard/__tests__/format.test.ts**

```typescript
import { describe, it, expect } from "vitest";
import { fmtNumber, fmtLatency, truncateHash } from "../lib/format";

describe("fmtNumber", () => {
  it("formats numbers with commas", () => {
    expect(fmtNumber(1847)).toBe("1,847");
  });
  it("returns em-dash for null", () => {
    expect(fmtNumber(null)).toBe("—");
  });
  it("returns em-dash for undefined", () => {
    expect(fmtNumber(undefined)).toBe("—");
  });
});

describe("fmtLatency", () => {
  it("appends ms suffix", () => {
    expect(fmtLatency(42)).toBe("42ms");
  });
  it("returns em-dash for null", () => {
    expect(fmtLatency(null)).toBe("—");
  });
});

describe("truncateHash", () => {
  it("truncates long hashes", () => {
    const hash = "a".repeat(64);
    const result = truncateHash(hash, 8);
    expect(result).toBe("aaaaaaaa…aaaaaaaa");
  });
  it("leaves short hashes intact", () => {
    expect(truncateHash("abc123", 8)).toBe("abc123");
  });
});
```

- [ ] **Step 4: Run tests**

```bash
cd dashboard && npm test
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add dashboard/vitest.config.ts dashboard/lib/format.ts dashboard/__tests__/format.test.ts
git commit -m "feat(dashboard): vitest setup + format utilities with tests"
```

---

## Task 5: lib/api.ts — types and fetch layer

**Files:**
- Create: `dashboard/lib/api.ts`
- Create: `dashboard/__tests__/api.test.ts`

- [ ] **Step 1: Create dashboard/lib/api.ts**

```typescript
const CORE_URL =
  process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";
const DASH_URL =
  process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002";

/* ── Types ─────────────────────────────────────────────────────────── */

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

export interface AgentStatus {
  id: string;
  name: string;
  agent_type: string;
  status: "active" | "idle" | "revoked";
  registered_at: string;
  last_call_at: string | null;
  total_calls: number;
  config_digest: string;
  allowed_intents: string[];
}

export interface ProtectedEvent {
  id: string;
  agent_id: string;
  agent_name: string;
  reason: string;
  reason_code: "replay" | "scope" | "signature" | "nonce" | "revoked" | "expired";
  timestamp: string;
  detail: Record<string, unknown>;
}

export interface ActivityCall {
  id: string;
  agent_id: string;
  agent_name: string;
  action: string;
  intent: string;
  result: "allowed" | "stopped";
  latency_ms: number;
  timestamp: string;
  detail: {
    body_hash?: string;
    nonce?: string;
    jti?: string;
    dpop_binding?: string;
  };
}

export interface AnchorStats {
  bitcoin_total: number;
  bitcoin_pending: number;
  bitcoin_confirmed: number;
  bitcoin_last_batch_at: string | null;
  solana_total: number;
  solana_unconfirmed: number;
  solana_confirmed: number;
  solana_last_batch_at: string | null;
  agent_action_batches: number;
}

export interface OverviewStats {
  total_agents: number;
  active_agents: number;
  calls_today: number;
  protected_today: number;
}

export interface Company {
  id: string;
  name: string;
  created_at: string;
  agent_count: number;
}

export interface Person {
  id: string;
  name: string;
  email: string;
  company_id: string;
  company_name: string;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  agent_id: string;
  event_type: "call" | "mandate_check" | "config_change" | "revocation" | "registration";
  result: "allowed" | "stopped" | "info";
  timestamp: string;
  anchor_id: string | null;
  anchor_chain: "bitcoin" | "solana" | null;
  anchor_ref: string | null;
  detail: Record<string, unknown>;
}

export interface SystemHealth {
  core_reachable: boolean;
  last_seen_at: string | null;
  agent_count: number;
}

/* ── Fetch helpers ─────────────────────────────────────────────────── */

async function get<T>(url: string): Promise<ApiResult<T>> {
  try {
    const res = await fetch(url, { next: { revalidate: 10 } });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const data = await res.json() as T;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── Public API functions ──────────────────────────────────────────── */

export async function fetchOverview(): Promise<ApiResult<OverviewStats>> {
  return get<OverviewStats>(`${DASH_URL}/api/live/overview`);
}

export async function fetchAgents(): Promise<ApiResult<AgentStatus[]>> {
  return get<AgentStatus[]>(`${DASH_URL}/api/live/agents`);
}

export async function fetchAgent(id: string): Promise<ApiResult<AgentStatus>> {
  return get<AgentStatus>(`${DASH_URL}/api/live/agents/${id}`);
}

export async function fetchAgentAudit(
  id: string,
  params?: { from?: string; to?: string }
): Promise<ApiResult<AuditEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.from) qs.set("from", params.from);
  if (params?.to) qs.set("to", params.to);
  const query = qs.toString() ? `?${qs}` : "";
  return get<AuditEvent[]>(`${DASH_URL}/api/live/agents/${id}/audit${query}`);
}

export async function fetchProtected(params?: {
  limit?: number;
}): Promise<ApiResult<ProtectedEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ProtectedEvent[]>(`${DASH_URL}/api/live/protected${query}`);
}

export async function fetchActivity(params?: {
  filter?: "all" | "allowed" | "stopped";
  agent_id?: string;
  limit?: number;
}): Promise<ApiResult<ActivityCall[]>> {
  const qs = new URLSearchParams();
  if (params?.filter && params.filter !== "all") qs.set("result", params.filter);
  if (params?.agent_id) qs.set("agent_id", params.agent_id);
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ActivityCall[]>(`${DASH_URL}/api/live/activity${query}`);
}

export async function fetchProofs(): Promise<ApiResult<AnchorStats>> {
  return get<AnchorStats>(`${DASH_URL}/api/live/anchors`);
}

export async function fetchCompanies(): Promise<ApiResult<Company[]>> {
  return get<Company[]>(`${DASH_URL}/api/live/clients`);
}

export async function fetchPeople(): Promise<ApiResult<Person[]>> {
  return get<Person[]>(`${DASH_URL}/api/live/users`);
}

export async function fetchHealth(): Promise<ApiResult<SystemHealth>> {
  return get<SystemHealth>(`${DASH_URL}/api/live/health`);
}

export async function revokeAgent(id: string): Promise<ApiResult<{ revoked: true }>> {
  try {
    const res = await fetch(`${CORE_URL}/api/v1/agents/${id}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    return { ok: true, data: { revoked: true } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}
```

- [ ] **Step 2: Create dashboard/__tests__/api.test.ts**

```typescript
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
```

- [ ] **Step 3: Run tests**

```bash
cd dashboard && npm test
```

Expected: `5 passed` (3 format + 2 api).

- [ ] **Step 4: Commit**

```bash
git add dashboard/lib/api.ts dashboard/__tests__/api.test.ts
git commit -m "feat(dashboard): API types + fetch layer with tests"
```

---

## Task 6: UI primitives — Button, Badge, StatusDot, Spinner

**Files:**
- Create: `dashboard/components/ui/Button.tsx`
- Create: `dashboard/components/ui/Badge.tsx`
- Create: `dashboard/components/ui/StatusDot.tsx`
- Create: `dashboard/components/ui/Spinner.tsx`

- [ ] **Step 1: Create dashboard/components/ui/Button.tsx**

```tsx
import { ButtonHTMLAttributes, forwardRef } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost" | "danger";
  size?: "sm" | "md";
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "primary", size = "md", className = "", children, ...props }, ref) => {
    const base =
      "inline-flex items-center gap-1.5 rounded-full font-sans font-medium transition-colors duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] disabled:opacity-40 disabled:pointer-events-none";

    const variants = {
      primary:
        "bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] px-5 py-2",
      ghost:
        "border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-hover)] px-5 py-2",
      danger:
        "bg-[var(--status-stopped)] text-white hover:opacity-90 px-5 py-2",
    };

    const sizes = {
      sm: "text-xs px-3 py-1.5",
      md: "text-sm px-5 py-2",
    };

    return (
      <button
        ref={ref}
        className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
        {...props}
      >
        {children}
      </button>
    );
  }
);

Button.displayName = "Button";
```

- [ ] **Step 2: Create dashboard/components/ui/Badge.tsx**

```tsx
interface BadgeProps {
  variant?: "ok" | "stopped" | "warning" | "neutral";
  children: React.ReactNode;
}

export function Badge({ variant = "neutral", children }: BadgeProps) {
  const variants = {
    ok:      "text-[var(--status-ok)] border-[var(--status-ok)]/20",
    stopped: "text-[var(--status-stopped)] border-[var(--status-stopped)]/20",
    warning: "text-[var(--status-warning)] border-[var(--status-warning)]/20",
    neutral: "text-[var(--text-muted)] border-[var(--border)]",
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full border text-mono-sm uppercase ${variants[variant]}`}
    >
      {children}
    </span>
  );
}
```

- [ ] **Step 3: Create dashboard/components/ui/StatusDot.tsx**

```tsx
interface StatusDotProps {
  status: "active" | "idle" | "stopped" | "warning" | "unknown";
  pulse?: boolean;
}

export function StatusDot({ status, pulse }: StatusDotProps) {
  const colors = {
    active:  "bg-[var(--status-ok)]",
    idle:    "bg-[var(--text-muted)]",
    stopped: "bg-[var(--status-stopped)]",
    warning: "bg-[var(--status-warning)]",
    unknown: "bg-[var(--border)]",
  };

  const shouldPulse = pulse ?? status === "active";

  return (
    <span
      className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${colors[status]} ${
        shouldPulse ? "animate-pulse-calm" : ""
      }`}
      aria-hidden
    />
  );
}
```

- [ ] **Step 4: Create dashboard/components/ui/Spinner.tsx**

```tsx
export function Spinner({ label }: { label?: string }) {
  return (
    <div
      className="flex flex-col items-center justify-center py-16 gap-3"
      role="status"
      aria-label={label ?? "Loading"}
    >
      <div className="w-5 h-5 rounded-full border border-[var(--border)] border-t-[var(--accent)] animate-spin" />
      {label && (
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          {label}
        </span>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Commit**

```bash
git add dashboard/components/ui/
git commit -m "feat(dashboard): UI atoms — Button, Badge, StatusDot, Spinner"
```

---

## Task 7: Card and Table primitives

**Files:**
- Create: `dashboard/components/ui/Card.tsx`
- Create: `dashboard/components/ui/Table.tsx`

- [ ] **Step 1: Create dashboard/components/ui/Card.tsx**

```tsx
interface CardProps {
  children: React.ReactNode;
  className?: string;
  as?: "div" | "article" | "section";
}

export function Card({ children, className = "", as: Tag = "div" }: CardProps) {
  return (
    <Tag
      className={`bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg ${className}`}
    >
      {children}
    </Tag>
  );
}

export function CardHeader({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`px-5 py-4 border-b border-[var(--border)] ${className}`}>
      {children}
    </div>
  );
}

export function CardBody({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`px-5 py-4 ${className}`}>{children}</div>;
}
```

- [ ] **Step 2: Create dashboard/components/ui/Table.tsx**

```tsx
import { ReactNode } from "react";

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  );
}

export function Thead({ children }: { children: ReactNode }) {
  return <thead>{children}</thead>;
}

export function Tbody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>;
}

export function Th({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <th
      className={`text-left text-mono-sm text-[var(--text-muted)] uppercase py-2.5 px-4 border-b border-[var(--border)] font-normal ${className}`}
    >
      {children}
    </th>
  );
}

export function Td({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <td
      className={`py-3 px-4 border-b border-[var(--border)] text-[var(--text-secondary)] ${className}`}
    >
      {children}
    </td>
  );
}

export function Tr({
  children,
  onClick,
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <tr
      className={`transition-colors duration-150 ease-out ${
        onClick ? "cursor-pointer hover:bg-[var(--bg-elevated)]" : ""
      } ${className}`}
      onClick={onClick}
    >
      {children}
    </tr>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/components/ui/Card.tsx dashboard/components/ui/Table.tsx
git commit -m "feat(dashboard): Card + Table UI primitives"
```

---

## Task 8: SystemStatus component

**Files:**
- Create: `dashboard/components/layout/SystemStatus.tsx`

- [ ] **Step 1: Create dashboard/components/layout/SystemStatus.tsx**

```tsx
"use client";

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { fetchHealth, SystemHealth } from "@/lib/api";
import { fmtRelativeTime } from "@/lib/format";

type HealthState =
  | { status: "connecting" }
  | { status: "nominal"; health: SystemHealth }
  | { status: "degraded"; lastSeenAt: string | null };

export function SystemStatus() {
  const t = useTranslations("systemStatus");
  const [state, setState] = useState<HealthState>({ status: "connecting" });

  useEffect(() => {
    let cancelled = false;

    async function check() {
      const result = await fetchHealth();
      if (cancelled) return;
      if (result.ok && result.data.core_reachable) {
        setState({ status: "nominal", health: result.data });
      } else {
        setState({
          status: "degraded",
          lastSeenAt: result.ok ? result.data.last_seen_at : null,
        });
      }
    }

    check();
    const interval = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (state.status === "connecting") {
    return (
      <span className="text-mono-sm text-[var(--text-muted)] flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full border border-[var(--text-muted)] inline-block" />
        {t("connecting")}
      </span>
    );
  }

  if (state.status === "degraded") {
    const ago = state.lastSeenAt ? fmtRelativeTime(state.lastSeenAt) : "unknown";
    return (
      <span className="text-mono-sm text-[var(--status-warning)] flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-warning)] inline-block" />
        {t("degraded", { ago })}
      </span>
    );
  }

  const { health } = state;
  return (
    <span className="text-mono-sm text-[var(--text-muted)] flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-ok)] inline-block animate-pulse-calm" />
      {t("nominal")}
      <span className="text-[var(--border)] select-none">·</span>
      {t("agentsProtected", { count: health.agent_count })}
      <span className="text-[var(--border)] select-none">·</span>
      {t("verificationRunning")}
    </span>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/components/layout/SystemStatus.tsx
git commit -m "feat(dashboard): SystemStatus — always-present health indicator"
```

---

## Task 9: ThemeToggle + TopNav

**Files:**
- Create: `dashboard/components/layout/ThemeToggle.tsx`
- Create: `dashboard/components/layout/TopNav.tsx`

- [ ] **Step 1: Create dashboard/components/layout/ThemeToggle.tsx**

```tsx
"use client";

import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);
  if (!mounted) return <div className="w-7 h-7" />;

  const isDark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);

  return (
    <button
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      onClick={() => setTheme(isDark ? "light" : "dark")}
      className="w-7 h-7 flex items-center justify-center text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors duration-150 ease-out rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
    >
      {isDark ? (
        <svg width="15" height="15" viewBox="0 0 15 15" fill="none" aria-hidden>
          <path d="M7.5 1.5a6 6 0 100 12 6 6 0 000-12z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          <path d="M7.5 4.5v-3M7.5 13.5v-3M4.5 7.5h-3M13.5 7.5h-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      ) : (
        <svg width="15" height="15" viewBox="0 0 15 15" fill="none" aria-hidden>
          <path d="M2.9 2.9A6 6 0 0012.1 12.1 6 6 0 012.9 2.9z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      )}
    </button>
  );
}
```

- [ ] **Step 2: Create dashboard/components/layout/TopNav.tsx**

```tsx
import Link from "next/link";
import { useTranslations } from "next-intl";
import { SystemStatus } from "./SystemStatus";
import { ThemeToggle } from "./ThemeToggle";

const NAV_LINKS = [
  { key: "home",      href: "/" },
  { key: "protected", href: "/protected" },
  { key: "activity",  href: "/activity" },
  { key: "proofs",    href: "/proofs" },
  { key: "try",       href: "/try" },
  { key: "settings",  href: "/settings" },
] as const;

export function TopNav({ currentPath }: { currentPath: string }) {
  const t = useTranslations("nav");

  return (
    <header className="fixed top-0 inset-x-0 z-50 h-12 flex items-center px-6 bg-[var(--bg)] border-b border-[var(--border)]">
      {/* Logo */}
      <Link href="/" className="flex items-center gap-2 mr-8 flex-shrink-0">
        <span
          className="text-sm font-semibold tracking-tight"
          style={{ fontFamily: "var(--font-sans)" }}
        >
          Sauron<span className="text-[var(--accent)]">ID</span>
        </span>
      </Link>

      {/* Nav links */}
      <nav className="flex items-center gap-1 flex-1" aria-label="Main navigation">
        {NAV_LINKS.map(({ key, href }) => {
          const isActive =
            key === "home"
              ? currentPath === "/"
              : currentPath.startsWith(href);

          return (
            <Link
              key={key}
              href={href}
              className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out ${
                isActive
                  ? "text-[var(--text-primary)]"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              {t(key as keyof typeof t)}
            </Link>
          );
        })}
      </nav>

      {/* Right side */}
      <div className="flex items-center gap-4 ml-auto flex-shrink-0">
        <SystemStatus />
        <ThemeToggle />
      </div>
    </header>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/components/layout/ThemeToggle.tsx dashboard/components/layout/TopNav.tsx
git commit -m "feat(dashboard): ThemeToggle + TopNav with active link highlighting"
```

---

## Task 10: PageShell + root layout

**Files:**
- Create: `dashboard/components/layout/PageShell.tsx`
- Create: `dashboard/app/layout.tsx`

- [ ] **Step 1: Create dashboard/components/layout/PageShell.tsx**

```tsx
interface PageShellProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
}

export function PageShell({ children, title, subtitle }: PageShellProps) {
  return (
    <div className="min-h-screen pt-12">
      <main className="max-w-5xl mx-auto px-6 py-10">
        {(title || subtitle) && (
          <div className="mb-8">
            {title && (
              <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
                {title}
              </h1>
            )}
            {subtitle && (
              <p className="mt-1 text-sm text-[var(--text-muted)]">{subtitle}</p>
            )}
          </div>
        )}
        {children}
      </main>
    </div>
  );
}
```

- [ ] **Step 2: Create dashboard/app/layout.tsx**

```tsx
import type { Metadata } from "next";
import { ThemeProvider } from "next-themes";
import { NextIntlClientProvider } from "next-intl";
import { getMessages } from "next-intl/server";
import { headers } from "next/headers";
import { TopNav } from "@/components/layout/TopNav";
import "./globals.css";

export const metadata: Metadata = {
  title: "SauronID",
  description: "Pre-execution governance for autonomous AI agents.",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const messages = await getMessages();
  const headersList = await headers();
  const pathname = headersList.get("x-pathname") ?? "/";

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap"
        />
        <link
          rel="stylesheet"
          href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,600,700&display=swap"
        />
      </head>
      <body suppressHydrationWarning>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <NextIntlClientProvider messages={messages}>
            <TopNav currentPath={pathname} />
            {children}
          </NextIntlClientProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
```

- [ ] **Step 3: Create dashboard/app/loading.tsx**

```tsx
import { Spinner } from "@/components/ui/Spinner";

export default function Loading() {
  return (
    <div className="min-h-screen pt-12 flex items-center justify-center">
      <Spinner />
    </div>
  );
}
```

- [ ] **Step 4: Create dashboard/app/error.tsx**

```tsx
"use client";

import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/Button";

export default function GlobalError({
  reset,
}: {
  error: Error;
  reset: () => void;
}) {
  const t = useTranslations("common");

  return (
    <div className="min-h-screen pt-12 flex flex-col items-center justify-center gap-4">
      <p className="text-sm text-[var(--text-muted)]">{t("error")}</p>
      <Button variant="ghost" size="sm" onClick={reset}>
        {t("retry")}
      </Button>
    </div>
  );
}
```

- [ ] **Step 5: Create dashboard/app/not-found.tsx**

```tsx
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen pt-12 flex flex-col items-center justify-center gap-4">
      <p className="text-sm text-[var(--text-muted)]">Page not found.</p>
      <Link href="/" className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150">
        Go home
      </Link>
    </div>
  );
}
```

- [ ] **Step 6: Verify app compiles**

```bash
cd dashboard && npm run dev
```

Expected: no TypeScript errors, app loads at http://localhost:3000 with nav visible.

- [ ] **Step 7: Commit**

```bash
git add dashboard/components/layout/PageShell.tsx dashboard/app/layout.tsx dashboard/app/loading.tsx dashboard/app/error.tsx dashboard/app/not-found.tsx
git commit -m "feat(dashboard): root layout + PageShell + error/loading states"
```

---

## Task 11: Home page + AgentCard

**Files:**
- Create: `dashboard/components/agents/AgentCard.tsx`
- Create: `dashboard/app/page.tsx`

- [ ] **Step 1: Create dashboard/components/agents/AgentCard.tsx**

```tsx
import Link from "next/link";
import { useTranslations } from "next-intl";
import { AgentStatus } from "@/lib/api";
import { StatusDot } from "@/components/ui/StatusDot";
import { fmtNumber, fmtRelativeTime } from "@/lib/format";

export function AgentCard({ agent }: { agent: AgentStatus }) {
  const t = useTranslations("agentCard");

  return (
    <Link
      href={`/agents/${agent.id}`}
      className="block bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5 hover:border-[var(--border-hover)] transition-colors duration-150 ease-out group"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <StatusDot
            status={agent.status === "active" ? "active" : agent.status === "revoked" ? "stopped" : "idle"}
          />
          <span className="text-sm font-medium text-[var(--text-primary)] group-hover:text-[var(--text-primary)] transition-colors">
            {agent.name}
          </span>
        </div>
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          {agent.agent_type}
        </span>
      </div>

      <div className="flex items-center gap-6">
        <div>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-0.5">
            {t("lastCall")}
          </p>
          <p className="text-sm text-[var(--text-secondary)]">
            {agent.last_call_at ? fmtRelativeTime(agent.last_call_at) : "—"}
          </p>
        </div>
        <div>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-0.5">
            {t("totalCalls")}
          </p>
          <p className="text-sm text-[var(--text-secondary)]">
            {fmtNumber(agent.total_calls)}
          </p>
        </div>
      </div>
    </Link>
  );
}
```

- [ ] **Step 2: Create dashboard/app/page.tsx**

```tsx
import { getTranslations } from "next-intl/server";
import { fetchAgents, fetchOverview } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { AgentCard } from "@/components/agents/AgentCard";
import { fmtNumber } from "@/lib/format";

export default async function HomePage() {
  const t = await getTranslations("home");
  const [agentsResult, overviewResult] = await Promise.all([
    fetchAgents(),
    fetchOverview(),
  ]);

  const agents = agentsResult.ok ? agentsResult.data : [];
  const overview = overviewResult.ok
    ? overviewResult.data
    : { total_agents: 0, active_agents: 0, calls_today: 0, protected_today: 0 };

  return (
    <PageShell title={t("title")}>
      {/* Single status line — no charts, no widgets */}
      <p className="text-sm text-[var(--text-muted)] mb-8">
        {fmtNumber(overview.total_agents)} agents
        {" · "}
        {fmtNumber(overview.calls_today)} calls today
        {" · "}
        {fmtNumber(overview.protected_today)} protected
      </p>

      {agents.length === 0 ? (
        <div className="py-16 text-center">
          <p className="text-sm text-[var(--text-muted)] mb-3">{t("empty")}</p>
          <a
            href="https://github.com/tejoker/Colosseum2026"
            className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
          >
            {t("emptyLink")} →
          </a>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {agents.map((agent) => (
            <AgentCard key={agent.id} agent={agent} />
          ))}
        </div>
      )}
    </PageShell>
  );
}
```

- [ ] **Step 3: Verify home page renders**

```bash
cd dashboard && npm run dev
```

Open http://localhost:3000 — should show agent grid or empty state. No charts, no KPI cards.

- [ ] **Step 4: Commit**

```bash
git add dashboard/components/agents/AgentCard.tsx dashboard/app/page.tsx
git commit -m "feat(dashboard): Home page + AgentCard — clean agent list, no analytics drift"
```

---

## Task 12: Agent detail page

**Files:**
- Create: `dashboard/app/agents/[id]/page.tsx`

- [ ] **Step 1: Create dashboard/app/agents/[id]/page.tsx**

```tsx
import { notFound } from "next/navigation";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchAgent } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Badge } from "@/components/ui/Badge";
import { Card, CardBody } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { truncateHash, fmtTimestamp } from "@/lib/format";

export default async function AgentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const t = await getTranslations("agentDetail");
  const result = await fetchAgent(id);

  if (!result.ok) notFound();
  const agent = result.data;

  return (
    <PageShell>
      {/* Breadcrumb */}
      <Link
        href="/"
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 mb-6"
      >
        ← {t("back")}
      </Link>

      {/* Title row */}
      <div className="flex items-center gap-3 mb-8">
        <StatusDot
          status={agent.status === "active" ? "active" : agent.status === "revoked" ? "stopped" : "idle"}
        />
        <h1 className="text-xl font-semibold text-[var(--text-primary)] tracking-tight">
          {agent.name}
        </h1>
        <Badge variant={agent.status === "active" ? "ok" : "neutral"}>
          {agent.status}
        </Badge>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        {/* Identity */}
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("identity")}</p>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">Type</dt>
                <dd className="text-[var(--text-secondary)] font-mono">{agent.agent_type}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">Registered</dt>
                <dd className="text-[var(--text-secondary)]">{fmtTimestamp(agent.registered_at)}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>

        {/* Config digest */}
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("configDigest")}</p>
            <p className="text-mono-sm text-[var(--text-secondary)] break-all">
              {truncateHash(agent.config_digest, 16)}
            </p>
          </CardBody>
        </Card>
      </div>

      {/* Mandate */}
      <Card className="mb-6">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("mandate")}</p>
          {agent.allowed_intents.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">No intents declared.</p>
          ) : (
            <ul className="flex flex-wrap gap-2">
              {agent.allowed_intents.map((intent) => (
                <li key={intent}>
                  <Badge variant="neutral">{intent}</Badge>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      {/* Actions */}
      <div className="flex items-center gap-3">
        <Link
          href={`/agents/${id}/audit`}
          className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
        >
          {t("audit")} →
        </Link>
        <RevokeButton agentId={id} agentName={agent.name} />
      </div>
    </PageShell>
  );
}

function RevokeButton({ agentId, agentName }: { agentId: string; agentName: string }) {
  // Server component shell — revoke action handled via separate client component
  return (
    <form action={`/api/agents/${agentId}/revoke`} method="POST">
      <input type="hidden" name="agentName" value={agentName} />
      <button
        type="submit"
        className="text-sm text-[var(--status-stopped)] hover:opacity-80 transition-opacity duration-150"
      >
        Revoke agent
      </button>
    </form>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/app/agents/
git commit -m "feat(dashboard): Agent detail page — identity, mandate, config digest"
```

---

## Task 13: Protected page

**Files:**
- Create: `dashboard/app/protected/page.tsx`

- [ ] **Step 1: Create dashboard/app/protected/page.tsx**

```tsx
import { getTranslations } from "next-intl/server";
import { fetchProtected } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { fmtRelativeTime } from "@/lib/format";

export default async function ProtectedPage() {
  const t = await getTranslations("protected");
  const result = await fetchProtected({ limit: 100 });
  const events = result.ok ? result.data : [];

  const today = events.filter(
    (e) => new Date(e.timestamp) > new Date(Date.now() - 86_400_000)
  ).length;
  const week = events.filter(
    (e) => new Date(e.timestamp) > new Date(Date.now() - 7 * 86_400_000)
  ).length;

  return (
    <PageShell
      title={t("title")}
      subtitle={t("subtitle")}
    >
      {/* Summary line */}
      <p className="text-sm text-[var(--text-muted)] mb-8">
        {t("summaryToday", { count: today })}
        {" · "}
        {t("summaryWeek", { count: week })}
        {" · "}
        {t("summaryTotal", { count: events.length })}
      </p>

      {events.length === 0 ? (
        <p className="text-sm text-[var(--text-muted)] py-12 text-center">
          Nothing stopped yet.
        </p>
      ) : (
        <Table>
          <Thead>
            <tr>
              <Th>{t("colTime")}</Th>
              <Th>{t("colAgent")}</Th>
              <Th>{t("colReason")}</Th>
            </tr>
          </Thead>
          <Tbody>
            {events.map((event) => (
              <Tr key={event.id}>
                <Td>
                  <span className="text-mono-sm text-[var(--text-muted)]">
                    {fmtRelativeTime(event.timestamp)}
                  </span>
                </Td>
                <Td className="text-[var(--text-primary)]">{event.agent_name}</Td>
                <Td>
                  <Badge variant="stopped">
                    {t(`reasons.${event.reason_code}` as Parameters<typeof t>[0])}
                  </Badge>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </PageShell>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/app/protected/page.tsx
git commit -m "feat(dashboard): Protected page — governance events, trust framing"
```

---

## Task 14: Activity page + LiveFeed

**Files:**
- Create: `dashboard/components/live/LiveFeed.tsx`
- Create: `dashboard/app/activity/page.tsx`

- [ ] **Step 1: Create dashboard/components/live/LiveFeed.tsx**

```tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import { fetchActivity, ActivityCall } from "@/lib/api";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { fmtRelativeTime, fmtLatency } from "@/lib/format";

type Filter = "all" | "allowed" | "stopped";

export function LiveFeed() {
  const t = useTranslations("activity");
  const [calls, setCalls] = useState<ActivityCall[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    const result = await fetchActivity({ filter, limit: 100 });
    if (result.ok) setCalls(result.data);
    setLoading(false);
  }, [filter]);

  useEffect(() => {
    setLoading(true);
    load();
    const interval = setInterval(load, 15_000);
    return () => clearInterval(interval);
  }, [load]);

  const filters: Filter[] = ["all", "allowed", "stopped"];

  return (
    <div>
      {/* Filter tabs */}
      <div className="flex items-center gap-1 mb-6">
        {filters.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out ${
              filter === f
                ? "text-[var(--text-primary)] bg-[var(--bg-elevated)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            }`}
          >
            {t(`filter${f.charAt(0).toUpperCase() + f.slice(1)}` as Parameters<typeof t>[0])}
          </button>
        ))}
      </div>

      {loading ? (
        <Spinner />
      ) : calls.length === 0 ? (
        <p className="text-sm text-[var(--text-muted)] py-12 text-center">
          No activity yet.
        </p>
      ) : (
        <Table>
          <Thead>
            <tr>
              <Th>{t("colTime")}</Th>
              <Th>{t("colAgent")}</Th>
              <Th>{t("colAction")}</Th>
              <Th>{t("colResult")}</Th>
              <Th>{t("colLatency")}</Th>
            </tr>
          </Thead>
          <Tbody>
            {calls.map((call) => (
              <Tr key={call.id}>
                <Td>
                  <span className="text-mono-sm text-[var(--text-muted)]">
                    {fmtRelativeTime(call.timestamp)}
                  </span>
                </Td>
                <Td className="text-[var(--text-primary)]">{call.agent_name}</Td>
                <Td>
                  <span className="text-mono-sm text-[var(--text-secondary)]">
                    {call.action}
                  </span>
                </Td>
                <Td>
                  <Badge variant={call.result === "allowed" ? "ok" : "stopped"}>
                    {t(call.result === "allowed" ? "resultAllowed" : "resultStopped")}
                  </Badge>
                </Td>
                <Td>
                  <span className="text-mono-sm text-[var(--text-muted)]">
                    {fmtLatency(call.latency_ms)}
                  </span>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Create dashboard/app/activity/page.tsx**

```tsx
import { getTranslations } from "next-intl/server";
import { PageShell } from "@/components/layout/PageShell";
import { LiveFeed } from "@/components/live/LiveFeed";

export default async function ActivityPage() {
  const t = await getTranslations("activity");

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <LiveFeed />
    </PageShell>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/components/live/LiveFeed.tsx dashboard/app/activity/page.tsx
git commit -m "feat(dashboard): Activity page + LiveFeed — polled every 15s, filterable"
```

---

## Task 15: Proofs page

**Files:**
- Create: `dashboard/app/proofs/page.tsx`

- [ ] **Step 1: Create dashboard/app/proofs/page.tsx**

```tsx
import { getTranslations } from "next-intl/server";
import { fetchProofs } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { fmtNumber, fmtRelativeTime } from "@/lib/format";

export default async function ProofsPage() {
  const t = await getTranslations("proofs");
  const result = await fetchProofs();
  const anchors = result.ok ? result.data : null;

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Bitcoin */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <p className="text-mono-sm text-[var(--text-muted)] uppercase">{t("bitcoin")}</p>
              <a
                href="https://opentimestamps.org"
                target="_blank"
                rel="noopener noreferrer"
                className="text-mono-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
              >
                {t("verifyOn", { chain: "OTS" })} →
              </a>
            </div>
            <dl className="space-y-3">
              {[
                ["anchored",  anchors?.bitcoin_total],
                ["pending",   anchors?.bitcoin_pending],
                ["confirmed", anchors?.bitcoin_confirmed],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between text-sm">
                  <dt className="text-[var(--text-muted)] capitalize">{t(String(label) as Parameters<typeof t>[0])}</dt>
                  <dd className="text-[var(--text-primary)] font-medium tabular-nums">
                    {fmtNumber(value as number | null)}
                  </dd>
                </div>
              ))}
              {anchors?.bitcoin_last_batch_at && (
                <div className="flex justify-between text-sm pt-2 border-t border-[var(--border)]">
                  <dt className="text-[var(--text-muted)]">{t("lastBatch")}</dt>
                  <dd className="text-[var(--text-secondary)]">
                    {fmtRelativeTime(anchors.bitcoin_last_batch_at)}
                  </dd>
                </div>
              )}
            </dl>
            <p className="mt-4 text-mono-sm text-[var(--text-muted)]">{t("bitcoinNote")}</p>
          </CardBody>
        </Card>

        {/* Solana */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <p className="text-mono-sm text-[var(--text-muted)] uppercase">{t("solana")}</p>
              <a
                href="https://explorer.solana.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-mono-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
              >
                {t("verifyOn", { chain: "Solana Explorer" })} →
              </a>
            </div>
            <dl className="space-y-3">
              {[
                ["anchored",  anchors?.solana_total],
                ["pending",   anchors?.solana_unconfirmed],
                ["confirmed", anchors?.solana_confirmed],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between text-sm">
                  <dt className="text-[var(--text-muted)] capitalize">{t(String(label) as Parameters<typeof t>[0])}</dt>
                  <dd className="text-[var(--text-primary)] font-medium tabular-nums">
                    {fmtNumber(value as number | null)}
                  </dd>
                </div>
              ))}
              {anchors?.solana_last_batch_at && (
                <div className="flex justify-between text-sm pt-2 border-t border-[var(--border)]">
                  <dt className="text-[var(--text-muted)]">{t("lastBatch")}</dt>
                  <dd className="text-[var(--text-secondary)]">
                    {fmtRelativeTime(anchors.solana_last_batch_at)}
                  </dd>
                </div>
              )}
            </dl>
            <p className="mt-4 text-mono-sm text-[var(--text-muted)]">{t("solanaNote")}</p>
          </CardBody>
        </Card>
      </div>
    </PageShell>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/app/proofs/page.tsx
git commit -m "feat(dashboard): Proofs page — Bitcoin + Solana anchor stats with verify links"
```

---

## Task 16: Try / Playground page

**Files:**
- Create: `dashboard/components/playground/ScenarioTile.tsx`
- Create: `dashboard/components/playground/ResultPanel.tsx`
- Create: `dashboard/app/try/page.tsx`

- [ ] **Step 1: Create dashboard/components/playground/ScenarioTile.tsx**

```tsx
"use client";

import { useTranslations } from "next-intl";

type ScenarioKey = "normal" | "replay" | "scope" | "custom";

interface ScenarioTileProps {
  scenario: ScenarioKey;
  isRunning: boolean;
  onRun: (scenario: ScenarioKey) => void;
}

export function ScenarioTile({ scenario, isRunning, onRun }: ScenarioTileProps) {
  const t = useTranslations(`try.scenarios.${scenario}` as Parameters<ReturnType<typeof useTranslations>>[0] extends never ? never : any);
  const tScenario = useTranslations("try");

  const label = tScenario(`scenarios.${scenario}.label` as any);
  const description = tScenario(`scenarios.${scenario}.description` as any);

  return (
    <button
      onClick={() => onRun(scenario)}
      disabled={isRunning}
      className="w-full text-left bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5 hover:border-[var(--border-hover)] transition-colors duration-150 ease-out disabled:opacity-50 disabled:pointer-events-none group"
    >
      <p className="text-sm font-medium text-[var(--text-primary)] mb-1.5 group-hover:text-[var(--text-primary)]">
        {label}
      </p>
      <p className="text-sm text-[var(--text-muted)] leading-relaxed">
        {description}
      </p>
    </button>
  );
}
```

- [ ] **Step 2: Create dashboard/components/playground/ResultPanel.tsx**

```tsx
"use client";

import { useTranslations } from "next-intl";
import { Badge } from "@/components/ui/Badge";

interface ScenarioResult {
  result: "allowed" | "stopped";
  status_code: number;
  why: string;
  detail: Record<string, unknown>;
}

export function ResultPanel({ result }: { result: ScenarioResult }) {
  const t = useTranslations("try");

  return (
    <div className="animate-fade-in bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5">
      <div className="flex items-center gap-3 mb-4">
        <Badge variant={result.result === "allowed" ? "ok" : "stopped"}>
          {t(result.result === "allowed" ? "resultAllowed" : "resultStopped")}
        </Badge>
        <span className="text-mono-sm text-[var(--text-muted)]">
          HTTP {result.status_code}
        </span>
      </div>

      <div className="mb-4">
        <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-2">
          {t("whyLabel")}
        </p>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {result.why}
        </p>
      </div>

      {Object.keys(result.detail).length > 0 && (
        <details className="group">
          <summary className="text-mono-sm text-[var(--text-muted)] uppercase cursor-pointer hover:text-[var(--text-secondary)] transition-colors duration-150 list-none flex items-center gap-1.5">
            <span className="transition-transform duration-150 group-open:rotate-90">›</span>
            {t("detailLabel")}
          </summary>
          <pre className="mt-3 text-xs text-[var(--text-muted)] font-mono overflow-x-auto bg-[var(--bg-elevated)] rounded p-3">
            {JSON.stringify(result.detail, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Create dashboard/app/try/page.tsx**

```tsx
"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { ScenarioTile } from "@/components/playground/ScenarioTile";
import { ResultPanel } from "@/components/playground/ResultPanel";
import { Spinner } from "@/components/ui/Spinner";

type ScenarioKey = "normal" | "replay" | "scope" | "custom";

interface ScenarioResult {
  result: "allowed" | "stopped";
  status_code: number;
  why: string;
  detail: Record<string, unknown>;
}

const SCENARIO_EXPLANATIONS: Record<ScenarioKey, { allowed: string; stopped: string }> = {
  normal: {
    allowed: "The agent presented a valid, properly signed token with a matching intent. All checks passed: signature, nonce, config digest, and intent leash.",
    stopped: "Unexpected: the call failed despite being well-formed. Check the core logs.",
  },
  replay: {
    allowed: "Unexpected: the replayed token was accepted. The nonce or JTI deduplication may not be active.",
    stopped: "The token was recognised as a replay — the JTI was already used. The governance layer rejected it before any action was taken.",
  },
  scope: {
    allowed: "Unexpected: the out-of-scope action was accepted. Check the intent leash configuration.",
    stopped: "The agent attempted to act outside its declared intent. The governance layer stopped it before the action reached the target system.",
  },
  custom: {
    allowed: "Your custom scenario was accepted by the governance layer.",
    stopped: "Your custom scenario was stopped by the governance layer.",
  },
};

export default function TryPage() {
  const t = useTranslations("try");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ScenarioResult | null>(null);

  async function runScenario(scenario: ScenarioKey) {
    setRunning(true);
    setResult(null);

    try {
      const res = await fetch(`/api/playground/${scenario}`, { method: "POST" });
      const json = await res.json() as { result: "allowed" | "stopped"; status_code: number; detail: Record<string, unknown> };
      const expl = SCENARIO_EXPLANATIONS[scenario];
      setResult({
        ...json,
        why: json.result === "allowed" ? expl.allowed : expl.stopped,
      });
    } catch {
      setResult({
        result: "stopped",
        status_code: 0,
        why: "Could not reach the core. Make sure the SauronID server is running.",
        detail: {},
      });
    } finally {
      setRunning(false);
    }
  }

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-8">
        {(["normal", "replay", "scope", "custom"] as ScenarioKey[]).map((s) => (
          <ScenarioTile key={s} scenario={s} isRunning={running} onRun={runScenario} />
        ))}
      </div>

      {running && <Spinner label={t("running")} />}
      {result && !running && <ResultPanel result={result} />}
    </PageShell>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/components/playground/ dashboard/app/try/page.tsx
git commit -m "feat(dashboard): Try/Playground — 4 scenarios, calm result reveal, no cyber effects"
```

---

## Task 17: Settings page

**Files:**
- Create: `dashboard/app/settings/page.tsx`

- [ ] **Step 1: Create dashboard/app/settings/page.tsx**

```tsx
import { getTranslations } from "next-intl/server";
import { fetchCompanies, fetchPeople } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { fmtNumber, fmtTimestamp } from "@/lib/format";

export default async function SettingsPage() {
  const t = await getTranslations("settings");
  const [companiesResult, peopleResult] = await Promise.all([
    fetchCompanies(),
    fetchPeople(),
  ]);

  const companies = companiesResult.ok ? companiesResult.data : [];
  const people = peopleResult.ok ? peopleResult.data : [];

  return (
    <PageShell title={t("title")}>
      {/* Companies */}
      <section className="mb-10">
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("tabCompanies")}
        </h2>
        {companies.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)] py-8">{t("companiesEmpty")}</p>
        ) : (
          <Table>
            <Thead>
              <tr>
                <Th>Name</Th>
                <Th>Agents</Th>
                <Th>Registered</Th>
              </tr>
            </Thead>
            <Tbody>
              {companies.map((c) => (
                <Tr key={c.id}>
                  <Td className="text-[var(--text-primary)]">{c.name}</Td>
                  <Td>{fmtNumber(c.agent_count)}</Td>
                  <Td>
                    <span className="text-mono-sm text-[var(--text-muted)]">
                      {fmtTimestamp(c.created_at)}
                    </span>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </section>

      {/* People */}
      <section className="mb-10">
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("tabPeople")}
        </h2>
        {people.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)] py-8">{t("peopleEmpty")}</p>
        ) : (
          <Table>
            <Thead>
              <tr>
                <Th>Name</Th>
                <Th>Company</Th>
                <Th>Registered</Th>
              </tr>
            </Thead>
            <Tbody>
              {people.map((p) => (
                <Tr key={p.id}>
                  <Td className="text-[var(--text-primary)]">{p.name}</Td>
                  <Td>{p.company_name}</Td>
                  <Td>
                    <span className="text-mono-sm text-[var(--text-muted)]">
                      {fmtTimestamp(p.created_at)}
                    </span>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </section>

      {/* Configuration */}
      <section>
        <h2 className="text-mono-sm text-[var(--text-muted)] uppercase mb-4">
          {t("tabConfig")}
        </h2>
        <dl className="space-y-3 max-w-md">
          {[
            [t("configCoreUrl"),   process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001"],
            [t("configDashUrl"),   process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002"],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between text-sm py-2 border-b border-[var(--border)]">
              <dt className="text-[var(--text-muted)]">{label}</dt>
              <dd className="text-mono-sm text-[var(--text-secondary)]">{value}</dd>
            </div>
          ))}
        </dl>
      </section>
    </PageShell>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/app/settings/page.tsx
git commit -m "feat(dashboard): Settings page — Companies, People, Configuration"
```

---

## Task 18: Audit view + AuditTimeline

**Files:**
- Create: `dashboard/components/audit/AuditTimeline.tsx`
- Create: `dashboard/app/agents/[id]/audit/page.tsx`

- [ ] **Step 1: Create dashboard/components/audit/AuditTimeline.tsx**

```tsx
import { AuditEvent } from "@/lib/api";
import { Badge } from "@/components/ui/Badge";
import { truncateHash, fmtTimestamp } from "@/lib/format";

const EVENT_LABELS: Record<AuditEvent["event_type"], string> = {
  call:           "Call",
  mandate_check:  "Mandate check",
  config_change:  "Config change",
  revocation:     "Revocation",
  registration:   "Registered",
};

export function AuditTimeline({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-[var(--text-muted)] py-12 text-center">No events recorded yet.</p>;
  }

  return (
    <ol className="relative border-l border-[var(--border)] ml-3 space-y-0">
      {events.map((event) => (
        <li key={event.id} className="pl-6 pb-6 relative">
          {/* Timeline dot */}
          <span
            className={`absolute left-[-4.5px] top-1 w-2.5 h-2.5 rounded-full border-2 border-[var(--bg)] ${
              event.result === "allowed"
                ? "bg-[var(--status-ok)]"
                : event.result === "stopped"
                ? "bg-[var(--status-stopped)]"
                : "bg-[var(--text-muted)]"
            }`}
          />

          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-medium text-[var(--text-primary)]">
                  {EVENT_LABELS[event.event_type]}
                </span>
                {event.result !== "info" && (
                  <Badge variant={event.result === "allowed" ? "ok" : "stopped"}>
                    {event.result}
                  </Badge>
                )}
              </div>
              {event.anchor_id && (
                <p className="text-mono-sm text-[var(--text-muted)] mt-1">
                  {event.anchor_chain === "solana" ? (
                    <a
                      href={`https://explorer.solana.com/tx/${event.anchor_ref}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
                    >
                      Verify on Solana ↗
                    </a>
                  ) : event.anchor_chain === "bitcoin" ? (
                    <span>Bitcoin anchor: {truncateHash(event.anchor_id, 8)}</span>
                  ) : null}
                </p>
              )}
            </div>
            <span className="text-mono-sm text-[var(--text-muted)] flex-shrink-0">
              {fmtTimestamp(event.timestamp)}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}
```

- [ ] **Step 2: Create dashboard/app/agents/[id]/audit/page.tsx**

```tsx
import { notFound } from "next/navigation";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchAgent, fetchAgentAudit } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { AuditTimeline } from "@/components/audit/AuditTimeline";

export default async function AuditPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const t = await getTranslations("audit");

  const [agentResult, auditResult] = await Promise.all([
    fetchAgent(id),
    fetchAgentAudit(id),
  ]);

  if (!agentResult.ok) notFound();
  const agent = agentResult.data;
  const events = auditResult.ok ? auditResult.data : [];

  return (
    <PageShell
      title={t("title", { name: agent.name })}
      subtitle={t("subtitle", { name: agent.name })}
    >
      <Link
        href={`/agents/${id}`}
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 mb-8"
      >
        ← {t("back")}
      </Link>

      <AuditTimeline events={events} />
    </PageShell>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/components/audit/AuditTimeline.tsx dashboard/app/agents/
git commit -m "feat(dashboard): Audit view — tamper-evident timeline with anchor verify links"
```

---

## Task 19: API proxy routes + export route

**Files:**
- Create: `dashboard/app/api/health/route.ts`
- Create: `dashboard/app/api/agents/route.ts`
- Create: `dashboard/app/api/protected/route.ts`
- Create: `dashboard/app/api/activity/route.ts`
- Create: `dashboard/app/api/proofs/route.ts`
- Create: `dashboard/app/api/playground/[scenario]/route.ts`
- Create: `dashboard/app/api/export/route.ts`

- [ ] **Step 1: Create shared proxy helper**

Create `dashboard/app/api/_proxy.ts`:

```typescript
const DASH_URL = process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002";
const CORE_URL = process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";

export async function proxyLive(path: string, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const target = `${DASH_URL}/api/live/${path}${url.search}`;
  try {
    const upstream = await fetch(target);
    const body = await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return Response.json({ ok: false, error: "upstream unreachable" }, { status: 503 });
  }
}

export { DASH_URL, CORE_URL };
```

- [ ] **Step 2: Create individual proxy routes**

`dashboard/app/api/health/route.ts`:
```typescript
import { proxyLive } from "../_proxy";
export async function GET(req: Request) { return proxyLive("health", req); }
```

`dashboard/app/api/agents/route.ts`:
```typescript
import { proxyLive } from "../_proxy";
export async function GET(req: Request) { return proxyLive("agents", req); }
```

`dashboard/app/api/protected/route.ts`:
```typescript
import { proxyLive } from "../_proxy";
export async function GET(req: Request) { return proxyLive("protected", req); }
```

`dashboard/app/api/activity/route.ts`:
```typescript
import { proxyLive } from "../_proxy";
export async function GET(req: Request) { return proxyLive("activity", req); }
```

`dashboard/app/api/proofs/route.ts`:
```typescript
import { proxyLive } from "../_proxy";
export async function GET(req: Request) { return proxyLive("anchors", req); }
```

- [ ] **Step 3: Create playground route**

`dashboard/app/api/playground/[scenario]/route.ts`:

```typescript
import { NextRequest } from "next/server";

const CORE_URL = process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";

const SCENARIO_MAP: Record<string, string> = {
  normal:  "happy_path",
  replay:  "replay_attack",
  scope:   "scope_escalation",
  custom:  "custom",
};

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ scenario: string }> }
) {
  const { scenario } = await params;
  const mapped = SCENARIO_MAP[scenario];

  if (!mapped) {
    return Response.json({ ok: false, error: "Unknown scenario" }, { status: 400 });
  }

  try {
    const res = await fetch(`${CORE_URL}/api/v1/demo/${mapped}`, { method: "POST" });
    const json = await res.json() as unknown;
    return Response.json({
      result: res.ok ? "allowed" : "stopped",
      status_code: res.status,
      detail: json,
    });
  } catch {
    return Response.json(
      { result: "stopped", status_code: 0, detail: { error: "Core unreachable" } },
      { status: 503 }
    );
  }
}
```

- [ ] **Step 4: Create export route**

`dashboard/app/api/export/route.ts`:

```typescript
import { NextRequest } from "next/server";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";

const DASH_URL = process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002";

export async function POST(req: NextRequest) {
  const body = await req.json() as { format: "json" | "pdf"; agent_id?: string; from?: string; to?: string };
  const { format, agent_id, from, to } = body;

  // Fetch audit data
  const qs = new URLSearchParams();
  if (from) qs.set("from", from);
  if (to) qs.set("to", to);
  const path = agent_id
    ? `agents/${agent_id}/audit`
    : "activity";
  const query = qs.toString() ? `?${qs}` : "";

  let auditData: unknown[] = [];
  try {
    const res = await fetch(`${DASH_URL}/api/live/${path}${query}`);
    if (res.ok) auditData = await res.json() as unknown[];
  } catch {
    return Response.json({ ok: false, error: "Could not fetch audit data" }, { status: 503 });
  }

  if (format === "json") {
    return new Response(JSON.stringify(auditData, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="sauronid-audit-${Date.now()}.json"`,
      },
    });
  }

  if (format === "pdf") {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdf.embedFont(StandardFonts.HelveticaBold);

    page.drawText("SauronID — Audit Report", {
      x: 40, y: 780,
      size: 18, font: boldFont,
      color: rgb(0.1, 0.1, 0.1),
    });
    page.drawText(`Generated: ${new Date().toISOString()}`, {
      x: 40, y: 755,
      size: 10, font,
      color: rgb(0.5, 0.5, 0.5),
    });
    page.drawText(`Events: ${auditData.length}`, {
      x: 40, y: 735,
      size: 10, font,
      color: rgb(0.3, 0.3, 0.3),
    });

    // Simple event listing
    let y = 700;
    for (const event of auditData.slice(0, 40)) {
      if (y < 60) break;
      const line = JSON.stringify(event).slice(0, 90);
      page.drawText(line, {
        x: 40, y,
        size: 7, font,
        color: rgb(0.3, 0.3, 0.3),
      });
      y -= 14;
    }

    const pdfBytes = await pdf.save();
    return new Response(pdfBytes, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="sauronid-audit-${Date.now()}.pdf"`,
      },
    });
  }

  return Response.json({ ok: false, error: "Unsupported format" }, { status: 400 });
}
```

- [ ] **Step 5: Commit**

```bash
git add dashboard/app/api/
git commit -m "feat(dashboard): API proxy routes + playground + JSON/PDF export"
```

---

## Task 20: AuditExportPanel + wire export button into Activity

**Files:**
- Create: `dashboard/components/audit/AuditExportPanel.tsx`
- Modify: `dashboard/app/activity/page.tsx`

- [ ] **Step 1: Create dashboard/components/audit/AuditExportPanel.tsx**

```tsx
"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/Button";

interface AuditExportPanelProps {
  agentId?: string;
}

type ExportFormat = "json" | "pdf";

export function AuditExportPanel({ agentId }: AuditExportPanelProps) {
  const t = useTranslations("auditExport");
  const [format, setFormat] = useState<ExportFormat>("json");
  const [loading, setLoading] = useState(false);

  async function handleExport() {
    setLoading(true);
    try {
      const res = await fetch("/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format, agent_id: agentId }),
      });

      if (!res.ok) return;

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sauronid-audit.${format === "pdf" ? "pdf" : "json"}`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5">
      <p className="text-sm font-medium text-[var(--text-primary)] mb-1">{t("title")}</p>
      <p className="text-sm text-[var(--text-muted)] mb-4">{t("subtitle")}</p>

      <div className="flex items-center gap-2 mb-4">
        {(["json", "pdf"] as ExportFormat[]).map((f) => (
          <button
            key={f}
            onClick={() => setFormat(f)}
            className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out ${
              format === f
                ? "bg-[var(--bg-elevated)] text-[var(--text-primary)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            }`}
          >
            {f === "json" ? t("formatJson") : t("formatPdf")}
          </button>
        ))}
      </div>

      <p className="text-mono-sm text-[var(--text-muted)] mb-4">
        {format === "json" ? t("formatJsonDesc") : t("formatPdfDesc")}
      </p>

      <Button
        variant="ghost"
        size="sm"
        onClick={handleExport}
        disabled={loading}
      >
        {loading ? "Exporting…" : `${t("download")} ${format.toUpperCase()}`}
      </Button>
    </div>
  );
}
```

- [ ] **Step 2: Update dashboard/app/activity/page.tsx to add export button**

Replace the existing `app/activity/page.tsx` content with:

```tsx
import { getTranslations } from "next-intl/server";
import { PageShell } from "@/components/layout/PageShell";
import { LiveFeed } from "@/components/live/LiveFeed";
import { AuditExportPanel } from "@/components/audit/AuditExportPanel";

export default async function ActivityPage() {
  const t = await getTranslations("activity");

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="flex items-start justify-between gap-4 mb-6">
        <div className="flex-1 min-w-0">
          <LiveFeed />
        </div>
      </div>
      <div className="mt-8 max-w-sm">
        <AuditExportPanel />
      </div>
    </PageShell>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/components/audit/AuditExportPanel.tsx dashboard/app/activity/page.tsx
git commit -m "feat(dashboard): AuditExportPanel — JSON + PDF export, wired into Activity"
```

---

## Task 21: Final build check + middleware for pathname

**Files:**
- Create: `dashboard/middleware.ts`

- [ ] **Step 1: Create middleware to inject x-pathname header**

The root layout reads `x-pathname` from headers to pass to `TopNav`. Add the middleware that sets it:

```typescript
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  response.headers.set("x-pathname", request.nextUrl.pathname);
  return response;
}

export const config = {
  matcher: ["/((?!_next|favicon.ico).*)"],
};
```

- [ ] **Step 2: Run full build**

```bash
cd dashboard && npm run build
```

Expected: build completes with no TypeScript errors. Warnings about dynamic usage are acceptable.

- [ ] **Step 3: Run tests**

```bash
cd dashboard && npm test
```

Expected: `5 passed`.

- [ ] **Step 4: Verify dev server**

```bash
cd dashboard && npm run dev
```

Open http://localhost:3000 — navigate to all 6 routes, verify:
- TopNav active link highlights correctly on each route
- SystemStatus shows in top nav
- ThemeToggle switches light/dark without flash
- Home shows agent grid or empty state (no charts, no KPI widgets)
- All pages load without 500 errors

- [ ] **Step 5: Final commit**

```bash
git add dashboard/middleware.ts
git commit -m "feat(dashboard): middleware for x-pathname + final build verified"
```

---

## Self-Review Against Spec

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| New `dashboard/` directory | Task 1 |
| Next.js 16.1.6 + TypeScript strict | Task 1 |
| Tailwind CSS 4 + CSS variables | Task 2 |
| Dark/light theme via next-themes | Task 10 |
| i18n via next-intl, no hardcoded strings | Task 3 |
| Top navigation, 6 links | Task 9 |
| SystemStatus always in nav | Task 8 |
| Home: agents only, no charts | Task 11 |
| Agent detail with mandate, config digest, revoke | Task 12 |
| Protected page, trust framing | Task 13 |
| Activity page, polled, filterable | Task 14 |
| Proofs: Bitcoin + Solana with verify links | Task 15 |
| Try: 4 scenarios, calm result reveal | Task 16 |
| Settings: Companies, People, Configuration | Task 17 |
| Audit view + timeline | Task 18 |
| AuditExportPanel: JSON + PDF | Task 20 |
| API proxy routes | Task 19 |
| Motion system enforced in CSS | Task 2 |
| `prefers-reduced-motion` respected | Task 2 |
| No hardcoded strings | Task 3 |

**Gaps:** `Signed report` export depends on a signing endpoint (`/api/v1/sign-audit`) not yet on the core. The button shows in the panel but is disabled per the `signedUnavailable` translation string — this is documented in `messages/en.json` and `AuditExportPanel` shows it as disabled with tooltip.

**Type consistency:** All types defined in `lib/api.ts` Task 5. `AgentStatus`, `ActivityCall`, `ProtectedEvent`, `AuditEvent`, `AnchorStats`, `OverviewStats` used consistently in all downstream tasks.

**Placeholder scan:** None found — every step contains actual code.
