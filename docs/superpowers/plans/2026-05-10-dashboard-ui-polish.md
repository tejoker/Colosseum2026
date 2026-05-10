# Dashboard UI Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the oversized PageHeader with a sticky TopBar, add delta+sparkline to KPI tiles, and tighten spacing across all dashboard pages — no API changes, no new dependencies.

**Architecture:** New `TopBar` component mounted in `layout.tsx` replaces `PageHeader` on all pages. `Kpi` in `shared.tsx` gains two optional props (`delta`, `sparkData`). Overview page computes these from already-fetched `daily` data. All other pages simply drop `PageHeader` and reduce `space-y-28` to `space-y-5`.

**Tech Stack:** Next.js 16 App Router, React 19, TypeScript strict, Tailwind CSS 4

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `sauron-dashboard/app/components/TopBar.tsx` | **Create** | Sticky glass bar: breadcrumb + live status |
| `sauron-dashboard/app/layout.tsx` | Modify | Mount TopBar, fix layout padding |
| `sauron-dashboard/app/shared.tsx` | Modify | Kpi: delta+sparkline props; Card: tighter padding |
| `sauron-dashboard/app/page.tsx` | Modify | Remove PageHeader, wire delta+sparkData, fix spacing |
| `sauron-dashboard/app/agents/page.tsx` | Modify | Remove PageHeader, fix spacing |
| `sauron-dashboard/app/requests/page.tsx` | Modify | Remove PageHeader, fix spacing |
| `sauron-dashboard/app/clients/page.tsx` | Modify | Remove PageHeader, fix spacing |
| `sauron-dashboard/app/anchors/page.tsx` | Modify | Remove PageHeader, fix spacing |
| `sauron-dashboard/app/users/page.tsx` | Modify | Remove PageHeader, fix spacing |

---

## Task 1: Create TopBar component

**Files:**
- Create: `sauron-dashboard/app/components/TopBar.tsx`

The TopBar is a 44px sticky bar inside `<main>`. It derives the current page label from `usePathname()` and shows the live status from `DashContext`.

- [ ] **Step 1: Create the file**

```tsx
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useDash } from "../context/DashContext";

const PAGE_MAP: Record<string, { label: string; hex: string }> = {
  "/":         { label: "Overview",  hex: "0x001" },
  "/agents":   { label: "Agents",    hex: "0x002" },
  "/anchors":  { label: "Anchors",   hex: "0x003" },
  "/requests": { label: "Activity",  hex: "0x004" },
  "/clients":  { label: "Clients",   hex: "0x005" },
  "/users":    { label: "Humans",    hex: "0x006" },
  "/demo":     { label: "Live Demo", hex: "0x009" },
};

export default function TopBar() {
  const pathname = usePathname();
  const { offline } = useDash();
  const page = PAGE_MAP[pathname] ?? { label: pathname.slice(1) || "Overview", hex: "0x000" };

  return (
    <div
      className="sticky top-0 z-20 flex items-center justify-between h-11 px-6 flex-shrink-0"
      style={{
        background: "rgba(3,17,35,0.85)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        borderBottom: "1px solid rgba(230,241,255,0.06)",
      }}
    >
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 font-mono-label text-[8.5px] tracking-[0.1em]">
        <Link href="/" className="text-white/30 hover:text-white/60 transition-colors">
          Console
        </Link>
        <span className="text-white/15">/</span>
        <span className="text-white/75">{page.label}</span>
        <span className="text-white/15">·</span>
        <span className="text-white/25">{page.hex}</span>
      </div>

      {/* Live status */}
      {offline ? (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-[#F87171]/20 bg-[#F87171]/06">
          <span className="w-1 h-1 rounded-full bg-[#F87171]" />
          <span className="font-mono-label text-[7.5px] text-[#F87171]/80">CORE OFFLINE</span>
        </div>
      ) : (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-[#34D399]/20 bg-[#34D399]/[0.06]">
          <span className="w-1 h-1 rounded-full bg-[#34D399] animate-status-pulse" />
          <span className="font-mono-label text-[7.5px] text-[#34D399]/80">LIVE · 10S</span>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
```

Expected: no errors related to `TopBar.tsx`.

- [ ] **Step 3: Commit**

```bash
git add sauron-dashboard/app/components/TopBar.tsx
git commit -m "feat(dashboard): add TopBar sticky glass component"
```

---

## Task 2: Mount TopBar in layout, fix padding

**Files:**
- Modify: `sauron-dashboard/app/layout.tsx`

The TopBar goes inside `<main>`, before the content padding wrapper. Padding changes: `px-24 pt-24 pb-40` → `px-6 lg:px-10 pb-16`.

- [ ] **Step 1: Update layout.tsx**

Replace the entire `layout.tsx` with:

```tsx
import type { Metadata } from "next";
import "./globals.css";
import { DashProvider } from "./context/DashContext";
import Sidebar from "./components/Sidebar";
import TopBar from "./components/TopBar";

export const metadata: Metadata = {
  title: "SauronID — Mandate console",
  description: "Pre-execution governance for autonomous AI agents.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Space+Mono:wght@400;700&display=swap"
        />
        <link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,600,700&display=swap" />
      </head>
      <body>
        <DashProvider>
          <div
            aria-hidden
            className="pointer-events-none fixed inset-0 -z-10"
            style={{
              background:
                "radial-gradient(900px 600px at 18% 12%, rgba(37,99,235,0.10), transparent 70%)," +
                "radial-gradient(700px 500px at 85% 90%, rgba(0,200,255,0.06), transparent 70%)",
            }}
          />
          <div className="relative flex min-h-screen">
            <Sidebar />
            <main className="flex-1 min-w-0 overflow-x-hidden flex flex-col">
              <TopBar />
              <div className="px-6 lg:px-10 pt-8 pb-16 max-w-[1280px]">
                {children}
              </div>
            </main>
          </div>
        </DashProvider>
      </body>
    </html>
  );
}
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add sauron-dashboard/app/layout.tsx
git commit -m "feat(dashboard): mount TopBar, reduce layout padding"
```

---

## Task 3: Update Kpi component — delta + sparkline

**Files:**
- Modify: `sauron-dashboard/app/shared.tsx` (lines 89–121, the `Kpi` function)

Add two optional props: `delta?: number` (raw count vs 7 days ago) and `sparkData?: number[]` (up to 90 values for the sparkline). Both are optional — existing callers need no changes.

- [ ] **Step 1: Replace the `Kpi` function in shared.tsx**

Find the existing `Kpi` function (starts at `export function Kpi`) and replace it entirely:

```tsx
/* ── Sparkline helper — inline SVG polyline ──────────────────────── */
function Sparkline({ data, color }: { data: number[]; color: string }) {
  const W = 44;
  const H = 24;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const pts = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * W;
      const y = H - ((v - min) / range) * (H - 2) - 1;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <svg
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      className="flex-shrink-0 overflow-visible"
      aria-hidden
    >
      <polyline
        points={pts}
        fill="none"
        stroke={color}
        strokeWidth={1.4}
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity={0.8}
      />
    </svg>
  );
}

/* Accent colour → raw hex for sparkline stroke */
const ACCENT_HEX: Record<string, string> = {
  blue:    "#4F8CFE",
  cyan:    "#00C8FF",
  red:     "#F87171",
  emerald: "#34D399",
  amber:   "#FCD34D",
  violet:  "#A78BFA",
  white:   "#FFFFFF",
};

/* ── KPI tile — glass surface, mono label, optional delta + sparkline */
export function Kpi({
  label,
  value,
  sub,
  accent,
  delta,
  sparkData,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
  delta?: number;
  sparkData?: number[];
}) {
  const accentClass = resolveAccent(accent);
  const accentHex =
    accent && ACCENT_HEX[accent]
      ? ACCENT_HEX[accent]
      : accent?.startsWith("#")
        ? accent
        : "#4F8CFE";

  const hasDelta = delta !== undefined;
  const hasSpark = sparkData && sparkData.length >= 2;

  return (
    <div className="relative glass rounded-md px-5 py-5 flex flex-col gap-3 overflow-hidden group transition-colors hover:border-[rgba(79,140,254,0.25)]">
      {/* Top hairline accent — sweeps in on hover */}
      <span
        aria-hidden
        className="absolute top-0 left-0 right-0 h-px bg-[#4F8CFE] origin-left scale-x-0 group-hover:scale-x-100 transition-transform duration-500"
      />

      <span className="font-mono-label text-[9px] text-white/45">{label}</span>

      <span
        className={`text-[28px] tabular-nums leading-none ${accentClass}`}
        style={{ fontFamily: "Satoshi, system-ui, sans-serif", fontWeight: 500, letterSpacing: "-0.025em" }}
      >
        {value}
      </span>

      {/* Bottom row: delta badge (left) + sparkline (right) */}
      {(hasDelta || hasSpark) && (
        <div className="flex items-end justify-between gap-2">
          {hasDelta ? (
            <span
              className={[
                "font-mono-label text-[7.5px] tracking-[0.08em]",
                delta > 0
                  ? "text-[#34D399]/85"
                  : delta < 0
                    ? "text-[#F87171]/85"
                    : "text-white/25",
              ].join(" ")}
            >
              {delta > 0 ? `↑ +${delta}` : delta < 0 ? `↓ ${delta}` : "─ 0"}
              {" · 7D"}
            </span>
          ) : (
            <span />
          )}
          {hasSpark && <Sparkline data={sparkData!} color={accentHex} />}
        </div>
      )}

      {sub && !hasDelta && (
        <span className="font-mono-label text-[10px] text-white/35 tracking-[0.12em]">
          {sub}
        </span>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Also update Card padding (same file)**

Find the `Card` function and update the padding classes and MonoLabel margin:

```tsx
export function Card({
  title,
  hex,
  children,
  className,
  bare,
}: {
  title?: string;
  hex?: string;
  children: React.ReactNode;
  className?: string;
  bare?: boolean;
}) {
  return (
    <div
      className={[
        bare ? "" : "glass",
        "relative rounded-md px-6 pt-5 pb-7",
        className ?? "",
      ].join(" ")}
    >
      {title && (
        <div className="mb-5">
          <MonoLabel label={title} hex={hex} />
        </div>
      )}
      {children}
    </div>
  );
}
```

- [ ] **Step 3: Verify TypeScript**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -30
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add sauron-dashboard/app/shared.tsx
git commit -m "feat(dashboard): Kpi delta+sparkline props, Card tighter padding"
```

---

## Task 4: Overview page — wire delta/sparklines, remove PageHeader

**Files:**
- Modify: `sauron-dashboard/app/page.tsx`

The overview page fetches `overview.daily.actions` (90-point series). Compute:
- `delta` = `actions[last] - actions[last - 7]` (if series has ≥ 8 points, else `undefined`)
- `sparkData` = the full `actions` array (Kpi renders it as a sparkline)

Pass both to the action-receipt-related KPI. Remove `<PageHeader>`. Change `space-y-8` to `space-y-5`. Change KPI grid `gap-6` to `gap-4`.

- [ ] **Step 1: Update the OverviewPage function**

At the top of the render block, add the delta/spark computation after the existing derived values (after `const popBoundAgents = ...`):

```tsx
const dailyActions = overview.daily?.actions ?? overview.daily?.credit_a ?? [];
const sparkData = dailyActions.length >= 2 ? dailyActions : undefined;
const actionDelta =
  dailyActions.length >= 8
    ? dailyActions[dailyActions.length - 1] - dailyActions[dailyActions.length - 8]
    : undefined;
```

- [ ] **Step 2: Replace the JSX return in OverviewPage**

Replace the entire `return (...)` block with:

```tsx
return (
  <div className="space-y-5">
    {/* Health bar */}
    {health && (
      <div className="glass rounded-md px-4 py-3 flex items-center justify-between flex-wrap gap-3 animate-fade-in-up">
        <div className="flex items-center gap-3 flex-wrap">
          <StatusPill
            status={health.ok ? "ok" : "warn"}
            label={health.ok ? "CORE.HEALTHY" : "CORE.DEGRADED"}
          />
          <Meta label="RUNTIME" value={health.runtime} />
          <Meta label="CALL.SIG" value={health.call_sig_enforce ? "ENFORCED" : "OFF"} />
          <Meta label="AGENT.TYPE" value={health.require_agent_type ? "REQUIRED" : "OPTIONAL"} />
        </div>
        {(health.warnings?.length ?? 0) > 0 && (
          <span className="font-mono-label text-[9.5px] text-[#FCD34D]/85 max-w-md text-right">
            ⚠ {health.warnings![0]}
          </span>
        )}
      </div>
    )}

    {/* KPI strip */}
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      <Kpi
        label="ACTIVE AGENTS"
        value={fmtNum(activeAgents)}
        sub={`${revokedAgents} REVOKED`}
        accent="emerald"
      />
      <Kpi
        label="POP-BOUND"
        value={fmtNum(popBoundAgents)}
        sub="HARDWARE-SHAPED KEY"
        accent="cyan"
      />
      <Kpi
        label="HUMANS"
        value={fmtNum(k.total_users)}
        sub="OPRF KEY IMAGES"
      />
      <Kpi
        label="CLIENTS"
        value={fmtNum(k.total_clients)}
        sub="RING MEMBERS"
      />
      <Kpi
        label="ANCHOR BATCHES"
        value={fmtNum(anchor?.agent_action_batches ?? 0)}
        sub={anchor?.last_batch_at ? `LAST ${fmtAgo(anchor.last_batch_at).toUpperCase()}` : "NO ANCHORS YET"}
        accent="violet"
        delta={actionDelta}
        sparkData={sparkData}
      />
      <Kpi
        label="BTC / SOL"
        value={`${anchor?.bitcoin_total ?? 0} / ${anchor?.solana_total ?? 0}`}
        sub={`${anchor?.bitcoin_upgraded ?? 0} BTC · ${anchor?.solana_confirmed ?? 0} SOL`}
        accent="amber"
      />
    </div>

    {/* Activity + anchor pipeline */}
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
      <div className="lg:col-span-2">
        <Card title="AGENT.ACTIVITY · 90D" hex="0x010">
          <div className="h-80">
            <Line
              data={{
                labels: overview.daily?.dates ?? [],
                datasets: [
                  {
                    label: "Action receipts",
                    data: overview.daily?.actions ?? overview.daily?.credit_a ?? [],
                    borderColor: BRAND.blue,
                    backgroundColor: (ctx: { chart: { ctx: CanvasRenderingContext2D; chartArea: { top: number; bottom: number } | null } }) => {
                      const chart = ctx.chart;
                      const { ctx: c, chartArea } = chart;
                      if (!chartArea) return "rgba(79,140,254,0.12)";
                      const g = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                      g.addColorStop(0, "rgba(79,140,254,0.32)");
                      g.addColorStop(1, "rgba(79,140,254,0.00)");
                      return g;
                    },
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: BRAND.blue,
                    borderWidth: 1.6,
                  },
                  {
                    label: "API requests",
                    data: overview.daily?.api_requests ?? overview.daily?.credit_b ?? [],
                    borderColor: BRAND.cyan,
                    backgroundColor: "rgba(0,200,255,0.05)",
                    fill: false,
                    tension: 0.35,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: BRAND.cyan,
                    borderWidth: 1.2,
                    borderDash: [4, 4],
                  },
                ],
              }}
              options={LINE_OPTS}
            />
          </div>
        </Card>
      </div>

      <Card title="ANCHOR.PIPELINE" hex="0x011">
        <div className="h-64 relative">
          <Doughnut
            data={{
              labels: ["BTC upgraded", "BTC pending", "SOL confirmed", "SOL unconfirmed"],
              datasets: [
                {
                  data: [
                    anchor?.bitcoin_upgraded ?? 0,
                    anchor?.bitcoin_pending_upgrade ?? 0,
                    anchor?.solana_confirmed ?? 0,
                    anchor?.solana_unconfirmed ?? 0,
                  ],
                  backgroundColor: [
                    BRAND.amber,
                    "rgba(252,211,77,0.32)",
                    BRAND.violet,
                    "rgba(167,139,250,0.32)",
                  ],
                  borderWidth: 0,
                  spacing: 2,
                },
              ],
            }}
            options={DOUGHNUT_OPTS}
          />
          <div className="absolute inset-0 flex flex-col items-center justify-center pb-12 pointer-events-none">
            <div className="font-mono-label text-[9px] text-white/45">TOTAL</div>
            <div
              className="text-[26px] tabular-nums text-white"
              style={{ fontFamily: "Satoshi, system-ui, sans-serif", fontWeight: 500 }}
            >
              {(anchor?.bitcoin_total ?? 0) + (anchor?.solana_total ?? 0)}
            </div>
          </div>
        </div>
      </Card>
    </div>

    {/* Agent registry + recent receipts */}
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <Card title="ACTION.RECEIPTS · RECENT" hex="0x020">
        <div className="overflow-y-auto max-h-96 -mx-3">
          {actions.length === 0 ? (
            <Empty hint="No action receipts. Run the receipt-verify flow to anchor agent decisions." />
          ) : (
            <table className="w-full text-[12px]">
              <thead className="sticky top-0 backdrop-blur bg-[#0F1A35]/70 z-10">
                <tr className="text-left">
                  <Th>WHEN</Th>
                  <Th>AGENT</Th>
                  <Th>HASH</Th>
                  <Th>STATUS</Th>
                </tr>
              </thead>
              <tbody>
                {actions.map((r) => (
                  <tr key={r.receipt_id} className="border-t border-white/[0.04]">
                    <Td muted>{fmtAgo(r.created_at)}</Td>
                    <Td mono>{r.agent_id.slice(0, 14)}…</Td>
                    <Td mono dim>{r.action_hash.slice(0, 12)}…</Td>
                    <Td>
                      <StatusPill
                        status={r.status === "approved" ? "ok" : "muted"}
                        label={r.status.toUpperCase()}
                      />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      <Card title="AGENT.REGISTRY" hex="0x021">
        <div className="overflow-y-auto max-h-96 -mx-3">
          {agents.length === 0 ? (
            <Empty hint="No agents registered. Bind your first agent via the Python adapter." />
          ) : (
            <table className="w-full text-[12px]">
              <thead className="sticky top-0 backdrop-blur bg-[#0F1A35]/70 z-10">
                <tr className="text-left">
                  <Th>AGENT</Th>
                  <Th>TYPE</Th>
                  <Th>ASSURANCE</Th>
                  <Th>POP</Th>
                  <Th>STATE</Th>
                </tr>
              </thead>
              <tbody>
                {agents.slice(0, 12).map((a) => (
                  <tr key={a.agent_id} className="border-t border-white/[0.04]">
                    <Td mono>{a.agent_id.slice(0, 14)}…</Td>
                    <Td muted>{a.agent_type || "—"}</Td>
                    <Td muted>{a.assurance_level}</Td>
                    <Td>
                      {a.has_pop ? (
                        <span className="text-[#34D399]" aria-label="proof-of-possession bound">●</span>
                      ) : (
                        <span className="text-white/25">○</span>
                      )}
                    </Td>
                    <Td>
                      <StatusPill
                        status={a.revoked ? "err" : "ok"}
                        label={a.revoked ? "REVOKED" : "ACTIVE"}
                      />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>

    {/* Ring memberships */}
    <Card title="RING.MEMBERSHIP" hex="0x030">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {(overview.rings?.names ?? []).map((name, i) => (
          <div
            key={name}
            className="bg-[#0F1A35] p-5 flex flex-col gap-3 group rounded border border-white/5 hover:bg-[#0F1A35]/60 transition-colors"
          >
            <div className="flex items-center justify-between">
              <span className="font-mono-label text-[9px] text-white/45">
                {name.toUpperCase()}
              </span>
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{
                  backgroundColor: [BRAND.blue, BRAND.cyan, BRAND.violet][i] ?? BRAND.blue,
                  boxShadow: `0 0 12px ${[BRAND.blue, BRAND.cyan, BRAND.violet][i] ?? BRAND.blue}`,
                }}
              />
            </div>
            <div
              className="text-[28px] tabular-nums text-white"
              style={{ fontFamily: "Satoshi, system-ui, sans-serif", fontWeight: 500, letterSpacing: "-0.025em" }}
            >
              {fmtNum(overview.rings?.counts[i] ?? 0)}
            </div>
            <div className="font-mono-label text-[8.5px] text-white/30">MEMBERS</div>
          </div>
        ))}
      </div>
    </Card>
  </div>
);
```

- [ ] **Step 3: Remove the PageHeader import from page.tsx**

In the import line `import { ..., PageHeader, ... } from "./shared"`, remove `PageHeader`.

- [ ] **Step 4: Verify TypeScript**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -30
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add sauron-dashboard/app/page.tsx
git commit -m "feat(dashboard): overview — TopBar replaces PageHeader, delta+sparkline on KPIs"
```

---

## Task 5: Agents page — remove PageHeader, fix spacing

**Files:**
- Modify: `sauron-dashboard/app/agents/page.tsx`

- [ ] **Step 1: Remove PageHeader import and usage**

In `app/agents/page.tsx`:

1. Remove `PageHeader` from the import: `import { sauronFetch, Card, Spinner, StatusPill, fmtNum } from "../shared";`

2. In the `AgentsPage` return, change `<div className="space-y-28">` → `<div className="space-y-5">` and delete the entire `<PageHeader ... />` block (lines with `eyebrow="MANDATE.AGENTS"` through the closing `/>` of PageHeader).

3. Change the filter grid gap: `gap-4` stays — it's already correct.

4. The final JSX top-level return should look like:

```tsx
return (
  <div className="space-y-5">
    {/* Filter strip */}
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {/* ... existing filter buttons unchanged ... */}
    </div>

    <Card title={`AGENT.LIST · ${filtered.length}`} hex="0x110">
      {/* ... existing card content unchanged ... */}
    </Card>
  </div>
);
```

- [ ] **Step 2: Verify TypeScript**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add sauron-dashboard/app/agents/page.tsx
git commit -m "feat(dashboard): agents — remove PageHeader, tighten spacing"
```

---

## Task 6: Requests page — remove PageHeader, fix spacing

**Files:**
- Modify: `sauron-dashboard/app/requests/page.tsx`

- [ ] **Step 1: Update requests page**

1. Remove `PageHeader` from import: `import { Card, PageHeader, StatusPill } from "../shared"` → `import { Card, StatusPill } from "../shared"`

2. In the return, change `<div className="space-y-28">` → `<div className="space-y-5">` and delete the `<PageHeader ... />` block (the one with `eyebrow="ACTIVITY.LOG"`).

The final return starts with:

```tsx
return (
  <div className="space-y-5">
    <Card title={`STREAM · ${events.length} EVENTS`} hex="0x310">
      {/* ... existing card content unchanged ... */}
    </Card>
  </div>
);
```

- [ ] **Step 2: Verify and commit**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
git add sauron-dashboard/app/requests/page.tsx
git commit -m "feat(dashboard): requests — remove PageHeader, tighten spacing"
```

---

## Task 7: Clients page — remove PageHeader, fix spacing

**Files:**
- Modify: `sauron-dashboard/app/clients/page.tsx`

- [ ] **Step 1: Update clients page**

1. Remove `PageHeader` from import: `import { sauronFetch, Card, Kpi, Spinner, StatusPill, fmtNum } from "../shared"`

2. Change `<div className="space-y-28">` → `<div className="space-y-5">`

3. Delete the `<PageHeader ... />` block (the one with `eyebrow="CLIENT.DIRECTORY"`).

4. Change KPI grid: `className="grid grid-cols-2 md:grid-cols-3 gap-6"` → `gap-4`.

The return starts with:

```tsx
return (
  <div className="space-y-5">
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      <Kpi label="TOTAL CLIENTS" value={fmtNum(clientList.length)} accent="cyan" />
      <Kpi label="ACTIVE · 90D" value={fmtNum(activeCount)} accent="emerald" />
      <Kpi label="DORMANT" value={fmtNum(clientList.length - activeCount)} sub="NO ACTIVITY · 90D" />
    </div>
    <Card title={`CLIENT.LIST · ${filtered.length}`} hex="0x410">
      {/* ... existing card content unchanged ... */}
    </Card>
  </div>
);
```

- [ ] **Step 2: Verify and commit**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
git add sauron-dashboard/app/clients/page.tsx
git commit -m "feat(dashboard): clients — remove PageHeader, tighten spacing"
```

---

## Task 8: Anchors page — remove PageHeader, fix spacing

**Files:**
- Modify: `sauron-dashboard/app/anchors/page.tsx`

- [ ] **Step 1: Update anchors page**

1. Remove `PageHeader` from import: `import { sauronFetch, Card, Spinner, Kpi, StatusPill, fmtNum } from "../shared"`

2. Change `<div className="space-y-28">` → `<div className="space-y-5">`

3. Delete the `<PageHeader ... />` block (the one with `eyebrow="ANCHOR.PIPELINE"`).

4. Change KPI grid: `className="grid grid-cols-2 md:grid-cols-4 gap-6"` → `gap-4`.

5. In the `ChainPane` function definition (local to this file, around line 186), change its outer `div` padding: `className="bg-[#0F1A35] p-10 relative overflow-hidden rounded border border-white/5"` → replace `p-10` with `p-6`.

The return starts with:

```tsx
return (
  <div className="space-y-5">
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {/* ... existing Kpi tiles unchanged ... */}
    </div>
    <Card title="DUAL.CHAIN.PROOF" hex="0x210">
      {/* ... existing card content unchanged ... */}
    </Card>
    <Card title="ACTION.RECEIPTS · RECENT" hex="0x220">
      {/* ... existing card content unchanged ... */}
    </Card>
  </div>
);
```

- [ ] **Step 2: Verify and commit**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
git add sauron-dashboard/app/anchors/page.tsx
git commit -m "feat(dashboard): anchors — remove PageHeader, tighten spacing"
```

---

## Task 9: Users page — remove PageHeader, fix spacing

**Files:**
- Modify: `sauron-dashboard/app/users/page.tsx`

- [ ] **Step 1: Update users page**

1. Remove `PageHeader` from import: `import { useDash } from "../context/DashContext"; import { Card, Kpi, Spinner, fmtNum } from "../shared";`

2. Change `<div className="space-y-28">` → `<div className="space-y-5">`

3. Delete the `<PageHeader ... />` block (the one with `eyebrow="HUMAN.REGISTRY"`).

4. Change KPI grid: `className="grid grid-cols-2 md:grid-cols-3 gap-6"` → `gap-4`.

The return starts with:

```tsx
return (
  <div className="space-y-5">
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      {/* ... existing Kpi tiles unchanged ... */}
    </div>
    <Card title={`USER.LIST · ${users.length}`} hex="0x510">
      {/* ... existing card content unchanged ... */}
    </Card>
  </div>
);
```

- [ ] **Step 2: Verify and commit**

```bash
cd sauron-dashboard && npx tsc --noEmit 2>&1 | head -20
git add sauron-dashboard/app/users/page.tsx
git commit -m "feat(dashboard): users — remove PageHeader, tighten spacing"
```

---

## Task 10: Final build check

- [ ] **Step 1: Full TypeScript check**

```bash
cd sauron-dashboard && npx tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 2: Lint check**

```bash
cd sauron-dashboard && npx eslint app/ --ext .ts,.tsx 2>&1 | head -40
```

Expected: no errors (warnings about unused `PageHeader` export are fine — it's kept intentionally).

- [ ] **Step 3: Production build**

```bash
cd sauron-dashboard && npm run build 2>&1 | tail -20
```

Expected: `Route (app)` table with no errors. Build completes successfully.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore(dashboard): verify build passes after UI polish"
```
