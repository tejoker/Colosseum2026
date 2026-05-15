# SauronID Dashboard Redesign — Design Spec
**Date:** 2026-05-15  
**Status:** Approved  
**Replaces:** `sauron-dashboard/`  
**New directory:** `dashboard/`

---

## 1. Context & Goal

The existing `sauron-dashboard/` is functionally complete but visually insufficient for user demos. Deals have been lost due to the interface not reflecting the product's quality. This redesign targets three outcomes:

1. **Demo-ready** — any operator can walk a prospect through the product in under 5 minutes without explanation
2. **Minimaliste premium** — Linear/Vercel aesthetic, not cyber/security aesthetic
3. **Accessible** — understandable in 10 seconds regardless of technical level

---

## 2. Architecture

### Directory structure
```
dashboard/
  app/
    layout.tsx              ← ThemeProvider + TopNav + PageShell
    page.tsx                ← Home
    blocked/page.tsx
    activity/page.tsx
    proofs/page.tsx
    try/page.tsx
    settings/page.tsx
    agents/[id]/page.tsx    ← Agent detail (not in nav)
    error.tsx               ← Global error boundary
    api/                    ← Proxy routes to core (:3001) and analytics (:8002)
  components/
    ui/                     ← Button, Badge, Card, Table, Input, Select,
    |                          Dialog, Tooltip, Tabs, Spinner, StatusDot
    layout/                 ← TopNav, ThemeToggle, PageShell
    charts/                 ← Chart.js wrappers
    agents/                 ← AgentCard, AgentDetail
    playground/             ← ScenarioTile, ResultPanel
  lib/
    api.ts                  ← All fetch functions + TypeScript types
    theme.ts                ← Token reference (mirrors globals.css)
```

### Stack
- **Next.js 16.1.6** App Router, TypeScript strict
- **Tailwind CSS 4**
- **Radix UI** — Dialog, DropdownMenu, Tooltip, Select, Tabs, Switch (behavior + accessibility only, no visual styling)
- **next-themes** — dark/light mode via CSS variables, no hydration flash
- **Chart.js + react-chartjs-2** — same as current dashboard, no migration

### Data flow rule
```
lib/api.ts  →  page.tsx (fetch at page level)  →  components (props only)
```
- Pages are `async` Server Components by default
- Components never fetch — they receive typed props only
- Live polling (Home, Activity) handled in dedicated `LiveFeed` Client Components via `useEffect` + interval
- All API errors return `{ ok: false, error: string }` — no unhandled throws in UI
- Every page has an `error.tsx` Next.js error boundary

---

## 3. Navigation

Top navigation bar. 6 primary links + theme toggle on the far right.

| Label | Route | Purpose |
|---|---|---|
| **Home** | `/` | System state + agent list |
| **Blocked** | `/blocked` | Blocked actions/attacks — immediate proof of value |
| **Activity** | `/activity` | All agent calls, filterable |
| **Proofs** | `/proofs` | Bitcoin + Solana audit anchors |
| **Try** | `/try` | Demo playground — predefined scenarios |
| **Settings** | `/settings` | Companies, People, configuration |

**Agent detail** (`/agents/[id]`) is accessible by clicking an agent card on Home — not surfaced in the nav.

**Rule:** Technical terms (`A-JWT`, `intent`, `DPoP`, `config digest`) appear only inside detail views, never in navigation labels or primary headings.

---

## 4. Pages

### Home (`/`)
- Slim status banner at top: `X agents active · Y calls today · Z blocked`
- Agent cards grid below (2 columns desktop, 1 mobile)
- Each **AgentCard**: agent name, type, status dot (green = active / gray = idle / red = error), last call timestamp, call count, "View activity" link
- Empty state: "No agents registered yet" with link to docs

### Agent detail (`/agents/[id]`)
- Accessed by clicking an AgentCard — breadcrumb back to Home
- Sections: Identity (name, type, registered), Mandate (allowed intents, scope), Config digest (current hash), Recent calls (last 10), Revoke button (destructive, behind Dialog confirmation)

### Blocked (`/blocked`)
- Feed of blocked attempts, most recent first
- Each row: timestamp, agent name, human-readable reason ("Replayed token", "Out-of-scope action", "Invalid signature"), technical detail available on expand
- Summary bar: total blocked today / this week / all time

### Activity (`/activity`)
- All calls, newest first. Columns: time, agent, action label, result (✓ / ✗), latency
- Filter by: agent, result (allowed/blocked), date range
- Row expand: full technical detail (intent, body hash, nonce, DPoP verification steps)

### Proofs (`/proofs`)
- Bitcoin section: total anchored, pending, confirmed. Last batch timestamp.
- Solana section: total, unconfirmed, confirmed (~30s finality noted).
- Note: "Bitcoin confirmation takes ~1 hour. Solana finalises in ~30s."
- Link to verify externally (Solana Explorer, `ots verify`)

### Try (`/try`)
Four scenario tiles, each clickable:

| Tile | What it does |
|---|---|
| **A normal call** | Agent makes a valid signed call → ✓ 200 |
| **A blocked replay** | Replays a captured token → ✗ 401 |
| **An out-of-scope action** | Agent acts outside its declared intent → ✗ 403 |
| **Your own scenario** | Free-form: choose agent type, intent, attack flag |

Click → spinner → animated result (green ✓ or red ✗) + plain-language explanation of what was checked and why it passed or failed. Technical detail (JWT claims, DPoP binding, nonce state) available in an expandable section below.

### Settings (`/settings`)
- Tabs: Companies / People / Configuration
- Companies: list of registered clients, add/remove
- People: users linked to companies
- Configuration: core URL, polling interval, feature flags

---

## 5. Theme System

### Mechanism
CSS custom properties on `:root` (light) and `.dark` (dark). `next-themes` adds `class="dark"` to `<html>`. `suppressHydrationWarning` on `<body>` to avoid SSR mismatch. Default: `system` (follows OS preference). Persisted in `localStorage`.

Toggle: sun/moon icon, top-right of nav.

### Dark mode tokens
Premium OS-like. Surfaces are neutral dark (zinc-adjacent), not navy-tinted.

| Token | Value | Note |
|---|---|---|
| `--bg` | `#06090F` | Base background |
| `--bg-surface` | `#111114` | Cards, elevated surfaces — neutral, not blue |
| `--bg-elevated` | `#18181B` | Modals, dropdowns |
| `--border` | `rgba(255,255,255,0.06)` | Hairline — barely visible |
| `--text-primary` | `#FFFFFF` | Headlines, primary |
| `--text-secondary` | `rgba(255,255,255,0.55)` | Supporting text |
| `--text-muted` | `rgba(255,255,255,0.30)` | Timestamps, captions |

### Light mode tokens
True light mode — breathing, not a dark-mode inversion.

| Token | Value | Note |
|---|---|---|
| `--bg` | `#F8FAFC` | Warm off-white base |
| `--bg-surface` | `#FFFFFF` | Pure white cards |
| `--bg-elevated` | `#F1F5F9` | Subtle elevation |
| `--border` | `rgba(0,0,0,0.08)` | Soft separator |
| `--text-primary` | `#0F172A` | Near-black |
| `--text-secondary` | `rgba(15,23,42,0.55)` | Supporting |
| `--text-muted` | `rgba(15,23,42,0.35)` | Captions |

### Shared tokens (both modes)
| Token | Value |
|---|---|
| `--accent` | `#2563EB` |
| `--accent-hover` | `#4F8CFE` (dark) / `#1D4ED8` (light) |
| `--status-ok` | `#34D399` (dark) / `#059669` (light) |
| `--status-blocked` | `#F87171` (dark) / `#DC2626` (light) |

---

## 6. Component Guidelines

- **No box shadows** — depth via background color stacking and border opacity
- **No rounded-xl cards** — `rounded-lg` max, consistent across all surfaces
- **StatusDot** — 6px circle, `animate-pulse` only when actively live (not on idle)
- **Buttons** — primary: `--accent` fill, `rounded-full`, arrow icon translates `+1px` on hover; ghost: `border --border`, no fill
- **Tables** — `border-collapse`, rows separated by `border-b --border`, no zebra striping
- **Typography** — Satoshi for all UI (nav, labels, body); no Instrument Serif in the dashboard (that's for the marketing site); Space Mono for monospaced values (hashes, timestamps, hex codes) only

---

## 7. What This Is Not

- Not a redesign of the marketing site or landing page
- Not a replacement for the Rust core or Python analytics API
- Not adding new backend features — the dashboard reads existing `/api/live/*` endpoints
- Not touching `sauron-dashboard/` until this is validated and running

---

## 8. Out of Scope

- Authentication / login flow (no auth in current dashboard, none added here)
- Mobile-first optimization (desktop-primary, responsive but not native mobile)
- i18n
