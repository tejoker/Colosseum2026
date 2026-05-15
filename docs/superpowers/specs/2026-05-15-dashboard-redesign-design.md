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

### Tone principle (non-negotiable)
This is not a SOC dashboard. It is not a security tool. It is an **interface of trust** — calm, obvious, breathing, almost invisible. Every design decision must reinforce confidence, not alarm. The product protects agents; the interface should feel like that protection is quietly, reliably running.

---

## 2. Architecture

### Directory structure
```
dashboard/
  app/
    layout.tsx              ← ThemeProvider + IntlProvider + TopNav + PageShell
    page.tsx                ← Home
    protected/page.tsx
    activity/page.tsx
    proofs/page.tsx
    try/page.tsx
    settings/page.tsx
    agents/[id]/page.tsx    ← Agent detail (not in nav)
    agents/[id]/audit/page.tsx  ← Audit view (accessible from Agent detail + Activity)
    error.tsx               ← Global error boundary
    api/                    ← Proxy routes to core (:3001) and analytics (:8002)
  components/
    ui/                     ← Button, Badge, Card, Table, Input, Select,
    |                          Dialog, Tooltip, Tabs, Spinner, StatusDot
    layout/                 ← TopNav, ThemeToggle, PageShell, SystemStatus
    charts/                 ← Chart.js wrappers
    agents/                 ← AgentCard, AgentDetail
    playground/             ← ScenarioTile, ResultPanel
    audit/                  ← AuditTimeline, AuditExportPanel
  lib/
    api.ts                  ← All fetch functions + TypeScript types
    theme.ts                ← Token reference (mirrors globals.css)
  messages/
    en.json                 ← All UI strings — no hardcoded text in components
```

### Stack
- **Next.js 16.1.6** App Router, TypeScript strict
- **Tailwind CSS 4**
- **Radix UI** — Dialog, DropdownMenu, Tooltip, Select, Tabs, Switch (behavior + accessibility only, no visual styling)
- **next-themes** — dark/light mode via CSS variables, no hydration flash
- **next-intl** — i18n provider, locale-aware routing, all strings from `messages/`
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

Top navigation bar. 6 primary links + system status indicator + theme toggle on the far right.

| Label | Route | Purpose |
|---|---|---|
| **Home** | `/` | System state + agent list |
| **Protected** | `/protected` | Actions stopped by governance — proof that it's working |
| **Activity** | `/activity` | All agent calls, filterable |
| **Proofs** | `/proofs` | Bitcoin + Solana audit anchors |
| **Try** | `/try` | Demo playground — predefined scenarios |
| **Settings** | `/settings` | Companies, People, configuration |

**Agent detail** (`/agents/[id]`) is accessible by clicking an agent card on Home — not surfaced in the nav.

**Audit view** (`/agents/[id]/audit`) accessible from Agent detail and from Activity row expand — not in nav.

**Rule:** Technical terms (`A-JWT`, `intent`, `DPoP`, `config digest`) appear only inside detail views, never in navigation labels or primary headings.

---

## 4. System Status — Always Present

A `SystemStatus` component lives in the top nav, left of the theme toggle. It is always visible on every page.

**States:**
- **Nominal** — `● All systems operational · 12 agents protected · Verification running`
- **Degraded** — `● Core unreachable — last seen 3m ago`
- **Unknown** — `○ Connecting…`

Design: small dot + mono text at `11px`, `--text-muted` color. Dot pulses subtly on nominal. No red/orange on degraded — use amber at low opacity. The goal is calm awareness, not alarm.

This gives every user, at every moment, the ambient sensation: *"The system is watching. Everything is fine."*

---

## 5. Pages

### Home (`/`)
- **SystemStatus** visible in nav (always)
- Slim status line below page title: `12 agents · 1,847 calls today · 3 protected`
- Agent cards grid below (2 columns desktop, 1 mobile)
- Each **AgentCard**: agent name, type, status dot (green = active / gray = idle), last call timestamp, call count, "View activity" link
- Empty state: "No agents registered yet" with link to docs

### Agent detail (`/agents/[id]`)
- Accessed by clicking an AgentCard — breadcrumb back to Home
- Sections: Identity (name, type, registered date), Mandate (allowed intents, scope), Config digest (current hash), Recent calls (last 10)
- **Audit** button → opens `/agents/[id]/audit`
- **Revoke** button — destructive, behind Dialog confirmation with typed confirmation

### Protected (`/protected`)
- Feed of actions stopped by the governance layer, most recent first
- Framing: "Your governance layer stopped these actions." — not "attacks blocked"
- Each row: timestamp, agent name, human-readable reason ("Replayed token", "Out-of-scope action", "Invalid signature"), technical detail on expand
- Summary: `3 today · 12 this week · 847 total` — phrased as coverage, not threat count

### Activity (`/activity`)
- All calls, newest first. Columns: time, agent, action label, result (✓ / ✗), latency
- Filter by: agent, result (allowed/stopped), date range
- Row expand: full technical detail (intent, body hash, nonce, DPoP verification steps)
- **Export audit** button → opens AuditExportPanel (see §Auditability)

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

Click → spinner → animated result (green ✓ or red ✗) + plain-language explanation of what was checked and why it passed or failed. Technical detail (JWT claims, DPoP binding, nonce state) in an expandable section below.

### Settings (`/settings`)
- Tabs: Companies / People / Configuration
- Companies: list of registered clients, add/remove
- People: users linked to companies
- Configuration: core URL, polling interval, feature flags

---

## 6. Auditability

The core governance promise is: *"Everything is traceable and provable."* The interface must make this tangible.

### Audit view (`/agents/[id]/audit`)
- Accessible from Agent detail and from the expand of any Activity row
- Full chronological timeline of every action taken by the agent: calls, mandate checks, governance events, config changes, revocation if any
- Each event: timestamp (ISO 8601), type, result, cryptographic reference (hash, anchor ID if available)
- **Verifiable** — each anchored event links to Solana Explorer or Bitcoin OTS receipt

### Export panel (`AuditExportPanel`)
- Accessible from Activity page and from Audit view
- Three export formats:
  - **JSON** — machine-readable full audit log with all cryptographic fields
  - **PDF** — human-readable report with agent identity, timeline, governance summary
  - **Signed report** — PDF + detached signature (Ed25519) over the PDF hash, verifiable independently
- Export is scoped: by agent, by date range, or full history
- Exports are generated server-side via an API route (`/api/export`) — never client-side

### Framing in UI
- Activity page header: *"Every action is recorded and verifiable."*
- Audit view header: *"Complete, tamper-evident history for [Agent name]."*
- Export button label: *"Export audit"* — never "Download logs"

---

## 7. Theme System

### Mechanism
CSS custom properties on `:root` (light) and `.dark` (dark). `next-themes` adds `class="dark"` to `<html>`. `suppressHydrationWarning` on `<body>` to avoid SSR mismatch. Default: `system` (follows OS preference). Persisted in `localStorage`.

Toggle: sun/moon icon, top-right of nav.

### Dark mode tokens
Premium OS-like. Surfaces are neutral dark (zinc-adjacent), not navy-tinted. No blue wash.

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

### Shared tokens (mode-dependent values noted)
| Token | Dark | Light |
|---|---|---|
| `--accent` | `#2563EB` | `#2563EB` |
| `--accent-hover` | `#4F8CFE` | `#1D4ED8` |
| `--status-ok` | `#34D399` | `#059669` |
| `--status-stopped` | `#F87171` | `#DC2626` |
| `--status-warning` | `rgba(251,191,36,0.6)` | `rgba(217,119,6,0.7)` |

---

## 8. i18n

All UI strings are externalized from day one. English only at launch, but the architecture supports additional locales without code changes.

### Rules
- **No hardcoded strings** in any component — all text via `next-intl` `useTranslations` hook
- All strings live in `messages/en.json`, organized by page/component namespace
- Locale provider wraps the root layout
- Routes: locale-neutral paths (`/activity`, not `/en/activity`) — locale is detected from browser `Accept-Language` and stored in a cookie, not in the URL, to keep links clean

### Structure example
```json
// messages/en.json
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
    "statLine": "{agents} agents · {calls} calls today · {protected} protected"
  }
}
```

---

## 9. Component Guidelines

- **No box shadows** — depth via background color stacking and border opacity
- **No rounded-xl cards** — `rounded-lg` max, consistent across all surfaces
- **StatusDot** — 6px circle, `animate-pulse` only when actively live (not on idle)
- **Buttons** — primary: `--accent` fill, `rounded-full`, arrow icon translates `+1px` on hover; ghost: `border --border`, no fill
- **Tables** — `border-collapse`, rows separated by `border-b --border`, no zebra striping
- **Typography** — Satoshi for all UI (nav, labels, body); no Instrument Serif in the dashboard (marketing site only); Space Mono for monospaced values (hashes, timestamps, hex codes) only
- **Language in UI** — never "attack", "threat", "breach", "hack". Use: "action stopped", "out-of-scope", "governance event", "protected"

---

## 10. What This Is Not

- Not a redesign of the marketing site or landing page
- Not a replacement for the Rust core or Python analytics API
- Not adding new backend features — the dashboard reads existing `/api/live/*` endpoints plus a new `/api/export` route
- Not touching `sauron-dashboard/` until this is validated and running

---

## 11. Out of Scope

- Authentication / login flow (no auth in current dashboard, none added here)
- Mobile-first optimization (desktop-primary, responsive but not native mobile)
- Additional locales beyond English (architecture supports it, translation is out of scope)
