# SauronID Dashboard — UI Polish Design Spec

**Date:** 2026-05-10  
**Branch:** `frontend-design-discussion`  
**Scope:** Tune & polish — surgical fixes to 3 pain points, no API changes, no architectural refactor  

---

## Problem

The mandate console has a solid aesthetic foundation (palette, typography, sidebar) but three friction points degrade its utility as an operational tool:

1. **Excessive scroll before data** — `PageHeader` consumes ~160px of vertical space on every page before any actionable content appears (`pb-16 + mb-12 + mb-10`).
2. **KPIs lack temporal context** — metric tiles show raw numbers with no delta or trend. A number alone doesn't tell the operator whether the situation is improving or degrading.
3. **Spacing calibrated for a landing page, not a dashboard** — `space-y-28` (7rem) between sections, `px-24 pt-24` layout padding, and `px-10 pt-10 pb-12` card internals leave most of the screen empty.

---

## Decision: Approach A — Surgical

Touch only what directly addresses the 3 pain points. No decomposition of `shared.tsx`, no backend changes. ~6–8 files modified.

**Not in scope:**
- Table row actions (revoke, copy ID)
- Command palette
- Sidebar collapse
- API delta endpoint
- Refactoring `shared.tsx` into separate component files

---

## Design

### 1. TopBar — replaces PageHeader on all pages

**New component:** `app/components/TopBar.tsx`

A sticky glass bar, 44px tall, at the top of the main content area (inside `<main>`, not full-viewport).

```
[ Console / Overview · 0x001 ]          [ ● LIVE · 10S ]
```

- **Left:** Breadcrumb derived from `usePathname()` + the `LINKS` array already used by `Sidebar`. Format: `Console / {PageLabel} · {hex}`
- **Right:** Live status pill — green dot + `LIVE · 10S` when online, amber `CORE OFFLINE` when `offline === true` (from `DashContext`)
- **Style:** `bg-[#031123]/85 backdrop-blur-md border-b border-white/[0.06]`
- **Positioning:** `sticky top-0 z-20` inside the scrollable main area

`PageHeader` component stays in `shared.tsx` but is no longer used anywhere. It can be deleted in a follow-up.

### 2. Layout padding — `layout.tsx`

| Before | After |
|--------|-------|
| `px-24 pt-24 pb-40` | `px-6 lg:px-10 pt-0 pb-16` |

`pt-0` because `TopBar` now handles the top boundary. Horizontal padding reduced from 96px to 24–40px.

### 3. Kpi component — delta + sparkline

**Props added (all optional):**
```ts
delta?: number        // raw count delta vs 7d ago (positive = up, negative = down)
sparkData?: number[]  // array of values for sparkline (up to 90 points)
```

**Delta badge** (shown only when `delta !== undefined`):
- `↑ +N · 7D` in `text-emerald-400/85` when positive
- `↓ −N · 7D` in `text-red-400/85` when negative  
- `─ 0` in `text-white/25` when zero

**Sparkline** (shown only when `sparkData` is provided and has ≥ 2 points):
- Inline SVG, `44×24px`, right-aligned in the KPI bottom row
- Color inherits from the KPI's `accent` color
- Simple polyline with a subtle gradient fill area beneath

**Spacing reduced:**
- `px-7 py-8` → `px-5 py-5`
- `gap-5` → `gap-3`

**Delta computation (frontend, no API change):**  
The Overview page already fetches `overview.daily` with `dates` and `actions` arrays (90d daily series). The 7-day delta is `actions[last] - actions[last - 7]` — last point vs 7 points back. If the series has fewer than 8 points, delta is left `undefined`. For KPIs without a historical series (e.g., total clients, total humans), `delta` is left `undefined` and no badge is shown.

### 4. Spacing reduction — all pages

| Location | Before | After |
|----------|--------|-------|
| Page top-level gap | `space-y-28` | `space-y-5` |
| Overview sections | `space-y-8` | `space-y-5` |
| KPI grid gap | `gap-6` | `gap-4` |
| Card padding | `px-10 pt-10 pb-12` | `px-6 pt-5 pb-7` |
| Card header margin | `mb-12` | `mb-5` |

### 5. Card component tweak

`MonoLabel` inside `Card` header margin: `mb-12` → `mb-5`.  
Card border-radius stays `rounded-md`. Glass treatment unchanged.

---

## Files touched

| File | Change |
|------|--------|
| `app/components/TopBar.tsx` | **New** — sticky topbar component |
| `app/layout.tsx` | Mount `<TopBar>`, remove pt-24/px-24 |
| `app/shared.tsx` | Update `Kpi` (delta + sparkline props), update `Card` padding, update `MonoLabel` margin |
| `app/page.tsx` | Remove `<PageHeader>`, compute `sparkData`/`delta` from `overview.daily`, fix spacings |
| `app/agents/page.tsx` | Remove `<PageHeader>`, fix `space-y-28` → `space-y-5` |
| `app/requests/page.tsx` | Remove `<PageHeader>`, fix spacing |
| `app/clients/page.tsx` | Remove `<PageHeader>`, fix spacing |
| `app/anchors/page.tsx` | Remove `<PageHeader>`, fix spacing |
| `app/users/page.tsx` | Remove `<PageHeader>`, fix spacing |

`app/demo/page.tsx` excluded — different content type, assess separately.

---

## Constraints

- No new npm dependencies
- No backend changes
- TypeScript strict — all new props must be properly typed
- The `PageHeader` export in `shared.tsx` is kept (not deleted) to avoid breaking any import until a follow-up cleanup PR
