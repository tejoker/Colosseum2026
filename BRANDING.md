# SauronID — Branding Guidelines

> Version 1.0 — May 2026  
> Source of truth for visual identity, voice, and design patterns.

---

## 1. Brand Essence

**Mission:** Make AI agents accountable before they act.

**Positioning:** SauronID is the mandate layer for autonomous AI — the control infrastructure that sits between an agent's intent and its real-world execution. Not monitoring. Not logging. Pre-execution governance.

**One-liner:** *Control agent execution.*

**Tagline variants in use:**
- "Make your AI accountable."
- "Stop the next incident."
- "Control agent execution."

**Brand personality:** Precise. Confrontational. Grounded in consequence. SauronID does not soften the risk — it names it, then solves it.

---

## 2. Logo

### Icon
An abstract eye motif — an oblique reference to Sauron (the all-seeing) reframed as a watchful governance layer rather than a threat. The eye communicates observation, verification, and control.

- The iris is rendered in electric blue (`#4F8CFE`) with a cyan halo (`#00C8FF`)
- The orbital ring around the eye represents the mandate boundary — what the agent is allowed to do
- On dark backgrounds only. Never on white or light surfaces without explicit approval.

### Wordmark
`Sauron` in white · `ID` in Ice Blue (`#4F8CFE`)

- Font: **Satoshi**, weight 600 (SemiBold)
- Letter spacing: `tracking-tight` (`-0.025em`)
- The `ID` suffix must always appear in Ice Blue — it is the identifier, the credential, the proof

### Lockup rules
- Minimum size: 28px icon height
- Always pair icon + wordmark together in navigation and footers
- Do not separate the icon from the wordmark in primary usage
- Do not rotate, recolor, or add effects beyond the existing glow

### Clearspace
Maintain at least `1×` the icon height as clearspace on all sides.

---

## 3. Color Palette

### Primary — Dark Canvas

| Name | Hex | Usage |
|------|-----|-------|
| Navy Base | `#06090F` | Default background, section fills |
| Navy Mid | `#0A1128` | Secondary backgrounds |
| Navy Surface | `#0F1A35` | Cards, elevated surfaces |
| Deep Midnight | `#011032` | Hero overlay, video backdrop |
| Dark Ink | `#060C1E` | Alternate section background |
| Glass Tint | `#031123` | Navbar/pill glass backgrounds |

### Primary — Blue Spectrum

| Name | Hex | Usage |
|------|-----|-------|
| Sauron Blue | `#2563EB` | Primary CTA, buttons, active states |
| Ice Blue | `#4F8CFE` | Hover state, logo suffix, accents |
| Cyan | `#00C8FF` | Gradient terminus, glow accents |

### Text Hierarchy

| Name | Value | Usage |
|------|-------|-------|
| White | `#FFFFFF` | Headlines, primary text |
| Ice Light | `#F1F5F9` | Wordmark, body emphasis |
| Cool Gray | `#C8D8E1` | Supporting stats, subtext |
| Muted | `white/65` | Body copy |
| Faint | `white/40–55` | Card descriptions, secondary info |
| Ghost | `white/25` | Footer legal, timestamps |

### Utility

| Name | Value | Usage |
|------|-------|-------|
| Alert Red | `#F87171` (red-400) | Threat labels, SYS.ALERT markers |
| Status Green | `emerald-400/60` | Live status indicators |
| Divider | `white/5–6` | Section borders, grid lines |

### Gradient
Used on headline emphasis and gradient text:
```
linear-gradient(135deg, #4F8CFE 0%, #00C8FF 100%)
```
Applied as `WebkitBackgroundClip: text` for gradient text effects.

---

## 4. Typography

### Type System

| Role | Font | Weight | Usage |
|------|------|--------|-------|
| Display | **Instrument Serif** | 400 (Regular) | Section headlines, monumental questions |
| UI / Body | **Satoshi** | 400–600 | Navigation, body copy, wordmark |
| Labels / Mono | **Space Mono** | 400 | Section tags, hex codes, status labels, CTA text |
| Body (system) | Readex Pro | 400 | Fallback prose body |

### Scale in use

| Element | Size | Font | Notes |
|---------|------|------|-------|
| Hero title | `14vw` / `13vw` (desktop) | Satoshi Medium | `letter-spacing: -0.04em`, `line-height: 0.95` |
| Section headline | `5xl–7xl` | Instrument Serif | `leading-[1.06]` |
| Sub-headline | `3xl–5xl` | Instrument Serif | Monumental questions |
| Body | `lg` (18px) | Satoshi / Readex Pro | `leading-relaxed` |
| Mono label | `9–11px` | Space Mono | `tracking-[0.15em–0.2em]`, always UPPERCASE |
| CTA text | `sm–base` | Satoshi SemiBold | Pill buttons |
| Legal / Caption | `10px` | Space Mono | `white/25` |

### Typography rules
- **Display font is italic-neutral**: use `not-italic` on `<em>` tags — emphasis is conveyed by color (gradient or Ice Blue), not oblique style
- **Hero text**: extreme negative tracking (`-0.04em`), near-collapsed line height (`0.95`)
- **Mono labels**: always uppercase, wide tracking, muted opacity — they are structural markers, not content
- **Hex codes in UI** (e.g. `0x002`, `0x004`): Space Mono, `white/15`, decorative only

---

## 5. Voice & Tone

### Brand voice pillars

**Precise.** Every word earns its place. No hedging, no filler. SauronID names the problem exactly.

**Confrontational (in service of clarity).** The copy asks the questions CTOs avoid. Not aggressive — factual about consequence.

**Technically grounded.** Terms like "mandate," "pre-execution," "audit trail," "kill switch" are used correctly, not metaphorically.

**Urgent without panic.** The threat is real. The solution exists. Urgency is resolved through capability, not fear.

### Voice patterns

**Do:**
- Lead with consequence: *"An agent that approves a supplier payment is a control failure."*
- Ask the uncomfortable question: *"Who gave this agent the right to spend?"*
- Use declarative statements: *"You will."* (not "you might")
- Name what others avoid: *"without pretending control exists when it does not"*

**Don't:**
- Soften risk with qualifiers ("might," "could potentially")
- Use generic SaaS vocabulary ("seamless," "powerful," "next-generation")
- Write long explanations when a question works better
- Use passive voice in CTAs

### CTA patterns
- Action-first, consequence-named: *"stop the next incident"*, *"answer these for your own stack"*
- Diagnostic framing: *"am I exposed?"*, *"check exposure"*
- Never generic: not "get started," not "learn more"

### Section label system
Sections use a mono-label + hex code system to signal structure:
```
SYS.ALERT  ──────────────────────────────  0x002
```
These are decorative structural markers. Keep them terse and system-like.

---

## 6. Layout & Spacing

### Container
- Max content width: `max-w-5xl` (1024px)
- Horizontal padding: `px-6` mobile, `px-10–12` desktop
- Section vertical padding: `py-28–32`

### Grid
- Background grid (decorative): `60px × 60px` white lines at `2% opacity`
- Card grids: `grid-cols-1 sm:grid-cols-2` with `gap-px` dividers on a `white/5` background (creates hairline borders without actual border elements)

### Dividers
- Horizontal: `h-px bg-white/5–6`
- Vertical accent: `w-px bg-white/4` on section left edge

### Elevation / Depth
No traditional box shadows. Depth is expressed through:
1. Background color stacking (darker = deeper)
2. Blue glow shadows on interactive elements
3. Glass overlays (`backdrop-blur` + semi-transparent fill)

---

## 7. Components

### Pill CTA (Primary)
```
bg-[#2563EB] text-white rounded-full px-7–9 py-3.5–4
hover:bg-[#4F8CFE]
shadow-[0_0_24px_rgba(37,99,235,0.4)]
hover:shadow-[0_0_32px_rgba(79,140,254,0.5)]
```
Always includes a `→` arrow icon that translates `+0.5px` on hover.

### Pill CTA (Ghost)
```
border border-white/20 text-white/70 rounded-full px-9 py-4
hover:text-white hover:border-white/40
```

### Glass Nav Pills
```
bg-[#031123]/85 backdrop-blur border border-[#E6F1FF]/10 rounded-full
```
Used for navbar brand lockup and nav link container.

### Section Mono Label
```
font-mono-label text-[10px] tracking-[0.2em] uppercase text-white/70
```
Always paired with a `h-px flex-1 bg-white/5–6` rule and a `0x00N` hex counter on the right.

### Mandate Card (Grid Item)
- Background: `#06090F`
- Top border: `bg-sauron-blue` that scales from 0 to 100% on hover (`scale-x-0 → scale-x-100`, `origin-left`)
- Dot indicator: `w-1.5 h-1.5 rounded-full bg-ice-blue/50`, glows on hover
- Hover fill: `sauron-blue/5`

### Status Badge
```
font-mono-label text-[9px] tracking-[0.15em] uppercase text-emerald-400/50
w-1.5 h-1.5 rounded-full bg-emerald-400/60 animate-pulse
```

---

## 8. Motion & Effects

### Philosophy
Motion is functional and atmospheric — never decorative for its own sake. Effects reinforce the "vigilant system watching everything" brand metaphor.

### Animations in use

| Name | Duration | Effect |
|------|----------|--------|
| `hero-glow` | 9s ease-in-out | Ambient background pulse |
| `hero-glow-2` | 13s ease-in-out | Secondary glow drift |
| `orbit-spin` | 14s linear | Eye orbital ring rotation |
| `iris-pulse` | 3.5s ease-in-out | Eye iris scale/opacity |
| `float-a/b/c` | 5–7s ease-in-out | Floating node drift |
| `ticker-scroll` | 32s linear | Horizontal ticker strip |
| `scanline` | 8s linear | Decorative scan overlay |
| `fade-in-up` | 0.7s ease-out | Section entrance |
| `question-fade` | 0.35s ease-out | Diagnostic question transition |
| `blink` | 1.1s step-end | Cursor blink |

### Hover states
- CTA buttons: background shift (`#2563EB → #4F8CFE`), glow intensifies, arrow translates `0.5px`
- Mono nav links: `white/50 → white` color transition
- Mandate cards: top-border sweep in, dot glow, background tint

### Grain overlay
A subtle noise texture (SVG fractalNoise at `0.9` frequency) applied at `50% opacity`, `mix-blend-mode: overlay` via the `.grain-overlay` class. Used on sections with a solid dark fill to break the flatness.

---

## 9. Iconography

### Style
- Stroke-based, `strokeWidth: 1.8`
- `strokeLinecap: round`, `strokeLinejoin: round`
- Minimal — only arrow directionals in current usage
- Color: `currentColor` (inherits from parent)

### Arrow convention
- `→` (right): forward action, navigation, CTAs
- `↓` (down): scroll, reveal, "see more"

---

## 10. Imagery & Video

### Hero background
A looping dark video (`hero-bg.mp4`) conveying abstract data flow, networks, or surveillance-adjacent motion. Overlaid with a `#011032/70` dark overlay to maintain text legibility.

### Moodboard aesthetic (from approved reference)
- Deep navy environments, electric blue glows
- Abstract eye motifs, orbital structures
- Dark UI screenshots showing the product interface
- No stock photography of people — the product is infrastructure, not human faces
- Mobile mockups maintain the same dark palette

### Photo/illustration rules
- Dark backgrounds only — never reverse the palette
- Blue/cyan highlights as the only accent color
- Avoid warm tones, greens (except status green), or reds outside alert contexts

---

## 11. What Not to Do

- Do not use white or light backgrounds — SauronID lives in the dark
- Do not recolor the `ID` suffix to anything other than `#4F8CFE`
- Do not use rounded-rectangle cards with standard drop shadows — use glass or grid-gap patterns
- Do not write generic enterprise copy ("empower your team," "robust solution")
- Do not use Instrument Serif in italic — emphasis is applied via color gradient, not oblique
- Do not add decorative dividers that aren't hairline (`1px`, `white/5`)
- Do not use the eye icon without the orbital ring — they are a single unit
- Do not animate anything at more than 14s — motion should feel deliberate, not hyperactive
