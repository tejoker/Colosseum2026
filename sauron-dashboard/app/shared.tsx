"use client";

/* ── API helpers ─────────────────────────────────────────────────────────── */

const DASH_API =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002")
    : "http://localhost:8002";

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * Resolve dashboard data with explicit live-source priority:
 *
 *   1. Try `${DASH_API}/api/live/${path}` first — these endpoints are
 *      backed by direct HTTP queries against the SauronID core, with no
 *      parquet / cached intermediate. Fresh on every request.
 *   2. If that returns 503 (core unreachable) or 404 (endpoint not yet
 *      migrated), fall back to the legacy `${DASH_API}/api/${path}`.
 *   3. Only on all-paths-failed, surface the structured fallback so the
 *      page can render something — but the page is responsible for showing
 *      a stale-data warning when this fallback fires.
 *
 * **Important:** the live path explicitly throws a `LiveUnreachableError`
 * on 503, which a page can catch and render a clear "core unreachable"
 * banner — never silently substituting stale data for live numbers.
 */
export class LiveUnreachableError extends Error {
  constructor(public hint: string) {
    super(`live source unreachable: ${hint}`);
  }
}

export async function sauronFetch<T>(path: string): Promise<T> {
  const cleaned = path.replace(/^\//, "");
  const liveUrl = `${DASH_API}/api/live/${cleaned}`;
  const legacyUrl = `${DASH_API}/api/${cleaned}`;

  // 1. Live path
  try {
    const res = await fetch(liveUrl);
    if (res.status === 503) {
      let hint = "503";
      try {
        const j = await res.json();
        hint = j?.detail?.hint ?? j?.detail ?? "503";
      } catch {
        /* not JSON */
      }
      throw new LiveUnreachableError(String(hint));
    }
    if (res.ok) return (await res.json()) as T;
    // 404 / non-503 4xx → endpoint not migrated yet, fall through.
  } catch (e) {
    if (e instanceof LiveUnreachableError) throw e;
    // network / DNS — fall through to legacy
  }

  // 2. Legacy path (FastAPI shim) — for endpoints not yet under /api/live
  return await fetchJson<T>(legacyUrl);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Visual primitives — SauronID dark palette per BRANDING.md
 *  Depth via stacking + glass + glow, never drop-shadow on white.
 * ──────────────────────────────────────────────────────────────────────── */

const ACCENT_MAP: Record<string, string> = {
  blue:    "text-[#4F8CFE]",
  cyan:    "text-[#00C8FF]",
  red:     "text-[#F87171]",
  emerald: "text-[#34D399]",
  amber:   "text-[#FCD34D]",
  violet:  "text-[#A78BFA]",
  white:   "text-white",
};

function resolveAccent(accent?: string): string {
  if (!accent) return "text-white";
  if (accent.startsWith("text-")) return accent;            // legacy hex / tailwind class
  return ACCENT_MAP[accent] ?? "text-white";
}

/* ── KPI tile — glass surface, mono label, gradient hairline divider ───── */
export function Kpi({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="relative glass rounded-md px-7 py-8 flex flex-col gap-5 overflow-hidden group transition-colors hover:border-[rgba(79,140,254,0.25)]">
      {/* Top hairline accent — sweeps in on hover */}
      <span
        aria-hidden
        className="absolute top-0 left-0 right-0 h-px bg-[#4F8CFE] origin-left scale-x-0 group-hover:scale-x-100 transition-transform duration-500"
      />
      <span className="font-mono-label text-[9px] text-white/45">{label}</span>
      <span
        className={`text-[32px] tabular-nums leading-none ${resolveAccent(accent)}`}
        style={{ fontFamily: "Satoshi, system-ui, sans-serif", fontWeight: 500, letterSpacing: "-0.025em" }}
      >
        {value}
      </span>
      {sub && (
        <span className="text-[10.5px] text-white/35 font-mono-label tracking-[0.12em] mt-1">
          {sub}
        </span>
      )}
    </div>
  );
}

/* ── Section header (Mono label + hairline + hex counter) ────────────────
 * Per BRANDING §3 + §6 — purely structural marker, not content.
 */
export function MonoLabel({ label, hex }: { label: string; hex?: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="font-mono-label text-[9.5px] text-white/55">{label}</span>
      <span className="h-px flex-1 hairline" />
      {hex && <span className="font-mono-label text-[9px] text-white/25">{hex}</span>}
    </div>
  );
}

export function Section({
  title,
  hex,
  children,
}: {
  title: string;
  hex?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-4">
      <MonoLabel label={title} hex={hex} />
      {children}
    </section>
  );
}

/* ── Page title — Instrument Serif display, gradient-tagged ──────────── */
export function PageHeader({
  eyebrow,
  title,
  description,
  hex,
}: {
  eyebrow?: string;
  title: React.ReactNode;
  description?: React.ReactNode;
  hex?: string;
}) {
  return (
    <header className="animate-fade-in-up pb-16">
      <div className="mb-12">
        <MonoLabel label={eyebrow ?? "MANDATE.CONSOLE"} hex={hex ?? "0x000"} />
      </div>
      <h1
        className="font-display text-[44px] leading-[1.1] text-white max-w-3xl mb-10"
        style={{ letterSpacing: "-0.015em" }}
      >
        {title}
      </h1>
      {description && (
        <p className="text-[14px] text-white/55 max-w-xl leading-[1.85]">
          {description}
        </p>
      )}
    </header>
  );
}

/* ── Card — glass deep with optional mono header ────────────────────── */
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
        "relative rounded-md px-10 pt-10 pb-12",
        className ?? "",
      ].join(" ")}
    >
      {title && (
        <div className="mb-12">
          <MonoLabel label={title} hex={hex} />
        </div>
      )}
      {children}
    </div>
  );
}

/* ── Spinner — ice-blue ring on dark ─────────────────────────────────── */
export function Spinner() {
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-3">
      <div className="relative w-10 h-10">
        <div
          className="absolute inset-0 rounded-full border-[2px] border-white/8 border-t-[#4F8CFE] animate-spin"
          style={{ animationDuration: "1.1s" }}
        />
        <div
          className="absolute inset-2 rounded-full border-[1.5px] border-transparent border-t-[#00C8FF] animate-spin"
          style={{ animationDuration: "1.6s", animationDirection: "reverse" }}
        />
      </div>
      <span className="font-mono-label text-[9.5px] text-white/45">
        QUERYING MANDATE LAYER
      </span>
    </div>
  );
}

/* ── Status pill — for tables and metric headers ─────────────────────── */
export function StatusPill({
  status,
  label,
}: {
  status: "ok" | "warn" | "err" | "muted";
  label: string;
}) {
  const map = {
    ok:    { dot: "bg-[#34D399]",  text: "text-[#34D399]/85", border: "border-[#34D399]/20" },
    warn:  { dot: "bg-[#FCD34D]",  text: "text-[#FCD34D]/85", border: "border-[#FCD34D]/20" },
    err:   { dot: "bg-[#F87171]",  text: "text-[#F87171]/85", border: "border-[#F87171]/25" },
    muted: { dot: "bg-white/30",   text: "text-white/45",     border: "border-white/8" },
  } as const;
  const c = map[status];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border ${c.border}`}>
      <span className={`w-1 h-1 rounded-full ${c.dot} ${status === "ok" ? "animate-status-pulse" : ""}`} />
      <span className={`font-mono-label text-[8.5px] ${c.text}`}>{label}</span>
    </span>
  );
}

/* ── Format helpers ───────────────────────────────────────────────────────── */
export function fmtNum(n: number | null | undefined, decimals = 0): string {
  if (n == null) return "\u2014";
  return n.toLocaleString("en-US", { maximumFractionDigits: decimals });
}

export function fmtPct(n: number | null | undefined): string {
  if (n == null) return "\u2014";
  return `${n.toFixed(1)}%`;
}

export function fmtUsd(n: number | null | undefined): string {
  if (n == null) return "\u2014";
  return `$${fmtNum(n, 2)}`;
}
