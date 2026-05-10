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
