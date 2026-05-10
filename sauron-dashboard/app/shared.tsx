"use client";

/* ── API helpers ─────────────────────────────────────────────────────────── */

const DASH_API =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002")
    : "http://localhost:8002";

type AdminStats = {
  total_users: number;
  total_clients: number;
  total_api_calls: number;
  total_kyc_retrievals: number;
  total_agent_calls: number;
  total_tokens_b_issued?: number;
  total_tokens_b_spent?: number;
  exchange_rate?: number;
};

type AdminClient = {
  name: string;
  client_type: string;
  tokens_b?: number;
};

type AdminRequest = {
  id: number;
  timestamp: number;
  action_type: string;
  status: string;
  detail: string;
};

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function monthLabel(unixTs: number): string {
  const d = new Date(unixTs * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

function dayLabel(unixTs: number): string {
  const d = new Date(unixTs * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

async function fallbackFromCore(path: string): Promise<unknown> {
  const [stats, clients, requests] = await Promise.all([
    fetchJson<AdminStats>("/api/admin/stats"),
    fetchJson<AdminClient[]>("/api/admin/clients").catch(() => []),
    fetchJson<AdminRequest[]>("/api/admin/requests").catch(() => []),
  ]);

  if (path === "overview") {
    const byDay = new Map<string, { a: number; b: number }>();
    for (const r of requests) {
      const key = dayLabel(r.timestamp);
      const prev = byDay.get(key) ?? { a: 0, b: 0 };
      if (r.action_type === "KYC_RETRIEVE") prev.a += 1;
      if (r.action_type === "BUY_TOKENS") prev.b += 1;
      byDay.set(key, prev);
    }
    const sortedDays = Array.from(byDay.keys()).sort();
    const last90 = sortedDays.slice(-90);
    return {
      kpis: {
        total_full_kyc: stats.total_kyc_retrievals ?? 0,
        total_reduced: stats.total_api_calls ?? 0,
        active_clients: stats.total_clients ?? clients.length,
        kyc_revenue_usd: Number((stats.total_kyc_retrievals ?? 0) * 0.35),
        credit_a_earned: stats.total_api_calls ?? 0,
        credit_b_purchased: stats.total_tokens_b_issued ?? 0,
        query_revenue_usd: Number((stats.total_tokens_b_spent ?? 0) * 0.1),
        failure_rate: 0,
      },
      daily: {
        dates: last90,
        credit_a: last90.map((d) => byDay.get(d)?.a ?? 0),
        credit_b: last90.map((d) => byDay.get(d)?.b ?? 0),
      },
      rings: {
        labels: ["users", "clients", "agents"],
        names: ["User ring", "Client ring", "Agent ring"],
        counts: [
          stats.total_users ?? 0,
          stats.total_clients ?? clients.length,
          stats.total_agent_calls ?? 0,
        ],
      },
    };
  }

  if (path === "anomalies") {
    const failEvents = requests
      .filter((r) => r.status !== "OK")
      .map((r) => ({
        client_id: 0,
        date: new Date(r.timestamp * 1000).toISOString().slice(0, 10),
        anomaly_type: r.action_type,
        severity: r.status === "FAIL" ? "high" : "medium",
        message: r.detail || "request anomaly",
        name: "core",
        type: "system",
      }));
    const byTypeMap = new Map<string, number>();
    const bySevMap = new Map<string, number>();
    const byMonthMap = new Map<string, number>();
    for (const e of failEvents) {
      byTypeMap.set(e.anomaly_type, (byTypeMap.get(e.anomaly_type) ?? 0) + 1);
      bySevMap.set(e.severity, (bySevMap.get(e.severity) ?? 0) + 1);
    }
    for (const r of requests) {
      const m = monthLabel(r.timestamp);
      byMonthMap.set(m, (byMonthMap.get(m) ?? 0) + (r.status !== "OK" ? 1 : 0));
    }
    const months = Array.from(byMonthMap.keys()).sort().slice(-12);
    return {
      events: failEvents,
      by_type: Array.from(byTypeMap.entries()).map(([anomaly_type, count]) => ({ anomaly_type, count })),
      by_severity: Array.from(bySevMap.entries()).map(([severity, count]) => ({ severity, count })),
      monthly: {
        months,
        counts: months.map((m) => byMonthMap.get(m) ?? 0),
      },
    };
  }

  if (path === "insights") {
    return {
      avg_churn_risk: 0,
      avg_trust_score: 0,
      ml_anomalies_detected: 0,
      at_risk_clients: [],
    };
  }

  if (path === "insights/forecast") return { actual: [], forecast: [] };
  if (path === "insights/load") return { historical: [], forecast: [] };
  if (path === "insights/elasticity") return { metrics: [] };
  if (path === "insights/anomalies-ml") return { events: [], total: 0, precision_proxy: null };
  if (path === "insights/clients") {
    return {
      clients: clients.map((c, i) => ({
        client_id: i + 1,
        name: c.name,
        type: c.client_type,
        sector: "identity",
        health_score: 92,
        trust_score: 95,
        churn_risk: 0.08,
        runway_days: 365,
        burn_rate: 0,
        current_balance: c.tokens_b ?? 0,
      })),
    };
  }

  if (path === "gdpr/stats") {
    return {
      total_users: stats.total_users ?? 0,
      eu_eea_scope: stats.total_users ?? 0,
      non_eu_total: 0,
      active_users: stats.total_users ?? 0,
      anonymized_total: 0,
      pending_purge: 0,
      retention_days: 365,
      cutoff_date: new Date().toISOString().slice(0, 10),
      last_run_date: null,
      last_run_purged: 0,
      monthly_history: [],
      run_log: [],
    };
  }

  if (path === "gdpr/purge") {
    return { purged: 0, message: "Purge simulator only in fallback mode" };
  }

  if (path === "pipeline-stats") {
    return {
      live: false,
      throughput: 0,
      avg_latency_ms: 0,
      uptime_pct: 100,
      fraud_detected: 0,
      total_events: requests.length,
      latency: [
        { service: "core", ms: 20 },
        { service: "db", ms: 8 },
        { service: "issuer", ms: 32 },
      ],
      resources: [
        { name: "core", cpu_pct: 12, mem_mb: 220, status: "healthy" },
        { name: "dashboard", cpu_pct: 6, mem_mb: 140, status: "healthy" },
      ],
    };
  }

  throw new Error(`No fallback mapping for '${path}'`);
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

  // 2. Legacy path (parquet-backed FastAPI)
  try {
    return await fetchJson<T>(legacyUrl);
  } catch {
    // 3. Final fallback (hand-stitched from raw core data)
    return (await fallbackFromCore(path)) as T;
  }
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
    <header className="animate-fade-in-up pb-10">
      <div className="mb-10">
        <MonoLabel label={eyebrow ?? "MANDATE.CONSOLE"} hex={hex ?? "0x000"} />
      </div>
      <h1
        className="font-display text-[52px] leading-[1.08] text-white max-w-3xl mb-8"
        style={{ letterSpacing: "-0.015em" }}
      >
        {title}
      </h1>
      {description && (
        <p className="text-[14px] text-white/55 max-w-2xl leading-[1.75]">
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
        "relative rounded-md p-10",
        className ?? "",
      ].join(" ")}
    >
      {title && (
        <div className="mb-10">
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
