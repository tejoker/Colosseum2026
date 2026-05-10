"use client";

import { useEffect, useState } from "react";
import "./chartSetup";
import { BRAND } from "./chartSetup";
import { Line, Doughnut } from "react-chartjs-2";
import {
  sauronFetch,
  Kpi,
  Card,
  Spinner,
  StatusPill,
  fmtNum,
} from "./shared";

/* ── Live data shapes (match /api/live/* in data/sauron/app.py) ──────── */

interface LiveOverview {
  kpis: {
    total_users: number;
    total_clients: number;
    total_agents: number;
    active_agents: number;
    total_api_calls?: number;
    total_kyc_retrievals?: number;
    total_agent_calls?: number;
  };
  daily?: {
    dates: string[];
    actions?: number[];
    api_requests?: number[];
    /** legacy aliases — still present for one release */
    credit_a?: number[];
    credit_b?: number[];
  };
  rings?: { names: string[]; counts: number[] };
  anchor?: AnchorStatus;
  controls?: Record<string, unknown>;
}

interface AnchorStatus {
  bitcoin_total: number;
  bitcoin_pending_upgrade: number;
  bitcoin_upgraded: number;
  solana_total: number;
  solana_unconfirmed: number;
  solana_confirmed: number;
  agent_action_batches: number;
  last_batch_at: number;
  last_batch_n_actions: number;
}

interface ActionReceipt {
  receipt_id: string;
  action_hash: string;
  agent_id: string;
  status: string;
  policy_version: string;
  created_at: number;
}

interface AgentRow {
  agent_id: string;
  human_key_image: string;
  agent_checksum: string;
  assurance_level: string;
  issued_at: number;
  expires_at: number;
  revoked: boolean;
  has_pop: boolean;
  agent_type: string;
}

interface HealthSummary {
  ok: boolean;
  runtime: string;
  call_sig_enforce: boolean;
  require_agent_type: boolean;
  warnings?: string[];
}

const LINE_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  interaction: { mode: "index" as const, intersect: false },
  plugins: {
    legend: {
      display: true,
      position: "top" as const,
      align: "end" as const,
      labels: {
        boxWidth: 8,
        boxHeight: 8,
        usePointStyle: true,
        pointStyle: "circle" as const,
        font: { family: "'Space Mono', monospace", size: 9 },
        color: "rgba(255,255,255,0.6)",
      },
    },
  },
  scales: {
    x: {
      grid: { display: false, drawTicks: false },
      ticks: {
        maxTicksLimit: 6,
        font: { family: "'Space Mono', monospace", size: 9 },
        color: "rgba(255,255,255,0.35)",
      },
      border: { display: false },
    },
    y: {
      beginAtZero: true,
      grid: { color: "rgba(255,255,255,0.04)", drawTicks: false },
      ticks: {
        font: { family: "'Space Mono', monospace", size: 9 },
        color: "rgba(255,255,255,0.35)",
        padding: 8,
      },
      border: { display: false },
    },
  },
};

const DOUGHNUT_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  cutout: "68%",
  plugins: {
    legend: {
      display: true,
      position: "bottom" as const,
      labels: {
        boxWidth: 8,
        boxHeight: 8,
        padding: 12,
        usePointStyle: true,
        pointStyle: "rect" as const,
        font: { family: "'Space Mono', monospace", size: 9 },
        color: "rgba(255,255,255,0.55)",
      },
    },
  },
};

function fmtAgo(unixSec: number): string {
  if (!unixSec) return "—";
  const sec = Math.floor(Date.now() / 1000) - unixSec;
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

/* ────────────────────────────────────────────────────────────────────── */

export default function OverviewPage() {
  const [overview, setOverview] = useState<LiveOverview | null>(null);
  const [actions, setActions] = useState<ActionReceipt[]>([]);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [health, setHealth] = useState<HealthSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [o, a, ag, h] = await Promise.all([
          sauronFetch<LiveOverview>("overview").catch(() => null),
          sauronFetch<ActionReceipt[]>("agent_actions/recent").catch(() => []),
          sauronFetch<AgentRow[]>("agents").catch(() => []),
          sauronFetch<HealthSummary>("health").catch(() => null),
        ]);
        if (cancelled) return;
        setOverview(o);
        setActions((a as ActionReceipt[]).slice(0, 8));
        setAgents(ag as AgentRow[]);
        setHealth(h);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    }
    load();
    const id = setInterval(load, 10_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (error) {
    return (
      <Card title="LIVE.SOURCE.UNREACHABLE" hex="0xFFF">
        <code className="block mt-2 text-[11px] text-[#F87171]/80 font-mono leading-relaxed">
          {error}
        </code>
        <p className="mt-3 text-[12px] text-white/55">
          The mandate console could not reach the SauronID core or the analytics
          shim. Check both processes are up: <code className="text-white/75">launch.sh</code>.
        </p>
      </Card>
    );
  }
  if (!overview) return <Spinner />;

  const k = overview.kpis;
  const anchor = overview.anchor;
  const activeAgents = agents.filter((a) => !a.revoked).length;
  const revokedAgents = agents.length - activeAgents;
  const popBoundAgents = agents.filter((a) => a.has_pop && !a.revoked).length;

  const DELTA_WINDOW = 7;
  const dailyActions = overview.daily?.actions ?? overview.daily?.credit_a ?? [];
  const sparkData = dailyActions.length >= 2 ? dailyActions : undefined;
  const actionDelta =
    dailyActions.length > DELTA_WINDOW
      ? dailyActions[dailyActions.length - 1] - dailyActions[dailyActions.length - 1 - DELTA_WINDOW]
      : undefined;

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
}

/* ── Local atoms ──────────────────────────────────────────────────── */

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <span className="flex items-center gap-2">
      <span className="font-mono-label text-[8.5px] text-white/35">{label}</span>
      <span className="font-mono-label text-[9px] text-white/75">{value}</span>
    </span>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="font-mono-label text-[8.5px] text-white/40 px-3 py-5 font-normal">
      {children}
    </th>
  );
}

function Td({
  children,
  mono,
  dim,
  muted,
}: {
  children: React.ReactNode;
  mono?: boolean;
  dim?: boolean;
  muted?: boolean;
}) {
  const base = "px-3 py-5 align-middle whitespace-nowrap";
  let cls = "text-white/85";
  if (mono) cls = "font-mono text-[11.5px] text-white/85";
  if (mono && dim) cls = "font-mono text-[11.5px] text-white/45";
  if (muted) cls = "text-white/55";
  return <td className={`${base} ${cls}`}>{children}</td>;
}

function Empty({ hint }: { hint: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-10 gap-2">
      <span className="font-mono-label text-[9.5px] text-white/35">EMPTY</span>
      <p className="text-[12px] text-white/45 max-w-xs text-center leading-relaxed">{hint}</p>
    </div>
  );
}
