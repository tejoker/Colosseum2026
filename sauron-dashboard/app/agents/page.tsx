"use client";

import { useEffect, useState } from "react";
import {
  sauronFetch,
  Card,
  Spinner,
  PageHeader,
  StatusPill,
  fmtNum,
} from "../shared";

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

interface PerAgentMetric {
  agent_id: string;
  action_count: number;
  egress_count: number;
  last_action_at: number;
}

type Filter = "all" | "active" | "revoked" | "no-pop";

function fmtAgo(unixSec: number): string {
  if (!unixSec) return "—";
  const sec = Math.floor(Date.now() / 1000) - unixSec;
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

const FILTERS: { id: Filter; label: string; hex: string; accent: string }[] = [
  { id: "all",     label: "TOTAL",   hex: "0x100", accent: "#4F8CFE" },
  { id: "active",  label: "ACTIVE",  hex: "0x101", accent: "#34D399" },
  { id: "revoked", label: "REVOKED", hex: "0x102", accent: "#F87171" },
  { id: "no-pop",  label: "NO·POP",  hex: "0x103", accent: "#FCD34D" },
];

export default function AgentsPage() {
  const [agents, setAgents] = useState<AgentRow[] | null>(null);
  const [metrics, setMetrics] = useState<Record<string, PerAgentMetric>>({});
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [a, m] = await Promise.all([
          sauronFetch<AgentRow[]>("agents"),
          sauronFetch<PerAgentMetric[]>("per_agent_metrics").catch(() => []),
        ]);
        if (cancelled) return;
        setAgents(a as AgentRow[]);
        const map: Record<string, PerAgentMetric> = {};
        for (const r of m as PerAgentMetric[]) map[r.agent_id] = r;
        setMetrics(map);
      } catch {
        if (!cancelled) setAgents([]);
      }
    }
    load();
    const id = setInterval(load, 10_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (agents === null) return <Spinner />;

  const filtered = agents.filter((a) => {
    if (filter === "active" && a.revoked) return false;
    if (filter === "revoked" && !a.revoked) return false;
    if (filter === "no-pop" && a.has_pop) return false;
    if (search && !a.agent_id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const total = agents.length;
  const counts = {
    all: total,
    active: agents.filter((a) => !a.revoked).length,
    revoked: agents.filter((a) => a.revoked).length,
    "no-pop": agents.filter((a) => !a.has_pop).length,
  } as Record<Filter, number>;

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="MANDATE.AGENTS"
        hex="0x100"
        title={
          <>
            Bound agents.{" "}
            <em className="not-italic gradient-text font-display">Auditable</em>{" "}
            keys, signed every step.
          </>
        }
        description="Each agent is a typed binding between a human key-image and a config digest. Revoke any one, anywhere, and its A-JWTs are dead the next call."
      />

      {/* Filter strip — clickable counter cards with brand-colored active accent */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-white/[0.04] rounded overflow-hidden">
        {FILTERS.map((f) => {
          const active = filter === f.id;
          return (
            <button
              key={f.id}
              onClick={() => setFilter(f.id)}
              className={[
                "relative bg-[#0F1A35] text-left p-4 transition-colors group",
                active ? "" : "hover:bg-[#0F1A35]/60",
              ].join(" ")}
            >
              <span
                aria-hidden
                className="absolute top-0 left-0 right-0 h-px transition-transform origin-left"
                style={{
                  backgroundColor: f.accent,
                  transform: active ? "scaleX(1)" : "scaleX(0)",
                  boxShadow: active ? `0 0 14px ${f.accent}` : "none",
                }}
              />
              <div className="flex items-center justify-between mb-2">
                <span
                  className={`font-mono-label text-[9px] ${
                    active ? "text-white/85" : "text-white/40 group-hover:text-white/65"
                  }`}
                >
                  {f.label}
                </span>
                <span className="font-mono-label text-[8.5px] text-white/20">{f.hex}</span>
              </div>
              <div
                className="text-[28px] tabular-nums leading-none"
                style={{
                  fontFamily: "Satoshi, system-ui, sans-serif",
                  fontWeight: 500,
                  letterSpacing: "-0.025em",
                  color: active ? f.accent : "rgba(255,255,255,0.85)",
                }}
              >
                {fmtNum(counts[f.id])}
              </div>
            </button>
          );
        })}
      </div>

      <Card title={`AGENT.LIST · ${filtered.length}`} hex="0x110">
        <div className="mb-4 flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <input
              type="text"
              placeholder="filter by agent_id…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#06090F] border border-white/10 rounded px-3 py-2 text-[12.5px] text-white placeholder:text-white/30 font-mono focus:outline-none focus:border-[#4F8CFE]/50 focus:bg-[#0A1128] transition-colors"
            />
            <span className="absolute right-3 top-1/2 -translate-y-1/2 font-mono-label text-[8.5px] text-white/25">
              REGEX
            </span>
          </div>
          <span className="font-mono-label text-[9px] text-white/35">
            {filtered.length} / {total}
          </span>
        </div>

        <div className="overflow-x-auto -mx-2">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <span className="font-mono-label text-[9.5px] text-white/35">NO MATCHES</span>
              <p className="text-[12px] text-white/45 max-w-xs text-center">
                Adjust the filter or clear the search.
              </p>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th>AGENT</Th>
                  <Th>TYPE</Th>
                  <Th>ASSURANCE</Th>
                  <Th>POP</Th>
                  <Th>CHECKSUM</Th>
                  <Th right>ACTIONS</Th>
                  <Th right>EGRESS</Th>
                  <Th>ISSUED</Th>
                  <Th>LAST.SEEN</Th>
                  <Th>STATE</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => {
                  const m = metrics[a.agent_id];
                  return (
                    <tr key={a.agent_id} className="border-t border-white/[0.04]">
                      <Td mono>{a.agent_id.slice(0, 20)}…</Td>
                      <Td muted>{a.agent_type || "—"}</Td>
                      <Td muted>{a.assurance_level}</Td>
                      <Td>
                        {a.has_pop ? (
                          <span className="text-[#34D399]">●</span>
                        ) : (
                          <span className="font-mono-label text-[9px] text-[#FCD34D]/85">NO·POP</span>
                        )}
                      </Td>
                      <Td mono dim>{a.agent_checksum.slice(7, 21)}…</Td>
                      <Td right>{m?.action_count ?? 0}</Td>
                      <Td right>{m?.egress_count ?? 0}</Td>
                      <Td muted>{fmtAgo(a.issued_at)}</Td>
                      <Td muted>{m?.last_action_at ? fmtAgo(m.last_action_at) : "—"}</Td>
                      <Td>
                        <StatusPill
                          status={a.revoked ? "err" : "ok"}
                          label={a.revoked ? "REVOKED" : "ACTIVE"}
                        />
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}

/* ── Local atoms ──────────────────────────────────────────────────── */

function Th({ children, right }: { children: React.ReactNode; right?: boolean }) {
  return (
    <th
      className={[
        "font-mono-label text-[8.5px] text-white/40 px-2 py-2 font-normal",
        right ? "text-right" : "",
      ].join(" ")}
    >
      {children}
    </th>
  );
}

function Td({
  children,
  mono,
  dim,
  muted,
  right,
}: {
  children: React.ReactNode;
  mono?: boolean;
  dim?: boolean;
  muted?: boolean;
  right?: boolean;
}) {
  let cls = "text-white/85";
  if (mono) cls = "font-mono text-[11px] text-white/85";
  if (mono && dim) cls = "font-mono text-[11px] text-white/40";
  if (muted) cls = "text-white/55";
  return (
    <td
      className={[
        "px-2 py-2 align-middle whitespace-nowrap",
        right ? "text-right tabular-nums" : "",
        cls,
      ].join(" ")}
    >
      {children}
    </td>
  );
}
