"use client";

import { useEffect, useState } from "react";
import {
  sauronFetch,
  Card,
  Spinner,
  Kpi,
  PageHeader,
  StatusPill,
  fmtNum,
} from "../shared";

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

// ADR-001: per-batch three-state surface. Each batch reports both chains
// independently so the dashboard can render the three honest states instead
// of a single "anchored" boolean.
interface AnchorBatch {
  anchor_id: string;
  batch_root_hex: string;
  n_actions: number;
  created_at: number;
  btc_anchor_id: string;
  sol_anchor_id: string;
  solana: {
    confirmed: boolean;
    slot: number | null;
    sig: string | null;
  };
  bitcoin: {
    provider: string;
    ots_upgraded: boolean;
    block_height: number | null;
  };
  /** @deprecated kept one minor version for back-compat — see ADR-001 */
  anchored?: boolean;
}

// Threshold past which a BTC anchor that has not been OTS-upgraded is treated
// as "failed — retry queued" instead of merely "pending". OTS calendars usually
// upgrade within one Bitcoin block (~1h); 6h is a generous slack window.
const BTC_STALE_FAILED_SECS = 6 * 60 * 60;

type AnchorState =
  | "pending"
  | "solana-only-pending"
  | "solana-only-failed"
  | "dually-anchored";

function batchState(b: AnchorBatch, nowSec: number): AnchorState {
  if (!b.solana.confirmed) return "pending";
  if (b.bitcoin.ots_upgraded) return "dually-anchored";
  const age = nowSec - b.created_at;
  if (age >= BTC_STALE_FAILED_SECS) return "solana-only-failed";
  return "solana-only-pending";
}

function stateCopy(s: AnchorState): { status: "ok" | "warn" | "err" | "muted"; label: string } {
  switch (s) {
    case "pending":
      return { status: "muted", label: "PENDING" };
    case "solana-only-pending":
      return { status: "warn", label: "SOLANA-CONFIRMED · BTC PENDING" };
    case "solana-only-failed":
      return { status: "err", label: "SOLANA-CONFIRMED · BTC FAILED · RETRY QUEUED" };
    case "dually-anchored":
      return { status: "ok", label: "DUALLY ANCHORED" };
  }
}

interface ActionReceipt {
  receipt_id: string;
  action_hash: string;
  agent_id: string;
  status: string;
  policy_version: string;
  created_at: number;
}

function fmtAgo(unixSec: number): string {
  if (!unixSec) return "—";
  const sec = Math.floor(Date.now() / 1000) - unixSec;
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

export default function AnchorsPage() {
  const [anchor, setAnchor] = useState<AnchorStatus | null>(null);
  const [batches, setBatches] = useState<AnchorBatch[]>([]);
  const [actions, setActions] = useState<ActionReceipt[]>([]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [a, b, r] = await Promise.all([
          sauronFetch<AnchorStatus>("anchor/status"),
          sauronFetch<AnchorBatch[]>("anchor/batches?limit=30").catch(
            () => [] as AnchorBatch[],
          ),
          sauronFetch<ActionReceipt[]>("agent_actions/recent").catch(() => []),
        ]);
        if (cancelled) return;
        setAnchor(a as AnchorStatus);
        setBatches((b as AnchorBatch[]) ?? []);
        setActions((r as ActionReceipt[]).slice(0, 30));
      } catch {
        if (!cancelled) setAnchor(null);
      }
    }
    load();
    const id = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (!anchor) return <Spinner />;

  return (
    <div className="space-y-28">
      <PageHeader
        eyebrow="ANCHOR.PIPELINE"
        hex="0x200"
        title={
          <>
            Receipts pinned to{" "}
            <em className="not-italic gradient-text font-display">two chains</em>{" "}
            in parallel.
          </>
        }
        description="Every batch of agent action receipts is committed to Bitcoin via OpenTimestamps and to Solana via the Memo program. Each batch surfaces three honest states — Pending, Solana-confirmed (BTC pending), Dually anchored — instead of a single 'anchored' summary. Tampering requires forging both chains."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        <Kpi
          label="ANCHOR.BATCHES"
          value={fmtNum(anchor.agent_action_batches)}
          sub={anchor.last_batch_at ? `LAST ${fmtAgo(anchor.last_batch_at).toUpperCase()}` : "NO ANCHORS YET"}
          accent="violet"
        />
        <Kpi
          label="LAST.BATCH.SIZE"
          value={fmtNum(anchor.last_batch_n_actions)}
          sub="ACTIONS IN LAST ANCHOR"
        />
        <Kpi
          label="BITCOIN · OTS"
          value={`${fmtNum(anchor.bitcoin_upgraded)} / ${fmtNum(anchor.bitcoin_total)}`}
          sub={`${anchor.bitcoin_pending_upgrade} PENDING BLOCK INCLUSION`}
          accent="amber"
        />
        <Kpi
          label="SOLANA · MEMO"
          value={`${fmtNum(anchor.solana_confirmed)} / ${fmtNum(anchor.solana_total)}`}
          sub={`${anchor.solana_unconfirmed} UNCONFIRMED`}
          accent="cyan"
        />
      </div>

      {/* Two-chain explainer */}
      <Card title="DUAL.CHAIN.PROOF" hex="0x210">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <ChainPane
            chain="BTC"
            color="#FCD34D"
            title="Bitcoin · OpenTimestamps"
            blurb="Root committed to a public OTS calendar; upgrades to a full Bitcoin block proof after one confirmation (~10 min)."
            verifyCmd="ots verify <receipt>.ots"
          />
          <ChainPane
            chain="SOL"
            color="#A78BFA"
            title="Solana · Memo program"
            blurb="Root posted as a memo transaction on the Memo program; finalised in roughly 30 seconds."
            verifyCmd="solana confirm -v <signature>"
          />
        </div>
      </Card>

      {/* ADR-001: per-batch three-state surface */}
      <Card title="ANCHOR.BATCHES · STATE" hex="0x215">
        <div className="overflow-x-auto -mx-3">
          {batches.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <span className="font-mono-label text-[9.5px] text-white/35">EMPTY</span>
              <p className="text-[12px] text-white/45 max-w-md text-center leading-relaxed">
                No anchor batches yet. Run{" "}
                <code className="text-white/75">POST /admin/anchor/agent-actions/run</code> after
                producing some action receipts.
              </p>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th>WHEN</Th>
                  <Th>BATCH</Th>
                  <Th>ROOT</Th>
                  <Th>ACTIONS</Th>
                  <Th>SOLANA</Th>
                  <Th>BITCOIN · OTS</Th>
                  <Th>STATE</Th>
                </tr>
              </thead>
              <tbody>
                {batches.map((b) => {
                  const nowSec = Math.floor(Date.now() / 1000);
                  const s = batchState(b, nowSec);
                  const pill = stateCopy(s);
                  return (
                    <tr key={b.anchor_id} className="border-t border-white/[0.04]">
                      <Td muted>{fmtAgo(b.created_at)}</Td>
                      <Td mono>{b.anchor_id.slice(0, 14)}…</Td>
                      <Td mono dim>{b.batch_root_hex.slice(0, 16)}…</Td>
                      <Td>{fmtNum(b.n_actions)}</Td>
                      <Td>
                        <StatusPill
                          status={b.solana.confirmed ? "ok" : "muted"}
                          label={b.solana.confirmed ? "CONFIRMED" : "UNCONFIRMED"}
                        />
                      </Td>
                      <Td>
                        <StatusPill
                          status={b.bitcoin.ots_upgraded ? "ok" : "warn"}
                          label={b.bitcoin.ots_upgraded ? "UPGRADED" : "PENDING"}
                        />
                      </Td>
                      <Td>
                        <StatusPill status={pill.status} label={pill.label} />
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      <Card title="ACTION.RECEIPTS · RECENT" hex="0x220">
        <div className="overflow-x-auto -mx-3">
          {actions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <span className="font-mono-label text-[9.5px] text-white/35">EMPTY</span>
              <p className="text-[12px] text-white/45 max-w-md text-center leading-relaxed">
                No action receipts yet. Run{" "}
                <code className="text-white/75">scripts/simulate_real_actions.py</code> to
                produce the action-challenge → receipt-verify flow.
              </p>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th>WHEN</Th>
                  <Th>RECEIPT</Th>
                  <Th>HASH</Th>
                  <Th>AGENT</Th>
                  <Th>STATUS</Th>
                  <Th>POLICY</Th>
                </tr>
              </thead>
              <tbody>
                {actions.map((r) => (
                  <tr key={r.receipt_id} className="border-t border-white/[0.04]">
                    <Td muted>{fmtAgo(r.created_at)}</Td>
                    <Td mono>{r.receipt_id.slice(0, 16)}…</Td>
                    <Td mono dim>{r.action_hash.slice(0, 18)}…</Td>
                    <Td mono>{r.agent_id.slice(0, 14)}…</Td>
                    <Td>
                      <StatusPill
                        status={
                          r.status === "approved" || r.status === "accepted" ? "ok" : "muted"
                        }
                        label={r.status.toUpperCase()}
                      />
                    </Td>
                    <Td muted>{r.policy_version}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}

/* ── Chain explainer pane ─────────────────────────────────────────── */

function ChainPane({
  chain,
  color,
  title,
  blurb,
  verifyCmd,
}: {
  chain: string;
  color: string;
  title: string;
  blurb: string;
  verifyCmd: string;
}) {
  return (
    <div className="bg-[#0F1A35] p-10 relative overflow-hidden rounded border border-white/5">
      <div
        className="absolute -top-16 -right-16 w-40 h-40 rounded-full opacity-20 blur-2xl pointer-events-none"
        style={{ background: color }}
      />
      <div className="flex items-center justify-between mb-7">
        <span className="font-mono-label text-[9.5px]" style={{ color }}>
          {chain} · CHAIN
        </span>
        <span
          className="w-1.5 h-1.5 rounded-full animate-status-pulse"
          style={{ backgroundColor: color, boxShadow: `0 0 12px ${color}` }}
        />
      </div>
      <h3
        className="font-display text-[26px] text-white leading-tight mb-5"
        style={{ letterSpacing: "-0.01em" }}
      >
        {title}
      </h3>
      <p className="text-[13px] text-white/55 leading-[1.7] mb-7">{blurb}</p>
      <div className="border-t border-white/5 pt-6">
        <div className="font-mono-label text-[8.5px] text-white/35 mb-3">
          INDEPENDENT.VERIFY
        </div>
        <code className="block bg-[#06090F] border border-white/5 rounded px-4 py-3 font-mono text-[11.5px] text-[#4F8CFE]">
          $ {verifyCmd}
        </code>
      </div>
    </div>
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
  let cls = "text-white/85";
  if (mono) cls = "font-mono text-[11px] text-white/85";
  if (mono && dim) cls = "font-mono text-[11px] text-white/40";
  if (muted) cls = "text-white/55";
  return (
    <td className={`px-3 py-5 align-middle whitespace-nowrap ${cls}`}>{children}</td>
  );
}
