"use client";

import { useState } from "react";
import { Card, PageHeader, StatusPill, fmtNum } from "../shared";

const DASH_API =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002")
    : "http://localhost:8002";

interface DemoReceipt {
  receipt_id: string;
  action_hash?: string;
}

interface DemoResult {
  ok: boolean;
  user: string;
  agent_id: string | null;
  config_digest: string | null;
  receipts: DemoReceipt[];
  anchor_id: string | null;
  anchor_status: {
    bitcoin_total: number;
    solana_total: number;
    agent_action_batches: number;
    last_batch_n_actions: number;
  };
  stdout: string;
}

const SEED_USERS = [
  { email: "alice@sauron.dev",   password: "pass_alice",   label: "ALICE" },
  { email: "bob@sauron.dev",     password: "pass_bob",     label: "BOB" },
  { email: "charlie@sauron.dev", password: "pass_charlie", label: "CHARLIE" },
  { email: "diana@sauron.dev",   password: "pass_diana",   label: "DIANA" },
];

export default function DemoPage() {
  const [user, setUser] = useState(SEED_USERS[0]);
  const [nActions, setNActions] = useState(1);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function runDemo() {
    setRunning(true);
    setResult(null);
    setErr(null);
    try {
      const res = await fetch(`${DASH_API}/api/live/demo/run`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: user.email,
          password: user.password,
          n_actions: nActions,
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        setErr(`HTTP ${res.status}: ${text.slice(0, 400)}`);
        return;
      }
      setResult((await res.json()) as DemoResult);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="space-y-14">
      <PageHeader
        eyebrow="LIVE.DEMO"
        hex="0x900"
        title={
          <>
            Bind an agent.{" "}
            <em className="not-italic gradient-text font-display">Sign</em> a real
            action. Anchor it on chain.
          </>
        }
        description="Click run. The dashboard will spin up a fresh agent under the human you pick, mint an A-JWT, sign a payment_initiation with ring + PoP keys, and fire a merkle anchor batch — all in under five seconds."
      />

      {/* Control panel */}
      <Card title="DEMO.CONTROLS" hex="0x901">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-10 mb-10">
          {/* Human picker */}
          <div className="space-y-4">
            <div className="font-mono-label text-[9px] text-white/45">
              SIGN AS HUMAN
            </div>
            <div className="grid grid-cols-2 gap-3">
              {SEED_USERS.map((u) => {
                const active = u.email === user.email;
                return (
                  <button
                    key={u.email}
                    onClick={() => setUser(u)}
                    className={[
                      "bg-[#0F1A35] py-4 px-4 transition-colors text-left rounded border border-white/5",
                      active ? "" : "hover:bg-[#0F1A35]/60",
                    ].join(" ")}
                    style={
                      active
                        ? {
                            boxShadow:
                              "inset 2px 0 0 0 #4F8CFE, 0 0 18px -10px rgba(79,140,254,0.6)",
                          }
                        : {}
                    }
                  >
                    <div className="font-mono-label text-[9px] text-white/85">
                      {u.label}
                    </div>
                    <div className="font-mono text-[10px] text-white/40 truncate mt-1">
                      {u.email}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* N actions */}
          <div className="space-y-4">
            <div className="font-mono-label text-[9px] text-white/45">
              ACTIONS PER RUN
            </div>
            <div className="grid grid-cols-3 gap-3">
              {[1, 2, 3].map((n) => (
                <button
                  key={n}
                  onClick={() => setNActions(n)}
                  className={[
                    "bg-[#0F1A35] py-4 transition-colors rounded border border-white/5",
                    nActions === n ? "text-[#4F8CFE]" : "text-white/55 hover:bg-[#0F1A35]/60",
                  ].join(" ")}
                  style={
                    nActions === n
                      ? {
                          boxShadow:
                            "inset 0 2px 0 0 #4F8CFE, 0 0 14px -8px rgba(79,140,254,0.7)",
                        }
                      : {}
                  }
                >
                  <div
                    className="text-[24px] tabular-nums"
                    style={{
                      fontFamily: "Satoshi, system-ui, sans-serif",
                      fontWeight: 500,
                      letterSpacing: "-0.025em",
                    }}
                  >
                    {n}
                  </div>
                </button>
              ))}
            </div>
            <div className="font-mono-label text-[8.5px] text-white/30">
              EACH ACTION = 1 RECEIPT IN agent_action_receipts
            </div>
          </div>

          {/* Run button */}
          <div className="space-y-4 flex flex-col">
            <div className="font-mono-label text-[9px] text-white/45">
              EXECUTE
            </div>
            <button
              onClick={runDemo}
              disabled={running}
              className={[
                "flex-1 rounded-md py-5 px-5 font-mono-label tracking-[0.2em] text-[11px]",
                "transition-all duration-200 relative overflow-hidden",
                running
                  ? "bg-[#0F1A35] text-white/40 cursor-not-allowed"
                  : "bg-[#2563EB] text-white hover:bg-[#4F8CFE]",
              ].join(" ")}
              style={
                !running
                  ? { boxShadow: "0 0 32px -6px rgba(37,99,235,0.55)" }
                  : {}
              }
            >
              {running ? (
                <span className="flex items-center justify-center gap-3">
                  <span className="w-3 h-3 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  RUNNING DEMO…
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  RUN END-TO-END DEMO →
                </span>
              )}
            </button>
            <div className="font-mono-label text-[8.5px] text-white/30 leading-relaxed">
              REGISTER → A-JWT → POP → ACTION → RING-SIG → ANCHOR
            </div>
          </div>
        </div>

        {/* Status row */}
        <div className="flex items-center gap-4 pt-5 border-t border-white/5">
          <StatusPill
            status={running ? "warn" : err ? "err" : result ? "ok" : "muted"}
            label={
              running
                ? "EXECUTING"
                : err
                ? "FAILED"
                : result
                ? `OK · ${result.receipts.length} RECEIPT${result.receipts.length === 1 ? "" : "S"}`
                : "IDLE"
            }
          />
          <span className="font-mono-label text-[9px] text-white/35">
            {result
              ? `AGENT ${result.agent_id?.slice(0, 18)}…`
              : "NO RUN YET"}
          </span>
        </div>
      </Card>

      {/* Error */}
      {err && (
        <Card title="ERROR" hex="0xFFF">
          <code className="block font-mono text-[11px] text-[#F87171]/85 leading-relaxed whitespace-pre-wrap">
            {err}
          </code>
          <p className="mt-4 text-[12px] text-white/55">
            Common causes: core not running on :3001, agent-action-tool binary not
            built (run <code className="text-white/75">cd core && cargo build --release</code>),
            or the chosen seed user has hit the per-agent rate limit. Stderr is in
            the analytics shim logs.
          </p>
        </Card>
      )}

      {/* Result */}
      {result && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <ResultTile
              label="AGENT.REGISTERED"
              value={result.agent_id ? result.agent_id.slice(0, 14) + "…" : "—"}
              sub="FRESH BINDING"
              accent="#4F8CFE"
            />
            <ResultTile
              label="RECEIPTS.MINTED"
              value={String(result.receipts.length)}
              sub={`POLICY KYA_MATRIX_V2`}
              accent="#34D399"
            />
            <ResultTile
              label="ANCHOR.BATCH"
              value={result.anchor_id ? result.anchor_id.slice(0, 14) + "…" : "—"}
              sub={`${result.anchor_status.last_batch_n_actions} ACTIONS`}
              accent="#A78BFA"
            />
            <ResultTile
              label="BTC / SOL"
              value={`${result.anchor_status.bitcoin_total} / ${result.anchor_status.solana_total}`}
              sub="ANCHORS PUBLISHED"
              accent="#FCD34D"
            />
          </div>

          <Card title={`RECEIPTS · ${result.receipts.length}`} hex="0x910">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th>#</Th>
                  <Th>RECEIPT.ID</Th>
                  <Th>ACTION.HASH</Th>
                  <Th>STATUS</Th>
                </tr>
              </thead>
              <tbody>
                {result.receipts.map((r, i) => (
                  <tr key={r.receipt_id} className="border-t border-white/[0.04]">
                    <Td muted mono>
                      {String(i + 1).padStart(2, "0")}
                    </Td>
                    <Td mono>{r.receipt_id.slice(0, 24)}…</Td>
                    <Td mono dim>
                      {r.action_hash ? r.action_hash.slice(0, 24) + "…" : "—"}
                    </Td>
                    <Td>
                      <StatusPill status="ok" label="ACCEPTED" />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="EXECUTION.LOG" hex="0x920">
            <pre className="text-[11px] text-white/55 leading-relaxed font-mono whitespace-pre-wrap max-h-72 overflow-y-auto bg-[#06090F] border border-white/5 rounded p-4">
              {result.stdout}
            </pre>
          </Card>

          <Card title="WHAT.JUST.HAPPENED" hex="0x930">
            <ol className="space-y-3 text-[13px] text-white/70 leading-relaxed">
              <Step n="01" label={`Authenticated ${result.user} via OPRF, got back the human key-image.`} />
              <Step n="02" label="Generated a fresh ring keypair (Ristretto) + PoP Ed25519 keypair." />
              <Step n="03" label="Registered the agent: server canonicalised checksum_inputs, computed sha256, stored intent + maxAmount." />
              <Step n="04" label={`Issued an A-JWT for the agent (jti single-use, expires 600 s).`} />
              <Step n="05" label="Pulled a one-time PoP challenge, signed it as a compact JWS." />
              <Step n="06" label="Pulled a canonical action envelope, ring-signed it through agent-action-tool." />
              <Step n="07" label={`Posted /agent/payment/authorize with the FULL proof: A-JWT + PoP JWS + ring sig + per-call DPoP-style sig — server inserted ${fmtNum(result.receipts.length)} row${result.receipts.length === 1 ? "" : "s"} into agent_action_receipts.`} />
              <Step n="08" label={`Forced an anchor batch: ${result.anchor_id ?? "n/a"}. Bitcoin OTS submitted; Solana fires when SAURON_SOLANA_ENABLED=1.`} />
            </ol>
          </Card>
        </>
      )}
    </div>
  );
}

/* ── Local atoms ─────────────────────────────────────────────────── */

function ResultTile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string;
  sub: string;
  accent: string;
}) {
  return (
    <div className="relative glass rounded-md px-5 py-5 flex flex-col gap-3 overflow-hidden">
      <span
        aria-hidden
        className="absolute top-0 left-0 right-0 h-px"
        style={{ background: accent, boxShadow: `0 0 14px ${accent}` }}
      />
      <span className="font-mono-label text-[9px] text-white/45">{label}</span>
      <span
        className="text-[20px] tabular-nums leading-none font-mono text-white"
        style={{ wordBreak: "break-all" }}
      >
        {value}
      </span>
      <span className="font-mono-label text-[8.5px] text-white/35 tracking-[0.18em]">
        {sub}
      </span>
    </div>
  );
}

function Step({ n, label }: { n: string; label: string }) {
  return (
    <li className="flex gap-5">
      <span className="font-mono-label text-[10px] text-[#4F8CFE] flex-shrink-0">
        {n}
      </span>
      <span>{label}</span>
    </li>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="font-mono-label text-[8.5px] text-white/40 px-3 py-4 font-normal text-left">
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
    <td className={`px-3 py-4 align-middle whitespace-nowrap ${cls}`}>{children}</td>
  );
}
