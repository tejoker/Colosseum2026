"use client";

import { useEffect, useRef, useState } from "react";
import { Card, PageHeader, StatusPill } from "../shared";

const DASH_API =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002")
    : "http://localhost:8002";

/* ── Event types from the streaming endpoint ─────────────────────── */

type Step = {
  id: string;
  label: string;
  state: "pending" | "running" | "done" | "fail";
  ms?: number;
  detail?: Record<string, unknown>;
  error?: string;
};

interface ReceiptOut {
  receipt_id: string;
  action_hash?: string;
  amount_minor?: number;
  currency?: string;
}

interface RunDone {
  agent_id: string;
  config_digest: string;
  receipts: ReceiptOut[];
  anchor_id: string | null;
  anchor_status: {
    bitcoin_total: number;
    solana_total: number;
    agent_action_batches: number;
    last_batch_n_actions: number;
  };
}

interface AttackSpec {
  kind: string;
  label: string;
  expect: string;
}

interface AttackResult {
  kind: string;
  label: string;
  blocked: boolean;
  status: number;
  detail: string;
}

/* ── Seed users ──────────────────────────────────────────────────── */

const SEED_USERS = [
  { email: "alice@sauron.dev",   password: "pass_alice",   label: "ALICE" },
  { email: "bob@sauron.dev",     password: "pass_bob",     label: "BOB" },
  { email: "charlie@sauron.dev", password: "pass_charlie", label: "CHARLIE" },
  { email: "diana@sauron.dev",   password: "pass_diana",   label: "DIANA" },
];

/* ── Stream parsing ──────────────────────────────────────────────── */

async function* readSseLines(res: Response): AsyncGenerator<string> {
  if (!res.body) return;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split("\n\n");
    buf = parts.pop() ?? "";
    for (const block of parts) {
      for (const line of block.split("\n")) {
        if (line.startsWith("data:")) {
          const payload = line.slice(5).trim();
          if (payload) yield payload;
        }
      }
    }
  }
}

/* ── Page ────────────────────────────────────────────────────────── */

export default function DemoPage() {
  const [user, setUser] = useState(SEED_USERS[0]);
  const [nActions, setNActions] = useState(1);

  // Custom intent
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [modelId, setModelId] = useState("claude-opus-4-7");
  const [systemPrompt, setSystemPrompt] = useState("You are a research agent that can search and fetch.");
  const [tools, setTools] = useState("search,fetch,pay");
  const [maxAmount, setMaxAmount] = useState("100.00");
  const [currency, setCurrency] = useState("EUR");
  const [merchantAllowlist, setMerchantAllowlist] = useState("mch_demo_payments");

  // Run state
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<Step[]>([]);
  const [done, setDone] = useState<RunDone | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const stepsRef = useRef<Step[]>([]);

  // Attacks
  const [catalog, setCatalog] = useState<AttackSpec[]>([]);
  const [attackResults, setAttackResults] = useState<Record<string, AttackResult>>({});
  const [attackInFlight, setAttackInFlight] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${DASH_API}/api/live/demo/attacks`)
      .then((r) => r.json())
      .then((j) => setCatalog(j.attacks ?? []))
      .catch(() => {});
  }, []);

  function pushStep(next: Step) {
    stepsRef.current = [...stepsRef.current, next];
    setSteps(stepsRef.current);
  }
  function patchStep(id: string, patch: Partial<Step>) {
    stepsRef.current = stepsRef.current.map((s) => (s.id === id ? { ...s, ...patch } : s));
    setSteps(stepsRef.current);
  }
  function resetSteps() {
    stepsRef.current = [];
    setSteps([]);
  }

  async function runDemo() {
    setRunning(true);
    setDone(null);
    setErr(null);
    resetSteps();

    const body = {
      email: user.email,
      password: user.password,
      n_actions: nActions,
      ...(showAdvanced && {
        model_id: modelId,
        system_prompt: systemPrompt,
        tools,
        max_amount: maxAmount,
        currency,
        merchant_allowlist: merchantAllowlist,
      }),
    };

    try {
      const res = await fetch(`${DASH_API}/api/live/demo/stream`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const text = await res.text();
        setErr(`HTTP ${res.status}: ${text.slice(0, 400)}`);
        return;
      }
      for await (const line of readSseLines(res)) {
        let evt: Record<string, unknown>;
        try {
          evt = JSON.parse(line);
        } catch {
          continue;
        }
        const ev = String(evt.event);
        if (ev === "step.start") {
          pushStep({
            id: String(evt.id),
            label: String(evt.label),
            state: "running",
          });
        } else if (ev === "step.done") {
          const { event: _e, id, label: _label, ms, ok: _ok, ...detail } = evt as {
            event: string;
            id: string;
            label?: string;
            ms?: number;
            ok?: boolean;
          };
          patchStep(String(id), {
            state: "done",
            ms: typeof ms === "number" ? ms : undefined,
            detail: detail as Record<string, unknown>,
          });
        } else if (ev === "step.fail") {
          patchStep(String(evt.id), {
            state: "fail",
            error: String(evt.error ?? ""),
          });
        } else if (ev === "run.done") {
          setDone(evt as unknown as RunDone);
        } else if (ev === "fatal" || ev === "subprocess.exit") {
          setErr(JSON.stringify(evt, null, 2));
        }
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  async function runAttack(kind: string) {
    setAttackInFlight(kind);
    setAttackResults((r) => {
      const next = { ...r };
      delete next[kind];
      return next;
    });
    try {
      const res = await fetch(`${DASH_API}/api/live/demo/attack/${kind}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: user.email, password: user.password }),
      });
      if (!res.ok) {
        setAttackResults((r) => ({
          ...r,
          [kind]: {
            kind,
            label: kind,
            blocked: false,
            status: res.status,
            detail: `HTTP ${res.status}`,
          },
        }));
        return;
      }
      let last: AttackResult | null = null;
      for await (const line of readSseLines(res)) {
        let evt: Record<string, unknown>;
        try {
          evt = JSON.parse(line);
        } catch {
          continue;
        }
        if (evt.event === "attack.done") {
          last = {
            kind: String(evt.kind),
            label: String(evt.label),
            blocked: Boolean(evt.blocked),
            status: Number(evt.status ?? 0),
            detail: String(evt.detail ?? ""),
          };
        }
      }
      if (last) setAttackResults((r) => ({ ...r, [kind]: last! }));
    } catch (e) {
      setAttackResults((r) => ({
        ...r,
        [kind]: {
          kind,
          label: kind,
          blocked: false,
          status: 0,
          detail: e instanceof Error ? e.message : String(e),
        },
      }));
    } finally {
      setAttackInFlight(null);
    }
  }

  return (
    <div className="space-y-28">
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
        description="Run the full agent-binding flow against the live core. Each step streams in real time, and a panel of negative tests lets you watch SauronID reject replays, tampering, drift, and impersonation."
      />

      {/* ── Control panel ─────────────────────────────────────── */}

      <Card title="DEMO.CONTROLS" hex="0x901">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-10 mb-10">
          {/* Human */}
          <div className="space-y-4">
            <div className="font-mono-label text-[9px] text-white/45">SIGN AS HUMAN</div>
            <div className="grid grid-cols-2 gap-3">
              {SEED_USERS.map((u) => {
                const active = u.email === user.email;
                return (
                  <button
                    key={u.email}
                    onClick={() => setUser(u)}
                    className="bg-[#0F1A35] py-4 px-4 transition-colors text-left rounded border border-white/5"
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
            <div className="font-mono-label text-[9px] text-white/45">ACTIONS PER RUN</div>
            <div className="grid grid-cols-3 gap-3">
              {[1, 2, 3].map((n) => (
                <button
                  key={n}
                  onClick={() => setNActions(n)}
                  className="bg-[#0F1A35] py-4 transition-colors rounded border border-white/5"
                  style={
                    nActions === n
                      ? {
                          color: "#4F8CFE",
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
            <div className="font-mono-label text-[9px] text-white/45">EXECUTE</div>
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
              style={!running ? { boxShadow: "0 0 32px -6px rgba(37,99,235,0.55)" } : {}}
            >
              {running ? (
                <span className="flex items-center justify-center gap-3">
                  <span className="w-3 h-3 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  STREAMING…
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

        {/* Advanced toggle */}
        <button
          onClick={() => setShowAdvanced((v) => !v)}
          className="font-mono-label text-[9px] text-white/45 hover:text-[#4F8CFE] transition-colors"
        >
          {showAdvanced ? "▾ HIDE" : "▸ SHOW"}  CUSTOM.INTENT
        </button>

        {showAdvanced && (
          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-5 pt-6 border-t border-white/5">
            <Field label="MODEL.ID"     value={modelId}       onChange={setModelId} />
            <Field label="CURRENCY"     value={currency}      onChange={setCurrency} />
            <FieldFull label="SYSTEM.PROMPT" value={systemPrompt} onChange={setSystemPrompt} multi />
            <Field label="TOOLS (CSV)"  value={tools}         onChange={setTools} />
            <Field label="MAX.AMOUNT"   value={maxAmount}     onChange={setMaxAmount} />
            <FieldFull label="MERCHANT.ALLOWLIST (CSV)" value={merchantAllowlist} onChange={setMerchantAllowlist} />
          </div>
        )}

        {/* Status row */}
        <div className="flex items-center gap-4 pt-6 mt-6 border-t border-white/5">
          <StatusPill
            status={running ? "warn" : err ? "err" : done ? "ok" : "muted"}
            label={
              running
                ? "STREAMING"
                : err
                ? "FAILED"
                : done
                ? `OK · ${done.receipts.length} RECEIPT${done.receipts.length === 1 ? "" : "S"}`
                : "IDLE"
            }
          />
          <span className="font-mono-label text-[9px] text-white/35">
            {done ? `AGENT ${done.agent_id.slice(0, 18)}…` : "NO RUN YET"}
          </span>
        </div>
      </Card>

      {/* ── Streaming step list ───────────────────────────────── */}

      {(steps.length > 0 || running) && (
        <Card title={`CRYPTO.FLOW · ${steps.filter((s) => s.state === "done").length}/${steps.length}`} hex="0x902">
          <ul className="space-y-2">
            {steps.map((s) => (
              <StepRow key={s.id} step={s} />
            ))}
          </ul>
        </Card>
      )}

      {/* ── Error ────────────────────────────────────────────── */}

      {err && (
        <Card title="ERROR" hex="0xFFF">
          <pre className="font-mono text-[11px] text-[#F87171]/85 whitespace-pre-wrap leading-relaxed">
            {err}
          </pre>
        </Card>
      )}

      {/* ── Result tiles ─────────────────────────────────────── */}

      {done && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <ResultTile label="AGENT.REGISTERED" value={done.agent_id.slice(0, 14) + "…"} sub="FRESH BINDING" accent="#4F8CFE" />
            <ResultTile label="RECEIPTS.MINTED"  value={String(done.receipts.length)}     sub="POLICY KYA_MATRIX_V2" accent="#34D399" />
            <ResultTile label="ANCHOR.BATCH"     value={done.anchor_id ? done.anchor_id.slice(0, 14) + "…" : "—"} sub={`${done.anchor_status.last_batch_n_actions} ACTIONS`} accent="#A78BFA" />
            <ResultTile label="BTC / SOL"        value={`${done.anchor_status.bitcoin_total} / ${done.anchor_status.solana_total}`} sub="ANCHORS PUBLISHED" accent="#FCD34D" />
          </div>

          {done.receipts.length > 0 && (
            <Card title={`RECEIPTS · ${done.receipts.length}`} hex="0x910">
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="text-left">
                    <Th>#</Th>
                    <Th>RECEIPT.ID</Th>
                    <Th>ACTION.HASH</Th>
                    <Th>AMOUNT</Th>
                    <Th>STATUS</Th>
                  </tr>
                </thead>
                <tbody>
                  {done.receipts.map((r, i) => (
                    <tr key={r.receipt_id} className="border-t border-white/[0.04]">
                      <Td muted mono>{String(i + 1).padStart(2, "0")}</Td>
                      <Td mono>{r.receipt_id.slice(0, 24)}…</Td>
                      <Td mono dim>
                        {r.action_hash ? r.action_hash.slice(0, 24) + "…" : "—"}
                      </Td>
                      <Td mono>
                        {typeof r.amount_minor === "number"
                          ? `${(r.amount_minor / 100).toFixed(2)} ${r.currency ?? ""}`
                          : "—"}
                      </Td>
                      <Td>
                        <StatusPill status="ok" label="ACCEPTED" />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}
        </>
      )}

      {/* ── Attack panel ─────────────────────────────────────── */}

      <Card title="ATTACK.SIMULATOR" hex="0x920">
        <p className="text-[13px] text-white/55 leading-[1.7] max-w-2xl mb-8">
          Each button provisions a fresh agent and performs one
          deliberately-broken request. Every defence is a separate
          cryptographic check; the panel proves SauronID rejects each
          class of attack.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {catalog.map((a) => {
            const res = attackResults[a.kind];
            const inFlight = attackInFlight === a.kind;
            return (
              <div
                key={a.kind}
                className="bg-[#0F1A35] rounded border border-white/5 p-6 flex flex-col gap-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-mono-label text-[9px] text-[#F87171]/85 mb-2">
                      {a.kind.toUpperCase()}
                    </div>
                    <div className="text-[14px] text-white/85 leading-snug">
                      {a.label}
                    </div>
                    <div className="font-mono-label text-[8.5px] text-white/30 mt-2 leading-relaxed">
                      EXPECT · {a.expect.toUpperCase()}
                    </div>
                  </div>
                  {res && (
                    <StatusPill
                      status={res.blocked ? "ok" : "err"}
                      label={res.blocked ? "BLOCKED" : "ESCAPED"}
                    />
                  )}
                </div>
                {res && (
                  <div className="bg-[#06090F] border border-white/5 rounded px-3 py-2.5 font-mono text-[11px] text-white/60 leading-relaxed">
                    <span className="text-white/40">→ {res.status} </span>
                    {res.detail.slice(0, 180)}
                  </div>
                )}
                <button
                  onClick={() => runAttack(a.kind)}
                  disabled={inFlight || running}
                  className={[
                    "self-start font-mono-label text-[10px] tracking-[0.18em] rounded-full",
                    "px-5 py-2.5 border transition-colors",
                    inFlight
                      ? "border-white/15 text-white/30 cursor-not-allowed"
                      : "border-[#F87171]/30 text-[#F87171]/85 hover:border-[#F87171] hover:bg-[#F87171]/10",
                  ].join(" ")}
                >
                  {inFlight ? "RUNNING…" : "RUN ATTACK →"}
                </button>
              </div>
            );
          })}
        </div>
      </Card>

      {/* ── What just happened (only after a run) ─────────────── */}

      {done && (
        <Card title="WHAT.JUST.HAPPENED" hex="0x930">
          <ol className="space-y-4 text-[13px] text-white/70 leading-[1.75]">
            <NumberedStep n="01" label={`Authenticated ${user.email} via OPRF, got back the human key-image.`} />
            <NumberedStep n="02" label="Generated a fresh ring keypair (Ristretto) + PoP Ed25519 keypair." />
            <NumberedStep n="03" label="Registered the agent: server canonicalised checksum_inputs, computed sha256, stored intent + maxAmount." />
            <NumberedStep n="04" label="Issued an A-JWT for the agent (jti single-use, expires 600 s)." />
            <NumberedStep n="05" label="Pulled a one-time PoP challenge, signed it as a compact JWS." />
            <NumberedStep n="06" label="Pulled a canonical action envelope, ring-signed it through agent-action-tool." />
            <NumberedStep n="07" label={`Posted /agent/payment/authorize with the FULL proof: A-JWT + PoP JWS + ring sig + per-call DPoP-style sig — server inserted ${done.receipts.length} row${done.receipts.length === 1 ? "" : "s"} into agent_action_receipts.`} />
            <NumberedStep n="08" label={`Forced an anchor batch: ${done.anchor_id ?? "n/a"}. Bitcoin OTS submitted; Solana fires when SAURON_SOLANA_ENABLED=1.`} />
          </ol>
        </Card>
      )}
    </div>
  );
}

/* ── Step row ────────────────────────────────────────────────────── */

function StepRow({ step }: { step: Step }) {
  const detailEntries = step.detail ? Object.entries(step.detail) : [];
  const [open, setOpen] = useState(false);
  const dotColor =
    step.state === "done"
      ? "#34D399"
      : step.state === "fail"
      ? "#F87171"
      : "#4F8CFE";
  return (
    <li className="border border-white/5 rounded bg-[#0F1A35]/60">
      <button
        onClick={() => detailEntries.length > 0 && setOpen((v) => !v)}
        className="w-full flex items-center gap-4 px-4 py-3 text-left"
      >
        <span
          className={[
            "w-2 h-2 rounded-full flex-shrink-0",
            step.state === "running" ? "animate-status-pulse" : "",
          ].join(" ")}
          style={{ backgroundColor: dotColor, boxShadow: `0 0 10px ${dotColor}` }}
        />
        <span className="font-mono text-[12px] text-white/85 flex-1">
          {step.label}
        </span>
        {step.ms !== undefined && (
          <span className="font-mono-label text-[9px] text-white/40">
            {step.ms}ms
          </span>
        )}
        {step.state === "fail" && step.error && (
          <span className="font-mono text-[10.5px] text-[#F87171]/85 truncate max-w-md">
            {step.error}
          </span>
        )}
        {detailEntries.length > 0 && (
          <span className="font-mono-label text-[9px] text-white/30">
            {open ? "▾" : "▸"}
          </span>
        )}
      </button>
      {open && detailEntries.length > 0 && (
        <div className="px-4 pb-4 pt-1 border-t border-white/5 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1.5">
          {detailEntries.map(([k, v]) => (
            <div key={k} className="font-mono text-[11px] flex gap-2">
              <span className="text-white/35">{k}=</span>
              <span className="text-white/75 break-all">{String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </li>
  );
}

/* ── Form fields ─────────────────────────────────────────────────── */

function Field({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <label className="block">
      <div className="font-mono-label text-[9px] text-white/45 mb-2">{label}</div>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-[#06090F] border border-white/10 rounded px-3 py-2.5 text-[12.5px] text-white font-mono focus:outline-none focus:border-[#4F8CFE]/50 focus:bg-[#0A1128] transition-colors"
      />
    </label>
  );
}

function FieldFull({
  label,
  value,
  onChange,
  multi,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  multi?: boolean;
}) {
  return (
    <label className="block md:col-span-2">
      <div className="font-mono-label text-[9px] text-white/45 mb-2">{label}</div>
      {multi ? (
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          rows={2}
          className="w-full bg-[#06090F] border border-white/10 rounded px-3 py-2.5 text-[12.5px] text-white font-mono focus:outline-none focus:border-[#4F8CFE]/50 focus:bg-[#0A1128] transition-colors resize-none"
        />
      ) : (
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full bg-[#06090F] border border-white/10 rounded px-3 py-2.5 text-[12.5px] text-white font-mono focus:outline-none focus:border-[#4F8CFE]/50 focus:bg-[#0A1128] transition-colors"
        />
      )}
    </label>
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
    <div className="relative glass rounded-md px-7 py-8 flex flex-col gap-5 overflow-hidden">
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
      <span className="font-mono-label text-[8.5px] text-white/35 tracking-[0.18em] mt-1">
        {sub}
      </span>
    </div>
  );
}

function NumberedStep({ n, label }: { n: string; label: string }) {
  return (
    <li className="flex gap-5">
      <span className="font-mono-label text-[10px] text-[#4F8CFE] flex-shrink-0">{n}</span>
      <span>{label}</span>
    </li>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="font-mono-label text-[8.5px] text-white/40 px-3 py-5 font-normal text-left">
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
  return <td className={`px-3 py-5 align-middle whitespace-nowrap ${cls}`}>{children}</td>;
}
