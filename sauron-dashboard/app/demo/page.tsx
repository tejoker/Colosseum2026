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

interface LlmProvider {
  id: string;
  label: string;
  default_model: string;
  needs_base_url: boolean;
  env_key: string;
  has_env_key: boolean;
}

interface LlmCallResult {
  provider: string;
  model: string;
  tool_call: { name: string; args: Record<string, unknown> } | null;
  text: string | null;
  usage: Record<string, unknown> | null;
  key_source?: "body" | "env" | "";
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

  // LLM (entirely optional — demo works without any key)
  const [showLlm, setShowLlm] = useState(false);
  const [providers, setProviders] = useState<LlmProvider[]>([]);
  const [llmProvider, setLlmProvider] = useState("anthropic");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmBaseUrl, setLlmBaseUrl] = useState("");
  const [llmModel, setLlmModel] = useState("");
  const [llmPrompt, setLlmPrompt] = useState(
    "Send 15.00 EUR to mch_demo_payments for invoice INV-2026-001."
  );
  const [llmResult, setLlmResult] = useState<LlmCallResult | null>(null);
  const [llmRunning, setLlmRunning] = useState(false);
  const [llmErr, setLlmErr] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${DASH_API}/api/live/demo/attacks`)
      .then((r) => r.json())
      .then((j) => setCatalog(j.attacks ?? []))
      .catch(() => {});
    fetch(`${DASH_API}/api/live/demo/llm-providers`)
      .then((r) => r.json())
      .then((j: { providers: LlmProvider[] }) => {
        setProviders(j.providers ?? []);
        const def = j.providers?.find((p) => p.id === "anthropic");
        if (def) setLlmModel(def.default_model);
      })
      .catch(() => {});
  }, []);

  function selectProvider(id: string) {
    setLlmProvider(id);
    const p = providers.find((x) => x.id === id);
    if (p) setLlmModel(p.default_model);
    if (id !== "openai-custom") setLlmBaseUrl("");
    setLlmResult(null);
    setLlmErr(null);
  }

  async function callLlm() {
    setLlmRunning(true);
    setLlmResult(null);
    setLlmErr(null);
    try {
      const res = await fetch(`${DASH_API}/api/live/demo/llm-call`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          provider: llmProvider,
          api_key: llmApiKey,
          base_url: llmBaseUrl,
          model: llmModel,
          user_message: llmPrompt,
        }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        setLlmErr(JSON.stringify(j.detail ?? j, null, 2));
        return;
      }
      setLlmResult((await res.json()) as LlmCallResult);
    } catch (e) {
      setLlmErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLlmRunning(false);
    }
  }

  /** Killer demo: LLM proposes -> SauronID binds + signs + anchors, all in one. */
  async function runLlmThenBind() {
    setLlmRunning(true);
    setRunning(true);
    setDone(null);
    setErr(null);
    setLlmResult(null);
    setLlmErr(null);
    resetSteps();

    try {
      const res = await fetch(`${DASH_API}/api/live/demo/llm-then-bind`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          provider:     llmProvider,
          api_key:      llmApiKey,
          base_url:     llmBaseUrl,
          model:        llmModel,
          user_message: llmPrompt,
          email:        user.email,
          password:     user.password,
        }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        setLlmErr(JSON.stringify(j.detail ?? j, null, 2));
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
        if (ev === "llm.start") {
          pushStep({
            id: "llm",
            label: `LLM CALL · ${String(evt.provider)} ${String(evt.model)}`,
            state: "running",
          });
        } else if (ev === "llm.done") {
          patchStep("llm", {
            state: "done",
            detail: {
              tool_call: JSON.stringify(evt.tool_call),
              text: String(evt.text ?? ""),
            },
          });
          // Surface the parsed tool call in the LLM result panel too.
          if (evt.tool_call && typeof evt.tool_call === "object") {
            setLlmResult({
              provider: llmProvider,
              model: llmModel,
              tool_call: evt.tool_call as { name: string; args: Record<string, unknown> },
              text: (evt.text as string) ?? null,
              usage: (evt.usage as Record<string, unknown>) ?? null,
            });
          }
        } else if (ev === "llm.fail") {
          patchStep("llm", { state: "fail", error: String(evt.reason ?? "unknown") });
          setLlmErr(String(evt.reason ?? "LLM did not produce a usable tool call"));
        } else if (ev === "step.start") {
          pushStep({ id: String(evt.id), label: String(evt.label), state: "running" });
        } else if (ev === "step.done") {
          const { event: _e, id, label: _l, ms, ok: _o, ...detail } = evt as {
            event: string; id: string; label?: string; ms?: number; ok?: boolean;
          };
          patchStep(String(id), {
            state: "done",
            ms: typeof ms === "number" ? ms : undefined,
            detail: detail as Record<string, unknown>,
          });
        } else if (ev === "step.fail") {
          patchStep(String(evt.id), { state: "fail", error: String(evt.error ?? "") });
        } else if (ev === "run.done") {
          setDone(evt as unknown as RunDone);
        }
      }
    } catch (e) {
      setLlmErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLlmRunning(false);
      setRunning(false);
    }
  }

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

      {/* ── Real LLM call (entirely optional, collapsed by default) ───── */}

      {!showLlm && (
        <div className="flex items-center gap-4">
          <button
            onClick={() => setShowLlm(true)}
            className="font-mono-label text-[10px] tracking-[0.2em] rounded-full px-5 py-2.5 border border-white/15 text-white/55 hover:border-[#4F8CFE]/50 hover:text-[#4F8CFE] transition-colors"
          >
            ▸ SHOW REAL.LLM.CALL  (OPTIONAL)
          </button>
          <span className="font-mono-label text-[9px] text-white/30 leading-relaxed">
            REQUIRES AN API KEY (PASTE OR .ENV) · DEMO ABOVE WORKS WITHOUT IT
          </span>
        </div>
      )}

      {showLlm && (
      <Card title="REAL.LLM.CALL · OPTIONAL" hex="0x915">
        <div className="flex items-center justify-between mb-6">
          <p className="text-[13px] text-white/55 leading-[1.7] max-w-2xl">
            Pick any provider, paste your key (or set it in .env), hit RUN.
            The dashboard sends a short prompt + one tool definition
            (<code className="text-white/75">pay_merchant</code>) to the model
            and surfaces the structured tool call. Pair this with the binding
            flow above to see the real round-trip: model proposes → SauronID
            ratifies + signs + anchors.
          </p>
          <button
            onClick={() => {
              setShowLlm(false);
              setLlmResult(null);
              setLlmErr(null);
            }}
            className="font-mono-label text-[9.5px] text-white/45 hover:text-white/85 transition-colors flex-shrink-0"
            aria-label="Hide LLM section"
          >
            ▾ HIDE
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
          {/* Provider */}
          <div className="space-y-3 md:col-span-1">
            <div className="font-mono-label text-[9px] text-white/45">PROVIDER</div>
            <div className="grid grid-cols-1 gap-2 max-h-[260px] overflow-y-auto pr-1">
              {providers.map((p) => {
                const active = llmProvider === p.id;
                return (
                  <button
                    key={p.id}
                    onClick={() => selectProvider(p.id)}
                    className="bg-[#0F1A35] py-3 px-4 transition-colors text-left rounded border border-white/5"
                    style={
                      active
                        ? { boxShadow: "inset 2px 0 0 0 #4F8CFE, 0 0 18px -10px rgba(79,140,254,0.6)" }
                        : {}
                    }
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[12.5px] text-white/85">{p.label}</span>
                      {p.has_env_key && (
                        <span className="font-mono-label text-[7.5px] text-[#34D399]/85 bg-[#34D399]/10 border border-[#34D399]/25 rounded px-1.5 py-0.5">
                          .ENV
                        </span>
                      )}
                    </div>
                    <div className="font-mono text-[10px] text-white/35 mt-1 truncate">
                      {p.default_model || "user-chosen"}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Config */}
          <div className="space-y-5 md:col-span-2">
            {(() => {
              const cur = providers.find((p) => p.id === llmProvider);
              const envOk = cur?.has_env_key ?? false;
              const canRun = llmRunning ? false : (envOk || llmApiKey.length > 0);
              return (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-5">
                    <Field
                      label={
                        envOk
                          ? `API.KEY (FOUND IN .ENV AS ${cur?.env_key} — OPTIONAL OVERRIDE)`
                          : `API.KEY (PASTE; SET ${cur?.env_key ?? "PROVIDER_API_KEY"} IN .ENV TO SKIP)`
                      }
                      value={llmApiKey}
                      onChange={setLlmApiKey}
                      type="password"
                    />
                    <Field
                      label={llmProvider === "tavily" ? "MODE" : "MODEL"}
                      value={llmModel}
                      onChange={setLlmModel}
                    />
                    {llmProvider === "openai-custom" && (
                      <FieldFull label="BASE.URL (OPENAI-COMPATIBLE)" value={llmBaseUrl} onChange={setLlmBaseUrl} />
                    )}
                    <FieldFull
                      label={llmProvider === "tavily" ? "SEARCH.QUERY" : "USER.MESSAGE"}
                      value={llmPrompt}
                      onChange={setLlmPrompt}
                      multi
                    />
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <button
                      onClick={callLlm}
                      disabled={!canRun}
                      className={[
                        "rounded-md py-4 px-6 font-mono-label tracking-[0.2em] text-[10.5px]",
                        "transition-all duration-200 border",
                        !canRun
                          ? "bg-[#0F1A35] text-white/40 cursor-not-allowed border-white/5"
                          : "bg-transparent text-white/85 border-white/15 hover:border-[#4F8CFE]/60 hover:text-[#4F8CFE]",
                      ].join(" ")}
                    >
                      {llmRunning
                        ? llmProvider === "tavily" ? "SEARCHING…" : "CALLING MODEL…"
                        : llmProvider === "tavily" ? "1. RUN TAVILY SEARCH →" : "1. CALL MODEL ONLY →"}
                    </button>
                    {llmProvider !== "tavily" && (
                      <button
                        onClick={runLlmThenBind}
                        disabled={!canRun}
                        className={[
                          "rounded-md py-4 px-6 font-mono-label tracking-[0.2em] text-[10.5px]",
                          "transition-all duration-200",
                          !canRun
                            ? "bg-[#0F1A35] text-white/40 cursor-not-allowed"
                            : "bg-[#2563EB] text-white hover:bg-[#4F8CFE]",
                        ].join(" ")}
                        style={canRun ? { boxShadow: "0 0 28px -8px rgba(37,99,235,0.55)" } : {}}
                      >
                        {llmRunning ? "RUNNING CHAIN…" : "2. CALL + BIND + ANCHOR →"}
                      </button>
                    )}
                  </div>
                  <div className="font-mono-label text-[8.5px] text-white/30 leading-relaxed">
                    {envOk && !llmApiKey
                      ? `USING ${cur?.env_key} FROM .ENV · PASTE A KEY ABOVE TO OVERRIDE`
                      : "KEY IS USED ONLY FOR THIS REQUEST · NEVER PERSISTED"}
                  </div>
                </>
              );
            })()}
          </div>
        </div>

        {llmErr && (
          <pre className="font-mono text-[11px] text-[#F87171]/85 whitespace-pre-wrap leading-relaxed bg-[#06090F] border border-[#F87171]/20 rounded p-4 mb-6">
            {llmErr}
          </pre>
        )}

        {llmResult && (
          <div className="space-y-5 pt-6 border-t border-white/5">
            <div className="flex items-center gap-4">
              <StatusPill
                status={llmResult.tool_call ? "ok" : "warn"}
                label={llmResult.tool_call ? "TOOL.CALL" : "NO.TOOL.USE"}
              />
              <span className="font-mono-label text-[9px] text-white/45">
                {llmResult.provider.toUpperCase()} · {llmResult.model}
              </span>
            </div>
            {llmResult.tool_call ? (
              <div className="bg-[#06090F] border border-white/5 rounded p-5">
                <div className="font-mono-label text-[9px] text-white/45 mb-3">
                  PROPOSED.ACTION
                </div>
                <div className="font-mono text-[12px] text-[#4F8CFE] mb-3">
                  {llmResult.tool_call.name}(
                </div>
                <div className="ml-4 space-y-1">
                  {Object.entries(llmResult.tool_call.args).map(([k, v]) => (
                    <div key={k} className="font-mono text-[11.5px]">
                      <span className="text-white/45">{k}: </span>
                      <span className="text-white/85">{JSON.stringify(v)}</span>
                    </div>
                  ))}
                </div>
                <div className="font-mono text-[12px] text-[#4F8CFE] mt-3">)</div>
                <div className="font-mono-label text-[8.5px] text-white/30 tracking-[0.18em] mt-5 pt-4 border-t border-white/5 leading-relaxed">
                  AT THIS POINT SAURONID WOULD SIGN THIS WITH THE AGENT&apos;S
                  RING + POP KEYS, ENFORCE THE INTENT MAX-AMOUNT + ALLOWLIST,
                  AND ANCHOR THE RECEIPT. RUN THE BINDING FLOW ABOVE TO SEE THAT.
                </div>
              </div>
            ) : (
              llmResult.text && (
                <pre className="font-mono text-[11.5px] text-white/70 whitespace-pre-wrap leading-relaxed bg-[#06090F] border border-white/5 rounded p-5">
                  {llmResult.text}
                </pre>
              )
            )}
            {llmResult.usage && (
              <div className="font-mono-label text-[8.5px] text-white/35 tracking-[0.18em]">
                USAGE · {Object.entries(llmResult.usage).map(([k, v]) => `${k}=${v}`).join(" · ")}
              </div>
            )}
          </div>
        )}
      </Card>
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
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: "text" | "password";
}) {
  return (
    <label className="block">
      <div className="font-mono-label text-[9px] text-white/45 mb-2">{label}</div>
      <input
        type={type}
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
