"use client";

import { useState, useEffect } from "react";
import { PageShell } from "@/components/layout/PageShell";

// Persist the Console across tab navigation. Next unmounts the page component
// when you switch tabs, so we mirror the run/transcript/misbehave/anchor state
// into sessionStorage and restore it on mount — the demo can flip to Proofs and
// back without losing what the agent just did.
const STORAGE_KEY = "sauronid-console-v2";

type Model = "gemma" | "groq";
interface Step { type: string; to?: string; url?: string; text?: string; turn?: number; detail?: string; status?: number }
interface RunResult { agent_id: string; model: string; model_label: string; steps: Step[]; answer: string | null; error?: string }
interface MisbehaveResult { kind: string; blocked: boolean; status_code: number; reason: string; accepted_status?: number; blocked_status?: number; endpoint?: string; error?: string }

const MODELS: { id: Model; label: string; sub: string }[] = [
  { id: "gemma", label: "Local agent", sub: "gemma · runs on the 4060Ti GPU" },
  { id: "groq", label: "Cloud agent", sub: "llama-3.3-70b · Groq API" },
];

const MISBEHAVE: { kind: string; label: string; explain: string }[] = [
  { kind: "replay", label: "Replay a captured request", explain: "An attacker re-sends a request the agent already made, to make it act twice." },
  { kind: "tamper", label: "Tamper with the request", explain: "The request is altered after the agent signed it." },
  { kind: "revoked", label: "Use the agent after revoking it", explain: "The agent is revoked, then tries to act again." },
];

const card = "border border-[var(--border)] rounded-lg p-5 bg-[var(--bg)]";
const btn = "px-4 py-2 text-sm rounded border transition-colors duration-150 ease-out disabled:opacity-40 disabled:cursor-not-allowed";

export default function ConsolePage() {
  const [model, setModel] = useState<Model>("groq");
  const [prompt, setPrompt] = useState("Fetch https://example.com and tell me in one sentence what it is.");
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState<RunResult | null>(null);
  const [misbehaving, setMisbehaving] = useState<string | null>(null);
  const [misbehave, setMisbehave] = useState<MisbehaveResult | null>(null);
  const [anchorMsg, setAnchorMsg] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  // Restore any prior session state once, on mount (after hydration, to avoid
  // an SSR mismatch).
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (raw) {
        const s = JSON.parse(raw);
        if (s.model === "gemma" || s.model === "groq") setModel(s.model);
        if (typeof s.prompt === "string") setPrompt(s.prompt);
        if (s.run) setRun(s.run);
        if (s.misbehave) setMisbehave(s.misbehave);
        if (typeof s.anchorMsg === "string") setAnchorMsg(s.anchorMsg);
      }
    } catch {
      /* ignore corrupt/absent storage */
    }
    setHydrated(true);
  }, []);

  // Mirror state to sessionStorage so it survives tab switches. Skip the first
  // render (pre-hydration) so we never overwrite stored state with defaults.
  useEffect(() => {
    if (!hydrated) return;
    try {
      sessionStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ model, prompt, run, misbehave, anchorMsg })
      );
    } catch {
      /* storage full / unavailable — non-fatal */
    }
  }, [hydrated, model, prompt, run, misbehave, anchorMsg]);

  function doClear() {
    setRun(null); setMisbehave(null); setAnchorMsg(null);
    try { sessionStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
  }

  async function doRun() {
    setRunning(true); setRun(null); setMisbehave(null); setAnchorMsg(null);
    try {
      const r = await fetch("/api/agent/run", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model, prompt }),
      });
      setRun(await r.json());
    } catch {
      setRun({ agent_id: "", model, model_label: "", steps: [], answer: null, error: "Could not reach the agent." });
    } finally { setRunning(false); }
  }

  async function doMisbehave(kind: string) {
    if (!run?.agent_id) return;
    setMisbehaving(kind); setMisbehave(null);
    try {
      const r = await fetch("/api/agent/misbehave", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ agent_id: run.agent_id, kind }),
      });
      setMisbehave(await r.json());
    } catch {
      setMisbehave({ kind, blocked: false, status_code: 0, reason: "", error: "Could not reach the agent." });
    } finally { setMisbehaving(null); }
  }

  async function doAnchor() {
    setAnchorMsg("Anchoring…");
    try {
      const r = await fetch("/api/agent/anchor", { method: "POST" });
      setAnchorMsg(r.ok ? "Sealed into Bitcoin — see the Proofs tab for the batch." : "Anchor request failed.");
    } catch { setAnchorMsg("Anchor request failed."); }
  }

  return (
    <PageShell title="Agent Console" subtitle="Give an agent a task, watch it work — then make it misbehave and watch SauronID stop it. Every action is recorded for tamper-proof Bitcoin audit.">
      {/* Step 1 — choose the agent */}
      <div className={`${card} mb-5`}>
        <div className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-3">1 · Choose an agent</div>
        <div className="flex gap-3 flex-wrap">
          {MODELS.map((m) => (
            <button key={m.id} onClick={() => setModel(m.id)}
              className={`${btn} text-left ${model === m.id ? "border-[var(--accent)] text-[var(--text-primary)]" : "border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]"}`}>
              <div className="font-medium">{m.label}</div>
              <div className="text-xs text-[var(--text-muted)]">{m.sub}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Step 2 — give it a task */}
      <div className={`${card} mb-5`}>
        <div className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-3">2 · Give it a task</div>
        <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} rows={3}
          className="w-full px-3 py-2 text-sm bg-[var(--bg)] border border-[var(--border)] rounded text-[var(--text-primary)] focus:outline-none focus:border-[var(--border-hover)]" />
        <button onClick={doRun} disabled={running || !prompt.trim()}
          className={`${btn} mt-3 border-[var(--accent)] text-[var(--text-primary)]`}>
          {running ? "Agent working…" : "▶ Run agent"}
        </button>
        {(run || misbehave || anchorMsg) && (
          <button onClick={doClear} disabled={running}
            className={`${btn} mt-3 ml-2 border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]`}>
            Clear
          </button>
        )}
      </div>

      {/* Transcript */}
      {run && (
        <div className={`${card} mb-5`}>
          <div className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-3">
            What the agent did {run.model_label ? `· ${run.model_label}` : ""}
          </div>
          {run.error ? (
            <div className="text-[var(--status-warning)] text-sm">{run.error}</div>
          ) : (
            <>
              <ol className="space-y-1.5 text-sm">
                {run.steps.map((s, i) => (
                  <li key={i} className="text-[var(--text-secondary)]">
                    {s.type === "llm_call" && <span>→ thinking (model at {s.to})</span>}
                    {s.type === "tool_call" && <span className="text-[var(--text-primary)]">→ tool: web_fetch {s.url}</span>}
                    {s.type === "answer" && <span className="text-[var(--status-ok)]">✓ answered</span>}
                    {(s.type === "llm_error" || s.type === "egress_error") && <span className="text-[var(--status-warning)]">! {s.type} {s.detail ?? s.status}</span>}
                  </li>
                ))}
              </ol>
              {run.answer && (
                <div className="mt-4 p-3 rounded border border-[var(--border)] text-sm text-[var(--text-primary)]">
                  <span className="text-[var(--text-muted)]">Answer: </span>{run.answer}
                </div>
              )}
              <div className="mt-2 text-xs text-[var(--text-muted)]">agent id {run.agent_id} · every call above was signed and logged</div>
            </>
          )}
        </div>
      )}

      {/* Step 3 — make it misbehave */}
      {run && !run.error && (
        <div className={`${card} mb-5`}>
          <div className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-3">3 · Now make it misbehave</div>
          <div className="flex gap-3 flex-wrap">
            {MISBEHAVE.map((m) => (
              <button key={m.kind} onClick={() => doMisbehave(m.kind)} disabled={!!misbehaving}
                title={m.explain}
                className={`${btn} border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--status-warning)]`}>
                {misbehaving === m.kind ? "…" : m.label}
              </button>
            ))}
          </div>
          {misbehave && (
            misbehave.error ? (
              <div className="mt-4 text-[var(--status-warning)] text-sm">{misbehave.error}</div>
            ) : (
              <div className={`mt-4 p-4 rounded border ${misbehave.blocked ? "border-[var(--status-ok)]" : "border-[var(--status-warning)]"}`}>
                <div className={`text-sm font-semibold ${misbehave.blocked ? "text-[var(--status-ok)]" : "text-[var(--status-warning)]"}`}>
                  {misbehave.blocked ? "🛡 STOPPED by SauronID" : "⚠ NOT stopped"}
                </div>
                {misbehave.endpoint && (
                  <div className="mt-2 text-xs text-[var(--text-muted)]">live core · {misbehave.endpoint}</div>
                )}
                <div className="mt-2 space-y-1 text-sm">
                  <div className="text-[var(--status-ok)]">✅ legitimate signed call → HTTP {misbehave.accepted_status ?? "?"} (accepted)</div>
                  <div className="text-[var(--status-warning)]">🛡 the attack → HTTP {misbehave.blocked_status ?? misbehave.status_code} (rejected)</div>
                </div>
                <div className="mt-2 text-sm text-[var(--text-secondary)]">{misbehave.reason}</div>
                <div className="mt-2 text-xs text-[var(--text-muted)]">This is the core&apos;s live HTTP response — not a simulation.</div>
              </div>
            )
          )}
        </div>
      )}

      {/* Step 4 — anchor */}
      <div className={card}>
        <div className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-3">4 · Tamper-proof audit</div>
        <button onClick={doAnchor} className={`${btn} border-[var(--accent)] text-[var(--text-primary)]`}>⛓ Seal all actions into Bitcoin</button>
        {anchorMsg && <span className="ml-3 text-sm text-[var(--text-secondary)]">{anchorMsg}</span>}
      </div>
    </PageShell>
  );
}
