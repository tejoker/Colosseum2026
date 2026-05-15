"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { ScenarioTile } from "@/components/playground/ScenarioTile";
import { ResultPanel } from "@/components/playground/ResultPanel";
import { Spinner } from "@/components/ui/Spinner";
import { Button } from "@/components/ui/Button";

type ScenarioKey = "normal" | "replay" | "scope" | "custom";

interface ScenarioResult {
  result: "allowed" | "stopped";
  status_code: number;
  why: string;
  detail: Record<string, unknown>;
}

interface CustomForm {
  agent_type: string;
  intent: string;
  scenario: string;
}

const SCENARIO_EXPLANATIONS: Record<ScenarioKey, { allowed: string; stopped: string }> = {
  normal: {
    allowed: "The agent presented a valid, properly signed token with a matching intent. All checks passed: signature, nonce, config digest, and intent leash.",
    stopped: "Unexpected: the call failed despite being well-formed. Check the core logs.",
  },
  replay: {
    allowed: "Unexpected: the replayed token was accepted. The nonce or JTI deduplication may not be active.",
    stopped: "The token was recognised as a replay — the JTI was already used. The governance layer rejected it before any action was taken.",
  },
  scope: {
    allowed: "Unexpected: the out-of-scope action was accepted. Check the intent leash configuration.",
    stopped: "The agent attempted to act outside its declared intent. The governance layer stopped it before the action reached the target system.",
  },
  custom: {
    allowed: "Your custom scenario was accepted by the governance layer.",
    stopped: "Your custom scenario was stopped by the governance layer.",
  },
};

const SCENARIOS: ScenarioKey[] = ["normal", "replay", "scope", "custom"];

const INPUT_CLASS =
  "w-full px-3 py-2 text-sm bg-[var(--bg)] border border-[var(--border)] rounded text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--border-hover)] transition-colors duration-150 ease-out";

const LABEL_CLASS = "text-xs text-[var(--text-muted)] mb-1 block";

export default function TryPage() {
  const t = useTranslations("try");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [selectedCustom, setSelectedCustom] = useState(false);
  const [customForm, setCustomForm] = useState<CustomForm>({
    agent_type: "",
    intent: "",
    scenario: "normal",
  });

  async function runScenario(scenario: ScenarioKey, body?: Record<string, string>) {
    setRunning(true);
    setResult(null);

    try {
      const res = await fetch(`/api/playground/${scenario}`, {
        method: "POST",
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const json = await res.json() as { result: "allowed" | "stopped"; status_code: number; detail: Record<string, unknown> };
      const expl = SCENARIO_EXPLANATIONS[scenario];
      setResult({
        ...json,
        why: json.result === "allowed" ? expl.allowed : expl.stopped,
      });
    } catch {
      setResult({
        result: "stopped",
        status_code: 0,
        why: "Could not reach the core. Make sure the SauronID server is running.",
        detail: {},
      });
    } finally {
      setRunning(false);
    }
  }

  function handleTileClick(s: ScenarioKey) {
    if (s === "custom") {
      setSelectedCustom(true);
    } else {
      setSelectedCustom(false);
      runScenario(s);
    }
  }

  function handleCustomRun() {
    runScenario("custom", {
      agent_type: customForm.agent_type,
      intent: customForm.intent,
      scenario: customForm.scenario,
    });
  }

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-8">
        {SCENARIOS.map((s) => (
          <ScenarioTile
            key={s}
            label={t(`scenarios.${s}.label` as any)}
            description={t(`scenarios.${s}.description` as any)}
            isRunning={running}
            isSelected={s === "custom" && selectedCustom}
            onRun={() => handleTileClick(s)}
          />
        ))}
      </div>

      {selectedCustom && (
        <div className="mb-6 bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
            <div>
              <label className={LABEL_CLASS}>{t("customAgentType")}</label>
              <input
                type="text"
                className={INPUT_CLASS}
                placeholder="e.g. assistant"
                value={customForm.agent_type}
                onChange={(e) => setCustomForm((f) => ({ ...f, agent_type: e.target.value }))}
              />
            </div>
            <div>
              <label className={LABEL_CLASS}>{t("customIntent")}</label>
              <input
                type="text"
                className={INPUT_CLASS}
                placeholder="e.g. send_email"
                value={customForm.intent}
                onChange={(e) => setCustomForm((f) => ({ ...f, intent: e.target.value }))}
              />
            </div>
            <div>
              <label className={LABEL_CLASS}>{t("customScenario")}</label>
              <select
                className={`${INPUT_CLASS} cursor-pointer`}
                value={customForm.scenario}
                onChange={(e) => setCustomForm((f) => ({ ...f, scenario: e.target.value }))}
              >
                <option value="normal">{t("customScenarioNormal")}</option>
                <option value="replay">{t("customScenarioReplay")}</option>
                <option value="scope_escalation">{t("customScenarioScope")}</option>
              </select>
            </div>
          </div>
          <Button variant="primary" size="sm" onClick={handleCustomRun} disabled={running}>
            {t("customRun")}
          </Button>
        </div>
      )}

      {running && <Spinner label={t("running")} />}
      {result && !running && <ResultPanel result={result} />}
    </PageShell>
  );
}
