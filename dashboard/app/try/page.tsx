"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { ScenarioTile } from "@/components/playground/ScenarioTile";
import { ResultPanel } from "@/components/playground/ResultPanel";
import { Spinner } from "@/components/ui/Spinner";

type ScenarioKey = "normal" | "replay" | "scope" | "custom";

interface ScenarioResult {
  result: "allowed" | "stopped";
  status_code: number;
  why: string;
  detail: Record<string, unknown>;
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

export default function TryPage() {
  const t = useTranslations("try");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ScenarioResult | null>(null);

  async function runScenario(scenario: ScenarioKey) {
    setRunning(true);
    setResult(null);

    try {
      const res = await fetch(`/api/playground/${scenario}`, { method: "POST" });
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

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-8">
        {SCENARIOS.map((s) => (
          <ScenarioTile
            key={s}
            label={t(`scenarios.${s}.label` as any)}
            description={t(`scenarios.${s}.description` as any)}
            isRunning={running}
            onRun={() => runScenario(s)}
          />
        ))}
      </div>

      {running && <Spinner label={t("running")} />}
      {result && !running && <ResultPanel result={result} />}
    </PageShell>
  );
}
