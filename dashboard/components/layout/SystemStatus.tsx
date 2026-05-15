"use client";

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { fetchHealth, SystemHealth } from "@/lib/api";
import { fmtRelativeTime } from "@/lib/format";

type HealthState =
  | { status: "connecting" }
  | { status: "nominal"; health: SystemHealth }
  | { status: "degraded"; lastSeenAt: string | null };

export function SystemStatus() {
  const t = useTranslations("systemStatus");
  const [state, setState] = useState<HealthState>({ status: "connecting" });

  useEffect(() => {
    let cancelled = false;

    async function check() {
      const result = await fetchHealth();
      if (cancelled) return;
      if (result.ok && result.data.core_reachable) {
        setState({ status: "nominal", health: result.data });
      } else {
        setState({
          status: "degraded",
          lastSeenAt: result.ok ? result.data.last_seen_at : null,
        });
      }
    }

    check();
    const interval = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (state.status === "connecting") {
    return (
      <span className="text-mono-sm text-[var(--text-muted)] flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full border border-[var(--text-muted)] inline-block" />
        {t("connecting")}
      </span>
    );
  }

  if (state.status === "degraded") {
    const ago = state.lastSeenAt ? fmtRelativeTime(state.lastSeenAt) : "unknown";
    return (
      <span className="text-mono-sm text-[var(--status-warning)] flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-warning)] inline-block" />
        {t("degraded", { ago })}
      </span>
    );
  }

  const { health } = state;
  return (
    <span className="text-mono-sm text-[var(--text-muted)] flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-ok)] inline-block animate-pulse-calm" />
      {t("nominal")}
      <span className="text-[var(--border)] select-none">·</span>
      {t("agentsProtected", { count: health.agent_count })}
      <span className="text-[var(--border)] select-none">·</span>
      {t("verificationRunning")}
    </span>
  );
}
