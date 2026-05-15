import Link from "next/link";
import { useTranslations } from "next-intl";
import { AgentStatus } from "@/lib/api";
import { StatusDot } from "@/components/ui/StatusDot";
import { fmtNumber, fmtRelativeTime } from "@/lib/format";

export function AgentCard({ agent }: { agent: AgentStatus }) {
  const t = useTranslations("agentCard");

  return (
    <Link
      href={`/agents/${agent.id}`}
      className="block bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5 hover:border-[var(--border-hover)] transition-colors duration-150 ease-out group"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <StatusDot
            status={agent.status === "active" ? "active" : agent.status === "revoked" ? "stopped" : "idle"}
          />
          <span className="text-sm font-medium text-[var(--text-primary)] group-hover:text-[var(--text-primary)] transition-colors">
            {agent.name}
          </span>
        </div>
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          {agent.agent_type}
        </span>
      </div>

      <div className="flex items-center gap-6">
        <div>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-0.5">
            {t("lastCall")}
          </p>
          <p className="text-sm text-[var(--text-secondary)]">
            {agent.last_call_at ? fmtRelativeTime(agent.last_call_at) : "—"}
          </p>
        </div>
        <div>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-0.5">
            {t("totalCalls")}
          </p>
          <p className="text-sm text-[var(--text-secondary)]">
            {fmtNumber(agent.total_calls)}
          </p>
        </div>
      </div>
    </Link>
  );
}
