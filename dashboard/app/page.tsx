import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchAgents, fetchOverview, fetchTenantRank } from "@/lib/api";

export const dynamic = "force-dynamic";
import { PageShell } from "@/components/layout/PageShell";
import { AgentCard } from "@/components/agents/AgentCard";
import { Card, CardBody } from "@/components/ui/Card";
import { RankBadge } from "@/components/cohorts/RankBadge";
import { fmtNumber } from "@/lib/format";

export default async function HomePage() {
  const t = await getTranslations("home");
  const [agentsResult, overviewResult, rankResult] = await Promise.all([
    fetchAgents(),
    fetchOverview(),
    fetchTenantRank("success_rate"),
  ]);

  const agents = agentsResult.ok ? agentsResult.data : [];
  const overview = overviewResult.ok
    ? overviewResult.data
    : { total_agents: 0, active_agents: 0, calls_today: 0, protected_today: 0 };
  const rank = rankResult.ok ? rankResult.data : null;

  return (
    <PageShell title={t("title")}>
      {/* Single status line — no charts, no widgets */}
      <p className="text-sm text-[var(--text-muted)] mb-8">
        {fmtNumber(overview.total_agents)} agents
        {" · "}
        {fmtNumber(overview.calls_today)} calls today
        {" · "}
        {fmtNumber(overview.protected_today)} protected
      </p>

      {/* Cohort rank widget (S9). Surfaces tenant's percentile in the most
          active metric. Shows the empty-state copy when no published cohort
          covers the tenant yet (i.e. fewer than k tenants have submitted). */}
      <Card className="mb-8">
        <CardBody>
          {rank ? (
            <div className="flex items-center gap-3 flex-wrap">
              <p className="text-sm text-[var(--text-secondary)]">
                Your agent ranks
              </p>
              <RankBadge rank={rank} label={rank.cohort_id} />
              <Link
                href={`/cohorts/${encodeURIComponent(rank.cohort_id)}`}
                className="text-mono-sm text-[var(--accent)] hover:text-[var(--accent-hover)] ml-auto"
              >
                View cohort →
              </Link>
            </div>
          ) : (
            <p className="text-sm text-[var(--text-muted)]">
              Insufficient data — submit weekly stats to see your rank.
            </p>
          )}
        </CardBody>
      </Card>

      {agents.length === 0 ? (
        <div className="py-16 text-center">
          <p className="text-sm text-[var(--text-muted)] mb-3">{t("empty")}</p>
          <a
            href="https://github.com/tejoker/Colosseum2026"
            className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
          >
            {t("emptyLink")} →
          </a>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {agents.map((agent) => (
            <AgentCard key={agent.id} agent={agent} />
          ))}
        </div>
      )}
    </PageShell>
  );
}
