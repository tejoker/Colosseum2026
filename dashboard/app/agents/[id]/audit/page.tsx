import { notFound } from "next/navigation";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchAgent, fetchAgentAudit } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { AuditTimeline } from "@/components/audit/AuditTimeline";

export default async function AuditPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const t = await getTranslations("audit");

  const [agentResult, auditResult] = await Promise.all([
    fetchAgent(id),
    fetchAgentAudit(id),
  ]);

  if (!agentResult.ok) notFound();
  const agent = agentResult.data;
  const events = auditResult.ok ? auditResult.data : [];

  return (
    <PageShell
      title={t("title", { name: agent.name })}
      subtitle={t("subtitle", { name: agent.name })}
    >
      <Link
        href={`/agents/${id}`}
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 mb-8"
      >
        ← {t("back")}
      </Link>

      <AuditTimeline events={events} />
    </PageShell>
  );
}
