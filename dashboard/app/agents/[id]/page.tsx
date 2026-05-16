import { notFound } from "next/navigation";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { fetchAgent, fetchActivity } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Badge } from "@/components/ui/Badge";
import { Card, CardBody } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { truncateHash, fmtTimestamp, fmtRelativeTime } from "@/lib/format";
import { RevokeButton } from "@/components/agents/RevokeButton";

export default async function AgentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const t = await getTranslations("agentDetail");
  const [result, activityResult] = await Promise.all([
    fetchAgent(id),
    fetchActivity({ agent_id: id, limit: 10 }),
  ]);

  if (!result.ok) notFound();
  const agent = result.data;
  const recentCalls = activityResult.ok ? activityResult.data : [];

  return (
    <PageShell>
      {/* Breadcrumb */}
      <Link
        href="/"
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 mb-6"
      >
        ← {t("back")}
      </Link>

      {/* Title row */}
      <div className="flex items-center gap-3 mb-8">
        <StatusDot
          status={agent.status === "active" ? "active" : agent.status === "revoked" ? "stopped" : "idle"}
        />
        <h1 className="text-xl font-semibold text-[var(--text-primary)] tracking-tight">
          {agent.name}
        </h1>
        <Badge variant={agent.status === "active" ? "ok" : "neutral"}>
          {agent.status}
        </Badge>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        {/* Identity */}
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("identity")}</p>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">{t("labelType")}</dt>
                <dd className="text-[var(--text-secondary)] font-mono">{agent.agent_type}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">{t("labelRegistered")}</dt>
                <dd className="text-[var(--text-secondary)]">{fmtTimestamp(agent.registered_at)}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>

        {/* Config digest */}
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("configDigest")}</p>
            <p className="text-mono-sm text-[var(--text-secondary)] break-all">
              {truncateHash(agent.config_digest, 16)}
            </p>
          </CardBody>
        </Card>
      </div>

      {/* Mandate */}
      <Card className="mb-6">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("mandate")}</p>
          {agent.allowed_intents.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">{t("noIntents")}</p>
          ) : (
            <ul className="flex flex-wrap gap-2">
              {agent.allowed_intents.map((intent) => (
                <li key={intent}>
                  <Badge variant="neutral">{intent}</Badge>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      {/* Recent calls */}
      <Card className="mb-6">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">{t("recentCalls")}</p>
          {recentCalls.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">—</p>
          ) : (
            <Table>
              <Thead>
                <Tr>
                  <Th>Time</Th>
                  <Th>Action</Th>
                  <Th>Result</Th>
                </Tr>
              </Thead>
              <Tbody>
                {recentCalls.map((call) => (
                  <Tr key={call.id}>
                    <Td className="text-mono-sm text-[var(--text-muted)]">
                      {fmtRelativeTime(call.timestamp)}
                    </Td>
                    <Td className="text-mono-sm text-[var(--text-secondary)]">
                      {call.action}
                    </Td>
                    <Td>
                      <Badge variant={call.result === "allowed" ? "ok" : "stopped"}>
                        {call.result === "allowed" ? "✓" : "✗"}
                      </Badge>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* Actions */}
      <div className="flex items-center gap-3">
        <Link
          href={`/agents/${id}/audit`}
          className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
        >
          {t("audit")} →
        </Link>
        <RevokeButton agentId={id} agentName={agent.name} label={t("revoke")} />
      </div>
    </PageShell>
  );
}
