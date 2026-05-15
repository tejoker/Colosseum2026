import { getTranslations } from "next-intl/server";
import { fetchProtected } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { fmtRelativeTime } from "@/lib/format";

export default async function ProtectedPage() {
  const t = await getTranslations("protected");
  const result = await fetchProtected({ limit: 100 });
  const events = result.ok ? result.data : [];

  const today = events.filter(
    (e) => new Date(e.timestamp) > new Date(Date.now() - 86_400_000)
  ).length;
  const week = events.filter(
    (e) => new Date(e.timestamp) > new Date(Date.now() - 7 * 86_400_000)
  ).length;

  return (
    <PageShell
      title={t("title")}
      subtitle={t("subtitle")}
    >
      {/* Summary line */}
      <p className="text-sm text-[var(--text-muted)] mb-8">
        {t("summaryToday", { count: today })}
        {" · "}
        {t("summaryWeek", { count: week })}
        {" · "}
        {t("summaryTotal", { count: events.length })}
      </p>

      {events.length === 0 ? (
        <p className="text-sm text-[var(--text-muted)] py-12 text-center">
          {t("empty")}
        </p>
      ) : (
        <Table>
          <Thead>
            <tr>
              <Th>{t("colTime")}</Th>
              <Th>{t("colAgent")}</Th>
              <Th>{t("colReason")}</Th>
            </tr>
          </Thead>
          <Tbody>
            {events.map((event) => (
              <Tr key={event.id}>
                <Td>
                  <span className="text-mono-sm text-[var(--text-muted)]">
                    {fmtRelativeTime(event.timestamp)}
                  </span>
                </Td>
                <Td className="text-[var(--text-primary)]">{event.agent_name}</Td>
                <Td>
                  <Badge variant="stopped">
                    {t(`reasons.${event.reason_code}` as Parameters<typeof t>[0])}
                  </Badge>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </PageShell>
  );
}
