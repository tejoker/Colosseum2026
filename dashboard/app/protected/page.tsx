import { getTranslations } from "next-intl/server";
import { fetchProtected } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { ProtectedFeed } from "@/components/protected/ProtectedFeed";

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
        <ProtectedFeed
          events={events}
          labels={{
            colTime: t("colTime"),
            colAgent: t("colAgent"),
            colReason: t("colReason"),
            reasons: {
              replay: t("reasons.replay"),
              scope: t("reasons.scope"),
              signature: t("reasons.signature"),
              nonce: t("reasons.nonce"),
              revoked: t("reasons.revoked"),
              expired: t("reasons.expired"),
            },
          }}
        />
      )}
    </PageShell>
  );
}
