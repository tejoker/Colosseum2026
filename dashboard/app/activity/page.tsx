import { getTranslations } from "next-intl/server";
import { PageShell } from "@/components/layout/PageShell";
import { LiveFeed } from "@/components/live/LiveFeed";

export default async function ActivityPage() {
  const t = await getTranslations("activity");

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <LiveFeed />
    </PageShell>
  );
}
