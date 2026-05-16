import { getTranslations } from "next-intl/server";
import { fetchProofs } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { fmtNumber, fmtRelativeTime } from "@/lib/format";

export default async function ProofsPage() {
  const t = await getTranslations("proofs");
  const result = await fetchProofs();
  const anchors = result.ok ? result.data : null;

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Bitcoin */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <p className="text-mono-sm text-[var(--text-muted)] uppercase">{t("bitcoin")}</p>
              <a
                href="https://opentimestamps.org"
                target="_blank"
                rel="noopener noreferrer"
                className="text-mono-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
              >
                {t("verifyOn", { chain: "OTS" })} →
              </a>
            </div>
            <dl className="space-y-3">
              {[
                ["anchored",  anchors?.bitcoin_total],
                ["pending",   anchors?.bitcoin_pending],
                ["confirmed", anchors?.bitcoin_confirmed],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between text-sm">
                  <dt className="text-[var(--text-muted)] capitalize">{t(String(label) as Parameters<typeof t>[0])}</dt>
                  <dd className="text-[var(--text-primary)] font-medium tabular-nums">
                    {fmtNumber(value as number | null)}
                  </dd>
                </div>
              ))}
              {anchors?.bitcoin_last_batch_at && (
                <div className="flex justify-between text-sm pt-2 border-t border-[var(--border)]">
                  <dt className="text-[var(--text-muted)]">{t("lastBatch")}</dt>
                  <dd className="text-[var(--text-secondary)]">
                    {fmtRelativeTime(anchors.bitcoin_last_batch_at)}
                  </dd>
                </div>
              )}
            </dl>
            <p className="mt-4 text-mono-sm text-[var(--text-muted)]">{t("bitcoinNote")}</p>
          </CardBody>
        </Card>

        {/* Solana */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <p className="text-mono-sm text-[var(--text-muted)] uppercase">{t("solana")}</p>
              <a
                href="https://explorer.solana.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-mono-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
              >
                {t("verifyOn", { chain: "Solana Explorer" })} →
              </a>
            </div>
            <dl className="space-y-3">
              {[
                ["anchored",  anchors?.solana_total],
                ["pending",   anchors?.solana_unconfirmed],
                ["confirmed", anchors?.solana_confirmed],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between text-sm">
                  <dt className="text-[var(--text-muted)] capitalize">{t(String(label) as Parameters<typeof t>[0])}</dt>
                  <dd className="text-[var(--text-primary)] font-medium tabular-nums">
                    {fmtNumber(value as number | null)}
                  </dd>
                </div>
              ))}
              {anchors?.solana_last_batch_at && (
                <div className="flex justify-between text-sm pt-2 border-t border-[var(--border)]">
                  <dt className="text-[var(--text-muted)]">{t("lastBatch")}</dt>
                  <dd className="text-[var(--text-secondary)]">
                    {fmtRelativeTime(anchors.solana_last_batch_at)}
                  </dd>
                </div>
              )}
            </dl>
            <p className="mt-4 text-mono-sm text-[var(--text-muted)]">{t("solanaNote")}</p>
          </CardBody>
        </Card>
      </div>
    </PageShell>
  );
}
