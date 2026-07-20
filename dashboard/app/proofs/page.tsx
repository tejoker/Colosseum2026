import { getTranslations } from "next-intl/server";
import { fetchProofs, fetchAnchorBatches } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { fmtNumber, fmtRelativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function ProofsPage() {
  const t = await getTranslations("proofs");
  const result = await fetchProofs();
  const anchors = result.ok ? result.data : null;
  const batchesRes = await fetchAnchorBatches();
  const batches = batchesRes.ok ? batchesRes.data : [];

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
                className="text-mono-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)] transition-colors duration-150"
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
                className="text-mono-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)] transition-colors duration-150"
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

      {/* The actual proofs — each batch is a Merkle root committed to Bitcoin. */}
      <div className="mt-6">
        <div className="flex items-center gap-3 mb-3 flex-wrap">
          <p className="text-mono-sm text-[var(--text-muted)] uppercase">
            Anchored batches ({batches.length})
          </p>
          <details className="text-xs text-[var(--text-muted)]">
            <summary className="cursor-pointer hover:text-[var(--text-secondary)] select-none">
              What is this?
            </summary>
            <div className="mt-2 max-w-prose text-[var(--text-secondary)] leading-relaxed">
              Every action an agent takes is fingerprinted, and the whole batch
              is reduced to one short code — a “Merkle root.” That root is
              committed to the Bitcoin blockchain through OpenTimestamps. Once
              Bitcoin confirms it (about an hour), the record is permanent and
              public: no one — not an attacker, not even us — can change what
              the agents did without breaking the on-chain match. Click
              “Download proof” on any row to get the OpenTimestamps file and
              verify it yourself with the open-source{" "}
              <span className="font-[var(--font-mono)]">ots</span> tool.
            </div>
          </details>
        </div>
        {batches.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)]">
            No batches yet — run an agent and click “Seal all actions into Bitcoin” in the Console.
          </p>
        ) : (
          <div className="border border-[var(--border)] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[var(--text-muted)] border-b border-[var(--border)]">
                  <th className="px-4 py-2 font-normal text-xs uppercase">Merkle root (committed to Bitcoin)</th>
                  <th className="px-4 py-2 font-normal text-xs uppercase">Actions</th>
                  <th className="px-4 py-2 font-normal text-xs uppercase">Bitcoin</th>
                  <th className="px-4 py-2 font-normal text-xs uppercase">When</th>
                  <th className="px-4 py-2 font-normal text-xs uppercase">Proof</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((b) => (
                  <tr key={b.anchor_id} className="border-b border-[var(--border)] last:border-0">
                    <td className="px-4 py-2 font-[var(--font-mono)] text-[var(--text-primary)]" title={b.root}>
                      {b.root.slice(0, 24)}…{b.root.slice(-8)}
                    </td>
                    <td className="px-4 py-2 text-[var(--text-secondary)] tabular-nums">{b.n_actions}</td>
                    <td className="px-4 py-2">
                      {b.btc_confirmed ? (
                        <span className="text-[var(--status-ok)]">✓ confirmed</span>
                      ) : (
                        <span className="text-[var(--text-muted)]">⏳ pending (~1h)</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-[var(--text-secondary)]">{fmtRelativeTime(b.created_at)}</td>
                    <td className="px-4 py-2">
                      {b.btc_anchor_id ? (
                        <a
                          href={`/api/proofs/ots/${encodeURIComponent(b.btc_anchor_id)}`}
                          className="text-[var(--accent-text)] hover:text-[var(--accent-hover)] transition-colors duration-150"
                          title="Download the OpenTimestamps .ots proof. Verify with: ots upgrade <file>.ots && ots info <file>.ots"
                        >
                          ↓ Download proof
                        </a>
                      ) : (
                        <span className="text-[var(--text-muted)]" title="Not yet committed to Bitcoin — the next anchor batch will include it.">
                          —
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-mono-sm text-[var(--text-muted)]">
          Each root is the cryptographic fingerprint of a batch of agent actions, committed to
          Bitcoin. Altering any past action would change its root and break the on-chain match.
        </p>
      </div>
    </PageShell>
  );
}
