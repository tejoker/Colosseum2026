import type { CohortRank } from "@/lib/api";

interface RankBadgeProps {
  rank: CohortRank;
  label?: string;
}

/**
 * Small inline badge showing "p{N} in {cohort_id|label}" for the calling
 * tenant. Colour-codes the percentile bucket so the user gets an at-a-glance
 * read: p>=75 = green, p>=50 = neutral, p<50 = warn.
 */
export function RankBadge({ rank, label }: RankBadgeProps) {
  const pct = Math.max(0, Math.min(100, Math.round(rank.tenant_rank_percentile)));
  const tone =
    pct >= 75
      ? "text-[var(--status-ok)] border-[var(--status-ok)]/30"
      : pct >= 50
      ? "text-[var(--text-secondary)] border-[var(--border)]"
      : "text-[var(--status-warning)] border-[var(--status-warning)]/30";

  return (
    <span
      data-testid="rank-badge"
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-mono-sm uppercase ${tone}`}
    >
      <span>p{pct}</span>
      {label ? <span className="text-[var(--text-muted)]">in {label}</span> : null}
    </span>
  );
}
