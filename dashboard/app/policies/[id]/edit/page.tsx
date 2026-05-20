import { notFound } from "next/navigation";
import { fetchPolicy } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import Link from "next/link";
import { PolicyEditClient } from "./PolicyEditClient";

export const dynamic = "force-dynamic";

export default async function PolicyEditPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const result = await fetchPolicy(id);
  if (!result.ok) notFound();

  // The server-side `GET /v1/policy/:id` returns the parsed Policy object,
  // not the original YAML text. We round-trip via JSON, which the upload
  // endpoint also accepts (it sniffs the first non-whitespace char).
  const initialText = JSON.stringify(result.data, null, 2);

  return (
    <PageShell>
      <Link
        href={`/policies/${encodeURIComponent(id)}`}
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-6"
      >
        ← Back to policy
      </Link>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
          Edit policy
        </h1>
        <p className="mt-1 text-sm text-[var(--text-muted)] font-mono break-all">{id}</p>
        <p className="mt-2 text-sm text-[var(--text-muted)]">
          Re-uploading produces a new policy_id only if the document changes
          (policy_id is a content hash). Editing keeps the agent name the same
          to act as an in-place update.
        </p>
      </div>
      <PolicyEditClient initialText={initialText} />
    </PageShell>
  );
}
