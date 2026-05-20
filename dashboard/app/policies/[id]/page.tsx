import { notFound } from "next/navigation";
import Link from "next/link";
import { fetchPolicy } from "@/lib/api";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { PolicySimulator } from "@/components/policies/PolicySimulator";
import { PolicyDeleteButton } from "@/components/policies/PolicyDeleteButton";

export const dynamic = "force-dynamic";

export default async function PolicyDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const result = await fetchPolicy(id);
  if (!result.ok) notFound();
  const p = result.data;

  // Compiled-checks list: enumerate every named binding field that produces
  // a runtime check. This mirrors the server-side `compiler::compile` mapping.
  const compiledChecks: string[] = [];
  if (p.binding?.max_budget_usd != null) compiledChecks.push("budget_cap");
  if (p.binding?.allowed_tools && p.binding.allowed_tools.length > 0) {
    compiledChecks.push("tool_allowlist");
  }
  if (p.binding?.data_scope) compiledChecks.push("data_scope");
  if (p.binding?.rate_limit) compiledChecks.push("rate_limit");
  if (p.binding?.time_window) compiledChecks.push("time_window");
  if (p.binding?.required_signatures && p.binding.required_signatures.length > 0) {
    compiledChecks.push("required_signatures");
  }
  if (p.binding?.delegation) compiledChecks.push("delegation");

  return (
    <PageShell>
      <Link
        href="/policies"
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-6"
      >
        ← Back to policies
      </Link>

      <div className="flex items-center gap-3 mb-2">
        <h1 className="text-xl font-semibold text-[var(--text-primary)] tracking-tight">
          {p.agent}
        </h1>
        <Badge variant="neutral">v{p.version}</Badge>
      </div>
      <p className="text-mono-sm text-[var(--text-muted)] mb-8 break-all">{id}</p>

      {p.description && (
        <Card className="mb-6">
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-2">
              Description
            </p>
            <p className="text-sm text-[var(--text-secondary)] whitespace-pre-wrap">
              {p.description}
            </p>
          </CardBody>
        </Card>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
              Compiled checks
            </p>
            {compiledChecks.length === 0 ? (
              <p className="text-sm text-[var(--text-muted)]">
                No binding-derived checks (invariants only).
              </p>
            ) : (
              <ul className="flex flex-wrap gap-2">
                {compiledChecks.map((c) => (
                  <li key={c}>
                    <Badge variant="neutral">{c}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
              Invariants
            </p>
            {!p.invariants || p.invariants.length === 0 ? (
              <p className="text-sm text-[var(--text-muted)]">
                None declared.
              </p>
            ) : (
              <ul className="space-y-1">
                {p.invariants.map((inv, i) => (
                  <li
                    key={i}
                    className="text-mono-sm text-[var(--text-secondary)] break-all"
                  >
                    {inv}
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mb-6">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
            Policy document (JSON view)
          </p>
          <pre className="text-mono-sm text-[var(--text-secondary)] bg-[var(--bg-elevated)] p-4 rounded overflow-auto max-h-96">
            {JSON.stringify(p, null, 2)}
          </pre>
        </CardBody>
      </Card>

      <Card className="mb-6">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
            Simulate
          </p>
          <PolicySimulator policyId={id} />
        </CardBody>
      </Card>

      <div className="flex items-center gap-3">
        <Link
          href={`/policies/${encodeURIComponent(id)}/edit`}
          className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
        >
          Edit
        </Link>
        <PolicyDeleteButton policyId={id} agent={p.agent} />
      </div>
    </PageShell>
  );
}
