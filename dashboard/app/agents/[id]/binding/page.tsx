"use client";

// Agent → Policy binding page (S10 server-backed).
//
// As of Sprint 10 the binding lives on the core at
// `/v1/agents/:id/policy_binding`. This page calls the proxy under
// `/api/agents/:id/policy_binding` (admin key auto-injected). The
// localStorage path remains only as an offline fallback when the proxy
// is unreachable — see `lib/agentPolicyBinding.ts`.

import { useEffect, useState } from "react";
import { use as usePromise } from "react";
import Link from "next/link";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { fetchPolicies, type PolicySummary } from "@/lib/api";
import {
  fetchAgentBindingPolicyId,
  bindAgentToPolicy,
  unbindAgentFromPolicy,
} from "@/lib/agentPolicyBinding";

export default function AgentBindingPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = usePromise(params);
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<string>("");
  const [boundId, setBoundId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [opError, setOpError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAgentBindingPolicyId(id).then((b) => {
      if (cancelled) return;
      setBoundId(b);
    });
    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    let cancelled = false;
    fetchPolicies().then((r) => {
      if (cancelled) return;
      if (!r.ok) {
        setLoadErr(r.error);
      } else {
        setPolicies(r.data);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function onBind() {
    if (!selected || busy) return;
    setBusy(true);
    setOpError(null);
    try {
      await bindAgentToPolicy(id, selected);
      setBoundId(selected);
    } catch (e) {
      setOpError(e instanceof Error ? e.message : "bind failed");
    } finally {
      setBusy(false);
    }
  }

  async function onUnbind() {
    if (busy) return;
    setBusy(true);
    setOpError(null);
    try {
      await unbindAgentFromPolicy(id);
      setBoundId(null);
    } catch (e) {
      setOpError(e instanceof Error ? e.message : "unbind failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <PageShell>
      <Link
        href={`/agents/${encodeURIComponent(id)}`}
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-6"
      >
        ← Back to agent
      </Link>

      <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight mb-2">
        Policy binding
      </h1>
      <p className="text-sm text-[var(--text-muted)] mb-6">
        Pick a policy to bind to this agent. Persisted server-side via
        <span className="font-mono"> /v1/agents/:id/policy_binding</span>.
      </p>

      {loadErr && (
        <Card className="mb-4">
          <CardBody>
            <p className="text-sm text-[var(--status-stopped)]">{loadErr}</p>
          </CardBody>
        </Card>
      )}
      {opError && (
        <Card className="mb-4">
          <CardBody>
            <p className="text-sm text-[var(--status-stopped)]">{opError}</p>
          </CardBody>
        </Card>
      )}

      <Card className="mb-4">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
            Current binding
          </p>
          {boundId ? (
            <div className="flex items-center gap-3 flex-wrap">
              <Link
                href={`/policies/${encodeURIComponent(boundId)}`}
                className="font-mono text-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)] break-all"
              >
                {boundId}
              </Link>
              <button
                type="button"
                onClick={onUnbind}
                disabled={busy}
                className="text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] disabled:opacity-40"
              >
                Unbind
              </button>
            </div>
          ) : (
            <p className="text-sm text-[var(--text-muted)]">No policy bound.</p>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
            Available policies
          </p>
          {policies.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">
              No policies available.{" "}
              <Link href="/policies/new" className="text-[var(--accent-text)]">
                Create one
              </Link>
              .
            </p>
          ) : (
            <div className="flex items-center gap-3 flex-wrap">
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="bg-[var(--bg-surface)] border border-[var(--border)] rounded px-3 py-1.5 text-sm text-[var(--text-secondary)]"
              >
                <option value="">Pick a policy…</option>
                {policies.map((p) => (
                  <option key={p.policy_id} value={p.policy_id}>
                    {p.agent} — {p.policy_id.slice(0, 14)}…
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={onBind}
                disabled={!selected || busy}
                className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-40"
              >
                Bind
              </button>
            </div>
          )}
        </CardBody>
      </Card>
    </PageShell>
  );
}
