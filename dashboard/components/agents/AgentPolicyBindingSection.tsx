"use client";

// Read-side panel for an agent's policy binding (S10 server-backed).
//
// Goes through `/api/agents/:id/policy_binding`. On a network/proxy
// error the fetch helper falls back to localStorage so demos running
// without the core attached still render something useful.

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  fetchAgentBindingPolicyId,
  unbindAgentFromPolicy,
} from "@/lib/agentPolicyBinding";

interface AgentPolicyBindingSectionProps {
  agentId: string;
  agentName: string;
}

export function AgentPolicyBindingSection({
  agentId,
  agentName,
}: AgentPolicyBindingSectionProps) {
  const [boundId, setBoundId] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [opError, setOpError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAgentBindingPolicyId(agentId).then((b) => {
      if (cancelled) return;
      setBoundId(b);
      setHydrated(true);
    });
    return () => {
      cancelled = true;
    };
  }, [agentId]);

  async function onUnbind() {
    if (busy) return;
    setBusy(true);
    setOpError(null);
    try {
      await unbindAgentFromPolicy(agentId);
      setBoundId(null);
    } catch (e) {
      setOpError(e instanceof Error ? e.message : "unbind failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
        Policy binding
      </p>
      {!hydrated ? (
        <p className="text-sm text-[var(--text-muted)]">…</p>
      ) : boundId ? (
        <div className="space-y-2">
          <p className="text-sm">
            <span className="text-[var(--text-muted)]">Agent:</span>{" "}
            <span className="font-mono text-[var(--text-secondary)]">{agentName}</span>
          </p>
          <p className="text-sm">
            <span className="text-[var(--text-muted)]">Policy:</span>{" "}
            <Link
              href={`/policies/${encodeURIComponent(boundId)}`}
              className="font-mono text-[var(--accent-text)] hover:text-[var(--accent-hover)] break-all"
            >
              {boundId}
            </Link>
          </p>
          <div className="flex items-center gap-3">
            <Link
              href={`/policies/${encodeURIComponent(boundId)}`}
              className="text-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)]"
            >
              View policy →
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
          {opError && (
            <p className="text-sm text-[var(--status-stopped)]">{opError}</p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-[var(--text-muted)]">
            No policy bound to this agent.
          </p>
          <Link
            href={`/agents/${encodeURIComponent(agentId)}/binding`}
            className="text-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)]"
          >
            Bind a policy →
          </Link>
        </div>
      )}
    </div>
  );
}
