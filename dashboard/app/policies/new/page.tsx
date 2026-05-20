"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody } from "@/components/ui/Card";
import { PolicyEditor } from "@/components/policies/PolicyEditor";
import { PolicyTemplates } from "@/components/policies/PolicyTemplates";
import { PolicyValidator } from "@/components/policies/PolicyValidator";
import { uploadPolicy } from "@/lib/api";

const STARTER_YAML = `version: "1"
agent: my_agent
description: My new agent policy.
binding:
  max_budget_usd: 100
  rate_limit:
    requests_per_minute: 60
invariants:
  - "spend_total <= max_budget_usd"
`;

export default function NewPolicyPage() {
  const router = useRouter();
  const [text, setText] = useState(STARTER_YAML);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSave() {
    setError(null);
    setPending(true);
    try {
      const r = await uploadPolicy(text, "application/yaml");
      if (!r.ok) {
        setError(r.error);
        return;
      }
      router.push(`/policies/${encodeURIComponent(r.data.policy_id)}`);
    } finally {
      setPending(false);
    }
  }

  return (
    <PageShell>
      <Link
        href="/policies"
        className="inline-flex items-center gap-1 text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-6"
      >
        ← Back to policies
      </Link>

      <div className="flex items-start justify-between mb-6 gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
            New policy
          </h1>
          <p className="mt-1 text-sm text-[var(--text-muted)]">
            Write or paste a YAML policy. Server validates on upload.
          </p>
        </div>
        <PolicyTemplates onPick={(yaml) => setText(yaml)} disabled={pending} />
      </div>

      <Card className="mb-4">
        <CardBody>
          <PolicyEditor value={text} onChange={setText} />
        </CardBody>
      </Card>

      <Card className="mb-6">
        <CardBody>
          <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-3">
            Pre-flight
          </p>
          <PolicyValidator text={text} />
        </CardBody>
      </Card>

      {error && (
        <Card className="mb-4">
          <CardBody>
            <p className="text-sm text-[var(--status-stopped)] font-mono whitespace-pre-wrap">
              {error}
            </p>
          </CardBody>
        </Card>
      )}

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onSave}
          disabled={pending}
          className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-40"
        >
          {pending ? "Uploading…" : "Upload policy"}
        </button>
        <Link
          href="/policies"
          className="text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
        >
          Cancel
        </Link>
      </div>
    </PageShell>
  );
}
