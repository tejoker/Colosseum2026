"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardBody } from "@/components/ui/Card";
import { PolicyEditor } from "@/components/policies/PolicyEditor";
import { PolicyTemplates } from "@/components/policies/PolicyTemplates";
import { PolicyValidator } from "@/components/policies/PolicyValidator";
import { uploadPolicy } from "@/lib/api";

export function PolicyEditClient({ initialText }: { initialText: string }) {
  const router = useRouter();
  const [text, setText] = useState(initialText);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSave() {
    setError(null);
    setPending(true);
    try {
      // Sniff content type by first non-whitespace char (same heuristic as core).
      const trimmed = text.trimStart();
      const ct = trimmed.startsWith("{")
        ? ("application/json" as const)
        : ("application/yaml" as const);
      const body = ct === "application/json" ? JSON.stringify({ raw_yaml: text }) : text;
      // uploadPolicy already wraps JSON for us when contentType === "application/json",
      // so pass text directly and let it handle the envelope.
      void body;
      const r = await uploadPolicy(text, ct);
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
    <>
      <div className="flex items-center justify-end mb-3 gap-4 flex-wrap">
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
          {pending ? "Saving…" : "Save policy"}
        </button>
      </div>
    </>
  );
}
