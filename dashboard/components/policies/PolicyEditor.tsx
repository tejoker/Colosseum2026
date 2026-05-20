"use client";

// Policy YAML/JSON editor (Sprint 10 — Monaco upgrade).
//
// Backed by `@monaco-editor/react`, dynamically imported so the editor
// (and its web worker) never enter the SSR bundle. Monaco's built-in
// YAML/JSON languages give us syntax highlighting + bracket matching
// out of the box; we additionally register the dashboard's policy
// JSON schema so users get IntelliSense + diagnostics on JSON-shaped
// inputs (YAML clients on the policy editor still benefit from the
// schema once `monaco-yaml` is added — tracked as a follow-up).
//
// Component API is preserved (`value`, `onChange`, `readOnly`, plus
// the pre-existing convenience props `rows` and `ariaLabel`) so the
// callers in `/policies/new` and `/policies/[id]/edit` keep working
// without changes.

import dynamic from "next/dynamic";
import type { OnChange, OnMount } from "@monaco-editor/react";
import policySchema from "@/schemas/policy.schema.json";

const MonacoEditor = dynamic(
  () => import("@monaco-editor/react").then((m) => m.default),
  {
    ssr: false,
    loading: () => (
      <div
        aria-label="Loading policy editor"
        className="w-full h-[480px] font-mono text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg px-4 py-3 text-[var(--text-muted)] flex items-center justify-center"
      >
        Loading editor…
      </div>
    ),
  }
);

interface PolicyEditorProps {
  value: string;
  onChange: (next: string) => void;
  readOnly?: boolean;
  /** Approximate row count → pixel height. Kept for API back-compat. */
  rows?: number;
  ariaLabel?: string;
  /**
   * Override the language. Defaults to `"yaml"` to match the previous
   * textarea behaviour; the edit page passes `"json"` when round-tripping
   * a JSON-formatted policy.
   */
  language?: "yaml" | "json";
}

const LINE_HEIGHT_PX = 19; // monaco default at 14px font

export function PolicyEditor({
  value,
  onChange,
  readOnly = false,
  rows = 24,
  ariaLabel = "Policy YAML editor",
  language = "yaml",
}: PolicyEditorProps) {
  const heightPx = Math.max(240, rows * LINE_HEIGHT_PX);

  const handleChange: OnChange = (next) => {
    onChange(next ?? "");
  };

  // Wire the policy JSON schema into Monaco's JSON validator. Safe to call
  // every mount — Monaco de-dupes by schema URI.
  const handleMount: OnMount = (_editor, monaco) => {
    try {
      monaco.languages.json.jsonDefaults.setDiagnosticsOptions({
        validate: true,
        allowComments: false,
        schemas: [
          {
            uri: "sauron://schemas/policy.schema.json",
            fileMatch: ["*"],
            schema: policySchema as unknown as object,
          },
        ],
      });
    } catch {
      // monaco JSON contribution missing — ignore, syntax highlighting
      // still works.
    }
  };

  return (
    <div
      aria-label={ariaLabel}
      data-testid="policy-editor"
      data-language={language}
      className="w-full font-mono text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg overflow-hidden focus-within:border-[var(--accent)]"
      style={{ height: heightPx }}
    >
      <MonacoEditor
        height="100%"
        language={language}
        value={value}
        onChange={handleChange}
        onMount={handleMount}
        theme="vs-dark"
        options={{
          readOnly,
          minimap: { enabled: false },
          fontSize: 13,
          lineNumbers: "on",
          scrollBeyondLastLine: false,
          tabSize: 2,
          wordWrap: "on",
          renderWhitespace: "selection",
          automaticLayout: true,
        }}
      />
    </div>
  );
}
