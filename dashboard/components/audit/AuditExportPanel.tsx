"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/Button";

interface AuditExportPanelProps {
  agentId?: string;
}

type ExportFormat = "json" | "pdf";

export function AuditExportPanel({ agentId }: AuditExportPanelProps) {
  const t = useTranslations("auditExport");
  const [format, setFormat] = useState<ExportFormat>("json");
  const [loading, setLoading] = useState(false);

  async function handleExport() {
    setLoading(true);
    try {
      const res = await fetch("/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format, agent_id: agentId }),
      });

      if (!res.ok) return;

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sauronid-audit.${format === "pdf" ? "pdf" : "json"}`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg p-5">
      <p className="text-sm font-medium text-[var(--text-primary)] mb-1">{t("title")}</p>
      <p className="text-sm text-[var(--text-muted)] mb-4">{t("subtitle")}</p>

      {/* Format selector — json + pdf active, signed disabled */}
      <div className="flex items-center gap-2 mb-4">
        {(["json", "pdf"] as ExportFormat[]).map((f) => (
          <button
            key={f}
            onClick={() => setFormat(f)}
            className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out ${
              format === f
                ? "bg-[var(--bg-elevated)] text-[var(--text-primary)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            }`}
          >
            {f === "json" ? t("formatJson") : t("formatPdf")}
          </button>
        ))}
        {/* Signed report — disabled until core provides signing endpoint */}
        <button
          disabled
          title={t("signedUnavailable")}
          className="px-3 py-1.5 text-sm rounded text-[var(--text-muted)] opacity-40 cursor-not-allowed"
        >
          {t("formatSigned")}
        </button>
      </div>

      <p className="text-mono-sm text-[var(--text-muted)] mb-4">
        {format === "json" ? t("formatJsonDesc") : t("formatPdfDesc")}
      </p>

      <Button
        variant="ghost"
        size="sm"
        onClick={handleExport}
        disabled={loading}
      >
        {loading ? t("exporting") : `${t("download")} ${format.toUpperCase()}`}
      </Button>
    </div>
  );
}
