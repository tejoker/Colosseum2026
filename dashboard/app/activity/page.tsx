"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { LiveFeed } from "@/components/live/LiveFeed";
import { AuditExportPanel } from "@/components/audit/AuditExportPanel";
import * as Dialog from "@radix-ui/react-dialog";

export default function ActivityPage() {
  const t = useTranslations("activity");
  const [exportOpen, setExportOpen] = useState(false);

  return (
    <PageShell>
      {/* Page header with export button */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
            {t("title")}
          </h1>
          <p className="mt-1 text-sm text-[var(--text-muted)]">{t("subtitle")}</p>
        </div>
        <Dialog.Root open={exportOpen} onOpenChange={setExportOpen}>
          <Dialog.Trigger asChild>
            <button className="text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors duration-150 ease-out">
              {t("exportAudit")} ↗
            </button>
          </Dialog.Trigger>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40 animate-fade-in" />
            <Dialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-md animate-fade-in">
              <AuditExportPanel />
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>
      </div>

      <LiveFeed />
    </PageShell>
  );
}
