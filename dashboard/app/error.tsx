"use client";

import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/Button";

export default function GlobalError({
  reset,
}: {
  error: Error;
  reset: () => void;
}) {
  const t = useTranslations("common");

  return (
    <div className="min-h-screen pt-12 flex flex-col items-center justify-center gap-4">
      <p className="text-sm text-[var(--text-muted)]">{t("error")}</p>
      <Button variant="ghost" size="sm" onClick={reset}>
        {t("retry")}
      </Button>
    </div>
  );
}
