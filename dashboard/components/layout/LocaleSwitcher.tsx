"use client";

import { useLocale } from "next-intl";
import { useRouter } from "next/navigation";

// Minimal en/fr toggle. Writes the `locale` cookie read by i18n/request.ts,
// then refreshes so server components re-render with the new messages.
export function LocaleSwitcher() {
  const router = useRouter();
  const locale = useLocale();
  const next = locale === "fr" ? "en" : "fr";

  function toggle() {
    document.cookie = `locale=${next}; Path=/; Max-Age=31536000; SameSite=Lax`;
    router.refresh();
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={next === "fr" ? "Passer en français" : "Switch to English"}
      className="w-7 h-7 flex items-center justify-center text-mono-sm uppercase text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors duration-150 ease-out rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
    >
      {locale}
    </button>
  );
}
