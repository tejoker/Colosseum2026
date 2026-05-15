import Link from "next/link";
import { getTranslations } from "next-intl/server";

export default async function NotFound() {
  const t = await getTranslations("notFound");
  return (
    <div className="min-h-screen pt-12 flex flex-col items-center justify-center gap-4">
      <p className="text-sm text-[var(--text-muted)]">{t("message")}</p>
      <Link href="/" className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150">
        {t("link")}
      </Link>
    </div>
  );
}
