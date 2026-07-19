import { cookies } from "next/headers";
import { getRequestConfig } from "next-intl/server";

export const LOCALES = ["en", "fr"] as const;
export const LOCALE_COOKIE = "locale";

export default getRequestConfig(async () => {
  let locale = "en";
  try {
    const raw = (await cookies()).get(LOCALE_COOKIE)?.value ?? "";
    if ((LOCALES as readonly string[]).includes(raw)) locale = raw;
  } catch {
    // Outside a request scope (build-time prerender) — default to en.
  }
  return {
    locale,
    messages: (await import(`../messages/${locale}.json`)).default,
  };
});
