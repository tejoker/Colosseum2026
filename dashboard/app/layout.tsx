import type { Metadata } from "next";
import { ThemeProvider } from "next-themes";
import { NextIntlClientProvider } from "next-intl";
import { getLocale, getMessages } from "next-intl/server";
import { TopNav } from "@/components/layout/TopNav";
import "./globals.css";

export const metadata: Metadata = {
  title: "SauronID",
  description: "Pre-execution governance for autonomous AI agents.",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  let messages: Awaited<ReturnType<typeof getMessages>>;
  let locale = "en";
  try {
    messages = await getMessages();
    locale = await getLocale();
  } catch {
    messages = {};
  }

  // Skip-link label — read straight from the loaded messages so a failed
  // getMessages() still renders a usable (English) link.
  const skipLabel =
    (messages as { common?: { skipToContent?: string } }).common
      ?.skipToContent ?? "Skip to content";

  return (
    <html lang={locale} suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        {/* This is the root App Router layout, so the font is global. The
            rule's pages/_document recommendation does not apply here. */}
        {/* eslint-disable-next-line @next/next/no-page-custom-font */}
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap"
        />
        <link
          rel="stylesheet"
          href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,600,700&display=swap"
        />
      </head>
      <body suppressHydrationWarning>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <NextIntlClientProvider messages={messages} locale={locale}>
            <a
              href="#main"
              className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100] focus:px-3 focus:py-1.5 focus:rounded focus:bg-[var(--accent)] focus:text-white text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-hover)]"
            >
              {skipLabel}
            </a>
            <TopNav />
            {children}
          </NextIntlClientProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
