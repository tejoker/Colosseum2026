import type { Metadata } from "next";
import "./globals.css";
import { DashProvider } from "./context/DashContext";
import Sidebar from "./components/Sidebar";

export const metadata: Metadata = {
  title: "SauronID — Mandate console",
  description: "Pre-execution governance for autonomous AI agents.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        {/*
          BRANDING.md type system: Instrument Serif (display), Space Mono (labels).
          Satoshi (UI) is loaded via Fontshare since it is not on Google Fonts.
        */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Space+Mono:wght@400;700&display=swap"
        />
        <link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,600,700&display=swap" />
      </head>
      <body>
        <DashProvider>
          {/* Ambient blue glow behind everything — atmosphere, not chrome */}
          <div
            aria-hidden
            className="pointer-events-none fixed inset-0 -z-10"
            style={{
              background:
                "radial-gradient(900px 600px at 18% 12%, rgba(37,99,235,0.10), transparent 70%)," +
                "radial-gradient(700px 500px at 85% 90%, rgba(0,200,255,0.06), transparent 70%)",
            }}
          />
          <div className="relative flex min-h-screen">
            <Sidebar />
            <main className="flex-1 min-w-0 overflow-x-hidden">
              <div className="px-16 py-14 space-y-14 max-w-[1500px]">
                {children}
              </div>
            </main>
          </div>
        </DashProvider>
      </body>
    </html>
  );
}
