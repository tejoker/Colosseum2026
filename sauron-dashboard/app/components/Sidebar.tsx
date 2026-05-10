"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useDash } from "../context/DashContext";
import BrandMark from "./BrandMark";

/**
 * Sidebar — SauronID mandate console nav.
 *
 * Aesthetic: dark glass panel, hairline divider on the right, animated eye
 * brand mark, mono section labels, Sauron Blue active pill with glow.
 * Active item gets the brand-blue underline + glow per BRANDING §7.
 */

const LINKS = [
  { href: "/",         label: "Overview",  hex: "0x001",
    icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" },
  { href: "/agents",   label: "Agents",    hex: "0x002",
    icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
  { href: "/anchors",  label: "Anchors",   hex: "0x003",
    icon: "M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" },
  { href: "/requests", label: "Activity",  hex: "0x004",
    icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { href: "/clients",  label: "Clients",   hex: "0x005",
    icon: "M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" },
  { href: "/users",    label: "Humans",    hex: "0x006",
    icon: "M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 7a4 4 0 110-8 4 4 0 010 8zM23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" },
];

function Icon({ d }: { d: string }) {
  return (
    <svg
      className="w-[15px] h-[15px] flex-shrink-0"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.6}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d={d} />
    </svg>
  );
}

export default function Sidebar() {
  const pathname = usePathname();
  const { stats, offline } = useDash();

  return (
    <aside
      className="relative w-[232px] flex-shrink-0 min-h-screen flex flex-col"
      style={{
        background: "linear-gradient(180deg, #06090F 0%, #060C1E 100%)",
        borderRight: "1px solid rgba(230,241,255,0.06)",
      }}
    >
      {/* Decorative left edge accent */}
      <span aria-hidden className="absolute right-0 top-24 h-40 w-px hairline" />

      {/* Brand lockup */}
      <div className="px-5 pt-7 pb-6">
        <Link href="/" className="flex items-center gap-3 group">
          <BrandMark size={36} />
          <div className="leading-tight">
            <div
              className="text-[15px] font-semibold tracking-tight"
              style={{ fontFamily: "Satoshi, system-ui, sans-serif" }}
            >
              <span className="text-white">Sauron</span>
              <span className="text-[#4F8CFE]">ID</span>
            </div>
            <div className="font-mono-label text-[9px] text-white/45 mt-0.5">
              Mandate console
            </div>
          </div>
        </Link>
      </div>

      {/* Section label — primary nav */}
      <div className="px-5 pb-3 flex items-center gap-3">
        <span className="font-mono-label text-[9px] text-white/35">SYS.NAV</span>
        <span className="h-px flex-1 hairline" />
        <span className="font-mono-label text-[9px] text-white/20">0x000</span>
      </div>

      {/* Nav */}
      <div className="flex-1 px-3 space-y-px">
        {LINKS.map(({ href, label, hex, icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={[
                "group relative flex items-center justify-between gap-2.5",
                "px-3 py-[9px] rounded-md text-[13.5px] transition-colors",
                active
                  ? "text-white"
                  : "text-white/55 hover:text-white hover:bg-white/[0.03]",
              ].join(" ")}
              style={
                active
                  ? {
                      background:
                        "linear-gradient(90deg, rgba(37,99,235,0.22) 0%, rgba(37,99,235,0.04) 100%)",
                      boxShadow: "inset 2px 0 0 0 #4F8CFE, 0 0 22px -10px rgba(79,140,254,0.7)",
                    }
                  : {}
              }
            >
              <span className="flex items-center gap-2.5 min-w-0">
                <Icon d={icon} />
                <span className="tracking-tight">{label}</span>
              </span>
              <span
                className={[
                  "font-mono-label text-[8.5px]",
                  active ? "text-[#4F8CFE]" : "text-white/20 group-hover:text-white/40",
                ].join(" ")}
              >
                {hex}
              </span>
            </Link>
          );
        })}
      </div>

      {/* Footer status */}
      <div className="px-5 pt-5 pb-5">
        <div className="flex items-center gap-3 mb-3">
          <span className="font-mono-label text-[9px] text-white/35">SYS.STATUS</span>
          <span className="h-px flex-1 hairline" />
        </div>

        {offline ? (
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#F87171]" />
            <span className="font-mono-label text-[9.5px] text-[#F87171]">
              CORE OFFLINE
            </span>
          </div>
        ) : stats ? (
          <div className="space-y-2.5">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#34D399] animate-status-pulse" />
              <span className="font-mono-label text-[9.5px] text-[#34D399]/80">
                LIVE
              </span>
            </div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 pt-1">
              <Stat label="CLIENTS" value={stats.total_clients} />
              <Stat label="HUMANS"  value={stats.total_users} />
              <Stat label="A·MIN"   value={stats.total_tokens_a_issued} />
              <Stat label="B·SPNT"  value={stats.total_tokens_b_spent} />
            </div>
          </div>
        ) : (
          <span className="font-mono-label text-[9.5px] text-white/35">
            CONNECTING…
          </span>
        )}

        <div className="mt-5 pt-4 border-t border-white/5">
          <span className="font-mono-label text-[8.5px] text-white/25 leading-relaxed block">
            v1.0 · sauronid.io
            <br/>
            {new Date().getUTCFullYear()} all-seeing
          </span>
        </div>
      </div>
    </aside>
  );
}

function Stat({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="leading-none">
      <div className="font-mono-label text-[8px] text-white/35">{label}</div>
      <div className="text-[12px] tabular-nums text-white/85 mt-1">
        {(value ?? 0).toLocaleString("en-US")}
      </div>
    </div>
  );
}
