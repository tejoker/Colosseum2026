"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useDash } from "../context/DashContext";

const PAGE_MAP: Record<string, { label: string; hex: string }> = {
  "/":         { label: "Overview",  hex: "0x001" },
  "/agents":   { label: "Agents",    hex: "0x002" },
  "/anchors":  { label: "Anchors",   hex: "0x003" },
  "/requests": { label: "Activity",  hex: "0x004" },
  "/clients":  { label: "Clients",   hex: "0x005" },
  "/users":    { label: "Humans",    hex: "0x006" },
  "/demo":     { label: "Live Demo", hex: "0x009" },
};

export default function TopBar() {
  const pathname = usePathname();
  const { offline, stats } = useDash();
  const page = PAGE_MAP[pathname] ?? { label: pathname.slice(1) || "Overview", hex: "0x000" };

  return (
    <div
      className="sticky top-0 z-20 flex items-center justify-between h-11 px-6 flex-shrink-0"
      style={{
        background: "rgba(3,17,35,0.85)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        borderBottom: "1px solid rgba(230,241,255,0.06)",
      }}
    >
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 font-mono-label text-[8.5px] tracking-[0.1em]">
        <Link href="/" className="text-white/30 hover:text-white/60 transition-colors">
          Console
        </Link>
        <span className="text-white/15">/</span>
        <span className="text-white/75">{page.label}</span>
        <span className="text-white/15">·</span>
        <span className="text-white/25">{page.hex}</span>
      </div>

      {/* Live status */}
      {offline ? (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-[#F87171]/20 bg-[#F87171]/[0.06]">
          <span className="w-1 h-1 rounded-full bg-[#F87171]" />
          <span className="font-mono-label text-[7.5px] text-[#F87171]/80">CORE OFFLINE</span>
        </div>
      ) : stats !== null ? (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-[#34D399]/20 bg-[#34D399]/[0.06]">
          <span className="w-1 h-1 rounded-full bg-[#34D399] animate-status-pulse" />
          <span className="font-mono-label text-[7.5px] text-[#34D399]/80">LIVE</span>
        </div>
      ) : (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-white/10">
          <span className="font-mono-label text-[7.5px] text-white/30">CONNECTING</span>
        </div>
      )}
    </div>
  );
}
