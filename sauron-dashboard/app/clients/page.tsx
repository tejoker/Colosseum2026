"use client";

import { useEffect, useState } from "react";
import {
  sauronFetch,
  Card,
  Kpi,
  Spinner,
  PageHeader,
  StatusPill,
  fmtNum,
} from "../shared";

interface ClientRow {
  client_id: number;
  name: string;
  type: string;
  last_active?: string;
  total_verifications?: number;
  is_active?: boolean;
}

interface ClientsData {
  clients: ClientRow[];
  active_count: number;
}

export default function ClientsPage() {
  const [data, setData] = useState<ClientsData | null>(null);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");

  useEffect(() => {
    sauronFetch<ClientsData>("clients").then(setData).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  // /api/live/clients returns AdminClient[] directly; legacy returns {clients}.
  const clientList: ClientsData["clients"] = Array.isArray(data)
    ? (data as unknown as ClientsData["clients"])
    : data.clients ?? [];

  const filtered = clientList.filter((c) => {
    if (typeFilter !== "all" && c.type !== typeFilter) return false;
    return (c.name ?? "").toLowerCase().includes(search.toLowerCase());
  });

  const types = [...new Set(clientList.map((c) => c.type ?? ""))].filter(Boolean);
  const activeCount = data.active_count ?? clientList.length;

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="CLIENT.DIRECTORY"
        hex="0x400"
        title={
          <>
            The{" "}
            <em className="not-italic gradient-text font-display">ring members</em>{" "}
            entitled to issue.
          </>
        }
        description="Partner sites that hold an authoring slot in the SauronID ring. Anonymous to each other; accountable to the core."
      />

      <div className="grid grid-cols-2 md:grid-cols-3 gap-5">
        <Kpi label="TOTAL CLIENTS" value={fmtNum(clientList.length)} accent="cyan" />
        <Kpi label="ACTIVE · 90D" value={fmtNum(activeCount)} accent="emerald" />
        <Kpi
          label="DORMANT"
          value={fmtNum(clientList.length - activeCount)}
          sub="NO ACTIVITY · 90D"
        />
      </div>

      <Card title={`CLIENT.LIST · ${filtered.length}`} hex="0x410">
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <input
            type="text"
            placeholder="search clients…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-[#06090F] border border-white/10 rounded px-3 py-2 text-[12.5px] text-white placeholder:text-white/30 font-mono w-56 focus:outline-none focus:border-[#4F8CFE]/50 focus:bg-[#0A1128] transition-colors"
          />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-[#06090F] border border-white/10 rounded px-3 py-2 text-[12.5px] text-white font-mono focus:outline-none focus:border-[#4F8CFE]/50"
          >
            <option value="all" className="bg-[#06090F]">
              ALL TYPES
            </option>
            {types.map((t) => (
              <option key={t} value={t} className="bg-[#06090F]">
                {t.toUpperCase()}
              </option>
            ))}
          </select>
          <span className="font-mono-label text-[9px] text-white/35 ml-auto">
            {filtered.length} / {clientList.length}
          </span>
        </div>

        <div className="overflow-x-auto -mx-3">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <span className="font-mono-label text-[9.5px] text-white/35">
                NO MATCHES
              </span>
              <p className="text-[12px] text-white/45">
                Adjust the filter or clear the search.
              </p>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th>NAME</Th>
                  <Th>TYPE</Th>
                  <Th right>VERIFICATIONS</Th>
                  <Th>STATE</Th>
                  <Th>LAST.ACTIVE</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c, i) => (
                  <tr
                    key={c.client_id ?? c.name ?? i}
                    className="border-t border-white/[0.04]"
                  >
                    <Td>{c.name}</Td>
                    <Td>
                      <span
                        className={[
                          "font-mono-label text-[9px] px-1.5 py-0.5 rounded",
                          c.type === "full_identification"
                            ? "bg-[#4F8CFE]/12 text-[#4F8CFE]"
                            : "bg-[#A78BFA]/12 text-[#A78BFA]",
                        ].join(" ")}
                      >
                        {(c.type ?? "").toUpperCase()}
                      </span>
                    </Td>
                    <Td right>{fmtNum(c.total_verifications ?? 0)}</Td>
                    <Td>
                      <StatusPill
                        status={c.is_active ? "ok" : "muted"}
                        label={c.is_active ? "ACTIVE" : "DORMANT"}
                      />
                    </Td>
                    <Td muted mono>
                      {c.last_active?.slice(0, 10) ?? "—"}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}

function Th({ children, right }: { children: React.ReactNode; right?: boolean }) {
  return (
    <th
      className={[
        "font-mono-label text-[8.5px] text-white/40 px-3 py-4 font-normal",
        right ? "text-right" : "",
      ].join(" ")}
    >
      {children}
    </th>
  );
}

function Td({
  children,
  mono,
  muted,
  right,
}: {
  children: React.ReactNode;
  mono?: boolean;
  muted?: boolean;
  right?: boolean;
}) {
  let cls = "text-white/85";
  if (mono) cls = "font-mono text-[11px] text-white/75";
  if (muted) cls = "text-white/50";
  if (mono && muted) cls = "font-mono text-[11px] text-white/45";
  return (
    <td
      className={[
        "px-3 py-4 align-middle whitespace-nowrap",
        right ? "text-right tabular-nums" : "",
        cls,
      ].join(" ")}
    >
      {children}
    </td>
  );
}
