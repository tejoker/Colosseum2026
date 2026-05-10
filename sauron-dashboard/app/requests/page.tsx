"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, PageHeader, StatusPill } from "../shared";

interface RequestEvent {
  id?: number;
  timestamp: number | string;
  action_type?: string;
  request_type?: string;       // legacy shape compat
  status?: string;             // "OK" | "FAIL" | other
  success?: boolean;           // legacy shape compat
  detail?: string;
  client_name?: string;
}

function fmtTs(ts: number | string): string {
  if (typeof ts === "string") return ts;
  if (!ts) return "—";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function actionType(e: RequestEvent): string {
  return (e.action_type ?? e.request_type ?? "UNKNOWN").toUpperCase();
}

function isOk(e: RequestEvent): boolean {
  if (typeof e.success === "boolean") return e.success;
  if (e.status) return e.status.toUpperCase() === "OK";
  return true;
}

export default function RequestsPage() {
  const [events, setEvents] = useState<RequestEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`/api/admin/requests`);
      if (res.ok) setEvents(await res.json());
    } catch {
      /* swallow — empty is fine */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5_000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="ACTIVITY.LOG"
        hex="0x300"
        title={
          <>
            Every request to the core,{" "}
            <em className="not-italic gradient-text font-display">in order</em>.
          </>
        }
        description="Append-only stream of every admin and agent action observed by the SauronID core. Nothing here is editable; every row is also part of the next merkle anchor."
      />

      <Card title={`STREAM · ${events.length} EVENTS`} hex="0x310">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4">
            <StatusPill
              status={loading ? "warn" : "ok"}
              label={loading ? "REFRESHING" : "LIVE · 5S"}
            />
            <span className="font-mono-label text-[9px] text-white/35">
              POLLING /api/admin/requests
            </span>
          </div>
          <button
            onClick={load}
            className="font-mono-label text-[9.5px] text-white/55 hover:text-[#4F8CFE] border border-white/10 hover:border-[#4F8CFE]/40 rounded-full px-3.5 py-1.5 transition-colors"
          >
            REFRESH NOW
          </button>
        </div>

        <div className="overflow-x-auto -mx-2">
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <span className="font-mono-label text-[9.5px] text-white/35">EMPTY</span>
              <p className="text-[12px] text-white/45">
                No activity yet — agents have not called the core.
              </p>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-left">
                  <Th right>#</Th>
                  <Th>TYPE</Th>
                  <Th>DETAIL</Th>
                  <Th>TIMESTAMP</Th>
                  <Th>STATUS</Th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => {
                  const ok = isOk(e);
                  return (
                    <tr key={e.id ?? i} className="border-t border-white/[0.04]">
                      <Td right muted mono>
                        {String(e.id ?? i + 1).padStart(4, "0")}
                      </Td>
                      <Td>
                        <span className="font-mono-label text-[9px] text-[#4F8CFE]/85 bg-[#4F8CFE]/10 px-1.5 py-0.5 rounded">
                          {actionType(e)}
                        </span>
                      </Td>
                      <Td muted mono>
                        {(e.detail ?? e.client_name ?? "").slice(0, 60) || "—"}
                      </Td>
                      <Td muted mono>
                        {fmtTs(e.timestamp)}
                      </Td>
                      <Td>
                        <StatusPill
                          status={ok ? "ok" : "err"}
                          label={ok ? "OK" : (e.status ?? "FAIL").toUpperCase()}
                        />
                      </Td>
                    </tr>
                  );
                })}
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
        "font-mono-label text-[8.5px] text-white/40 px-2 py-3 font-normal",
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
        "px-2 py-3 align-middle whitespace-nowrap",
        right ? "text-right tabular-nums" : "",
        cls,
      ].join(" ")}
    >
      {children}
    </td>
  );
}
