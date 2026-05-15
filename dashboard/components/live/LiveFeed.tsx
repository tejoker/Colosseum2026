"use client";

import { useEffect, useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import { fetchActivity, ActivityCall } from "@/lib/api";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { Spinner } from "@/components/ui/Spinner";
import { fmtRelativeTime, fmtLatency } from "@/lib/format";

type Filter = "all" | "allowed" | "stopped";

export function LiveFeed() {
  const t = useTranslations("activity");
  const [calls, setCalls] = useState<ActivityCall[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [agentFilter, setAgentFilter] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const load = useCallback(async () => {
    const result = await fetchActivity({ filter, limit: 100 });
    if (result.ok) setCalls(result.data);
    setLoading(false);
  }, [filter]);

  useEffect(() => {
    setLoading(true);
    load();
    const interval = setInterval(load, 15_000);
    return () => clearInterval(interval);
  }, [load]);

  const filters: Filter[] = ["all", "allowed", "stopped"];

  const visibleCalls = calls
    .filter((c) => filter === "all" || c.result === filter)
    .filter((c) => !agentFilter || c.agent_name.toLowerCase().includes(agentFilter.toLowerCase()))
    .filter((c) => !dateFrom || new Date(c.timestamp) >= new Date(dateFrom))
    .filter((c) => !dateTo || new Date(c.timestamp) <= new Date(dateTo + "T23:59:59"));

  const INPUT_CLASS =
    "px-3 py-1.5 text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded " +
    "text-[var(--text-primary)] placeholder:text-[var(--text-muted)] " +
    "focus:outline-none focus:border-[var(--border-hover)] transition-colors duration-150 ease-out";

  return (
    <div>
      {/* Filter tabs */}
      <div className="flex items-center gap-1">
        {filters.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out ${
              filter === f
                ? "text-[var(--text-primary)] bg-[var(--bg-elevated)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            }`}
          >
            {t(`filter${f.charAt(0).toUpperCase() + f.slice(1)}` as Parameters<typeof t>[0])}
          </button>
        ))}
      </div>

      {/* Secondary filters */}
      <div className="flex items-center gap-3 mt-3 mb-6">
        <input
          type="text"
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          placeholder={t("filterAgent")}
          className={`${INPUT_CLASS} w-40`}
        />
        <input
          type="date"
          value={dateFrom}
          onChange={(e) => setDateFrom(e.target.value)}
          placeholder={t("filterFrom")}
          className={`${INPUT_CLASS} w-36`}
        />
        <input
          type="date"
          value={dateTo}
          onChange={(e) => setDateTo(e.target.value)}
          placeholder={t("filterTo")}
          className={`${INPUT_CLASS} w-36`}
        />
      </div>

      {loading ? (
        <Spinner />
      ) : visibleCalls.length === 0 ? (
        <p className="text-sm text-[var(--text-muted)] py-12 text-center">
          {t("empty")}
        </p>
      ) : (
        <Table>
          <Thead>
            <tr>
              <Th>{t("colTime")}</Th>
              <Th>{t("colAgent")}</Th>
              <Th>{t("colAction")}</Th>
              <Th>{t("colResult")}</Th>
              <Th>{t("colLatency")}</Th>
            </tr>
          </Thead>
          <Tbody>
            {visibleCalls.map((call) => {
              const isExpanded = expandedId === call.id;
              const { body_hash, nonce, jti, dpop_binding } = call.detail;
              const detailEntries: { label: string; value: string }[] = [
                { label: t("detailIntent"), value: call.intent },
                ...(body_hash ? [{ label: t("detailBodyHash"), value: body_hash }] : []),
                ...(nonce ? [{ label: t("detailNonce"), value: nonce }] : []),
                ...(jti ? [{ label: t("detailJti"), value: jti }] : []),
                ...(dpop_binding ? [{ label: t("detailDpop"), value: dpop_binding }] : []),
              ];

              return (
                <>
                  <Tr
                    key={call.id}
                    onClick={() => toggleExpand(call.id)}
                    className="cursor-pointer"
                  >
                    <Td>
                      <span className="inline-flex items-center gap-1.5">
                        <span
                          className={`inline-block transition-transform duration-150 ease-out text-[var(--text-muted)] text-xs ${
                            isExpanded ? "rotate-90" : ""
                          }`}
                        >
                          ›
                        </span>
                        <span className="text-mono-sm text-[var(--text-muted)]">
                          {fmtRelativeTime(call.timestamp)}
                        </span>
                      </span>
                    </Td>
                    <Td className="text-[var(--text-primary)]">{call.agent_name}</Td>
                    <Td>
                      <span className="text-mono-sm text-[var(--text-secondary)]">
                        {call.action}
                      </span>
                    </Td>
                    <Td>
                      <Badge variant={call.result === "allowed" ? "ok" : "stopped"}>
                        {t(call.result === "allowed" ? "resultAllowed" : "resultStopped")}
                      </Badge>
                    </Td>
                    <Td>
                      <span className="text-mono-sm text-[var(--text-muted)]">
                        {fmtLatency(call.latency_ms)}
                      </span>
                    </Td>
                  </Tr>
                  {isExpanded && (
                    <tr key={`${call.id}-detail`}>
                      <td colSpan={5} className="px-4 pb-3 pt-0">
                        <dl className="bg-[var(--bg-elevated)] rounded p-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
                          {detailEntries.map(({ label, value }) => (
                            <>
                              <dt className="text-xs text-[var(--text-muted)]">{label}</dt>
                              <dd className="font-mono text-xs text-[var(--text-muted)] break-all">{value}</dd>
                            </>
                          ))}
                        </dl>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </Tbody>
        </Table>
      )}
    </div>
  );
}
