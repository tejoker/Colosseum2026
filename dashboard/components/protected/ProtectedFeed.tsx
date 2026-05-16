"use client";

import { useState } from "react";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { fmtRelativeTime } from "@/lib/format";
import type { ProtectedEvent } from "@/lib/api";

interface ProtectedFeedProps {
  events: ProtectedEvent[];
  labels: {
    colTime: string;
    colAgent: string;
    colReason: string;
    reasons: Record<string, string>;
  };
}

export function ProtectedFeed({ events, labels }: ProtectedFeedProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  function toggleRow(id: string) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  return (
    <Table>
      <Thead>
        <tr>
          <Th>{labels.colTime}</Th>
          <Th>{labels.colAgent}</Th>
          <Th>{labels.colReason}</Th>
        </tr>
      </Thead>
      <Tbody>
        {events.map((event) => {
          const isExpanded = expandedId === event.id;
          const hasDetail = Object.keys(event.detail).length > 0;

          return (
            <>
              <Tr
                key={event.id}
                onClick={() => toggleRow(event.id)}
              >
                <Td>
                  <span className="flex items-center gap-1.5">
                    <span
                      className="inline-block text-[var(--text-muted)] transition-transform duration-150 ease-out"
                      style={{ transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)" }}
                      aria-hidden="true"
                    >
                      ›
                    </span>
                    <span className="text-mono-sm text-[var(--text-muted)]">
                      {fmtRelativeTime(event.timestamp)}
                    </span>
                  </span>
                </Td>
                <Td className="text-[var(--text-primary)]">{event.agent_name}</Td>
                <Td>
                  <Badge variant="stopped">
                    {labels.reasons[event.reason_code] ?? event.reason_code}
                  </Badge>
                </Td>
              </Tr>
              {isExpanded && (
                <tr key={`${event.id}-detail`}>
                  <td colSpan={3} className="px-4 pb-3 pt-0">
                    <div className="bg-[var(--bg-elevated)] rounded p-3">
                      {hasDetail ? (
                        <pre className="text-xs font-mono text-[var(--text-muted)] whitespace-pre-wrap break-all">
                          {JSON.stringify(event.detail, null, 2)}
                        </pre>
                      ) : (
                        <span className="text-xs text-[var(--text-muted)]">—</span>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </>
          );
        })}
      </Tbody>
    </Table>
  );
}
