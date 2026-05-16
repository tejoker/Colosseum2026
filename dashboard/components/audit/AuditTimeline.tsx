import { AuditEvent } from "@/lib/api";
import { Badge } from "@/components/ui/Badge";
import { truncateHash, fmtTimestamp } from "@/lib/format";

const EVENT_LABELS: Record<AuditEvent["event_type"], string> = {
  call:           "Call",
  mandate_check:  "Mandate check",
  config_change:  "Config change",
  revocation:     "Revocation",
  registration:   "Registered",
};

export function AuditTimeline({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-[var(--text-muted)] py-12 text-center">No events recorded yet.</p>;
  }

  return (
    <ol className="relative border-l border-[var(--border)] ml-3 space-y-0">
      {events.map((event) => (
        <li key={event.id} className="pl-6 pb-6 relative">
          {/* Timeline dot */}
          <span
            className={`absolute left-[-4.5px] top-1 w-2.5 h-2.5 rounded-full border-2 border-[var(--bg)] ${
              event.result === "allowed"
                ? "bg-[var(--status-ok)]"
                : event.result === "stopped"
                ? "bg-[var(--status-stopped)]"
                : "bg-[var(--text-muted)]"
            }`}
          />

          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-medium text-[var(--text-primary)]">
                  {EVENT_LABELS[event.event_type]}
                </span>
                {event.result !== "info" && (
                  <Badge variant={event.result === "allowed" ? "ok" : "stopped"}>
                    {event.result}
                  </Badge>
                )}
              </div>
              {event.anchor_id && (
                <p className="text-mono-sm text-[var(--text-muted)] mt-1">
                  {event.anchor_chain === "solana" ? (
                    <a
                      href={`https://explorer.solana.com/tx/${event.anchor_ref}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
                    >
                      Verify on Solana ↗
                    </a>
                  ) : event.anchor_chain === "bitcoin" ? (
                    <span>Bitcoin anchor: {truncateHash(event.anchor_id, 8)}</span>
                  ) : null}
                </p>
              )}
            </div>
            <span className="text-mono-sm text-[var(--text-muted)] flex-shrink-0">
              {fmtTimestamp(event.timestamp)}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}
