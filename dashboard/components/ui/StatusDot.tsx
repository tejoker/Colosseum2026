interface StatusDotProps {
  status: "active" | "idle" | "stopped" | "warning" | "unknown";
  pulse?: boolean;
}

export function StatusDot({ status, pulse }: StatusDotProps) {
  const colors = {
    active:  "bg-[var(--status-ok)]",
    idle:    "bg-[var(--text-muted)]",
    stopped: "bg-[var(--status-stopped)]",
    warning: "bg-[var(--status-warning)]",
    unknown: "bg-[var(--border)]",
  };

  const shouldPulse = pulse ?? status === "active";

  return (
    <span
      className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${colors[status]} ${
        shouldPulse ? "animate-pulse-calm" : ""
      }`}
      aria-hidden
    />
  );
}
