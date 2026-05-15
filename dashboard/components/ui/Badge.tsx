interface BadgeProps {
  variant?: "ok" | "stopped" | "warning" | "neutral";
  children: React.ReactNode;
}

export function Badge({ variant = "neutral", children }: BadgeProps) {
  const variants = {
    ok:      "text-[var(--status-ok)] border-[var(--status-ok)]/20",
    stopped: "text-[var(--status-stopped)] border-[var(--status-stopped)]/20",
    warning: "text-[var(--status-warning)] border-[var(--status-warning)]/20",
    neutral: "text-[var(--text-muted)] border-[var(--border)]",
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full border text-mono-sm uppercase ${variants[variant]}`}
    >
      {children}
    </span>
  );
}
