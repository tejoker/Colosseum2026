export function Spinner({ label }: { label?: string }) {
  return (
    <div
      className="flex flex-col items-center justify-center py-16 gap-3"
      role="status"
      aria-label={label ?? "Loading"}
    >
      <div className="w-5 h-5 rounded-full border border-[var(--border)] border-t-[var(--accent)] animate-spin" />
      {label && (
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          {label}
        </span>
      )}
    </div>
  );
}
