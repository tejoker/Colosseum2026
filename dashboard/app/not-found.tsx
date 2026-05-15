import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen pt-12 flex flex-col items-center justify-center gap-4">
      <p className="text-sm text-[var(--text-muted)]">Page not found.</p>
      <Link
        href="/"
        className="text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
      >
        Return home
      </Link>
    </div>
  );
}
