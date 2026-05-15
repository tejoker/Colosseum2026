interface PageShellProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
}

export function PageShell({ children, title, subtitle }: PageShellProps) {
  return (
    <div className="min-h-screen pt-12">
      <main className="max-w-5xl mx-auto px-6 py-10">
        {(title || subtitle) && (
          <div className="mb-8">
            {title && (
              <h1 className="text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
                {title}
              </h1>
            )}
            {subtitle && (
              <p className="mt-1 text-sm text-[var(--text-muted)]">{subtitle}</p>
            )}
          </div>
        )}
        {children}
      </main>
    </div>
  );
}
