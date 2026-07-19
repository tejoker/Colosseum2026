"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/Button";

const INPUT_CLASS =
  "px-3 py-2 text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded " +
  "text-[var(--text-primary)] placeholder:text-[var(--text-muted)] " +
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] " +
  "focus:border-[var(--border-hover)] transition-colors duration-150 ease-out";

export default function LoginPage() {
  // useSearchParams must sit under a Suspense boundary for the Next build.
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const t = useTranslations("login");
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/";
  const [operator, setOperator] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operator, password }),
      });
      const data = (await r.json().catch(() => ({}))) as { error?: string };
      if (!r.ok) {
        setError(data.error || t("failed", { status: r.status }));
        return;
      }
      router.replace(next);
    } catch {
      setError(t("networkError"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main id="main" className="min-h-[70vh] flex items-center justify-center px-6">
      <form onSubmit={submit} className="grid gap-4 w-80 max-w-full">
        <h1 className="text-xl font-semibold text-[var(--text-primary)] tracking-tight">
          {t("title")}
        </h1>

        <div className="grid gap-1.5">
          <label htmlFor="login-operator" className="text-sm text-[var(--text-secondary)]">
            {t("operator")}
          </label>
          <input
            id="login-operator"
            name="username"
            value={operator}
            onChange={(e) => setOperator(e.target.value)}
            autoComplete="username"
            required
            className={INPUT_CLASS}
          />
        </div>

        <div className="grid gap-1.5">
          <label htmlFor="login-password" className="text-sm text-[var(--text-secondary)]">
            {t("password")}
          </label>
          <input
            id="login-password"
            name="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className={INPUT_CLASS}
          />
        </div>

        <p role="status" aria-live="polite" className="text-sm text-[var(--status-stopped)] min-h-5 m-0">
          {error}
        </p>

        <Button type="submit" disabled={busy}>
          {busy ? t("signingIn") : t("signIn")}
        </Button>
      </form>
    </main>
  );
}
