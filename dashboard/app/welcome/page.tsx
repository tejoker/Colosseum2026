"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { CopyButton } from "@/components/ui/CopyButton";
import { Badge } from "@/components/ui/Badge";
import { fetchActivity, ActivityCall } from "@/lib/api";
import { currentTenant } from "@/lib/tenant";
import { fmtRelativeTime } from "@/lib/format";
import {
  INSTALL_SNIPPETS,
  LANG_LABELS,
  REGISTER_SNIPPETS,
  SNIPPET_LANGS,
  SnippetLang,
} from "@/components/welcome/snippets";

interface SessionInfo {
  operator: string;
  tenant: string;
}

const SUMMARY_CLASS =
  "flex items-center gap-3 px-5 py-4 cursor-pointer select-none list-none " +
  "text-sm font-medium text-[var(--text-primary)] rounded-lg " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] " +
  "[&::-webkit-details-marker]:hidden";

function Step({
  n,
  title,
  defaultOpen,
  children,
}: {
  n: number;
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  // Native <details>/<summary>: keyboard accessible (Enter/Space) for free.
  return (
    <details
      open={defaultOpen}
      className="group bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg"
    >
      <summary className={SUMMARY_CLASS}>
        <span className="flex-shrink-0 w-6 h-6 rounded-full border border-[var(--border)] flex items-center justify-center text-mono-sm text-[var(--text-muted)]">
          {n}
        </span>
        {title}
        <span
          aria-hidden
          className="ml-auto text-[var(--text-muted)] transition-transform duration-150 ease-out group-open:rotate-90"
        >
          ›
        </span>
      </summary>
      <div className="px-5 pb-5 pt-1">{children}</div>
    </details>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <pre className="bg-[var(--bg-elevated)] rounded p-4 overflow-x-auto text-xs leading-relaxed font-mono text-[var(--text-secondary)]">
      <code>{code}</code>
    </pre>
  );
}

function LangTabs({
  lang,
  onChange,
}: {
  lang: SnippetLang;
  onChange: (l: SnippetLang) => void;
}) {
  return (
    <div className="flex items-center gap-1 mb-3">
      {SNIPPET_LANGS.map((l) => (
        <button
          key={l}
          type="button"
          aria-pressed={lang === l}
          onClick={() => onChange(l)}
          className={`px-3 py-1.5 text-sm rounded transition-colors duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
            lang === l
              ? "text-[var(--text-primary)] bg-[var(--bg-elevated)]"
              : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
          }`}
        >
          {LANG_LABELS[l]}
        </button>
      ))}
    </div>
  );
}

export default function WelcomePage() {
  const t = useTranslations("welcome");
  const tc = useTranslations("common");
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [sessionError, setSessionError] = useState(false);
  const [lang, setLang] = useState<SnippetLang>("python");
  const [firstEvent, setFirstEvent] = useState<ActivityCall | null>(null);

  // Step 1 — who is logged in (same source the auth layer exposes).
  useEffect(() => {
    fetch("/api/auth/session", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((data: { operator?: string }) => {
        setSession({
          operator: data.operator ?? "?",
          tenant: currentTenant(),
        });
      })
      .catch(() => setSessionError(true));
  }, []);

  // Step 4 — poll the activity endpoint every 3s until the first event shows.
  useEffect(() => {
    if (firstEvent) return;
    let cancelled = false;
    async function poll() {
      const result = await fetchActivity({ limit: 1 });
      if (!cancelled && result.ok && result.data.length > 0) {
        setFirstEvent(result.data[0]);
      }
    }
    void poll();
    const interval = setInterval(poll, 3000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [firstEvent]);

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="space-y-3">
        <Step n={1} title={t("step1Title")} defaultOpen>
          <p className="text-sm text-[var(--text-muted)] mb-3">{t("step1Body")}</p>
          {sessionError ? (
            <p className="text-sm text-[var(--status-stopped)]">{t("step1Error")}</p>
          ) : !session ? (
            <p className="text-sm text-[var(--text-muted)]">{t("step1Loading")}</p>
          ) : (
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm">
              <dt className="text-[var(--text-muted)]">{t("step1Operator")}</dt>
              <dd className="font-mono text-[var(--text-primary)]">{session.operator}</dd>
              <dt className="text-[var(--text-muted)]">{t("step1Tenant")}</dt>
              <dd className="font-mono text-[var(--text-primary)]">{session.tenant}</dd>
            </dl>
          )}
        </Step>

        <Step n={2} title={t("step2Title")}>
          <p className="text-sm text-[var(--text-muted)] mb-3">{t("step2Body")}</p>
          <LangTabs lang={lang} onChange={setLang} />
          <div className="flex items-start gap-3">
            <div className="flex-1 min-w-0">
              <CodeBlock code={INSTALL_SNIPPETS[lang]} />
            </div>
            <CopyButton
              text={INSTALL_SNIPPETS[lang]}
              label={tc("copy")}
              copiedLabel={tc("copied")}
            />
          </div>
        </Step>

        <Step n={3} title={t("step3Title")}>
          <p className="text-sm text-[var(--text-muted)] mb-3">{t("step3Body")}</p>
          <LangTabs lang={lang} onChange={setLang} />
          <div className="flex items-start gap-3">
            <div className="flex-1 min-w-0">
              <CodeBlock code={REGISTER_SNIPPETS[lang]} />
            </div>
            <CopyButton
              text={REGISTER_SNIPPETS[lang]}
              label={tc("copy")}
              copiedLabel={tc("copied")}
            />
          </div>
        </Step>

        <Step n={4} title={t("step4Title")}>
          <div aria-live="polite">
            {firstEvent ? (
              <div>
                <p className="text-sm text-[var(--status-ok)] mb-3">
                  {t("step4Received")}
                </p>
                <div className="bg-[var(--bg-elevated)] rounded p-4 flex items-center gap-4 text-sm">
                  <Badge variant={firstEvent.result === "allowed" ? "ok" : "stopped"}>
                    {firstEvent.result}
                  </Badge>
                  <span className="text-[var(--text-primary)]">
                    {firstEvent.agent_name}
                  </span>
                  <span className="font-mono text-xs text-[var(--text-secondary)]">
                    {firstEvent.action}
                  </span>
                  <span className="text-mono-sm text-[var(--text-muted)] ml-auto">
                    {fmtRelativeTime(firstEvent.timestamp)}
                  </span>
                </div>
                <Link
                  href="/activity"
                  className="inline-block mt-3 text-sm text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors duration-150"
                >
                  {t("step4GoActivity")} →
                </Link>
              </div>
            ) : (
              <p className="text-sm text-[var(--text-muted)] flex items-center gap-2">
                <span className="inline-block w-2 h-2 rounded-full bg-[var(--status-warning)] animate-pulse-calm" />
                {t("step4Waiting")}
              </p>
            )}
          </div>
        </Step>
      </div>
    </PageShell>
  );
}
