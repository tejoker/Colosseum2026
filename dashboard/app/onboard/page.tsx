"use client";

// Provision page — self-serve onboarding (backlog: "self-serve onboarding").
//
// Three cards, three provisioning actions, zero env editing for keys:
//   1. Tenant       — registers the name for the switcher; tenants become
//                     real on first use (the core has no tenant CRUD yet).
//   2. SDK key      — mints a scoped, tenant-locked admin JWT via the core
//                     (POST /admin/keys/issue, super operators only).
//   3. Operator     — generates the SAURON_DASHBOARD_OPERATORS JSON fragment
//                     (runtime creation is impossible without persistence).
// Secrets are shown once with copy-to-clipboard; nothing is stored.

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { PageShell } from "@/components/layout/PageShell";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { currentTenant } from "@/lib/tenant";

const INPUT_CLASS =
  "px-3 py-2 text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded " +
  "text-[var(--text-primary)] placeholder:text-[var(--text-muted)] " +
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] " +
  "focus:border-[var(--border-hover)] transition-colors duration-150 ease-out w-full";

const TTL_CHOICES = [
  { label: "1h", secs: 3600 },
  { label: "24h", secs: 86_400 },
  { label: "7d", secs: 7 * 86_400 },
  { label: "30d", secs: 30 * 86_400 },
  { label: "90d", secs: 90 * 86_400 },
] as const;

/** Parse the error envelope of a failed provisioning call into one line. */
async function errorLine(r: Response): Promise<string> {
  try {
    const data = (await r.json()) as {
      error?: string | { message?: string; fix?: string };
    };
    if (typeof data.error === "string") return data.error;
    if (data.error?.message) {
      return data.error.fix
        ? `${data.error.message} — ${data.error.fix}`
        : data.error.message;
    }
  } catch {
    // fall through
  }
  return `HTTP ${r.status}`;
}

function SecretBlock({ value, copyLabel, copiedLabel }: { value: string; copyLabel: string; copiedLabel: string }) {
  return (
    <div className="flex items-start gap-3">
      <pre className="flex-1 min-w-0 bg-[var(--bg-elevated)] rounded p-3 overflow-x-auto text-xs leading-relaxed font-mono text-[var(--text-secondary)] whitespace-pre-wrap break-all">
        <code>{value}</code>
      </pre>
      <CopyButton text={value} label={copyLabel} copiedLabel={copiedLabel} />
    </div>
  );
}

function TenantCard({ isSuper }: { isSuper: boolean }) {
  const t = useTranslations("onboard");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setCreated(null);
    try {
      const r = await fetch("/api/tenants", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: name.trim() }),
      });
      if (!r.ok) {
        setError(await errorLine(r));
        return;
      }
      setCreated(name.trim());
      setName("");
    } catch {
      setError(t("networkError"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card as="section">
      <CardHeader>
        <h2 className="text-sm font-medium text-[var(--text-primary)]">{t("tenantTitle")}</h2>
      </CardHeader>
      <CardBody>
        <p className="text-sm text-[var(--text-muted)] mb-4">{t("tenantBody")}</p>
        <form onSubmit={submit} className="grid gap-3">
          <div className="grid gap-1.5">
            <label htmlFor="tenant-name" className="text-sm text-[var(--text-secondary)]">
              {t("tenantName")}
            </label>
            <input
              id="tenant-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              pattern="[A-Za-z0-9_\-]{1,64}"
              placeholder="acme-corp"
              required
              className={INPUT_CLASS}
              aria-describedby="tenant-hint"
            />
          </div>
          <p id="tenant-hint" className="text-xs text-[var(--text-muted)] m-0">
            {t("tenantHint")}
          </p>
          <div>
            <Button type="submit" size="sm" disabled={busy || !isSuper}>
              {t("tenantCreate")}
            </Button>
          </div>
        </form>
        {!isSuper && (
          <p className="text-xs text-[var(--status-warning)] mt-3">{t("superOnly")}</p>
        )}
        <p role="status" aria-live="polite" className="text-sm mt-3 m-0">
          {error && <span className="text-[var(--status-stopped)]">{error}</span>}
          {created && (
            <span className="text-[var(--status-ok)]">
              {t("tenantCreated", { name: created })}
            </span>
          )}
        </p>
      </CardBody>
    </Card>
  );
}

interface IssuedKey {
  token: string;
  scopes: string[];
  tenants: string[];
  expires_at: number;
}

function SdkKeyCard({ isSuper }: { isSuper: boolean }) {
  const t = useTranslations("onboard");
  const tc = useTranslations("common");
  const [write, setWrite] = useState(false);
  const [tenants, setTenants] = useState("");
  const [ttl, setTtl] = useState<number>(86_400);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<IssuedKey | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setTenants(currentTenant());
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setIssued(null);
    try {
      const r = await fetch("/api/keys/issue", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          scopes: write ? ["admin:read", "admin:write"] : ["admin:read"],
          tenants: tenants
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          ttl_secs: ttl,
        }),
      });
      if (!r.ok) {
        setError(await errorLine(r));
        return;
      }
      setIssued((await r.json()) as IssuedKey);
    } catch {
      setError(t("networkError"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card as="section">
      <CardHeader>
        <h2 className="text-sm font-medium text-[var(--text-primary)]">{t("keyTitle")}</h2>
      </CardHeader>
      <CardBody>
        <p className="text-sm text-[var(--text-muted)] mb-4">{t("keyBody")}</p>
        <form onSubmit={submit} className="grid gap-3">
          <fieldset className="grid gap-1.5 border-0 p-0 m-0">
            <legend className="text-sm text-[var(--text-secondary)] mb-1.5 p-0">
              {t("keyScopes")}
            </legend>
            <label className="flex items-center gap-2 text-sm text-[var(--text-primary)]">
              <input
                type="radio"
                name="key-scope"
                checked={!write}
                onChange={() => setWrite(false)}
              />
              {t("keyScopeRead")}
            </label>
            <label className="flex items-center gap-2 text-sm text-[var(--text-primary)]">
              <input
                type="radio"
                name="key-scope"
                checked={write}
                onChange={() => setWrite(true)}
              />
              {t("keyScopeReadWrite")}
            </label>
          </fieldset>
          <div className="grid gap-1.5">
            <label htmlFor="key-tenants" className="text-sm text-[var(--text-secondary)]">
              {t("keyTenants")}
            </label>
            <input
              id="key-tenants"
              value={tenants}
              onChange={(e) => setTenants(e.target.value)}
              required
              className={INPUT_CLASS}
            />
          </div>
          <div className="grid gap-1.5">
            <label htmlFor="key-ttl" className="text-sm text-[var(--text-secondary)]">
              {t("keyTtl")}
            </label>
            <select
              id="key-ttl"
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
              className={INPUT_CLASS}
            >
              {TTL_CHOICES.map((c) => (
                <option key={c.secs} value={c.secs}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <Button type="submit" size="sm" disabled={busy || !isSuper}>
              {busy ? t("keyIssuing") : t("keyIssue")}
            </Button>
          </div>
        </form>
        {!isSuper && (
          <p className="text-xs text-[var(--status-warning)] mt-3">{t("superOnly")}</p>
        )}
        <div role="status" aria-live="polite" className="mt-3">
          {error && <p className="text-sm text-[var(--status-stopped)] m-0">{error}</p>}
          {issued && (
            <div className="grid gap-2">
              <p className="text-sm text-[var(--status-warning)] m-0">{t("shownOnce")}</p>
              <SecretBlock
                value={issued.token}
                copyLabel={tc("copy")}
                copiedLabel={tc("copied")}
              />
              <p className="text-xs text-[var(--text-muted)] m-0">
                {t("keyExpires")}:{" "}
                <span className="font-mono">
                  {new Date(issued.expires_at * 1000).toISOString()}
                </span>{" "}
                — {issued.scopes.join(", ")} — {issued.tenants.join(", ")}
              </p>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
}

function OperatorCard() {
  const t = useTranslations("onboard");
  const tc = useTranslations("common");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [tenants, setTenants] = useState("");
  const [isSuper, setIsSuper] = useState(false);
  const [busy, setBusy] = useState(false);
  const [fragment, setFragment] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setTenants(currentTenant());
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setFragment(null);
    try {
      const r = await fetch("/api/operators/generate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          password,
          tenants: tenants
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          super: isSuper,
        }),
      });
      if (!r.ok) {
        setError(await errorLine(r));
        return;
      }
      const data = (await r.json()) as { fragment: string };
      setFragment(data.fragment);
      setPassword("");
    } catch {
      setError(t("networkError"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card as="section">
      <CardHeader>
        <h2 className="text-sm font-medium text-[var(--text-primary)]">{t("opTitle")}</h2>
      </CardHeader>
      <CardBody>
        <p className="text-sm text-[var(--text-muted)] mb-4">{t("opBody")}</p>
        <form onSubmit={submit} className="grid gap-3">
          <div className="grid gap-1.5">
            <label htmlFor="op-name" className="text-sm text-[var(--text-secondary)]">
              {t("opName")}
            </label>
            <input
              id="op-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              pattern="[A-Za-z0-9_\-]{1,64}"
              autoComplete="off"
              required
              className={INPUT_CLASS}
            />
          </div>
          <div className="grid gap-1.5">
            <label htmlFor="op-password" className="text-sm text-[var(--text-secondary)]">
              {t("opPassword")}
            </label>
            <input
              id="op-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={12}
              autoComplete="new-password"
              required
              className={INPUT_CLASS}
            />
          </div>
          <div className="grid gap-1.5">
            <label htmlFor="op-tenants" className="text-sm text-[var(--text-secondary)]">
              {t("opTenants")}
            </label>
            <input
              id="op-tenants"
              value={tenants}
              onChange={(e) => setTenants(e.target.value)}
              disabled={isSuper}
              className={INPUT_CLASS}
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-[var(--text-primary)]">
            <input
              type="checkbox"
              checked={isSuper}
              onChange={(e) => setIsSuper(e.target.checked)}
            />
            {t("opSuper")}
          </label>
          <div>
            <Button type="submit" size="sm" disabled={busy}>
              {busy ? t("opGenerating") : t("opGenerate")}
            </Button>
          </div>
        </form>
        <div role="status" aria-live="polite" className="mt-3">
          {error && <p className="text-sm text-[var(--status-stopped)] m-0">{error}</p>}
          {fragment && (
            <div className="grid gap-2">
              <p className="text-sm text-[var(--status-warning)] m-0">{t("shownOnce")}</p>
              <SecretBlock
                value={fragment}
                copyLabel={tc("copy")}
                copiedLabel={tc("copied")}
              />
              <p className="text-xs text-[var(--text-muted)] m-0">{t("opPasteHint")}</p>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
}

export default function OnboardPage() {
  const t = useTranslations("onboard");
  const [sessionSuper, setSessionSuper] = useState(false);

  useEffect(() => {
    fetch("/api/auth/session", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((data: { super?: boolean }) => setSessionSuper(data.super === true))
      .catch(() => setSessionSuper(false));
  }, []);

  return (
    <PageShell title={t("title")} subtitle={t("subtitle")}>
      <div className="grid gap-4 lg:grid-cols-3 items-start">
        <TenantCard isSuper={sessionSuper} />
        <SdkKeyCard isSuper={sessionSuper} />
        <OperatorCard />
      </div>
    </PageShell>
  );
}
