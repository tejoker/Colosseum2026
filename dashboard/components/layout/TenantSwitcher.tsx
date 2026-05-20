"use client";

// TenantSwitcher — dropdown of known tenant ids next to the user avatar.
//
// On mount we resolve the active tenant from the cookie/localStorage and
// fetch the list of available tenants from `/api/tenants`. Selecting an
// entry persists the choice via `setCurrentTenant`, which also dispatches
// the `sauron:tenant-changed` event; we then `router.refresh()` so RSCs
// re-render with the new tenant header forwarded by the middleware.

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  availableTenants,
  currentTenant,
  DEFAULT_TENANT,
  setCurrentTenant,
} from "@/lib/tenant";

export function TenantSwitcher() {
  const router = useRouter();
  const [active, setActive] = useState<string>(DEFAULT_TENANT);
  const [tenants, setTenants] = useState<string[]>([DEFAULT_TENANT]);
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  // Hydrate active id once on mount (cookie/localStorage are browser-only).
  useEffect(() => {
    setActive(currentTenant());
    void availableTenants().then((list) => {
      if (list.length > 0) setTenants(list);
    });
  }, []);

  // Close the dropdown on outside-click.
  useEffect(() => {
    if (!open) return;
    function onClick(ev: MouseEvent) {
      if (!wrapRef.current) return;
      if (!wrapRef.current.contains(ev.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  function pick(id: string) {
    setOpen(false);
    if (id === active) return;
    setCurrentTenant(id);
    setActive(id);
    // RSC + route handlers read the cookie via middleware → refresh.
    router.refresh();
  }

  return (
    <div ref={wrapRef} className="relative">
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label="Switch tenant"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 px-2 py-1 text-xs font-mono rounded border border-[var(--border)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors"
        data-testid="tenant-switcher-button"
      >
        <span className="text-[var(--text-muted)] uppercase tracking-wide">tenant</span>
        <span className="text-[var(--text-primary)] truncate max-w-[10rem]">{active}</span>
        <svg
          aria-hidden
          viewBox="0 0 12 12"
          className="h-2.5 w-2.5 opacity-70"
          fill="currentColor"
        >
          <path d="M2 4l4 4 4-4z" />
        </svg>
      </button>

      {open && (
        <ul
          role="listbox"
          aria-label="Available tenants"
          className="absolute right-0 mt-1 min-w-[14rem] max-h-72 overflow-y-auto z-50 rounded border border-[var(--border)] bg-[var(--bg)] shadow-lg"
          data-testid="tenant-switcher-menu"
        >
          {tenants.map((id) => {
            const isActive = id === active;
            return (
              <li key={id} role="option" aria-selected={isActive}>
                <button
                  type="button"
                  onClick={() => pick(id)}
                  className={`w-full text-left px-3 py-1.5 text-xs font-mono flex items-center justify-between gap-2 hover:bg-[var(--bg-surface)] ${
                    isActive
                      ? "text-[var(--accent)]"
                      : "text-[var(--text-secondary)]"
                  }`}
                >
                  <span className="truncate">{id}</span>
                  {isActive && (
                    <span aria-hidden className="text-[var(--accent)]">
                      ✓
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
