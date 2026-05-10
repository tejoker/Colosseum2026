"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";

export const API      = process.env.NEXT_PUBLIC_API_URL      || "http://localhost:3001";
export const DASH_API = process.env.NEXT_PUBLIC_DASH_API_URL || "http://localhost:8002";

// ── Types ─────────────────────────────────────────────────────────────────────
export interface LiveStats {
  total_users:   number;
  total_clients: number;
}

export interface LiveClient {
  name:           string;
  public_key_hex: string;
  key_image_hex:  string;
  client_type:    string;
}

export interface LiveUser {
  key_image_hex: string;
  first_name:    string;
  last_name:     string;
  nationality:   string;
}

// ── Context ───────────────────────────────────────────────────────────────────
// SauronID-native counters (replace banking-era token A/B fields).
export interface AgentCounters {
  agents_total:       number;   // sum of all rows in agents
  agents_active:      number;   // not revoked, not expired
  receipts_total:     number;   // rows in agent_action_receipts
  anchor_batches:     number;   // rows in agent_action_anchors
}

interface DashContextType {
  stats:     LiveStats | null;
  counters:  AgentCounters | null;
  clients:   LiveClient[];
  users:     LiveUser[];
  offline:   boolean;
  loading:   boolean;
  refresh:   () => Promise<void>;
}

const DashContext = createContext<DashContextType | null>(null);

export function DashProvider({ children }: { children: React.ReactNode }) {
  const [stats,    setStats]    = useState<LiveStats | null>(null);
  const [counters, setCounters] = useState<AgentCounters | null>(null);
  const [clients,  setClients]  = useState<LiveClient[]>([]);
  const [users,    setUsers]    = useState<LiveUser[]>([]);
  const [offline,  setOffline]  = useState(false);
  const [loading,  setLoading]  = useState(true);

  const refresh = useCallback(async () => {
    try {
      const [sRes, cRes, uRes, agentsRes, anchorRes, actionsRes] = await Promise.all([
        fetch(`/api/admin/stats`),
        fetch(`/api/admin/clients`),
        fetch(`/api/admin/users`),
        fetch(`${DASH_API}/api/live/agents`).catch(() => null),
        fetch(`${DASH_API}/api/live/anchor/status`).catch(() => null),
        fetch(`${DASH_API}/api/live/agent_actions/recent?limit=1000`).catch(() => null),
      ]);
      if (sRes.ok)  setStats(await sRes.json());
      if (cRes.ok)  setClients(await cRes.json());
      if (uRes.ok)  setUsers(await uRes.json());

      // SauronID counters from live admin endpoints
      const nowSec = Math.floor(Date.now() / 1000);
      let agents_total = 0, agents_active = 0;
      if (agentsRes && agentsRes.ok) {
        const list = (await agentsRes.json()) as Array<{
          revoked: boolean;
          expires_at: number;
        }>;
        agents_total = list.length;
        agents_active = list.filter((a) => !a.revoked && a.expires_at > nowSec).length;
      }
      let anchor_batches = 0;
      if (anchorRes && anchorRes.ok) {
        const a = await anchorRes.json();
        anchor_batches = a.agent_action_batches ?? 0;
      }
      let receipts_total = 0;
      if (actionsRes && actionsRes.ok) {
        const list = await actionsRes.json();
        receipts_total = Array.isArray(list) ? list.length : 0;
      }
      setCounters({ agents_total, agents_active, receipts_total, anchor_batches });

      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10_000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <DashContext.Provider value={{ stats, counters, clients, users, offline, loading, refresh }}>
      {children}
    </DashContext.Provider>
  );
}

export function useDash() {
  const ctx = useContext(DashContext);
  if (!ctx) throw new Error("useDash must be inside DashProvider");
  return ctx;
}
