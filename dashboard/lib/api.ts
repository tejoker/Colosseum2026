// All public fetchers hit the SAME-ORIGIN Next.js /api/* surface. The dashboard's
// /api routes proxy to the SauronID core /admin/* surface server-side. The
// browser never knows the core URL — no CORS, no env leakage.

/* ── Types ─────────────────────────────────────────────────────────── */

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

export interface AgentStatus {
  id: string;
  name: string;
  agent_type: string;
  status: "active" | "idle" | "revoked";
  registered_at: string;
  last_call_at: string | null;
  total_calls: number;
  config_digest: string;
  allowed_intents: string[];
}

export interface ProtectedEvent {
  id: string;
  agent_id: string;
  agent_name: string;
  reason: string;
  reason_code: "replay" | "scope" | "signature" | "nonce" | "revoked" | "expired";
  timestamp: string;
  detail: Record<string, unknown>;
}

export interface ActivityCall {
  id: string;
  agent_id: string;
  agent_name: string;
  action: string;
  intent: string;
  result: "allowed" | "stopped";
  latency_ms: number;
  timestamp: string;
  detail: {
    body_hash?: string;
    nonce?: string;
    jti?: string;
    dpop_binding?: string;
  };
}

export interface AnchorStats {
  bitcoin_total: number;
  bitcoin_pending: number;
  bitcoin_confirmed: number;
  bitcoin_last_batch_at: string | null;
  solana_total: number;
  solana_unconfirmed: number;
  solana_confirmed: number;
  solana_last_batch_at: string | null;
  agent_action_batches: number;
}

export interface OverviewStats {
  total_agents: number;
  active_agents: number;
  calls_today: number;
  protected_today: number;
}

export interface Company {
  id: string;
  name: string;
  created_at: string;
  agent_count: number;
}

export interface Person {
  id: string;
  name: string;
  email: string;
  company_id: string;
  company_name: string;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  agent_id: string;
  event_type: "call" | "mandate_check" | "config_change" | "revocation" | "registration";
  result: "allowed" | "stopped" | "info";
  timestamp: string;
  anchor_id: string | null;
  anchor_chain: "bitcoin" | "solana" | null;
  anchor_ref: string | null;
  detail: Record<string, unknown>;
}

export interface SystemHealth {
  core_reachable: boolean;
  last_seen_at: string | null;
  agent_count: number;
}

/* ── Fetch helpers ─────────────────────────────────────────────────── */

// Server-side fetches (Server Components, route handlers) need absolute URLs.
// Browser fetches use relative URLs (same-origin proxy).
function absolutize(path: string): string {
  if (typeof window !== "undefined") return path; // browser: relative is fine
  const port = process.env.PORT ?? "3000";
  return `http://127.0.0.1:${port}${path}`;
}

async function get<T>(url: string): Promise<ApiResult<T>> {
  try {
    const res = await fetch(absolutize(url), { next: { revalidate: 10 } });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as T;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── Public API functions (all same-origin) ────────────────────────── */

export async function fetchOverview(): Promise<ApiResult<OverviewStats>> {
  return get<OverviewStats>(`/api/overview`);
}

export async function fetchAgents(): Promise<ApiResult<AgentStatus[]>> {
  return get<AgentStatus[]>(`/api/agents`);
}

export async function fetchAgent(id: string): Promise<ApiResult<AgentStatus>> {
  return get<AgentStatus>(`/api/agents/${id}`);
}

export async function fetchAgentAudit(
  id: string,
  params?: { from?: string; to?: string }
): Promise<ApiResult<AuditEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.from) qs.set("from", params.from);
  if (params?.to) qs.set("to", params.to);
  const query = qs.toString() ? `?${qs}` : "";
  return get<AuditEvent[]>(`/api/agents/${id}/audit${query}`);
}

export async function fetchProtected(params?: {
  limit?: number;
}): Promise<ApiResult<ProtectedEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ProtectedEvent[]>(`/api/protected${query}`);
}

export async function fetchActivity(params?: {
  filter?: "all" | "allowed" | "stopped";
  agent_id?: string;
  limit?: number;
}): Promise<ApiResult<ActivityCall[]>> {
  const qs = new URLSearchParams();
  if (params?.filter && params.filter !== "all") qs.set("result", params.filter);
  if (params?.agent_id) qs.set("agent_id", params.agent_id);
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ActivityCall[]>(`/api/activity${query}`);
}

export async function fetchProofs(): Promise<ApiResult<AnchorStats>> {
  return get<AnchorStats>(`/api/proofs`);
}

export async function fetchCompanies(): Promise<ApiResult<Company[]>> {
  return get<Company[]>(`/api/clients`);
}

export async function fetchCompany(id: string): Promise<ApiResult<Company>> {
  return get<Company>(`/api/clients/${id}`);
}

export async function fetchPeople(): Promise<ApiResult<Person[]>> {
  return get<Person[]>(`/api/users`);
}

export async function fetchCompanyPeople(companyId: string): Promise<ApiResult<Person[]>> {
  return get<Person[]>(`/api/users?company_id=${encodeURIComponent(companyId)}`);
}

export async function fetchHealth(): Promise<ApiResult<SystemHealth>> {
  return get<SystemHealth>(`/api/health`);
}

export async function revokeAgent(id: string): Promise<ApiResult<{ revoked: true }>> {
  try {
    const res = await fetch(absolutize(`/api/agents/${id}/revoke`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    return { ok: true, data: { revoked: true } };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}
