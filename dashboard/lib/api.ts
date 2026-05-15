const CORE_URL =
  process.env.NEXT_PUBLIC_CORE_URL ?? "http://localhost:3001";
const DASH_URL =
  process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002";

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

async function get<T>(url: string): Promise<ApiResult<T>> {
  try {
    const res = await fetch(url, { next: { revalidate: 10 } });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}` };
    }
    const data = await res.json() as T;
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

/* ── Public API functions ──────────────────────────────────────────── */

export async function fetchOverview(): Promise<ApiResult<OverviewStats>> {
  return get<OverviewStats>(`${DASH_URL}/api/live/overview`);
}

export async function fetchAgents(): Promise<ApiResult<AgentStatus[]>> {
  return get<AgentStatus[]>(`${DASH_URL}/api/live/agents`);
}

export async function fetchAgent(id: string): Promise<ApiResult<AgentStatus>> {
  return get<AgentStatus>(`${DASH_URL}/api/live/agents/${id}`);
}

export async function fetchAgentAudit(
  id: string,
  params?: { from?: string; to?: string }
): Promise<ApiResult<AuditEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.from) qs.set("from", params.from);
  if (params?.to) qs.set("to", params.to);
  const query = qs.toString() ? `?${qs}` : "";
  return get<AuditEvent[]>(`${DASH_URL}/api/live/agents/${id}/audit${query}`);
}

export async function fetchProtected(params?: {
  limit?: number;
}): Promise<ApiResult<ProtectedEvent[]>> {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString() ? `?${qs}` : "";
  return get<ProtectedEvent[]>(`${DASH_URL}/api/live/protected${query}`);
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
  return get<ActivityCall[]>(`${DASH_URL}/api/live/activity${query}`);
}

export async function fetchProofs(): Promise<ApiResult<AnchorStats>> {
  return get<AnchorStats>(`${DASH_URL}/api/live/anchors`);
}

export async function fetchCompanies(): Promise<ApiResult<Company[]>> {
  return get<Company[]>(`${DASH_URL}/api/live/clients`);
}

export async function fetchPeople(): Promise<ApiResult<Person[]>> {
  return get<Person[]>(`${DASH_URL}/api/live/users`);
}

export async function fetchHealth(): Promise<ApiResult<SystemHealth>> {
  return get<SystemHealth>(`${DASH_URL}/api/live/health`);
}

export async function revokeAgent(id: string): Promise<ApiResult<{ revoked: true }>> {
  try {
    const res = await fetch(`${CORE_URL}/api/v1/agents/${id}/revoke`, {
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
