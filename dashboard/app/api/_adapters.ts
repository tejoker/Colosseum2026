// Shape adapters: core /admin/* response → dashboard TypeScript interfaces.
//
// The core returns SQL rows (snake_case, unix epoch seconds, no UI niceties).
// The dashboard expects ISO timestamps, agent display names, etc. Adapt here
// so the rest of the dashboard can stay shape-agnostic.

import type {
  ActivityCall,
  AgentStatus,
  AnchorStats,
  AuditEvent,
  Company,
  OverviewStats,
  Person,
  ProtectedEvent,
  SystemHealth,
} from "@/lib/api";

/* ── Core record shapes (mirror of admin.rs structs) ──────────────── */

export interface CoreAgentRecord {
  agent_id: string;
  human_key_image: string;
  agent_checksum: string;
  assurance_level: string;
  issued_at: number; // unix secs
  expires_at: number; // unix secs
  revoked: boolean;
  has_pop: boolean;
  agent_type: string;
}

export interface CoreActionReceipt {
  receipt_id: string;
  action_hash: string;
  agent_id: string;
  status: string;
  policy_version: string;
  created_at: number;
}

export interface CoreAnchorStatus {
  bitcoin_total: number;
  bitcoin_pending_upgrade: number;
  bitcoin_upgraded: number;
  solana_total: number;
  solana_unconfirmed: number;
  solana_confirmed: number;
  agent_action_batches: number;
  last_batch_at: number;
  last_batch_n_actions: number;
}

export interface CoreClientRecord {
  name: string;
  public_key_hex: string;
  key_image_hex: string;
  tokens_b: number;
  client_type: string;
}

export interface CoreUserRecord {
  key_image_hex: string;
  first_name: string;
  last_name: string;
  nationality: string;
}

export interface CorePerAgentMetric {
  agent_id: string;
  action_count: number;
  egress_count: number;
  last_action_at: number;
}

export interface CoreHealthResponse {
  ok: boolean;
  runtime: string;
  database: { ok: boolean; detail: string };
}

/* ── Helpers ──────────────────────────────────────────────────────── */

function epochToIso(ts: number | null | undefined): string {
  if (!ts || ts <= 0) return new Date(0).toISOString();
  // Core uses unix seconds; JS Date wants ms.
  return new Date(ts * 1000).toISOString();
}

function epochToIsoNullable(ts: number | null | undefined): string | null {
  if (!ts || ts <= 0) return null;
  return new Date(ts * 1000).toISOString();
}

function shortId(id: string, len = 8): string {
  if (id.length <= len * 2 + 2) return id;
  return `${id.slice(0, len)}…${id.slice(-len)}`;
}

function agentDisplayName(r: CoreAgentRecord): string {
  const type = r.agent_type?.trim() || "agent";
  return `${type}-${shortId(r.agent_id, 6)}`;
}

function statusFromAgent(r: CoreAgentRecord, lastActionAt: number | null): AgentStatus["status"] {
  if (r.revoked) return "revoked";
  const now = Math.floor(Date.now() / 1000);
  if (lastActionAt && now - lastActionAt < 60 * 30) return "active";
  return "idle";
}

/* ── Adapters ─────────────────────────────────────────────────────── */

export function adaptAgent(
  r: CoreAgentRecord,
  metricsById: Map<string, CorePerAgentMetric>
): AgentStatus {
  const m = metricsById.get(r.agent_id);
  return {
    id: r.agent_id,
    name: agentDisplayName(r),
    agent_type: r.agent_type || "",
    status: statusFromAgent(r, m?.last_action_at ?? null),
    registered_at: epochToIso(r.issued_at),
    last_call_at: m?.last_action_at ? epochToIsoNullable(m.last_action_at) : null,
    total_calls: m?.action_count ?? 0,
    config_digest: r.agent_checksum || "",
    allowed_intents: [], // not exposed by /admin/agents — empty array preserves UI
  };
}

export function adaptAgents(
  agents: CoreAgentRecord[],
  metrics: CorePerAgentMetric[]
): AgentStatus[] {
  const m = new Map<string, CorePerAgentMetric>();
  for (const x of metrics) m.set(x.agent_id, x);
  return agents.map((a) => adaptAgent(a, m));
}

/** A REAL outbound call an agent made — from /admin/egress/recent. */
export interface CoreEgressRow {
  id: number;
  agent_id: string;
  target_host: string;
  target_path: string;
  method: string;
  status_code: number;
  ts: number;
  allowed?: boolean;
}

/** Adapt real agent egress into the Activity feed shape (live monitor). */
export function adaptEgress(
  rows: CoreEgressRow[],
  agentNameById: Map<string, string>
): ActivityCall[] {
  return rows.map((e) => ({
    id: `egr_${e.id}`,
    agent_id: e.agent_id,
    agent_name: agentNameById.get(e.agent_id) ?? e.agent_id,
    action: `${e.method} ${e.target_host}${e.target_path ?? ""}`,
    intent: e.target_host,
    result: e.allowed === false ? "stopped" : "allowed",
    latency_ms: 0,
    timestamp: epochToIso(e.ts),
    detail: {},
  }));
}

export function adaptActivity(
  receipts: CoreActionReceipt[],
  agentNameById: Map<string, string>
): ActivityCall[] {
  return receipts.map((r) => {
    const result: ActivityCall["result"] =
      r.status?.toLowerCase() === "ok" || r.status?.toLowerCase() === "allowed"
        ? "allowed"
        : "stopped";
    return {
      id: r.receipt_id,
      agent_id: r.agent_id,
      agent_name: agentNameById.get(r.agent_id) ?? r.agent_id,
      action: r.action_hash,
      intent: r.policy_version || "",
      result,
      latency_ms: 0, // core does not record per-call latency at this layer
      timestamp: epochToIso(r.created_at),
      detail: {},
    };
  });
}

/**
 * The "Protected" feed = governance stops that ACTUALLY happened. The only
 * genuine stops in the live system are blocked agent calls — egress attempts
 * the core REJECTED (allowed = false): a replayed nonce (409), a tampered body
 * or revoked agent (401/403). We read those directly, so every row is a real
 * rejection the core made, never an accepted action mislabeled as blocked.
 */
export function adaptProtected(
  rows: CoreEgressRow[],
  agentNameById: Map<string, string>
): ProtectedEvent[] {
  return rows
    .filter((e) => e.allowed === false)
    .map((e) => ({
      id: `egr_${e.id}`,
      agent_id: e.agent_id,
      agent_name: agentNameById.get(e.agent_id) ?? e.agent_id,
      reason: `HTTP ${e.status_code}`,
      reason_code: mapEgressReason(e.status_code, e.target_path),
      timestamp: epochToIso(e.ts),
      detail: {
        method: e.method,
        target: `${e.target_host}${e.target_path ?? ""}`,
        status_code: e.status_code,
      },
    }));
}

function mapEgressReason(
  statusCode: number,
  path: string | undefined
): ProtectedEvent["reason_code"] {
  const p = (path ?? "").toLowerCase();
  if (p.includes("revoke")) return "revoked";
  if (statusCode === 409) return "replay";
  if (statusCode === 401 || statusCode === 403) return "signature";
  return "scope";
}

export function adaptAuditEvents(
  receipts: CoreActionReceipt[]
): AuditEvent[] {
  return receipts.map((r) => {
    const s = r.status?.toLowerCase();
    const result: AuditEvent["result"] =
      s === "ok" || s === "allowed" ? "allowed" : "stopped";
    return {
      id: r.receipt_id,
      agent_id: r.agent_id,
      event_type: "call",
      result,
      timestamp: epochToIso(r.created_at),
      anchor_id: null,
      anchor_chain: null,
      anchor_ref: null,
      detail: { action_hash: r.action_hash, policy_version: r.policy_version, status: r.status },
    };
  });
}

export function adaptAnchorStats(s: CoreAnchorStatus): AnchorStats {
  return {
    bitcoin_total: s.bitcoin_total,
    bitcoin_pending: s.bitcoin_pending_upgrade,
    bitcoin_confirmed: s.bitcoin_upgraded,
    bitcoin_last_batch_at: epochToIsoNullable(s.last_batch_at),
    solana_total: s.solana_total,
    solana_unconfirmed: s.solana_unconfirmed,
    solana_confirmed: s.solana_confirmed,
    solana_last_batch_at: epochToIsoNullable(s.last_batch_at),
    agent_action_batches: s.agent_action_batches,
  };
}

export function adaptCompanies(
  clients: CoreClientRecord[],
  agentCountByClient?: Map<string, number>
): Company[] {
  return clients.map((c) => ({
    id: c.key_image_hex || c.name,
    name: c.name,
    created_at: new Date(0).toISOString(),
    agent_count: agentCountByClient?.get(c.key_image_hex) ?? 0,
  }));
}

export function adaptPeople(users: CoreUserRecord[]): Person[] {
  return users.map((u) => ({
    id: u.key_image_hex,
    name: `${u.first_name} ${u.last_name}`.trim(),
    email: "",
    company_id: "",
    company_name: "",
    created_at: new Date(0).toISOString(),
  }));
}

export function adaptHealth(h: CoreHealthResponse, agentCount: number): SystemHealth {
  // The core's top-level `ok` is false whenever ANY operator warning is set
  // (e.g. Solana disabled in dev), which is too strict for the UI's
  // "core_reachable" badge. We treat the core as reachable iff the DB
  // round-trip succeeded — that's what the dashboard actually cares about.
  const reachable = Boolean(h?.database?.ok ?? h?.ok ?? false);
  return {
    core_reachable: reachable,
    last_seen_at: new Date().toISOString(),
    agent_count: agentCount,
  };
}

/**
 * Home counters, derived from REAL agent egress (the same source as Activity).
 * `calls_today` = outbound calls the agents actually made today; `protected_today`
 * = the subset the core rejected (allowed === false). No receipt-status guessing,
 * so an accepted action can never be miscounted as "protected".
 */
export function adaptOverview(
  agents: CoreAgentRecord[],
  egress: CoreEgressRow[]
): OverviewStats {
  const total_agents = agents.length;
  const active_agents = agents.filter((a) => !a.revoked).length;
  const now = Math.floor(Date.now() / 1000);
  const startOfDay = Math.floor(new Date(new Date().setHours(0, 0, 0, 0)).getTime() / 1000);
  let calls_today = 0;
  let protected_today = 0;
  for (const e of egress) {
    if (e.ts < startOfDay || e.ts > now) continue;
    calls_today += 1;
    if (e.allowed === false) protected_today += 1;
  }
  return { total_agents, active_agents, calls_today, protected_today };
}

/* ── Filter helpers ───────────────────────────────────────────────── */

export function filterReceiptsByAgent(
  receipts: CoreActionReceipt[],
  agentId: string | null
): CoreActionReceipt[] {
  if (!agentId) return receipts;
  return receipts.filter((r) => r.agent_id === agentId);
}

export function filterReceiptsByResult(
  receipts: CoreActionReceipt[],
  result: "allowed" | "stopped" | null
): CoreActionReceipt[] {
  if (!result) return receipts;
  return receipts.filter((r) => {
    const s = r.status?.toLowerCase();
    const isAllowed = s === "ok" || s === "allowed";
    return result === "allowed" ? isAllowed : !isAllowed;
  });
}

export function buildAgentNameMap(agents: CoreAgentRecord[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of agents) m.set(a.agent_id, agentDisplayName(a));
  return m;
}
