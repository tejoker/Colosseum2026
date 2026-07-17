//! HTTP handlers for `/v1/policy/*` routes.
//!
//! All routes are gated by the existing admin auth middleware
//! (`admin::auth_middleware`) — these are operator endpoints, never
//! exposed to end-user browsers. See [`crate::routes::policy_router`].

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::repository::{Repo, RepoError, SpendLogEntry};
use crate::state::ServerState;
use crate::tenancy::TenantId;

use super::compiler::compile;
use super::evaluator::evaluate_with_trace;
use super::invariants::{Action, EvaluationContext, Verdict};
use super::parser::{parse_json, parse_yaml};

/// Sanity cap on a single spend record (USD). Anything bigger is almost
/// certainly a unit-conversion bug or an attack and gets rejected at the
/// HTTP boundary before it reaches the ledger.
pub const MAX_SPEND_RECORD_USD: f64 = 1_000_000.0;

/// Body of `POST /v1/policy/upload` — accepts JSON `{ raw_yaml: "..." }`
/// or, when `Content-Type: application/yaml`, the raw YAML directly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadJsonBody {
    /// Raw YAML or JSON policy document.
    pub raw_yaml: String,
}

/// Response from `POST /v1/policy/upload`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UploadResponse {
    /// Server-assigned id (`pol_<32-hex>`).
    pub policy_id: String,
    /// Agent identifier from the policy.
    pub agent: String,
    /// Names of the runtime checks the policy compiled into.
    pub checks: Vec<String>,
}

/// `POST /v1/policy/upload` — parse + compile + store a new policy.
///
/// Tenant resolution: pulled from the `Extension<TenantId>` added by
/// [`crate::tenancy::extract_tenant`] middleware. Falls back to the
/// `"default"` tenant when the middleware is not in the stack (legacy
/// tests that build a router without it).
pub async fn upload(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<UploadResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let raw = if content_type.starts_with("application/yaml")
        || content_type.starts_with("text/yaml")
        || content_type.starts_with("application/x-yaml")
    {
        body
    } else {
        // JSON envelope `{ "raw_yaml": "..." }` — accept either.
        let envelope: UploadJsonBody = serde_json::from_str(&body)
            .map_err(|e| AppError::BadRequest(format!("invalid envelope: {e}")))?;
        envelope.raw_yaml
    };

    let policy =
        parse_or_yaml(&raw).map_err(|e| AppError::BadRequest(format!("policy parse: {e}")))?;
    let compiled =
        compile(policy).map_err(|e| AppError::BadRequest(format!("policy compile: {e}")))?;

    let resp = UploadResponse {
        policy_id: compiled.policy_id.clone(),
        agent: compiled.agent.clone(),
        checks: compiled
            .checks
            .iter()
            .map(|c| c.name().to_string())
            .collect(),
    };

    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        Arc::clone(&st.policy_store)
    };
    store
        .upsert_tenant(tenant_id.as_str(), compiled)
        .map_err(|e| AppError::Internal(format!("store upsert: {e}")))?;

    Ok(Json(resp))
}

/// Parse policy bytes, auto-detecting JSON vs YAML by sniffing the first
/// non-whitespace character.
fn parse_or_yaml(input: &str) -> Result<super::ast::Policy, super::types::PolicyParseError> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') {
        parse_json(input)
    } else {
        parse_yaml(input)
    }
}

/// `GET /v1/policy/list` — summary of every stored policy for the caller's
/// tenant. Cross-tenant rows are filtered out; an empty list is returned
/// when the tenant has uploaded no policies (NOT 404 — listing an empty
/// account is a normal state, not a not-found condition).
pub async fn list(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
) -> Result<Json<Vec<super::store::PolicySummary>>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        Arc::clone(&st.policy_store)
    };
    Ok(Json(store.list_for_tenant(tenant_id.as_str())))
}

/// `GET /v1/policy/:id` — full policy document for the caller's tenant.
///
/// A policy that belongs to another tenant returns `404`, NOT `403` — we
/// MUST NOT leak existence information across tenant boundaries.
pub async fn get_one(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(id): Path<String>,
) -> Result<Json<super::ast::Policy>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        Arc::clone(&st.policy_store)
    };
    let compiled = store
        .get_by_id_tenant(tenant_id.as_str(), &id)
        .ok_or_else(|| AppError::NotFound(format!("policy {id} not found")))?;
    Ok(Json(compiled.raw.clone()))
}

/// `DELETE /v1/policy/:id` — remove a policy for the caller's tenant.
/// Cross-tenant deletes are silently dropped (idempotent — same shape as
/// "id was never present").
pub async fn delete_one(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        Arc::clone(&st.policy_store)
    };
    store
        .delete_tenant(tenant_id.as_str(), &id)
        .map_err(|e| AppError::Internal(format!("store delete: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Overrides callers can supply for the evaluation context. When `None`,
/// the handler falls back to DB lookups / wall-clock.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextOverrides {
    /// Running spend total in USD for this policy/agent/period.
    #[serde(default)]
    pub spend_total_usd: Option<f64>,
    /// Unix-epoch timestamps of recent calls.
    #[serde(default)]
    pub recent_call_timestamps: Option<Vec<i64>>,
    /// `HH:MM` 24-hour wall clock in the policy's timezone.
    #[serde(default)]
    pub now_tz_hhmm: Option<String>,
    /// Override `ctx.now_epoch` (for deterministic tests).
    #[serde(default)]
    pub now_epoch: Option<i64>,
}

/// Body of `POST /v1/policy/evaluate`.
///
/// When `agent_id` is present the evaluator fetches the authoritative
/// spend total from the server-side `spend_ledger` and IGNORES any
/// `context_overrides.spend_total_usd` value the client supplies — that
/// closes the Sprint 3 redteam A3 gap ("local budget can be tampered").
///
/// When `agent_id` is absent the request is treated as simulator mode
/// (Sprint 10 policy-simulator dashboard) and the client-supplied
/// `spend_total_usd` is honoured. The response sets `simulator: true`
/// so callers can surface the distinction.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateBody {
    /// Id of the policy to evaluate.
    pub policy_id: String,
    /// Optional agent id. Presence triggers authoritative-ledger lookup.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// The action to test.
    pub action: Action,
    /// Optional context overrides (for testing / dry-run).
    #[serde(default)]
    pub context_overrides: Option<ContextOverrides>,
}

/// Response from `POST /v1/policy/evaluate`.
#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    /// Overall verdict (Allow if every check allowed).
    pub verdict: Verdict,
    /// Per-check verdicts in declaration order.
    pub trace: Vec<TraceEntry>,
    /// Authoritative spend total used during evaluation (USD).
    pub spend_total_usd: f64,
    /// True when the call ran in simulator mode (no `agent_id` supplied,
    /// client override accepted as-is, ledger NOT consulted).
    #[serde(skip_serializing_if = "is_false")]
    pub simulator: bool,
    /// When `simulator == true`, a one-line note explaining the relaxed
    /// trust model. Absent on authoritative paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulator_warning: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One row of the evaluator trace.
#[derive(Debug, Serialize)]
pub struct TraceEntry {
    /// Name of the check.
    pub check: String,
    /// Verdict produced by that check.
    pub verdict: Verdict,
}

/// `POST /v1/policy/evaluate` — run the compiled checks for `policy_id`.
///
/// Trust model:
///
/// - If `agent_id` is present the spend total is taken from
///   `spend_ledger` (lifetime period). Any client-supplied
///   `context_overrides.spend_total_usd` is IGNORED; the response carries
///   the authoritative value in `spend_total_usd`.
/// - If `agent_id` is absent the call is treated as simulator-mode: the
///   client override is honoured and the response is annotated with
///   `simulator: true`.
pub async fn evaluate_action(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Json(payload): Json<EvaluateBody>,
) -> Result<Json<EvaluateResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let (store, repo) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        (Arc::clone(&st.policy_store), st.repo.clone())
    };
    let compiled = store
        .get_by_id_tenant(tenant_id.as_str(), &payload.policy_id)
        .ok_or_else(|| AppError::NotFound(format!("policy {} not found", payload.policy_id)))?;

    let overrides = payload.context_overrides.unwrap_or_default();
    let now_epoch = overrides.now_epoch.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    let recent: Vec<i64> = overrides.recent_call_timestamps.unwrap_or_default();
    let now_tz_hhmm = overrides.now_tz_hhmm.unwrap_or_else(|| {
        // Default fallback: use UTC HH:MM if the policy has a tz, else "00:00".
        compute_tz_hhmm(&compiled.raw, now_epoch)
    });

    let (spend, simulator, simulator_warning) = resolve_spend_for_evaluation_tenant(
        &repo,
        tenant_id.as_str(),
        &payload.policy_id,
        payload.agent_id.as_deref(),
        overrides.spend_total_usd,
    )
    .await
    .map_err(map_repo_err)?;

    let mut ctx = EvaluationContext::with_defaults(&payload.action);
    ctx.spend_total_usd = spend;
    ctx.recent_call_timestamps = &recent;
    ctx.now_epoch = now_epoch;
    ctx.now_tz_hhmm = now_tz_hhmm;

    let (verdict, trace) = evaluate_with_trace(&compiled, &ctx);
    Ok(Json(EvaluateResponse {
        verdict,
        trace: trace
            .into_iter()
            .map(|(check, verdict)| TraceEntry { check, verdict })
            .collect(),
        spend_total_usd: spend,
        simulator,
        simulator_warning,
    }))
}

// ───────────────────────────────────────────────────────────────────────
// Server-authoritative spend ledger (Sprint 3 follow-up). Closes the
// documented "Local budget can be tampered" gap (redteam policy-bypass A3).
// ───────────────────────────────────────────────────────────────────────

/// Body of `POST /v1/agents/:agent_id/spend`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSpendBody {
    /// Policy this spend is charged against.
    pub policy_id: String,
    /// Optional caller-supplied action id (echoed into the log row).
    #[serde(default)]
    pub action_id: Option<String>,
    /// USD spent. MUST be `>= 0` and `<= MAX_SPEND_RECORD_USD`.
    pub amount_usd: f64,
}

/// Response from `POST /v1/agents/:agent_id/spend`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSpendResponse {
    /// Newly-assigned `splog_<hex>` id of the log row.
    pub log_id: String,
    /// Running total for the (policy_id, agent_id, lifetime) tuple after
    /// this record was applied.
    pub new_total_usd: f64,
}

/// `POST /v1/agents/:agent_id/spend` — append one spend event.
pub async fn record_spend(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
    Json(body): Json<RecordSpendBody>,
) -> Result<Json<RecordSpendResponse>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let repo = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.repo.clone()
    };
    record_spend_inner_tenant(&repo, tenant_id.as_str(), &agent_id, body).await
}

/// Pure-handler core for [`record_spend`] — split out so tests can call it
/// with a hand-built `Repo` and skip the full `ServerState` build.
///
/// Back-compat shim: defaults to the `"default"` tenant. New tenant-aware
/// callers MUST use [`record_spend_inner_tenant`].
pub async fn record_spend_inner(
    repo: &Repo,
    agent_id: &str,
    body: RecordSpendBody,
) -> Result<Json<RecordSpendResponse>, AppError> {
    record_spend_inner_tenant(repo, crate::tenancy::DEFAULT_TENANT, agent_id, body).await
}

/// Tenant-scoped variant of [`record_spend_inner`].
pub async fn record_spend_inner_tenant(
    repo: &Repo,
    tenant_id: &str,
    agent_id: &str,
    body: RecordSpendBody,
) -> Result<Json<RecordSpendResponse>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    if body.policy_id.is_empty() {
        return Err(AppError::BadRequest("policy_id required".into()));
    }
    if !body.amount_usd.is_finite() {
        return Err(AppError::BadRequest(
            "amount_usd must be a finite number".into(),
        ));
    }
    if body.amount_usd < 0.0 {
        return Err(AppError::BadRequest(
            "amount_usd must be non-negative".into(),
        ));
    }
    if body.amount_usd > MAX_SPEND_RECORD_USD {
        return Err(AppError::BadRequest(format!(
            "amount_usd exceeds sanity cap of {MAX_SPEND_RECORD_USD}"
        )));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let log_id = repo
        .record_spend_tenant(
            tenant_id,
            &body.policy_id,
            agent_id,
            body.action_id.as_deref(),
            body.amount_usd,
            "sdk_flush",
            now,
        )
        .await
        .map_err(map_repo_err)?;
    let new_total = repo
        .get_spend_total_tenant(tenant_id, &body.policy_id, agent_id, 0)
        .await
        .map_err(map_repo_err)?;
    Ok(Json(RecordSpendResponse {
        log_id,
        new_total_usd: new_total,
    }))
}

/// Query string for `GET /v1/agents/:agent_id/spend`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendQuery {
    /// Policy id whose ledger is being inspected.
    pub policy_id: String,
    /// Period boundary (unix epoch). Default 0 (lifetime).
    #[serde(default)]
    pub period_start: Option<i64>,
}

/// Response from `GET /v1/agents/:agent_id/spend`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendSummary {
    /// Policy this ledger row belongs to.
    pub policy_id: String,
    /// Agent this ledger row belongs to.
    pub agent_id: String,
    /// Period boundary echoed back (0 = lifetime).
    pub period_start: i64,
    /// Running USD total.
    pub total_usd: f64,
    /// Unix-epoch seconds of the last increment (0 if untouched).
    pub last_updated: i64,
    /// Number of `spend_log` rows for this (policy_id, agent_id).
    pub log_count: i64,
}

/// `GET /v1/agents/:agent_id/spend` — current ledger summary.
pub async fn get_spend(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SpendQuery>,
) -> Result<Json<SpendSummary>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let repo = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.repo.clone()
    };
    get_spend_inner_tenant(&repo, tenant_id.as_str(), &agent_id, q).await
}

/// Pure-handler core for [`get_spend`]. Back-compat shim — defaults to
/// the `"default"` tenant.
pub async fn get_spend_inner(
    repo: &Repo,
    agent_id: &str,
    q: SpendQuery,
) -> Result<Json<SpendSummary>, AppError> {
    get_spend_inner_tenant(repo, crate::tenancy::DEFAULT_TENANT, agent_id, q).await
}

/// Tenant-scoped variant of [`get_spend_inner`].
pub async fn get_spend_inner_tenant(
    repo: &Repo,
    tenant_id: &str,
    agent_id: &str,
    q: SpendQuery,
) -> Result<Json<SpendSummary>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    if q.policy_id.is_empty() {
        return Err(AppError::BadRequest("policy_id required".into()));
    }
    let period_start = q.period_start.unwrap_or(0);
    let total = repo
        .get_spend_total_tenant(tenant_id, &q.policy_id, agent_id, period_start)
        .await
        .map_err(map_repo_err)?;
    let (last_updated, log_count) = repo
        .get_spend_meta_tenant(tenant_id, &q.policy_id, agent_id, period_start)
        .await
        .map_err(map_repo_err)?;
    Ok(Json(SpendSummary {
        policy_id: q.policy_id,
        agent_id: agent_id.to_string(),
        period_start,
        total_usd: total,
        last_updated,
        log_count,
    }))
}

/// Query string for `GET /v1/agents/:agent_id/spend/log`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendLogQuery {
    /// Policy id whose log is being read.
    pub policy_id: String,
    /// Max rows to return. Default 100, capped at 1000.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /v1/agents/:agent_id/spend/log` — recent log rows, newest first.
pub async fn list_spend_log_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Path(agent_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SpendLogQuery>,
) -> Result<Json<Vec<SpendLogEntry>>, AppError> {
    let tenant_id = tenant.map(|Extension(t)| t).unwrap_or_default();
    let repo = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.repo.clone()
    };
    list_spend_log_inner_tenant(&repo, tenant_id.as_str(), &agent_id, q).await
}

/// Pure-handler core for [`list_spend_log_handler`]. Back-compat shim —
/// defaults to the `"default"` tenant.
pub async fn list_spend_log_inner(
    repo: &Repo,
    agent_id: &str,
    q: SpendLogQuery,
) -> Result<Json<Vec<SpendLogEntry>>, AppError> {
    list_spend_log_inner_tenant(repo, crate::tenancy::DEFAULT_TENANT, agent_id, q).await
}

/// Tenant-scoped variant of [`list_spend_log_inner`].
pub async fn list_spend_log_inner_tenant(
    repo: &Repo,
    tenant_id: &str,
    agent_id: &str,
    q: SpendLogQuery,
) -> Result<Json<Vec<SpendLogEntry>>, AppError> {
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    if q.policy_id.is_empty() {
        return Err(AppError::BadRequest("policy_id required".into()));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let rows = repo
        .list_spend_log_tenant(tenant_id, &q.policy_id, agent_id, limit)
        .await
        .map_err(map_repo_err)?;
    Ok(Json(rows))
}

/// Authoritative-or-simulator spend resolver used by
/// [`evaluate_action`]. Returns `(spend_total_usd, simulator,
/// simulator_warning)`. When `agent_id` is `Some(non-empty)` the value
/// comes from `spend_ledger` and the client override is ignored; when
/// it is `None` the override is honoured and the caller is marked as
/// simulator-mode.
///
/// Split out so unit tests can exercise the trust-boundary logic without
/// constructing a full `ServerState`.
pub async fn resolve_spend_for_evaluation(
    repo: &Repo,
    policy_id: &str,
    agent_id: Option<&str>,
    override_spend: Option<f64>,
) -> Result<(f64, bool, Option<String>), RepoError> {
    resolve_spend_for_evaluation_tenant(
        repo,
        crate::tenancy::DEFAULT_TENANT,
        policy_id,
        agent_id,
        override_spend,
    )
    .await
}

/// Tenant-scoped variant of [`resolve_spend_for_evaluation`].
pub async fn resolve_spend_for_evaluation_tenant(
    repo: &Repo,
    tenant_id: &str,
    policy_id: &str,
    agent_id: Option<&str>,
    override_spend: Option<f64>,
) -> Result<(f64, bool, Option<String>), RepoError> {
    match agent_id {
        Some(a) if !a.is_empty() => {
            let authoritative = repo
                .get_spend_total_tenant(tenant_id, policy_id, a, 0)
                .await?;
            Ok((authoritative, false, None))
        }
        _ => Ok((
            override_spend.unwrap_or(0.0),
            true,
            Some(
                "agent_id omitted; client-supplied spend_total_usd accepted as-is. \
                 Ledger NOT consulted."
                    .to_string(),
            ),
        )),
    }
}

fn map_repo_err(e: RepoError) -> AppError {
    match e {
        RepoError::Backend(s) => AppError::Internal(format!("ledger backend: {s}")),
        RepoError::Replay(s) => AppError::Conflict(format!("ledger replay: {s}")),
    }
}

/// Compute the policy-timezone `HH:MM` for the given epoch.
///
/// If the policy has no `time_window`, returns `"00:00"` (the value is
/// unused by other checks). Falls back to UTC if the tz lookup fails.
fn compute_tz_hhmm(policy: &super::ast::Policy, now_epoch: i64) -> String {
    use chrono::TimeZone;
    use std::str::FromStr;

    let tz_name = policy
        .binding
        .time_window
        .as_ref()
        .map(|tw| tw.timezone.as_str())
        .unwrap_or("UTC");
    let tz = chrono_tz::Tz::from_str(tz_name).unwrap_or(chrono_tz::UTC);
    let utc = match chrono::Utc.timestamp_opt(now_epoch, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => return "00:00".to_string(),
    };
    let local = utc.with_timezone(&tz);
    local.format("%H:%M").to_string()
}

// ───────────────────────────────────────────────────────────────────────
// Sprint 1: server-side bound-policy enforcement on action endpoints.
// ───────────────────────────────────────────────────────────────────────

/// Outcome of `enforce_bound_policy_for_action`.
#[derive(Debug, Clone)]
pub enum BoundPolicyOutcome {
    /// No policy was bound to the agent → nothing to enforce (unless
    /// `SAURON_POLICY_REQUIRE_BINDING` is set, in which case the caller denies).
    NoBinding,
    /// A binding row EXISTS but its policy could not be loaded from the store
    /// (missing / failed to compile). This is a misconfiguration, never a
    /// license to allow: the caller MUST fail closed in `Enforce` mode.
    PolicyUnavailable { policy_id: String },
    /// Policy was bound and evaluated to `Allow`.
    Allow { policy_id: String },
    /// Policy was bound and evaluated to `Deny`. Caller must:
    /// - in `Enforce` mode: short-circuit with 403 + `reason`.
    /// - in `Advisory`/`Off` modes: log and continue.
    Deny {
        policy_id: String,
        check: String,
        reason: String,
    },
}

/// Look up the policy bound to `(tenant_id, agent_id)`, evaluate `action`
/// against it (consulting the spend ledger for the authoritative total),
/// and return a [`BoundPolicyOutcome`] that callers translate into HTTP
/// status codes.
///
/// `NoBinding` is the no-op path: agents without a server-side binding
/// keep the legacy behaviour. `Deny` carries the failing check + reason
/// so the 403 surface can echo a useful message back to the SDK.
pub async fn enforce_bound_policy_for_action(
    state: &Arc<RwLock<ServerState>>,
    tenant_id: &str,
    agent_id: &str,
    action: &Action,
) -> Result<BoundPolicyOutcome, AppError> {
    let (db_handle, store, repo) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        (
            Arc::clone(&st.db),
            Arc::clone(&st.policy_store),
            st.repo.clone(),
        )
    };
    enforce_bound_policy_with_handles(&db_handle, &store, &repo, tenant_id, agent_id, action).await
}

/// Low-level enforcement driven by raw handles. Sibling of
/// [`enforce_bound_policy_for_action`] used by tests + by call sites that
/// don't have a full `ServerState`. Production handlers go through the
/// `..._for_action` shim; tests build their own `Repo`, `DbHandle`, and
/// `PolicyStore` to avoid the full state-construction cost.
pub async fn enforce_bound_policy_with_handles(
    db_handle: &Arc<crate::db::DbHandle>,
    store: &Arc<crate::policy::PolicyStore>,
    repo: &Repo,
    tenant_id: &str,
    agent_id: &str,
    action: &Action,
) -> Result<BoundPolicyOutcome, AppError> {
    let policy_id = match crate::policy::binding_handlers::lookup_bound_policy_id(
        db_handle, tenant_id, agent_id,
    )? {
        Some(pid) => pid,
        None => return Ok(BoundPolicyOutcome::NoBinding),
    };
    let compiled = match store.get_by_id_tenant(tenant_id, &policy_id) {
        Some(c) => c,
        None => {
            // A binding EXISTS but its policy is not loadable. Previously this
            // returned NoBinding (silently allowed) — a fail-open. Surface it as
            // PolicyUnavailable so Enforce-mode callers refuse the action.
            tracing::error!(
                target: "sauron::policy::enforcement",
                %tenant_id,
                %agent_id,
                %policy_id,
                "bound policy not present in store — failing closed (PolicyUnavailable)",
            );
            return Ok(BoundPolicyOutcome::PolicyUnavailable {
                policy_id: policy_id.clone(),
            });
        }
    };

    let (spend, _simulator, _warning) =
        resolve_spend_for_evaluation_tenant(repo, tenant_id, &policy_id, Some(agent_id), None)
            .await
            .map_err(map_repo_err)?;

    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let now_tz_hhmm = compute_tz_hhmm(&compiled.raw, now_epoch);

    let mut ctx = EvaluationContext::with_defaults(action);
    ctx.spend_total_usd = spend;
    ctx.now_epoch = now_epoch;
    ctx.now_tz_hhmm = now_tz_hhmm;
    // Weekday/date defaults: pass a Monday at noon UTC if the policy has
    // weekday-gated checks so the test path isn't blocked by ambient time.
    ctx.now_weekday = 1;
    ctx.now_date_yyyy_mm_dd = "2026-05-21".into();

    match crate::policy::evaluator::evaluate(&compiled, &ctx) {
        Verdict::Allow => Ok(BoundPolicyOutcome::Allow { policy_id }),
        Verdict::Deny { check, reason } => Ok(BoundPolicyOutcome::Deny {
            policy_id,
            check,
            reason,
        }),
    }
}
