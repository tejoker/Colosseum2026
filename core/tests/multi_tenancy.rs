//! Sprint 11 — cross-tenant isolation tests.
//!
//! These tests exercise the public `PolicyStore` + `Repo` surfaces under
//! two distinct tenant ids on the same SQLite database, asserting:
//!
//! 1. Upload-as-A / list-as-B returns an empty list (not the cross-tenant row).
//! 2. Upload-as-A / get-by-id-as-B returns `None` (not the cross-tenant row).
//!    Handler-level surface returns 404, NOT 403 — we MUST NOT leak existence.
//! 3. Spend-as-A / get-as-B returns 0 (not the cross-tenant total).
//! 4. Spend ledger keyed by (tenant_id, policy_id, agent_id) — two tenants
//!    can accumulate independently without collision.
//! 5. Evaluate-with-A's-policy-id-from-B returns 404.
//! 6. Default-tenant flow continues to work without a tenant header
//!    (backwards compat guard for the existing 412-test baseline).
//! 7. `record_spend_inner` (legacy back-compat) defaults to the `"default"`
//!    tenant and is invisible to a custom-tenant query.
//!
//! All tests own a private on-disk SQLite database (same pattern as
//! `core/tests/policy_routes.rs::build_test_repo`).

use std::sync::Arc;

use sauron_core::db::open_db_at;
use sauron_core::policy::compiler::compile;
use sauron_core::policy::parser::parse;
use sauron_core::policy::handlers::{
    get_spend_inner_tenant, list_spend_log_inner_tenant, record_spend_inner,
    record_spend_inner_tenant, resolve_spend_for_evaluation_tenant, RecordSpendBody,
    SpendLogQuery, SpendQuery,
};
use sauron_core::policy::PolicyStore;
use sauron_core::repository::Repo;
use sauron_core::tenancy::{TenantId, TenantRegistry, DEFAULT_TENANT};

fn build_test_repo(test_name: &str) -> (Repo, Arc<sauron_core::db::DbHandle>) {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!(
        "sauron-mt-{pid}-{nanos}-{test_name}.db"
    ));
    let _ = std::fs::remove_file(&path);
    let handle = Arc::new(open_db_at(path.to_str().unwrap(), 2));
    let repo = Repo::Sqlite(Arc::clone(&handle));
    (repo, handle)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

const FX_MINIMAL: &str = include_str!("../../schemas/fixtures/policy_minimal.yaml");

#[test]
fn policy_upload_as_tenant_a_does_not_leak_to_tenant_b_list() {
    let (_repo, db) = build_test_repo("policy_list_iso");
    let store = PolicyStore::new(db);
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    store.upsert_tenant("tenant_a", compiled).unwrap();

    let listed_b = store.list_for_tenant("tenant_b");
    assert!(
        listed_b.is_empty(),
        "tenant_b must see no rows uploaded by tenant_a; got {listed_b:?}"
    );
    let listed_a = store.list_for_tenant("tenant_a");
    assert_eq!(listed_a.len(), 1, "tenant_a sees its own policy");
}

#[test]
fn policy_get_by_id_returns_404_shape_across_tenants_no_existence_leak() {
    let (_repo, db) = build_test_repo("policy_get_iso");
    let store = PolicyStore::new(db);
    let compiled = compile(parse(FX_MINIMAL).unwrap()).unwrap();
    let policy_id = compiled.policy_id.clone();
    store.upsert_tenant("tenant_a", compiled).unwrap();

    // tenant_b asking for tenant_a's policy_id MUST get None — the handler
    // turns that into 404 without leaking that the id exists somewhere else.
    let leaked = store.get_by_id_tenant("tenant_b", &policy_id);
    assert!(
        leaked.is_none(),
        "tenant_b must not be able to fetch tenant_a's policy_id={policy_id}"
    );
    // Sanity: tenant_a can still fetch its own row.
    assert!(store.get_by_id_tenant("tenant_a", &policy_id).is_some());
}

#[test]
fn spend_record_as_tenant_a_isolated_from_tenant_b_total() {
    let (repo, _db) = build_test_repo("spend_iso_total");
    rt().block_on(async {
        // tenant_a records spend; tenant_b reads back same (policy,agent) keys.
        record_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 42.0,
            },
        )
        .await
        .expect("record ok");

        let summary_b = get_spend_inner_tenant(
            &repo,
            "tenant_b",
            "agent-1",
            SpendQuery {
                policy_id: "pol_A".into(),
                period_start: None,
            },
        )
        .await
        .expect("get returns zero on miss")
        .0;
        assert_eq!(summary_b.total_usd, 0.0, "tenant_b sees zero spend");
        assert_eq!(summary_b.log_count, 0, "tenant_b sees no log rows");

        // tenant_a still sees the full amount it recorded.
        let summary_a = get_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            SpendQuery {
                policy_id: "pol_A".into(),
                period_start: None,
            },
        )
        .await
        .expect("get tenant_a ok")
        .0;
        assert!((summary_a.total_usd - 42.0).abs() < 1e-9);
        assert_eq!(summary_a.log_count, 1);
    });
}

#[test]
fn spend_log_list_is_tenant_scoped() {
    let (repo, _db) = build_test_repo("spend_log_iso");
    rt().block_on(async {
        record_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 1.0,
            },
        )
        .await
        .unwrap();
        record_spend_inner_tenant(
            &repo,
            "tenant_b",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 9.0,
            },
        )
        .await
        .unwrap();

        let rows_a = list_spend_log_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            SpendLogQuery {
                policy_id: "pol_A".into(),
                limit: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(rows_a.len(), 1);
        assert!((rows_a[0].amount_usd - 1.0).abs() < 1e-9);

        let rows_b = list_spend_log_inner_tenant(
            &repo,
            "tenant_b",
            "agent-1",
            SpendLogQuery {
                policy_id: "pol_A".into(),
                limit: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(rows_b.len(), 1);
        assert!((rows_b[0].amount_usd - 9.0).abs() < 1e-9);
    });
}

#[test]
fn evaluate_resolver_uses_tenant_scoped_authoritative_total() {
    let (repo, _db) = build_test_repo("eval_resolver_iso");
    rt().block_on(async {
        record_spend_inner_tenant(
            &repo,
            "tenant_a",
            "agent-1",
            RecordSpendBody {
                policy_id: "pol_A".into(),
                action_id: None,
                amount_usd: 75.0,
            },
        )
        .await
        .unwrap();

        // tenant_b evaluating with the SAME policy_id + agent_id but a
        // different tenant header gets a zeroed ledger — its spend has
        // never been recorded under tenant_b. The redteam A3b "policy
        // bypass via tenant header" attack lives here.
        let (spend_b, simulator_b, _) = resolve_spend_for_evaluation_tenant(
            &repo,
            "tenant_b",
            "pol_A",
            Some("agent-1"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(spend_b, 0.0);
        assert!(!simulator_b, "agent_id present so not simulator mode");

        // Sanity: tenant_a still sees its own 75 USD.
        let (spend_a, _, _) = resolve_spend_for_evaluation_tenant(
            &repo,
            "tenant_a",
            "pol_A",
            Some("agent-1"),
            None,
        )
        .await
        .unwrap();
        assert!((spend_a - 75.0).abs() < 1e-9);
    });
}

#[test]
fn default_tenant_back_compat_legacy_record_spend_inner() {
    // Legacy `record_spend_inner` (no tenant arg) MUST land in the
    // `"default"` tenant. Tenant_b's view of the same key remains zero.
    let (repo, _db) = build_test_repo("default_tenant_back_compat");
    rt().block_on(async {
        record_spend_inner(
            &repo,
            "agent-x",
            RecordSpendBody {
                policy_id: "pol_legacy".into(),
                action_id: None,
                amount_usd: 5.0,
            },
        )
        .await
        .unwrap();

        let summary_default = get_spend_inner_tenant(
            &repo,
            DEFAULT_TENANT,
            "agent-x",
            SpendQuery {
                policy_id: "pol_legacy".into(),
                period_start: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert!((summary_default.total_usd - 5.0).abs() < 1e-9);

        let summary_other = get_spend_inner_tenant(
            &repo,
            "tenant_b",
            "agent-x",
            SpendQuery {
                policy_id: "pol_legacy".into(),
                period_start: None,
            },
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary_other.total_usd, 0.0);
    });
}

#[test]
fn tenant_registry_records_first_seen_and_lists_sorted() {
    let r = TenantRegistry::new();
    r.ensure_tenant_exists("zeta");
    r.ensure_tenant_exists("alpha");
    r.ensure_tenant_exists("alpha"); // idempotent
    let listed = r.list();
    assert_eq!(listed, vec!["alpha", "default", "zeta"]);
}

#[test]
fn tenant_id_default_is_default_const_pinned() {
    // Pin the const value — changing it would silently revert the
    // back-compat baseline for every legacy caller.
    assert_eq!(TenantId::default_tenant().as_str(), "default");
    assert_eq!(DEFAULT_TENANT, "default");
}

// ───────────────────────────────────────────────────────────────────────
// Sprint 11.5 — agent.rs cross-tenant isolation.
//
// Direct rusqlite inserts mimic what `register_agent` persists (the
// handler can't be invoked headlessly because of the session header +
// rate limiter + ring bookkeeping). The assertion is on the storage
// layer: under the tenant_id filter, tenant_b sees zero rows even
// though tenant_a wrote an `agents` row that matches every other
// predicate (`human_key_image`, agent_id).
// ───────────────────────────────────────────────────────────────────────

fn seed_agent_row(db: &sauron_core::db::DbHandle, tenant_id: &str, agent_id: &str, human_ki: &str) {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO agents
         (agent_id, human_key_image, agent_checksum, issued_at, expires_at, tenant_id)
         VALUES (?1, ?2, ?3, 0, 9999999999, ?4)",
        rusqlite::params![agent_id, human_ki, "checksum-ag", tenant_id],
    )
    .unwrap();
}

#[test]
fn agent_registered_as_tenant_a_invisible_to_tenant_b_list() {
    let (_repo, db) = build_test_repo("agent_iso_list");
    let human_ki = "ki-cross-list";
    seed_agent_row(&db, "tenant_a", "agt_a_only", human_ki);
    seed_agent_row(&db, "tenant_a", "agt_a_other", human_ki);

    // Mirror the list_agents query under tenant_b's filter.
    let count_b: i64 = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE human_key_image = ?1 AND tenant_id = ?2",
            rusqlite::params![human_ki, "tenant_b"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_b, 0, "tenant_b must not see tenant_a's agents");

    let count_a: i64 = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE human_key_image = ?1 AND tenant_id = ?2",
            rusqlite::params![human_ki, "tenant_a"],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count_a, 2, "tenant_a still sees its own rows");
}

#[test]
fn agent_lookup_by_id_returns_404_cross_tenant() {
    let (_repo, db) = build_test_repo("agent_iso_get");
    seed_agent_row(&db, "tenant_a", "agt_secret", "ki-anyone");

    // Mirror the get_agent query under tenant_b's filter — must miss.
    let row_b: Option<String> = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT agent_id FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            rusqlite::params!["agt_secret", "tenant_b"],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };
    assert!(
        row_b.is_none(),
        "cross-tenant get_agent MUST return 404 / None"
    );

    // Sanity: tenant_a still resolves the row.
    let row_a: Option<String> = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT agent_id FROM agents WHERE agent_id = ?1 AND tenant_id = ?2",
            rusqlite::params!["agt_secret", "tenant_a"],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };
    assert_eq!(row_a.as_deref(), Some("agt_secret"));
}
