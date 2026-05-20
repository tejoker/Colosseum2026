//! Integration tests for the Paillier homomorphic aggregator + DB store.
//!
//! NEEDS_CRYPTO_REVIEW: these tests exercise correctness, not security.
//! Production deployments must additionally engage a cryptographer to
//! audit modular arithmetic, randomness sampling, message-space encoding,
//! ciphertext re-randomization, and side-channel resistance.

use std::sync::Arc;

use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sauron_core::aggregation::{
    get_he_aggregation, upsert_he_aggregation, HeAggregationRow, HeAggregator,
};
use sauron_core::db::{open_db_at, DbHandle};
use sauron_core::he::paillier::PaillierPrivateKey;
use sauron_core::he::serde_impl::{ciphertext_from_b64, ciphertext_to_b64};

fn temp_db(label: &str) -> Arc<DbHandle> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir()
        .join(format!("sauron-he-it-{pid}-{nanos}-{label}.db"));
    let _ = std::fs::remove_file(&path);
    Arc::new(open_db_at(path.to_str().unwrap(), 2))
}

/// Use a small modulus for speed — n = 17 * 19 = 323. Plenty of headroom for
/// sums under 100. NEEDS_CRYPTO_REVIEW: never use in production.
fn small_keypair() -> PaillierPrivateKey {
    PaillierPrivateKey::from_primes(&BigUint::from(17u32), &BigUint::from(19u32)).unwrap()
}

#[test]
fn it_aggregates_five_ciphertexts_and_decrypts_correct_sum() {
    let db = temp_db("five");
    let sk = small_keypair();
    let mut rng = StdRng::seed_from_u64(101);

    let mut agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
    let values = [5u32, 10, 15, 20, 25];
    for v in values {
        let ct = sk.public.encrypt(&BigUint::from(v), &mut rng).unwrap();
        agg.add_encrypted(&ct).unwrap();

        // Persist the running ciphertext after every contribution so the
        // store path is exercised end-to-end.
        let row = HeAggregationRow {
            aggregation_id: "agg_five".into(),
            cohort_id: "coh_demo".into(),
            metric_id: "secret_sum".into(),
            period_start: 0,
            pk_id: "pk_demo".into(),
            sum_ciphertext_b64: ciphertext_to_b64(&agg.sum_ciphertext),
            n_contributions: agg.n_contributions as i64,
            last_updated: 1,
        };
        upsert_he_aggregation(&db, &row).unwrap();
    }

    // Reload from the store, decrypt, verify.
    let stored = get_he_aggregation(&db, "agg_five").unwrap().unwrap();
    assert_eq!(stored.n_contributions, 5);
    let ct = ciphertext_from_b64(&stored.sum_ciphertext_b64).unwrap();
    let restored = HeAggregator::from_parts(
        sk.public.clone(),
        ct,
        stored.n_contributions as u32,
    );
    let total = restored.finalize(&sk).unwrap();
    assert_eq!(total, 75);
}

#[test]
fn it_isolates_aggregations_across_cohorts() {
    let db = temp_db("iso");
    let sk = small_keypair();
    let mut rng = StdRng::seed_from_u64(102);

    // Two separate aggregations; sums must not bleed.
    for (label, vals) in [("agg_a", vec![10u32, 20]), ("agg_b", vec![5u32, 50])] {
        let mut agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
        for v in &vals {
            let ct = sk.public.encrypt(&BigUint::from(*v), &mut rng).unwrap();
            agg.add_encrypted(&ct).unwrap();
        }
        let row = HeAggregationRow {
            aggregation_id: label.into(),
            cohort_id: label.into(),
            metric_id: "secret_sum".into(),
            period_start: 0,
            pk_id: "pk_demo".into(),
            sum_ciphertext_b64: ciphertext_to_b64(&agg.sum_ciphertext),
            n_contributions: agg.n_contributions as i64,
            last_updated: 1,
        };
        upsert_he_aggregation(&db, &row).unwrap();
    }

    let a = get_he_aggregation(&db, "agg_a").unwrap().unwrap();
    let b = get_he_aggregation(&db, "agg_b").unwrap().unwrap();
    let ct_a = ciphertext_from_b64(&a.sum_ciphertext_b64).unwrap();
    let ct_b = ciphertext_from_b64(&b.sum_ciphertext_b64).unwrap();
    let sum_a = HeAggregator::from_parts(sk.public.clone(), ct_a, 2)
        .finalize(&sk)
        .unwrap();
    let sum_b = HeAggregator::from_parts(sk.public.clone(), ct_b, 2)
        .finalize(&sk)
        .unwrap();
    assert_eq!(sum_a, 30);
    assert_eq!(sum_b, 55);
}

#[test]
fn it_handles_idempotent_resubmission_via_upsert() {
    // Same `aggregation_id` upserted twice must end with the second row's
    // ciphertext only — no doubling.
    let db = temp_db("idem");
    let sk = small_keypair();
    let mut rng = StdRng::seed_from_u64(103);

    let mut agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
    let ct = sk.public.encrypt(&BigUint::from(42u32), &mut rng).unwrap();
    agg.add_encrypted(&ct).unwrap();
    let first_b64 = ciphertext_to_b64(&agg.sum_ciphertext);

    let row1 = HeAggregationRow {
        aggregation_id: "agg_idem".into(),
        cohort_id: "coh".into(),
        metric_id: "secret_sum".into(),
        period_start: 0,
        pk_id: "pk_demo".into(),
        sum_ciphertext_b64: first_b64.clone(),
        n_contributions: 1,
        last_updated: 100,
    };
    upsert_he_aggregation(&db, &row1).unwrap();

    // Replay same aggregation_id with an updated ciphertext + counter.
    let ct2 = sk.public.encrypt(&BigUint::from(8u32), &mut rng).unwrap();
    agg.add_encrypted(&ct2).unwrap();
    let second_b64 = ciphertext_to_b64(&agg.sum_ciphertext);
    let row2 = HeAggregationRow {
        aggregation_id: "agg_idem".into(),
        cohort_id: "coh".into(),
        metric_id: "secret_sum".into(),
        period_start: 0,
        pk_id: "pk_demo".into(),
        sum_ciphertext_b64: second_b64.clone(),
        n_contributions: 2,
        last_updated: 200,
    };
    upsert_he_aggregation(&db, &row2).unwrap();

    let stored = get_he_aggregation(&db, "agg_idem").unwrap().unwrap();
    assert_eq!(stored.n_contributions, 2);
    assert_eq!(stored.last_updated, 200);
    assert_eq!(stored.sum_ciphertext_b64, second_b64);

    let restored_ct = ciphertext_from_b64(&stored.sum_ciphertext_b64).unwrap();
    let total = HeAggregator::from_parts(sk.public.clone(), restored_ct, 2)
        .finalize(&sk)
        .unwrap();
    assert_eq!(total, 50);
}
