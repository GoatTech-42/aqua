use super::*;

#[test]
fn decimal_money_and_cost_are_exact_and_overflow_checked() {
    assert_eq!(usd("0.15"), Some(150_000_000));
    for bad in ["", "-1", "+1", "NaN", "1e3", "1.1234567890", "1.", ".1"] {
        assert_eq!(usd(bad), None, "{bad}");
    }
    let p = Price { input: 150_000_000, output: 500_000_000 };
    assert_eq!(p.cost(2000, 500), Some(550_000));
    assert_eq!(p.cost(1, 0), Some(150));
    assert_eq!(Price { input: u64::MAX, output: u64::MAX }.cost(u64::MAX, u64::MAX), None);
}

#[test]
fn concurrent_reservations_cannot_cross_a_cap_and_exact_boundary_stops() {
    let mut ledger = Ledger::default();
    let cap = Caps { daily: 100, monthly: 200 };
    let a = ledger.reserve("sam", "m", "2026-11-16", 60, Some(cap)).unwrap();
    assert!(ledger.reserve("sam", "m", "2026-11-16", 41, Some(cap)).is_err());
    ledger.settle(a, Some(60)).unwrap();
    let b = ledger.reserve("sam", "m", "2026-11-16", 40, Some(cap)).unwrap();
    ledger.settle(b, Some(40)).unwrap();
    assert!(ledger.reserve("sam", "m", "2026-11-16", 1, Some(cap)).is_err());
}

#[test]
fn settlement_refunds_unused_reservation_and_missing_usage_keeps_hold() {
    let mut ledger = Ledger::default();
    let cap = Caps { daily: 100, monthly: 200 };
    let a = ledger.reserve("sam", "m", "2026-11-16", 90, Some(cap)).unwrap();
    ledger.settle(a, Some(20)).unwrap();
    let b = ledger.reserve("sam", "m", "2026-11-16", 80, Some(cap)).unwrap();
    ledger.settle(b, None).unwrap();
    let usage = &ledger.users["sam"];
    assert_eq!(usage.day.models["m"], Totals { confirmed: 20, held: 80 });
    assert!(ledger.reserve("sam", "m", "2026-11-16", 1, Some(cap)).is_err());
}

#[test]
fn owner_is_uncapped_but_model_usage_is_counted() {
    let mut ledger = Ledger::default();
    for model in ["one", "two"] {
        let a = ledger.reserve("luke", model, "2026-11-16", 0, None).unwrap();
        ledger.settle(a, Some(100_000_000_000)).unwrap();
    }
    assert_eq!(ledger.users["luke"].day.total().unwrap().confirmed, 200_000_000_000);
    assert_eq!(ledger.users["luke"].month.models.len(), 2);
}

#[test]
fn daily_rollover_does_not_reset_month_and_late_settlement_does_not_charge_new_day() {
    let mut ledger = Ledger::default();
    let cap = Caps { daily: 100, monthly: 120 };
    let old = ledger.reserve("sam", "m", "2026-11-16", 100, Some(cap)).unwrap();
    let new = ledger.reserve("sam", "m", "2026-11-17", 20, Some(cap)).unwrap();
    ledger.settle(old, Some(10)).unwrap();
    ledger.settle(new, Some(20)).unwrap();
    assert_eq!(ledger.users["sam"].day.total().unwrap(), Totals { confirmed: 20, held: 0 });
    assert_eq!(ledger.users["sam"].month.total().unwrap(), Totals { confirmed: 30, held: 0 });
}

#[test]
fn monthly_rollover_resets_both_windows() {
    let mut ledger = Ledger::default();
    let cap = Caps { daily: 100, monthly: 100 };
    let a = ledger.reserve("sam", "m", "2026-11-30", 100, Some(cap)).unwrap();
    ledger.settle(a, Some(100)).unwrap();
    assert!(ledger.reserve("sam", "m", "2026-12-01", 100, Some(cap)).is_ok());
}

#[test]
fn duplicate_settlement_and_above_bound_usage_are_not_silent() {
    let mut ledger = Ledger::default();
    let a = ledger.reserve("sam", "m", "2026-11-16", 5, Some(Caps { daily: 10, monthly: 10 })).unwrap();
    ledger.settle(a, Some(6)).unwrap();
    assert_eq!(ledger.users["sam"].day.total().unwrap().confirmed, 6);
    assert!(ledger.users["sam"].accounting_error);
    assert!(ledger.settle(a, Some(5)).is_err());
}

#[test]
fn expensive_models_default_admin_only_and_explicit_override_is_respected() {
    let cheap = Price { input: 1, output: 9_999_999_999 };
    let expensive = Price { input: 1, output: 10_000_000_000 };
    assert!(!admin_only(cheap, None));
    assert!(admin_only(expensive, None));
    assert!(admin_only(cheap, Some(true)));
    assert!(!admin_only(expensive, Some(false)));
}

#[test]
fn serialized_ledger_retains_unsettled_reservations_on_restart() {
    let mut ledger = Ledger::default();
    ledger.reserve("sam", "m", "2026-11-16", 100, Some(Caps { daily: 100, monthly: 200 })).unwrap();
    let mut restarted: Ledger = serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
    assert!(restarted.reserve("sam", "m", "2026-11-16", 1, Some(Caps { daily: 100, monthly: 200 })).is_err());
}

#[test]
fn ledger_store_persists_before_return_and_rejects_corrupt_state() {
    let path = std::env::temp_dir().join(format!("aqua-spend-{}-{}.json", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    {
        let mut store = Store::open(Some(path.clone())).unwrap();
        store.change(|l| l.reserve("sam", "m", "2026-11-16", 100, Some(Caps { daily: 100, monthly: 200 }))).unwrap();
    }
    let mut restarted = Store::open(Some(path.clone())).unwrap();
    assert!(restarted.change(|l| l.reserve("sam", "m", "2026-11-16", 1, Some(Caps { daily: 100, monthly: 200 }))).is_err());
    std::fs::write(&path, b"broken").unwrap();
    assert!(Store::open(Some(path.clone())).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn failed_persistence_leaves_memory_unchanged() {
    let path = std::env::temp_dir().join(format!("aqua-no-parent-{}", std::process::id())).join("state.json");
    let mut store = Store::open(None).unwrap();
    store.path = Some(path);
    assert!(store.change(|l| l.reserve("sam", "m", "2026-11-16", 10, Some(FRIEND_CAPS))).is_err());
    assert!(store.ledger.users.is_empty());
}

#[test]
fn backward_clock_cannot_reset_budget() {
    let mut ledger = Ledger::default();
    ledger.reserve("sam", "m", "2026-11-17", 100, Some(Caps { daily: 100, monthly: 200 })).unwrap();
    assert!(ledger.reserve("sam", "m", "2026-11-16", 1, Some(Caps { daily: 100, monthly: 200 })).is_err());
}

#[test]
fn cap_parser_and_default_policy_fail_closed_for_unpriced_models() {
    assert!(parse_caps("-1/15").is_none());
    assert!(parse_caps("2/NaN").is_none());
    assert_eq!(parse_caps("2/15").unwrap().monthly, 15 * USD);
    let s = Settings { enabled: true, ..Settings::default() };
    assert!(s.restricted("unpriced"));
    assert!(!s.restricted("glm-5.3-flash"));
    assert_eq!(s.default_caps.daily, 2 * USD);
}

#[test]
fn same_state_file_cannot_be_owned_by_two_server_processes() {
    let path = std::env::temp_dir().join(format!("aqua-spend-lock-{}-{}.json", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let first = Store::open(Some(path.clone())).unwrap();
    assert!(Store::open(Some(path.clone())).is_err());
    drop(first);
    assert!(Store::open(Some(path.clone())).is_ok());
    let _ = std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn above_bound_report_persistently_blocks_capped_admissions_even_after_rollover() {
    let mut store = Store::open(None).unwrap();
    let id = store.change(|l|l.reserve("sam","m","2026-11-16",5,Some(FRIEND_CAPS))).unwrap();
    store.change(|l|l.settle(id,Some(6))).unwrap();
    assert_eq!(store.ledger.users["sam"].day.total().unwrap().confirmed,6);
    assert!(store.change(|l|l.reserve("sam","m","2026-12-01",1,Some(FRIEND_CAPS))).is_err());
    assert!(store.change(|l|l.reserve("sam","m","2026-12-01",0,None)).is_ok());
}

#[test]
fn restarted_unfinished_owner_request_is_explicitly_unknown_not_zero() {
    let path=std::env::temp_dir().join(format!("aqua-owner-unknown-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    { let mut store=Store::open(Some(path.clone())).unwrap();store.change(|l|l.reserve("luke","m","2026-11-16",0,None)).unwrap(); }
    let restarted=Store::open(Some(path.clone())).unwrap();
    assert_eq!(restarted.ledger.users["luke"].unknown_requests,1);
    drop(restarted);let _=std::fs::remove_file(path);
}

#[test]
fn reviewer_alias_must_not_allow_two_owners_of_same_ledger() {
    let dir = std::env::temp_dir().join(format!("aqua-review-lockalias-{}",std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let real = dir.join("state.json");
    let alias = dir.join("alias.json");
    let mut first = Store::open(Some(real.clone())).unwrap();
    first.change(|l|l.reserve("sam","m","2026-11-16",1,Some(FRIEND_CAPS))).unwrap();
    std::os::unix::fs::symlink(&real,&alias).unwrap();
    let second = Store::open(Some(alias));
    assert!(second.is_err(), "same ledger accepted through symlink with a different lock path");
}


#[cfg(unix)]
#[test]
fn parent_directory_symlink_cannot_create_a_second_ledger_budget() {
    let dir=std::env::temp_dir().join(format!("aqua-parent-alias-{}",std::process::id()));
    std::fs::create_dir_all(dir.join("real")).unwrap();
    std::os::unix::fs::symlink(dir.join("real"),dir.join("alias")).unwrap();
    // The ledger does not exist yet: parent canonicalization must still work.
    let first=Store::open(Some(dir.join("real/state.json"))).unwrap();
    assert!(Store::open(Some(dir.join("alias/state.json"))).is_err());
    drop(first);let _=std::fs::remove_dir_all(dir);
}

#[test]
fn account_reservations_share_owner_friend_and_neuron_budgets() {
    let mut l=Ledger::default();
    l.admit_account("cloudflare","2026-11-17","sam",false,"glm",8_000_000_000,10_000_000_000,8_000_000_000,5,60).unwrap();
    assert!(l.admit_account("cloudflare","2026-11-17","jane",false,"glm",1,10_000_000_000,8_000_000_000,5,60).is_err());
    l.admit_account("cloudflare","2026-11-17","luke",true,"glm",2_000_000_000,10_000_000_000,8_000_000_000,5,60).unwrap();
    assert!(l.admit_account("cloudflare","2026-11-17","luke",true,"glm",1,10_000_000_000,8_000_000_000,5,60).is_err());
    assert!(l.admit_account("cloudflare","2026-11-16","luke",true,"glm",1,10_000_000_000,8_000_000_000,5,60).is_err());
    l.admit_account("cloudflare","2026-11-18","sam",false,"glm",1,10_000_000_000,8_000_000_000,5,60).unwrap();
    assert_eq!(l.accounts["cloudflare"].total,1);
}
#[test]
fn account_call_fairness_does_not_reset_on_model_switch() {
    let mut l=Ledger::default();
    for model in ["a","b","c"] {l.admit_account("openrouter","2026-11-17","sam",false,model,1,40,40,3,10).unwrap();}
    assert!(l.admit_account("openrouter","2026-11-17","sam",false,"d",1,40,40,3,10).is_err());
    assert_eq!(l.accounts["openrouter"].total,3);
}
#[test]
fn account_admission_is_atomic_at_last_slot_under_concurrency() {
    let store=std::sync::Arc::new(std::sync::Mutex::new(Store::open(None).unwrap()));
    let mut workers=vec![];
    for n in 0..16 {let store=store.clone();workers.push(std::thread::spawn(move||store.lock().unwrap().change(|l|l.admit_account("openrouter","2026-11-17",&format!("user{n}"),false,"free",1,1,1,3,10)).is_ok()));}
    assert_eq!(workers.into_iter().filter_map(|w|w.join().ok()).filter(|ok|*ok).count(),1);
    assert_eq!(store.lock().unwrap().ledger.accounts["openrouter"].total,1);
}
#[test]
fn account_bounds_error_has_no_partial_mutation() {
    let mut l=Ledger::default();
    l.admit_account("cloudflare","2026-11-17","luke",true,"glm",u64::MAX,u64::MAX,0,5,60).unwrap();
    assert!(l.admit_account("cloudflare","2026-11-17","luke",true,"glm",1,u64::MAX,0,5,60).is_err());
    assert_eq!(l.accounts["cloudflare"].total,u64::MAX);
    assert_eq!(l.accounts["cloudflare"].users["luke"],1);
}
