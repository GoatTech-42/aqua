//! Passive route observations only. No probes, persistence or quota changes.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde_json::{json, Value};

pub const FRESHNESS_SECONDS: u64 = 900;
const MAX_ROUTES: usize = 1024;
type Route = (String, String, String); // provider, canonical model, upstream binding
#[derive(Clone, Copy)]
struct Stamp { monotonic: Instant, unix: u64 }
impl Stamp {
    fn now() -> Self { Self { monotonic: Instant::now(), unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) } }
}
#[derive(Default)]
struct Observation {
    last_attempt: Option<Stamp>,
    last_code: Option<u16>,
    last_exact_200: Option<Stamp>,
    last_failure: Option<Stamp>,
    last_outcome: Option<(Stamp, bool)>,
}
#[derive(Default)]
pub struct Tracker { routes: HashMap<Route, Observation> }
impl Tracker {
    fn row(&mut self, provider: &str, model: &str, upstream: &str) -> Option<&mut Observation> {
        if [provider,model,upstream].iter().any(|v|v.len()>256) { return None; }
        let key = (provider.into(),model.into(),upstream.into());
        if self.routes.len()>=MAX_ROUTES && !self.routes.contains_key(&key) { return None; }
        Some(self.routes.entry(key).or_default())
    }
    pub fn attempt(&mut self, p:&str, m:&str, u:&str) {
        if let Some(row)=self.row(p,m,u) { row.last_attempt=Some(Stamp::now()); }
    }
    pub fn header(&mut self, p:&str, m:&str, u:&str, code:u16) {
        if let Some(row)=self.row(p,m,u) {
            row.last_code=Some(code);
            if code==200 { row.last_exact_200=Some(Stamp::now()); }
        }
    }
    // A 200 with invalid JSON/SSE is not a usable healthy route. We still retain
    // its exact-200 timestamp separately, without claiming successful generation.
    pub fn finish(&mut self, p:&str, m:&str, u:&str, healthy:bool) {
        if let Some(row)=self.row(p,m,u) {
            let stamp=Stamp::now();
            if !healthy { row.last_failure=Some(stamp); }
            row.last_outcome=Some((stamp,healthy));
        }
    }
    pub fn transport_failure(&mut self, p:&str, m:&str, u:&str) {
        if let Some(row)=self.row(p,m,u) { row.last_code=None; }
        self.finish(p,m,u,false);
    }
    pub fn aggregate<'a>(&self, bindings:impl Iterator<Item=(&'a str,&'a str,&'a str)>) -> Value {
        self.aggregate_at(bindings,Instant::now())
    }
    fn aggregate_at<'a>(&self, bindings:impl Iterator<Item=(&'a str,&'a str,&'a str)>, now:Instant) -> Value {
        let mut seen=HashSet::new();
        let (mut healthy,mut failed,mut unknown)=(0usize,0usize,0usize);
        let mut observed_at=None;
        for (p,m,u) in bindings {
            let key=(p.to_string(),m.to_string(),u.to_string());
            if !seen.insert(key.clone()) { continue; }
            match self.routes.get(&key).and_then(|r|r.last_outcome) {
                Some((stamp,ok)) => {
                    observed_at=Some(observed_at.map_or(stamp.unix,|v:u64|v.max(stamp.unix)));
                    if now.checked_duration_since(stamp.monotonic).is_some_and(|age|age<Duration::from_secs(FRESHNESS_SECONDS)) {
                        if ok { healthy+=1; } else { failed+=1; }
                    } else { unknown+=1; }
                }
                None=>unknown+=1,
            }
        }
        let total=healthy+failed+unknown;
        let status=if healthy>0 { if failed>0 {"degraded"}else{"healthy"} }
            else if failed>0 && failed==total {"down"}else{"unknown"};
        json!({"status":status,"eligible_routes":total,"healthy_routes":healthy,"failed_routes":failed,"unknown_routes":unknown,"observed_at":observed_at,"freshness_seconds":FRESHNESS_SECONDS})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bindings()->std::array::IntoIter<(&'static str,&'static str,&'static str),2> {[("one","model","v1"),("two","model","v2")].into_iter()}
    #[test] fn starts_unknown_never_assumes_configured_means_healthy(){let t=Tracker::default();let v=t.aggregate(bindings());assert_eq!(v["status"],"unknown");assert_eq!(v["unknown_routes"],2);assert!(v["observed_at"].is_null());}
    #[test] fn mixed_then_all_failed_then_recovery(){let mut t=Tracker::default();t.header("one","model","v1",200);t.finish("one","model","v1",true);assert_eq!(t.aggregate(bindings())["status"],"healthy");t.header("two","model","v2",503);t.finish("two","model","v2",false);assert_eq!(t.aggregate(bindings())["status"],"degraded");t.transport_failure("one","model","v1");assert_eq!(t.aggregate(bindings())["status"],"down");t.header("two","model","v2",200);t.finish("two","model","v2",true);assert_eq!(t.aggregate(bindings())["status"],"degraded");}
    #[test] fn failed_plus_unobserved_is_unknown_not_down(){let mut t=Tracker::default();t.finish("one","model","v1",false);assert_eq!(t.aggregate(bindings())["status"],"unknown");}
    #[test] fn stale_at_exact_boundary_and_empty_are_unknown(){let mut t=Tracker::default();t.finish("one","model","v1",true);let now=t.routes.values().next().unwrap().last_outcome.unwrap().0.monotonic+Duration::from_secs(900);assert_eq!(t.aggregate_at(bindings(),now)["status"],"unknown");assert_eq!(t.aggregate(std::iter::empty())["eligible_routes"],0);}
    #[test] fn deduplicates_and_never_leaks_identifiers(){let t=Tracker::default();let v=t.aggregate([("private-provider","model","private-upstream"),("private-provider","model","private-upstream")].into_iter());assert_eq!(v["eligible_routes"],1);assert!(!v.to_string().contains("private"));}
    #[test] fn invalid_200_retains_code_but_is_not_healthy(){let mut t=Tracker::default();t.attempt("one","model","v1");t.header("one","model","v1",200);t.finish("one","model","v1",false);let row=t.routes.values().next().unwrap();assert_eq!(row.last_code,Some(200));assert!(row.last_exact_200.is_some());assert!(row.last_failure.is_some());assert_eq!(t.aggregate(bindings())["healthy_routes"],0);}
    #[test] fn route_store_is_bounded_and_existing_rows_still_update(){let mut t=Tracker::default();for n in 0..1100{t.attempt("p","m",&n.to_string());}assert_eq!(t.routes.len(),1024);t.header("p","m","0",200);assert_eq!(t.routes.get(&("p".into(),"m".into(),"0".into())).unwrap().last_code,Some(200));}
    #[test] fn late_attempt_does_not_clear_recent_success(){let mut t=Tracker::default();t.header("one","model","v1",200);t.finish("one","model","v1",true);t.attempt("one","model","v1");assert_eq!(t.aggregate(bindings())["healthy_routes"],1);}
}
