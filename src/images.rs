//! Owner image API core. Network connectors are deliberately qualification-locked.
//! This module does not contain an HTTP client, an artifact store, or a decoder.
//! Enabling config alone cannot dispatch until those components are reviewed.
use serde::Deserialize;
use serde_json::{json,Value};
use std::collections::HashMap;
use std::time::{Duration,Instant};

pub const MAX_BODY:usize=8192;
pub const CLASSIC_INTERVAL:Duration=Duration::from_secs(45);
pub const REQUEST_BUDGET:Duration=Duration::from_secs(180);
#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    pub model:String,
    pub prompt:String,
    #[serde(default="one")] pub n:u8,
    #[serde(default="size")] pub size:String,
    #[serde(default="format")] pub response_format:String,
}
fn one()->u8{1}
fn size()->String{"512x512".into()}
fn format()->String{"b64_json".into()}
impl Generation {
    pub fn parse(body:&[u8])->Result<Self,Failure>{
        if body.len()>MAX_BODY{return Err(Failure::Invalid)}
        let v:Self=serde_json::from_slice(body).map_err(|_|Failure::Invalid)?;
        if v.model!="image-auto" || v.prompt.trim().is_empty() || v.prompt.chars().count()>2048
            || v.prompt.len()>4096 || v.prompt.chars().any(|c|c=='\0')
            || v.n!=1 || v.size!="512x512" || v.response_format!="b64_json" {return Err(Failure::Invalid)}
        Ok(v)
    }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Failure {Invalid,Owner,Privacy,Unavailable,Busy,Rate,Deadline,Payment,Moderation,Media,Transport}
impl Failure {
    pub fn response(self)->(u16,Value){
        let (status,message,kind)=match self {
            Self::Invalid=>(400,"unsupported image request","invalid_request_error"),
            Self::Owner=>(403,"owner access required","auth_error"),
            Self::Privacy=>(403,"no image route meets the account privacy setting","privacy_error"),
            Self::Unavailable=>(503,"no qualified free image provider is enabled","image_unavailable"),
            Self::Busy|Self::Rate=>(429,"image generation is rate limited","rate_limit_error"),
            Self::Deadline=>(504,"image generation deadline exceeded","timeout_error"),
            Self::Payment=>(503,"free image provider unavailable","image_unavailable"),
            Self::Moderation=>(400,"image request refused","content_policy_error"),
            Self::Media|Self::Transport=>(502,"image generation failed","upstream_error"),
        };
        (status,json!({"error":{"message":message,"type":kind}}))
    }
    pub fn may_fallback(self)->bool{matches!(self,Self::Transport|Self::Media)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Hash)]
pub enum Lane{Classic,Horde}
impl Lane {
    // Explicitly not verified end-to-end ZDR. No default-to-true privacy.
    fn permits_strict(self)->bool{false}
}
#[derive(Default)]
pub struct Switches {pub classic:bool,pub horde:bool}
impl Switches {
    pub fn from_env()->Self {
        let yes=|k:&str|std::env::var(k).ok().as_deref()==Some("1");
        Self{classic:yes("AQUA_IMAGES_CLASSIC"),horde:yes("AQUA_IMAGES_HORDE")}
    }
    pub fn qualified_lanes(&self,_strict:bool)->Vec<Lane>{
        // Deliberate hard gate, not a secret env override. Future change needs
        // decoder, SSRF-safe storage download, policies, durable cooldown review.
        let _requested=(self.classic,self.horde);Vec::new()
    }
}

// Pure admission/routing policy for future reviewed transports. No provider I/O.
// Production endpoint below does NOT call these while qualification is locked.
#[derive(Default)]
pub struct Policy {
    active:bool,
    recent:Vec<Instant>,
    classic_last:Option<Instant>,
    latency:HashMap<Lane,u64>,
}
impl Policy {
    pub fn admit(&mut self,now:Instant)->Result<(),Failure>{
        if self.active{return Err(Failure::Busy)}
        self.recent.retain(|t|now.saturating_duration_since(*t)<Duration::from_secs(60));
        if self.recent.len()>=2{return Err(Failure::Rate)}
        self.active=true;self.recent.push(now);Ok(())
    }
    pub fn release(&mut self){self.active=false}
    pub fn before_classic(&mut self,now:Instant,durable_written:bool)->Result<(),Failure>{
        // A future caller MUST durably reserve the public-egress-IP cooldown
        // before starting HTTP. Restart alone cannot erase that reservation.
        if !durable_written{return Err(Failure::Unavailable)}
        if self.classic_last.is_some_and(|t|now.saturating_duration_since(t)<CLASSIC_INTERVAL){return Err(Failure::Rate)}
        self.classic_last=Some(now);Ok(())
    }
    pub fn order(&self,lanes:&[Lane],strict:bool)->Vec<Lane>{
        let mut out:Vec<_>=lanes.iter().copied().filter(|p|!strict||p.permits_strict()).collect();
        out.sort_by_key(|p|self.latency.get(p).copied().unwrap_or(u64::MAX));out
    }
    pub fn completed_validated_image(&mut self,lane:Lane,elapsed:Duration){
        // Caller must include queue, status and full image download+validation.
        // HTTP202 and header/error responses must never reach this method.
        let us=elapsed.as_micros().min(u64::MAX as u128)as u64;
        self.latency.entry(lane).and_modify(|old|*old=(*old/4)*3+us/4).or_insert(us);
    }
    pub fn remaining(start:Instant,now:Instant)->Result<Duration,Failure>{
        REQUEST_BUDGET.checked_sub(now.saturating_duration_since(start)).filter(|d|!d.is_zero()).ok_or(Failure::Deadline)
    }
}

pub fn unavailable(body:&[u8],owner:bool,strict:bool,switches:&Switches)->(u16,Value){
    let result=(||{
        if !owner{return Err(Failure::Owner)}
        let _request=Generation::parse(body)?;
        if strict{return Err(Failure::Privacy)}
        let _lanes=switches.qualified_lanes(strict);
        // No network connector exists in this packet, even if switches say1.
        Err::<(),_>(Failure::Unavailable)
    })();
    result.unwrap_err().response()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid()->Vec<u8>{br#"{"model":"image-auto","prompt":"a mug"}"#.to_vec()}
    #[test] fn schema_is_an_explicit_bounded_subset(){
        let r=Generation::parse(&valid()).unwrap();assert_eq!(r.n,1);assert_eq!(r.size,"512x512");assert_eq!(r.response_format,"b64_json");
        for raw in [r#"{"model":"flux","prompt":"x"}"#,r#"{"model":"auto","prompt":"x"}"#,r#"{"model":"image-auto","prompt":"x","n":2}"#,r#"{"model":"image-auto","prompt":"x","size":"1024x1024"}"#,r#"{"model":"image-auto","prompt":"x","response_format":"url"}"#,r#"{"model":"image-auto","prompt":"x","tools":[]}"#,r#"{"model":"image-auto","prompt":" "}"#,r#"{"model":"image-auto","prompt":"x","n":true}"#,r#"{"model":"image-auto","model":"flux","prompt":"x"}"#] {assert_eq!(Generation::parse(raw.as_bytes()).unwrap_err(),Failure::Invalid)}
        assert!(Generation::parse(&[255]).is_err());assert!(Generation::parse(&vec![b' ';8193]).is_err());
        for s in ["x".repeat(2049),"🦀".repeat(1025)]{assert!(Generation::parse(&serde_json::to_vec(&json!({"model":"image-auto","prompt":s})).unwrap()).is_err())}
    }
    #[test] fn off_or_unqualified_never_dispatches(){
        for switches in [Switches::default(),Switches{classic:true,horde:true}]{
            assert!(switches.qualified_lanes(false).is_empty());assert!(switches.qualified_lanes(true).is_empty());
            assert_eq!(unavailable(&valid(),true,false,&switches).0,503);
            assert_eq!(unavailable(&valid(),true,true,&switches).0,403);
            assert_eq!(unavailable(&valid(),false,false,&switches).0,403);
        }
    }
    #[test] fn privacy_filters_before_any_future_dispatch(){let p=Policy::default();assert!(p.order(&[Lane::Classic,Lane::Horde],true).is_empty())}
    #[test] fn admission_and_egress_cooldown_are_separate_and_bounded(){
        let mut p=Policy::default();let t=Instant::now();p.admit(t).unwrap();assert_eq!(p.admit(t),Err(Failure::Busy));p.release();p.admit(t).unwrap();p.release();assert_eq!(p.admit(t),Err(Failure::Rate));assert_eq!(p.recent.len(),2);
        assert_eq!(p.before_classic(t,false),Err(Failure::Unavailable));p.before_classic(t,true).unwrap();assert_eq!(p.before_classic(t+Duration::from_secs(44),true),Err(Failure::Rate));p.before_classic(t+Duration::from_secs(45),true).unwrap();
    }
    #[test] fn ranking_uses_validated_full_ready_and_stable_unknown_order(){
        let mut p=Policy::default();assert_eq!(p.order(&[Lane::Classic,Lane::Horde],false),vec![Lane::Classic,Lane::Horde]);
        p.completed_validated_image(Lane::Horde,Duration::from_secs(68));p.completed_validated_image(Lane::Classic,Duration::from_secs(7));assert_eq!(p.order(&[Lane::Horde,Lane::Classic],false),vec![Lane::Classic,Lane::Horde]);assert_eq!(p.latency.len(),2);
    }
    #[test] fn no_payment_moderation_or_fresh_deadline_fallback(){
        assert!(!Failure::Payment.may_fallback());assert!(!Failure::Privacy.may_fallback());assert!(!Failure::Moderation.may_fallback());assert!(Failure::Transport.may_fallback());
        let t=Instant::now();assert_eq!(Policy::remaining(t,t+Duration::from_secs(179)).unwrap(),Duration::from_secs(1));assert_eq!(Policy::remaining(t,t+Duration::from_secs(180)),Err(Failure::Deadline));
    }
}

// Fixture-backed submission boundary, not an async network implementation.
// Caller must acquire current privacy/disconnect state under its own shared
// lock immediately before each external prompt-bearing action. A toggle after
// this boundary cannot retract a send. No retrospective ZDR promise is made.
#[derive(Default)]
pub struct Flow { submitted:bool, cancelled:bool }
impl Flow {
    pub fn before_prompt_action(&mut self,strict_now:bool,disconnected:bool,start:Instant,now:Instant)->Result<(),Failure>{
        if disconnected || Policy::remaining(start,now).is_err(){self.cancelled=self.submitted;return Err(Failure::Deadline)}
        if strict_now {self.cancelled=self.submitted;return Err(Failure::Privacy)}
        Ok(())
    }
    pub fn sent(&mut self){self.submitted=true}
    pub fn cancel_due(&self)->bool{self.cancelled}
}
#[cfg(test)]
mod flow_tests {
    use super::*;
    #[test] fn strict_toggle_queued_or_between_candidates_stops_further_submissions(){
        let t=Instant::now();let mut queued=Flow::default();assert_eq!(queued.before_prompt_action(true,false,t,t),Err(Failure::Privacy));assert!(!queued.cancel_due());
        let mut f=Flow::default();f.before_prompt_action(false,false,t,t).unwrap();f.sent();assert_eq!(f.before_prompt_action(true,false,t,t+Duration::from_secs(2)),Err(Failure::Privacy));assert!(f.cancel_due());
    }
    #[test] fn disconnect_and_deadline_mark_owned_job_for_best_effort_cancel(){
        let t=Instant::now();for disconnected in [false,true]{let mut f=Flow::default();f.sent();let now=if disconnected{t}else{t+REQUEST_BUDGET};assert_eq!(f.before_prompt_action(false,disconnected,t,now),Err(Failure::Deadline));assert!(f.cancel_due());}
    }
          }
