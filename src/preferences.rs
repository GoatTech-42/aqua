//! Account preferences. A privacy preference is enforced on the server, not just in the picker.
use serde::{Deserialize,Serialize};

#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub zdr_only: bool,
    pub default_model: String,
    pub show_cost: bool,
}
impl Default for Preferences {
    fn default()->Self {Self {zdr_only:false,default_model:"auto".into(),show_cost:true}}
}
impl Preferences {
    pub fn valid(&self)->bool {
        !self.default_model.is_empty() && self.default_model.len()<=128 &&
            self.default_model.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_.:/".contains(&b))
    }
}

#[derive(Clone,Copy,Serialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum Retention { VerifiedRoute, NonZdr, Unknown }

// No route has a reviewed end-to-end retention contract and current configuration
// in this source revision. Broker-only claims never satisfy a strict preference.
pub fn retention(provider:&str)->Retention {
    match provider { "logfare"|"radeon"|"nim"=>Retention::NonZdr,_=>Retention::Unknown }
}
pub fn facts(provider:&str)->serde_json::Value {
    let sources=match provider {
        "logfare"=>vec!["https://logfare.ai/privacy","https://logfare.ai/tos"],
        "radeon"=>vec!["https://amd-aim.github.io/radeon-cloud-docs/api/terms/"],
        "nim"=>vec!["https://assets.ngc.nvidia.com/products/api-catalog/legal/NVIDIA%20API%20Trial%20Terms%20of%20Service.pdf"],
        "zro"=>vec!["https://zro.moonmath.ai/privacy","https://zro.moonmath.ai/docs/privacy"],
        "orcarouter"=>vec!["https://docs.orcarouter.ai/operations/zero-data-retention","https://docs.orcarouter.ai/privacy/provider-retention"],
        "nextrouter"=>vec!["https://nextrouter.me/","https://nextrouter.me/v1/models"],
        "hmsrelay"=>vec!["https://100milionseek.top/privacy","https://100milionseek.top/terms"],
        "pollinations"=>vec!["https://pollinations.ai/privacy","https://pollinations.ai/terms","https://text.pollinations.ai/models"],
        "sambanova"=>vec!["https://docs.sambanova.ai/docs/en/models/rate-limits","https://docs.sambanova.ai/docs/en/models/sambacloud-models"],
        "gonka"=>vec!["https://docs.gonkabroker.com/support/faq/"],
        "cloudflare"=>vec!["https://developers.cloudflare.com/workers-ai/platform/data-usage/"],
        _=>vec![],
    };
    serde_json::json!({"status":retention(provider),"sources":sources,"warning":match provider {"pollinations"=>Some("Anonymous shared-IP tier, upstream OVH retention not independently verified; JSON only"),"nextrouter"=>Some("Unverified model relay; upstream origin and retention unverified"),"hmsrelay"=>Some("Unverified third-party relay; upstream retention unknown"),"sambanova"=>Some("Preview: owner evaluation only, not production;20 requests/day, no payment method"),_=>None},"checked_at":if provider=="pollinations" {Some("2026-11-21T21:14:00Z")}else if matches!(provider,"hmsrelay"|"sambanova"|"nextrouter"){Some("2026-11-20T23:12:00Z")}else if sources.is_empty(){None}else{Some("2026-11-17T02:46:00Z")}})
}
pub fn allows(provider:&str, strict:bool)->bool {
    !strict || matches!(retention(provider),Retention::VerifiedRoute)
}
