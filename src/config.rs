use std::collections::HashMap;
use std::collections::HashSet;

use crate::auth::OAuthConfig;

// reserved public alias: "auto" never maps to an upstream model id directly.
// It resolves through the configured coding shortlist (AQUA_AUTO_SHORTLIST),
// model by model, provider by provider. A provider-side "free router" id must
// never be wired to this name: that would delegate model choice (and model
// quality) to the provider, bypassing the shortlist.
pub const AUTO_ALIAS: &str = "auto";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Off,      // never called
    Personal, // owner keys only
    Friends,  // any valid gateway key
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Off => "off",
            Status::Personal => "personal",
            Status::Friends => "friends",
        }
    }
    fn parse(s: &str) -> Option<Status> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Some(Status::Off),
            "enabled" | "personal" => Some(Status::Personal),
            "friends" => Some(Status::Friends),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Owner,
    Friend,
}

#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub name: String,
    pub role: Role,
}

// public: the model name clients see and request (model maker/name is public).
// upstream: the id sent to the provider (never leaves the gateway).
// context: verified context window in tokens, when the provider lane has
// confirmed it. Used only for sound rejections (a requested max_tokens larger
// than the window can never succeed); never used to estimate prompt size.
// Two entries on different providers with the same public name are bindings
// of one canonical model - the provider lane must verify the upstream ids
// really are the same model variant; this code cannot prove that.
#[derive(Clone, Debug)]
pub struct ModelEntry {
    pub public: String,
    pub upstream: String,
    pub context: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub id: String,
    pub base_url: String,
    pub api_key: String,
    pub models: Vec<ModelEntry>,
    pub status: Status,
}

impl Provider {
    pub(crate) fn configured(&self) -> bool {
        if self.id=="pollinations" {
            self.base_url=="https://text.pollinations.ai" && !self.models.is_empty() && self.models.iter().all(|m|
                m.public=="gpt-oss-20b" && m.upstream=="openai-fast")
        } else { !self.api_key.is_empty() }
    }
}

/// Handler admission limits. Normalized on use, including programmatic configs.
#[derive(Clone, Debug)]
pub struct ConnectionLimits {
    pub total: usize,
    pub reserve: usize,
}
impl Default for ConnectionLimits {
    fn default() -> Self { Self { total: 64, reserve: 8 } }
}
impl ConnectionLimits {
    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            total: lookup("AQUA_MAX_CONNECTIONS").and_then(|v| v.parse().ok()).unwrap_or(64),
            reserve: lookup("AQUA_CONTROL_RESERVE").and_then(|v| v.parse().ok()).unwrap_or(8),
        }
    }
    pub fn total(&self) -> usize { self.total.clamp(2, 1024) }
    pub fn ordinary(&self) -> usize {
        self.total() - self.reserve.clamp(1, self.total() - 1)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuthThrottle {
    pub failures: u32,
    pub window_secs: u64,
    pub entries: usize,
}
impl Default for AuthThrottle {
    fn default() -> Self { Self {failures:5, window_secs:60, entries:10_000} }
}
impl AuthThrottle {
    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            failures: lookup("AQUA_AUTH_FAILURE_LIMIT").and_then(|v|v.parse().ok()).unwrap_or(5),
            window_secs: lookup("AQUA_AUTH_WINDOW_SECS").and_then(|v|v.parse().ok()).unwrap_or(60),
            entries: lookup("AQUA_AUTH_FAILURE_ENTRIES").and_then(|v|v.parse().ok()).unwrap_or(10_000),
        }
    }
    pub fn failures(self) -> u32 { self.failures.clamp(1,1_000) }
    pub fn window(self) -> std::time::Duration { std::time::Duration::from_secs(self.window_secs.clamp(1,3_600)) }
    pub fn entries(self) -> usize { self.entries.clamp(1,100_000) }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub auth_throttle: AuthThrottle,
    pub backoff: Backoff,
    pub connections: ConnectionLimits,
    pub keys: HashMap<String, KeyEntry>,
    pub admin_key: String,
    pub daily_limit: u32,
    pub allowed_origin: String,
    pub providers: Vec<Provider>,
    pub oauth: OAuthConfig,
    pub spend: crate::spend::Settings,
    // ordered canonical model names the "auto" alias walks, model first,
    // then every eligible provider carrying that model. Empty: auto disabled.
    pub auto_shortlist: Vec<String>,
    // aggregate deadline shared by ALL fallback attempts of one client
    // request: a 300s stall on every candidate must not multiply
    pub upstream_budget: std::time::Duration,
    // idle floor for a single upstream exchange: any socket read (response
    // headers or body chunk) that stalls longer than this fails the attempt.
    // ureq's per-read timeout restarts on every successful read, so a
    // drip-feeding upstream making progress faster than this window survives
    // (bounded only by upstream_budget); a stuck one is cut here.
    pub upstream_idle: std::time::Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    pub missing_429_secs: u64,
    pub retry_after_max_secs: u64,
    pub soft_secs: u64,
}
impl Default for Backoff {
    fn default() -> Self {
        Self { missing_429_secs: 60, retry_after_max_secs: 3600, soft_secs: 15 }
    }
}
impl Backoff {
    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        let mut read = |name: &str, fallback| lookup(name)
            .and_then(|v| v.parse::<u64>().ok()).unwrap_or(fallback).clamp(1, 3600);
        Self {
            missing_429_secs: read("AQUA_BACKOFF_429_SECS", defaults.missing_429_secs),
            retry_after_max_secs: read("AQUA_BACKOFF_RETRY_AFTER_MAX_SECS", defaults.retry_after_max_secs),
            soft_secs: read("AQUA_BACKOFF_SOFT_SECS", defaults.soft_secs),
        }
    }
    // Bound at use too: synthetic/test configs cannot overflow Instant math
    // or disable mandatory blocking with zero, regardless of env parsing.
    pub fn missing_429_secs(self) -> u64 { self.missing_429_secs.clamp(1, 3600) }
    pub fn retry_after_secs(self, parsed: u64) -> u64 {
        parsed.clamp(1, self.retry_after_max_secs.clamp(1, 3600))
    }
    pub fn soft_secs(self) -> u64 { self.soft_secs.clamp(1, 3600) }
}

#[cfg(test)]
mod backoff_config_tests {
    use super::Backoff;
    #[test]
    fn backoff_lookup_defaults_and_invalids_are_safe() {
        let d = Backoff::default();
        assert_eq!(Backoff::from_lookup(|_| None), d);
        for bad in ["", "soon", "+not-number", "-1", "18446744073709551616"] {
            assert_eq!(Backoff::from_lookup(|_| Some(bad.into())), d);
        }
    }
    #[test]
    fn backoff_lookup_uses_exact_knobs_and_bounds() {
        let custom = Backoff::from_lookup(|name| Some(match name {
            "AQUA_BACKOFF_429_SECS" => "17",
            "AQUA_BACKOFF_RETRY_AFTER_MAX_SECS" => "42",
            "AQUA_BACKOFF_SOFT_SECS" => "9",
            _ => panic!("unexpected lookup {name}"),
        }.into()));
        assert_eq!(custom, Backoff { missing_429_secs:17, retry_after_max_secs:42, soft_secs:9 });
        assert_eq!(custom.retry_after_secs(120), 42);
        assert_eq!(Backoff::from_lookup(|_| Some("0".into())), Backoff { missing_429_secs:1, retry_after_max_secs:1, soft_secs:1 });
        assert_eq!(Backoff::from_lookup(|_| Some(u64::MAX.to_string())), Backoff { missing_429_secs:3600, retry_after_max_secs:3600, soft_secs:3600 });
        let wild = Backoff { missing_429_secs:u64::MAX, retry_after_max_secs:u64::MAX, soft_secs:0 };
        assert_eq!(wild.missing_429_secs(),3600);
        assert_eq!(wild.retry_after_secs(u64::MAX),3600);
        assert_eq!(wild.soft_secs(),1);
    }
}

struct RegistryEntry {
    id: &'static str,
    base_url: &'static str,
    base_url_env: Option<&'static str>,
    key_env: &'static str,
    models_env: Option<&'static str>,
}

// Every provider ships OFF. A "free" label on a registry row is not proof a
// route costs nothing: enable with AQUA_STATUS_<ID> only after the provider
// lane has verified cost (no credits, no metered billing) and terms.
const REGISTRY: &[RegistryEntry] = &[
    RegistryEntry { id:"pollinations", base_url:"https://text.pollinations.ai", base_url_env:None, key_env:"", models_env:Some("POLLINATIONS_MODELS") },
    RegistryEntry { id:"nextrouter", base_url:"https://nextrouter.me/v1", base_url_env:None, key_env:"NEXTROUTER_API_KEY", models_env:Some("NEXTROUTER_MODELS") },
    RegistryEntry {
        id: "openrouter",
        base_url: "https://openrouter.ai/api/v1",
        base_url_env: None,
        key_env: "OPENROUTER_API_KEY",
        models_env: Some("OPENROUTER_MODELS"),
    },
    RegistryEntry {
        id: "zro",
        base_url: "https://zro.moonmath.ai/v1",
        base_url_env: None,
        key_env: "ZRO_API_KEY",
        models_env: Some("ZRO_MODELS"),
    },
    RegistryEntry {
        id: "orcarouter",
        base_url: "https://api.orcarouter.ai/v1",
        base_url_env: None,
        key_env: "ORCAROUTER_API_KEY",
        models_env: Some("ORCAROUTER_MODELS"),
    },
    RegistryEntry {
        id: "zai",
        base_url: "https://api.z.ai/api/paas/v4",
        base_url_env: None,
        key_env: "ZAI_API_KEY",
        models_env: Some("ZAI_MODELS"),
    },
    RegistryEntry {
        id: "inferbase",
        base_url: "https://api.inferbase.ai/v1",
        base_url_env: None,
        key_env: "INFERBASE_API_KEY",
        models_env: Some("INFERBASE_MODELS"),
    },
    RegistryEntry {
        id: "logfare",
        base_url: "https://logfare.ai/v1",
        base_url_env: None,
        key_env: "LOGFARE_API_KEY",
        models_env: Some("LOGFARE_MODELS"),
    },
    RegistryEntry {
        id: "nim",
        base_url: "https://integrate.api.nvidia.com/v1",
        base_url_env: None,
        key_env: "NVIDIA_NIM_API_KEY",
        models_env: Some("NVIDIA_NIM_MODELS"),
    },
    RegistryEntry {
        id: "radeon",
        base_url: "https://developer.amd.com.cn/radeon/api/v1",
        base_url_env: None,
        key_env: "AMD_RADEON_API_KEY",
        models_env: Some("AMD_RADEON_MODELS"),
    },
    RegistryEntry {
        id: "cloudflare",
        // Workers AI's OpenAI-compatible endpoint carries the account id in
        // its path; the full base url comes from env so no account identifier
        // lands in the repo (same pattern as gonka)
        base_url: "",
        base_url_env: Some("CLOUDFLARE_AI_BASE_URL"),
        key_env: "CLOUDFLARE_API_TOKEN",
        models_env: Some("CLOUDFLARE_MODELS"),
    },
    RegistryEntry {
        id: "gonka",
        base_url: "",
        base_url_env: Some("GONKA_BASE_URL"),
        key_env: "GONKA_BROKER_API_KEY",
        models_env: Some("GONKA_MODELS"),
    },
    RegistryEntry {
        id: "hmsrelay",
        base_url: "https://100milionseek.top/v1",
        base_url_env: None,
        key_env: "HMSRELAY_API_KEY",
        models_env: Some("HMSRELAY_MODELS"),
    },
    RegistryEntry {
        id: "sambanova",
        base_url: "https://api.sambanova.ai/v1",
        base_url_env: None,
        key_env: "SAMBANOVA_API_KEY",
        models_env: Some("SAMBANOVA_MODELS"),
    },
];

pub fn parse_keys(value: Option<String>, role: Role, out: &mut HashMap<String, KeyEntry>) {
    for pair in value.unwrap_or_default().split(',') {
        let Some(i) = pair.find(':') else { continue };
        let name = pair[..i].trim().to_string();
        let key = pair[i + 1..].trim().to_string();
        // fail closed: empty or placeholder keys never authenticate
        if name.is_empty() || key.is_empty() || key.eq_ignore_ascii_case("change-me") {
            continue;
        }
        out.insert(key, KeyEntry { name, role });
    }
}

// AQUA_AUTO_SHORTLIST: "coder-alpha,coder-beta" - ordered, model-first.
// Names must be public model names from the enabled providers; unknown names
// are kept (config may enable the provider later) but resolve to nothing.
pub fn parse_shortlist(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(AUTO_ALIAS))
        .collect()
}

// AQUA_MODEL_META: "coder-alpha=128000,coder-beta=64000" - verified context
// window in tokens per public model name. Only sound metadata is stored here;
// a guessed number is worse than none.
pub fn parse_model_meta(value: Option<String>) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    for pair in value.unwrap_or_default().split(',') {
        let Some((name, ctx)) = pair.split_once('=') else { continue };
        let (name, ctx) = (name.trim(), ctx.trim());
        if name.is_empty() || name.eq_ignore_ascii_case(AUTO_ALIAS) {
            continue;
        }
        if let Ok(n) = ctx.parse::<u32>() {
            if n > 0 {
                out.insert(name.to_string(), n);
            }
        }
    }
    out
}

// One provider's model list, cleaned: no empty ids, no reserved alias, no
// public name carrying the provider id, no duplicates; verified context
// metadata attached by public name.
pub(crate) const NEXTROUTER_CHAT_MODELS: &[&str] = &["grok-4.7","Qwen4-Max-Preview","Qwen3.8-Max","muse-spark-open","kimi-k3.1-pro","claude-opus-5","claude-haiku-5.5","claude-haiku-3-5","claude-opus-5-5"];

pub fn sanitize_models(
    provider_id: &str,
    entries: Vec<ModelEntry>,
    meta: &HashMap<String, u32>,
) -> Vec<ModelEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for mut m in entries {
        if m.public.trim().is_empty() || m.upstream.trim().is_empty() {
            continue;
        }
        // Intake adapters are exact-model allowlists, not general catalogs.
        // Never turn an operator typo into a paid or unqualified fallback.
        let allowed = match provider_id {
            "nextrouter" => NEXTROUTER_CHAT_MODELS.contains(&m.upstream.as_str()),
            "orcarouter" => m.upstream == "deepseek/deepseek-v4.1-flash-free",
            "zai" => matches!(m.upstream.as_str(), "glm-4.7-flash" | "glm-4.5-flash"),
            "inferbase" => m.upstream == "deepseek-v4-flash",
            "hmsrelay" => m.upstream == "deepseek-v4.1-flash-free",
            "sambanova" => m.upstream == "gemma-4-31B-it",
            "pollinations" => m.public == "gpt-oss-20b" && m.upstream == "openai-fast",
            _ => true,
        };
        if !allowed { continue; }
        // the reserved alias must never be a concrete upstream binding
        if m.public.eq_ignore_ascii_case(AUTO_ALIAS) {
            continue;
        }
        // public names must never carry the provider id
        // Restore this exact known maker-model alias without relaxing the
        // provider-name filter for any other binding.
        let nim_minimax = provider_id=="nim" && m.public=="minimax-m3.1-flash"
            && m.upstream=="minimaxai/minimax-m3.1-flash";
        if m.public.contains(provider_id) && !nim_minimax {
            continue;
        }
        if !seen.insert(m.public.clone()) {
            continue;
        }
        m.context = meta.get(&m.public).copied();
        out.push(m);
    }
    out
}

fn parse_models_spec(spec: &str) -> Vec<ModelEntry> {
    // MODELS env: "public=upstream,public2=upstream2"
    spec.split(',')
        .filter_map(|pair| {
            let (a, b) = pair.split_once('=')?;
            let (a, b) = (a.trim(), b.trim());
            Some(ModelEntry {
                public: a.to_string(),
                upstream: b.to_string(),
                context: None,
            })
        })
        .collect()
}

pub fn from_env() -> Config {
    let env = |k: &str| std::env::var(k).ok();
    let mut keys = HashMap::new();
    parse_keys(env("AQUA_OWNER_KEYS"), Role::Owner, &mut keys);
    parse_keys(env("AQUA_FRIEND_KEYS"), Role::Friend, &mut keys);
    let users = |k: &str| {
        env(k)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    };
    let meta = parse_model_meta(env("AQUA_MODEL_META"));
    Config {
        auth_throttle: AuthThrottle::from_lookup(|name|env(name)),
        backoff: Backoff::from_lookup(|name| env(name)),
        connections: ConnectionLimits::from_lookup(|name| env(name)),
        spend: crate::spend::Settings::from_env(),
        keys,
        admin_key: env("AQUA_ADMIN_KEY").unwrap_or_default(),
        daily_limit: env("AQUA_DAILY_LIMIT").and_then(|v| v.parse().ok()).unwrap_or(200),
        allowed_origin: env("AQUA_ALLOWED_ORIGIN").unwrap_or_default(),
        auto_shortlist: parse_shortlist(env("AQUA_AUTO_SHORTLIST")),
        upstream_budget: env("AQUA_UPSTREAM_BUDGET_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            // sensible bounds: a wild env value can never panic the clock math
            .map(|n| n.clamp(1, 3600))
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(300)),
        upstream_idle: env("AQUA_UPSTREAM_IDLE_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            // sensible bounds: a wild env value can never panic the clock math
            .map(|n| n.clamp(1, 600))
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(60)),
        oauth: OAuthConfig {
            client_id: env("AQUA_GITHUB_CLIENT_ID").unwrap_or_default(),
            client_secret: env("AQUA_GITHUB_CLIENT_SECRET").unwrap_or_default(),
            public_url: env("AQUA_PUBLIC_URL")
                .unwrap_or_else(|| "http://localhost:8080".to_string())
                .trim_end_matches('/')
                .to_string(),
            console_url: env("AQUA_CONSOLE_URL")
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string(),
            owner_users: users("AQUA_GITHUB_OWNERS"),
            friend_users: users("AQUA_GITHUB_FRIENDS"),
            exchange_global: env("AQUA_GITHUB_TIMEOUT_SECS")
                .and_then(|v| v.parse::<u64>().ok())
                // sensible bounds: a wild env value can never panic the clock math
                .map(|n| n.clamp(1, 120))
                .map(std::time::Duration::from_secs),
            exchange_idle: env("AQUA_GITHUB_IDLE_SECS")
                .and_then(|v| v.parse::<u64>().ok())
                .map(|n| n.clamp(1, 60))
                .map(std::time::Duration::from_secs),
        },
        providers: REGISTRY
            .iter()
            .map(|p| {
                let base_url = match p.base_url_env {
                    Some(e) => env(e).unwrap_or_default(),
                    None => p.base_url.to_string(),
                };
                let raw = match p.models_env.and_then(|e| env(e)) {
                    Some(spec) => parse_models_spec(&spec),
                    None => Vec::new(),
                };
                let models = sanitize_models(p.id, raw, &meta);
                let status = env(&format!("AQUA_STATUS_{}", p.id.to_uppercase()))
                    .and_then(|s| Status::parse(&s))
                    .unwrap_or(Status::Off);
                Provider {
                    id: p.id.to_string(),
                    base_url,
                    api_key: if p.key_env.is_empty() {String::new()} else {env(p.key_env).unwrap_or_default()},
                    models,
                    status,
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod intake_registry_tests {
    use super::*;
    #[test]
    fn new_adapters_have_exact_nonsecret_wiring() {
        for (id, base, key, models) in [
            ("orcarouter", "https://api.orcarouter.ai/v1", "ORCAROUTER_API_KEY", "ORCAROUTER_MODELS"),
            ("zai", "https://api.z.ai/api/paas/v4", "ZAI_API_KEY", "ZAI_MODELS"),
            ("inferbase", "https://api.inferbase.ai/v1", "INFERBASE_API_KEY", "INFERBASE_MODELS"),
        ] {
            let row=REGISTRY.iter().find(|p|p.id==id).unwrap();
            assert_eq!(row.base_url,base);assert_eq!(row.key_env,key);assert_eq!(row.models_env,Some(models));
            assert_eq!(row.base_url_env,None);
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;

    const TIMEOUT_VARS: [&str; 3] = [
        "AQUA_UPSTREAM_IDLE_SECS",
        "AQUA_GITHUB_TIMEOUT_SECS",
        "AQUA_GITHUB_IDLE_SECS",
    ];

    // Restores the captured values on drop, including on panic, so a failed
    // assertion can never leak test values into the process env.
    struct EnvGuard(Vec<(&'static str, Option<String>)>);
    impl EnvGuard {
        fn capture(vars: &[&'static str]) -> Self {
            Self(vars.iter().map(|v| (*v, std::env::var(v).ok())).collect())
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    // Verified on this tree: no other test calls config::from_env or touches
    // these three vars, so this single-writer test faces no concurrent env
    // writer. Concurrent from_env READERS of disjoint vars are unaffected by
    // these mutations. If another env-writing test is ever added, guard all
    // of them with one shared mutex.
    #[test]
    fn timeout_env_clamps_and_defaults() {
        let _guard = EnvGuard::capture(&TIMEOUT_VARS);
        let [v_idle, v_gh_global, v_gh_idle] = TIMEOUT_VARS;
        for v in TIMEOUT_VARS { std::env::remove_var(v); }

        // unset: upstream idle resolves to its 60s default; the GitHub
        // knobs stay None so the agent builder's named consts apply
        let c = super::from_env();
        assert_eq!(c.upstream_idle, Duration::from_secs(60));
        assert_eq!(c.oauth.exchange_global, None);
        assert_eq!(c.oauth.exchange_idle, None);

        // garbage parses to the same defaults, never a panic
        for v in TIMEOUT_VARS { std::env::set_var(v, "not-a-number"); }
        let c = super::from_env();
        assert_eq!(c.upstream_idle, Duration::from_secs(60));
        assert_eq!(c.oauth.exchange_global, None);
        assert_eq!(c.oauth.exchange_idle, None);

        // in-range values pass through
        std::env::set_var(v_idle, "45");
        std::env::set_var(v_gh_global, "30");
        std::env::set_var(v_gh_idle, "20");
        let c = super::from_env();
        assert_eq!(c.upstream_idle, Duration::from_secs(45));
        assert_eq!(c.oauth.exchange_global, Some(Duration::from_secs(30)));
        assert_eq!(c.oauth.exchange_idle, Some(Duration::from_secs(20)));

        // below range clamps up to the floor, never zero
        std::env::set_var(v_idle, "0");
        std::env::set_var(v_gh_global, "0");
        std::env::set_var(v_gh_idle, "0");
        let c = super::from_env();
        assert_eq!(c.upstream_idle, Duration::from_secs(1));
        assert_eq!(c.oauth.exchange_global, Some(Duration::from_secs(1)));
        assert_eq!(c.oauth.exchange_idle, Some(Duration::from_secs(1)));

        // above range clamps down to the cap
        std::env::set_var(v_idle, "999999");
        std::env::set_var(v_gh_global, "999999");
        std::env::set_var(v_gh_idle, "999999");
        let c = super::from_env();
        assert_eq!(c.upstream_idle, Duration::from_secs(600));
        assert_eq!(c.oauth.exchange_global, Some(Duration::from_secs(120)));
        assert_eq!(c.oauth.exchange_idle, Some(Duration::from_secs(60)));
    }
}

#[cfg(test)]
mod connection_config_tests {
    use super::ConnectionLimits;
    #[test]
    fn lookup_and_programmatic_limits_are_always_bounded() {
        for invalid in [None, Some(""), Some("bad"), Some("-1"), Some("18446744073709551616")] {
            let limits=ConnectionLimits::from_lookup(|_| invalid.map(str::to_string));
            assert_eq!((limits.total(),limits.ordinary()),(64,56));
        }
        let custom=ConnectionLimits::from_lookup(|key| Some(match key {
            "AQUA_MAX_CONNECTIONS"=>"10", "AQUA_CONTROL_RESERVE"=>"3", _=>panic!("unknown knob"),
        }.into()));
        assert_eq!((custom.total(),custom.ordinary()),(10,7));
        for (total,reserve,want) in [(0,0,(2,1)),(usize::MAX,usize::MAX,(1024,1)),(10,0,(10,9)),(10,20,(10,1))] {
            let limits=ConnectionLimits {total,reserve};
            assert_eq!((limits.total(),limits.ordinary()),want);
        }
    }
}

#[cfg(test)]
mod auth_throttle_config_tests {
    use super::AuthThrottle;
    #[test]
    fn exact_knobs_defaults_invalids_and_extreme_values_are_bounded() {
        for bad in [None,Some(""),Some("bad"),Some("-1"),Some("18446744073709551616")] {
            let p=AuthThrottle::from_lookup(|_|bad.map(str::to_string));
            assert_eq!((p.failures(),p.window().as_secs(),p.entries()),(5,60,10000));
        }
        let p=AuthThrottle::from_lookup(|k|Some(match k {
            "AQUA_AUTH_FAILURE_LIMIT"=>"2","AQUA_AUTH_WINDOW_SECS"=>"17","AQUA_AUTH_FAILURE_ENTRIES"=>"3",_=>panic!("unexpected knob"),
        }.into()));assert_eq!((p.failures(),p.window().as_secs(),p.entries()),(2,17,3));
        for (p,want) in [(AuthThrottle{failures:0,window_secs:0,entries:0},(1,1,1)),(AuthThrottle{failures:u32::MAX,window_secs:u64::MAX,entries:usize::MAX},(1000,3600,100000))] {
            assert_eq!((p.failures(),p.window().as_secs(),p.entries()),want);
        }
    }
}

#[cfg(test)]
mod lowest_provider_registry_tests {
    use super::*;
    #[test]
    fn lowest_provider_wiring_and_exact_allowlists() {
        for (id,base,key,models,allowed) in [
            ("hmsrelay","https://100milionseek.top/v1","HMSRELAY_API_KEY","HMSRELAY_MODELS","deepseek-v4.1-flash-free"),
            ("sambanova","https://api.sambanova.ai/v1","SAMBANOVA_API_KEY","SAMBANOVA_MODELS","gemma-4-31B-it"),
        ] {
            let row=REGISTRY.iter().find(|p|p.id==id).unwrap();
            assert_eq!(row.base_url,base);assert_eq!(row.base_url_env,None);
            assert_eq!(row.key_env,key);assert_eq!(row.models_env,Some(models));
            let entries=[allowed,"gpt-oss-120b","paid-model","Gemma-4-31B-it"].iter().enumerate()
                .map(|(i,up)|ModelEntry{public:format!("model-{i}"),upstream:up.to_string(),context:None}).collect();
            let clean=sanitize_models(id,entries,&HashMap::new());
            assert_eq!(clean.len(),1);assert_eq!(clean[0].upstream,allowed);
        }
    }
}

#[cfg(test)]
mod nextrouter_claude_intake_tests {
    use super::*;
    #[test]
    fn four_exact_claudes_and_existing_frontier_ids_survive_no_lookalikes() {
        let old=["grok-4.7","Qwen4-Max-Preview","Qwen3.8-Max","muse-spark-open","kimi-k3.1-pro"];
        let claude=["claude-opus-5","claude-haiku-5.5","claude-haiku-3-5","claude-opus-5-5"];
        let rejected=["claude-opus-5-paid","claude-opus-5.5","claude-haiku-3.5","claude-sonnet-5","gpt-oss-120b","flux-2-dev"];
        let entries=old.iter().chain(claude.iter()).chain(rejected.iter()).map(|id|ModelEntry{public:id.to_string(),upstream:id.to_string(),context:None}).collect();
        let clean=sanitize_models("nextrouter",entries,&HashMap::new());
        assert_eq!(clean.iter().map(|m|m.upstream.as_str()).collect::<Vec<_>>(),old.iter().chain(claude.iter()).copied().collect::<Vec<_>>());
        assert_eq!(Status::parse("enabled"),Some(Status::Personal));
        assert_eq!(Status::parse("personal"),Some(Status::Personal));
    }
}

#[cfg(test)]
mod migration_r4_config_tests {
    use super::*;
    #[test]
    fn live_registry_status_and_minimax_mapping_survive() {
        let p=REGISTRY.iter().find(|p|p.id=="nextrouter").unwrap();
        assert_eq!(p.base_url,"https://nextrouter.me/v1");assert_eq!(p.key_env,"NEXTROUTER_API_KEY");assert_eq!(p.models_env,Some("NEXTROUTER_MODELS"));
        for status in ["enabled","ENABLED","personal","PERSONAL"] {assert_eq!(Status::parse(status),Some(Status::Personal));}
        assert_eq!(Status::parse("off"),Some(Status::Off));assert_eq!(Status::parse("invalid"),None);
        let entry=|public:&str,upstream:&str|ModelEntry{public:public.into(),upstream:upstream.into(),context:None};
        let mut meta=HashMap::new();meta.insert("minimax-m3.1-flash".into(),8192);
        let clean=sanitize_models("nim",vec![entry("minimax-m3.1-flash","minimaxai/minimax-m3.1-flash"),entry("minimax-m3.1-flash","other"),entry("nim/model","private"),entry("model-nim","private")],&meta);
        assert_eq!(clean.len(),1);assert_eq!(clean[0].public,"minimax-m3.1-flash");assert_eq!(clean[0].upstream,"minimaxai/minimax-m3.1-flash");assert_eq!(clean[0].context,Some(8192));
        assert!(sanitize_models("nim",vec![entry("minimax-m3.1-flash","other")],&meta).is_empty());
    }
}

#[cfg(test)]
mod pollinations_config_tests {
    use super::*;
    #[test]
    fn pollinations_anonymous_route_is_registered_without_key_or_endpoint_override() {
        let row=REGISTRY.iter().find(|p|p.id=="pollinations").expect("anonymous route registered");
        assert_eq!(row.base_url,"https://text.pollinations.ai");
        assert_eq!(row.base_url_env,None);
        let valid=ModelEntry{public:"gpt-oss-20b".into(),upstream:"openai-fast".into(),context:None};
        assert_eq!(sanitize_models("pollinations",vec![valid.clone()],&HashMap::new()).len(),1);
        for (public,upstream) in [("gpt-oss-120b","openai-fast"),("gpt-oss-20b","openai"),("gpt-oss-20b","paid-model")] {
            assert!(sanitize_models("pollinations",vec![ModelEntry{public:public.into(),upstream:upstream.into(),..valid.clone()}],&HashMap::new()).is_empty());
        }
    }
    #[test]
    fn pollinations_requires_nonempty_exact_binding_even_in_programmatic_configs() {
        let mut p=Provider{id:"pollinations".into(),base_url:"https://text.pollinations.ai".into(),api_key:"accidental-stored-secret".into(),models:vec![],status:Status::Personal};
        assert!(!p.configured());
        p.models=vec![ModelEntry{public:"gpt-oss-20b".into(),upstream:"openai-fast".into(),context:None}];
        assert!(p.configured());
        p.models[0].upstream="openai".into();assert!(!p.configured());
        p.models[0].upstream="openai-fast".into();p.models[0].public="gpt-oss-120b".into();assert!(!p.configured());
    }

    #[test]
    fn pollinations_env_is_default_off_and_opt_in_is_keyless() {
        struct Restore(Vec<(&'static str,Option<std::ffi::OsString>)>);
        impl Drop for Restore {fn drop(&mut self){for (key,value) in &self.0 {match value {Some(v)=>std::env::set_var(key,v),None=>std::env::remove_var(key)}}}}
        let vars=["AQUA_STATUS_POLLINATIONS","POLLINATIONS_MODELS"];
        let _restore=Restore(vars.iter().map(|key|(*key,std::env::var_os(key))).collect());
        for key in vars {std::env::remove_var(key);}
        let cfg=from_env();let p=cfg.providers.iter().find(|p|p.id=="pollinations").unwrap();
        assert_eq!(p.status,Status::Off);assert!(!p.configured());assert!(p.api_key.is_empty());
        std::env::set_var("AQUA_STATUS_POLLINATIONS","personal");
        std::env::set_var("POLLINATIONS_MODELS","gpt-oss-20b=openai-fast");
        let cfg=from_env();let p=cfg.providers.iter().find(|p|p.id=="pollinations").unwrap();
        assert_eq!(p.status,Status::Personal);assert!(p.configured());assert!(p.api_key.is_empty());
    }

}
