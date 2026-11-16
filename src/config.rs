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
            "personal" => Some(Status::Personal),
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

#[derive(Clone, Debug)]
pub struct Config {
    pub keys: HashMap<String, KeyEntry>,
    pub admin_key: String,
    pub daily_limit: u32,
    pub allowed_origin: String,
    pub providers: Vec<Provider>,
    pub oauth: OAuthConfig,
    // ordered canonical model names the "auto" alias walks, model first,
    // then every eligible provider carrying that model. Empty: auto disabled.
    pub auto_shortlist: Vec<String>,
    // aggregate deadline shared by ALL fallback attempts of one client
    // request: a 300s stall on every candidate must not multiply
    pub upstream_budget: std::time::Duration,
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
        id: "tokenlab",
        base_url: "https://api.tokenlab.amd.com/v1",
        base_url_env: None,
        key_env: "AMD_TOKENLAB_API_KEY",
        models_env: Some("AMD_TOKENLAB_MODELS"),
    },
    RegistryEntry {
        id: "gonka",
        base_url: "",
        base_url_env: Some("GONKA_BASE_URL"),
        key_env: "GONKA_BROKER_API_KEY",
        models_env: Some("GONKA_MODELS"),
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
        // the reserved alias must never be a concrete upstream binding
        if m.public.eq_ignore_ascii_case(AUTO_ALIAS) {
            continue;
        }
        // public names must never carry the provider id
        if m.public.contains(provider_id) {
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
                    api_key: env(p.key_env).unwrap_or_default(),
                    models,
                    status,
                }
            })
            .collect(),
    }
}
