use std::collections::HashMap;

use crate::auth::OAuthConfig;

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
#[derive(Clone, Debug)]
pub struct ModelEntry {
    pub public: String,
    pub upstream: String,
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
}

struct RegistryEntry {
    id: &'static str,
    base_url: &'static str,
    base_url_env: Option<&'static str>,
    key_env: &'static str,
    models_env: Option<&'static str>,
    default_models: &'static [(&'static str, &'static str)], // (public, upstream)
    default_status: Status,
}

// Defaults are deliberate: restricted providers ship off. Override at runtime
// with AQUA_STATUS_<ID> only once the matching policy question is settled.
const REGISTRY: &[RegistryEntry] = &[
    RegistryEntry {
        id: "openrouter",
        base_url: "https://openrouter.ai/api/v1",
        base_url_env: None,
        key_env: "OPENROUTER_API_KEY",
        models_env: Some("OPENROUTER_MODELS"),
        // router alias: upstream id names the provider, so its public name is the router "auto"
        default_models: &[("auto", "openrouter/free")],
        default_status: Status::Personal, // one shared key for friends not cleared by ToS
    },
    RegistryEntry {
        id: "zro",
        base_url: "https://zro.moonmath.ai/v1",
        base_url_env: None,
        key_env: "ZRO_API_KEY",
        models_env: Some("ZRO_MODELS"), // free plan: DeepSeek V4.1 Flash; exact upstream id unverified
        default_models: &[],
        default_status: Status::Personal, // free plan says allowances are for your own use
    },
    RegistryEntry {
        id: "logfare",
        base_url: "https://logfare.ai/v1",
        base_url_env: None,
        key_env: "LOGFARE_API_KEY",
        models_env: Some("LOGFARE_MODELS"),
        default_models: &[("auto", "logfare/auto")],
        default_status: Status::Off, // logs every prompt/response; 18+ and Discord required
    },
    RegistryEntry {
        id: "nim",
        base_url: "https://integrate.api.nvidia.com/v1",
        base_url_env: None,
        key_env: "NVIDIA_NIM_API_KEY",
        models_env: Some("NVIDIA_NIM_MODELS"),
        default_models: &[],
        default_status: Status::Off, // free trial: internal testing/evaluation only
    },
    RegistryEntry {
        id: "tokenlab",
        base_url: "https://api.tokenlab.amd.com/v1",
        base_url_env: None,
        key_env: "AMD_TOKENLAB_API_KEY",
        models_env: Some("AMD_TOKENLAB_MODELS"),
        default_models: &[],
        default_status: Status::Off, // "points" may be credits; keys expire after 30 days
    },
    RegistryEntry {
        id: "gonka",
        base_url: "",
        base_url_env: Some("GONKA_BASE_URL"),
        key_env: "GONKA_BROKER_API_KEY",
        models_env: Some("GONKA_MODELS"),
        default_models: &[],
        default_status: Status::Off, // paid metered service
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
    Config {
        keys,
        admin_key: env("AQUA_ADMIN_KEY").unwrap_or_default(),
        daily_limit: env("AQUA_DAILY_LIMIT").and_then(|v| v.parse().ok()).unwrap_or(200),
        allowed_origin: env("AQUA_ALLOWED_ORIGIN").unwrap_or_default(),
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
                let models = match p.models_env.and_then(|e| env(e)) {
                    // MODELS env: "public=upstream,public2=upstream2"
                    Some(spec) => spec
                        .split(',')
                        .filter_map(|pair| {
                            let (a, b) = pair.split_once('=')?;
                            let (a, b) = (a.trim(), b.trim());
                            if a.is_empty() || b.is_empty() || a.contains(p.id) {
                                None // public names must never carry the provider id
                            } else {
                                Some(ModelEntry { public: a.to_string(), upstream: b.to_string() })
                            }
                        })
                        .collect(),
                    None => p
                        .default_models
                        .iter()
                        .map(|(a, b)| ModelEntry { public: a.to_string(), upstream: b.to_string() })
                        .collect(),
                };
                let status = env(&format!("AQUA_STATUS_{}", p.id.to_uppercase()))
                    .and_then(|s| Status::parse(&s))
                    .unwrap_or(p.default_status);
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
