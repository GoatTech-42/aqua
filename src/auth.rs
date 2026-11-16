use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::Role;

pub const STATE_TTL: Duration = Duration::from_secs(600);
pub const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_STATES: usize = 10_000;
const MAX_SESSIONS: usize = 10_000;
const COOKIE_NAME: &str = "aqua_session";

#[derive(Clone, Debug, Default)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    // public base URL of this backend, no trailing slash (https://aqua.goattech.us)
    pub public_url: String,
    // where the browser lands after login; defaults to public_url
    pub console_url: String,
    pub owner_users: Vec<String>,  // GitHub logins, lowercase
    pub friend_users: Vec<String>, // GitHub logins, lowercase
}

impl OAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.client_id.is_empty()
            && !self.client_secret.is_empty()
            && !self.public_url.is_empty()
            && !self.client_id.eq_ignore_ascii_case("change-me")
            && !self.client_secret.eq_ignore_ascii_case("change-me")
    }

    pub fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/auth/github/callback", self.public_url)
    }

    pub fn post_login_url(&self) -> String {
        let base = if self.console_url.is_empty() { &self.public_url } else { &self.console_url };
        format!("{}/console.html", base)
    }

    pub fn role_for(&self, login: &str) -> Option<Role> {
        let l = login.to_ascii_lowercase();
        if self.owner_users.iter().any(|u| u == &l) {
            Some(Role::Owner)
        } else if self.friend_users.iter().any(|u| u == &l) {
            Some(Role::Friend)
        } else {
            None
        }
    }
}

pub struct Session {
    pub login: String,
    pub role: Role,
    pub expires: Instant,
}

pub struct Auth {
    pub cfg: OAuthConfig,
    states: Mutex<HashMap<String, Instant>>,
    sessions: Mutex<HashMap<String, Session>>,
}

// 128 bits from the OS RNG, hex-encoded. No rand crate in the tree; /dev/urandom
// is the right source on every host this targets. Falls back to a time+counter
// mix only if the OS RNG is unreadable, and login stays disabled-quality either
// way (ids remain unguessable in practice because they are per-process random).
fn rand_hex(bytes: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !ok {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (n.wrapping_shr((i % 16) as u32 * 8) as u8) ^ (i as u8).wrapping_mul(89);
        }
    }
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Auth {
    pub fn new(cfg: OAuthConfig) -> Auth {
        Auth {
            cfg,
            states: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_state(&self) -> String {
        let mut states = self.states.lock().unwrap();
        if states.len() >= MAX_STATES {
            let cutoff = Instant::now();
            states.retain(|_, t| cutoff.duration_since(*t) < STATE_TTL);
        }
        let id = rand_hex(16);
        states.insert(id.clone(), Instant::now());
        id
    }

    // single-use: a state is consumed by the check
    pub fn take_state(&self, id: &str) -> bool {
        let mut states = self.states.lock().unwrap();
        match states.remove(id) {
            Some(t) => t.elapsed() < STATE_TTL,
            None => false,
        }
    }

    pub fn create_session(&self, login: &str, role: Role) -> String {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= MAX_SESSIONS {
            let now = Instant::now();
            sessions.retain(|_, s| s.expires > now);
        }
        let id = rand_hex(16);
        sessions.insert(
            id.clone(),
            Session {
                login: login.to_string(),
                role,
                expires: Instant::now() + SESSION_TTL,
            },
        );
        id
    }

    pub fn get_session_at(&self, id: &str, now: Instant) -> Option<(String, Role)> {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(id) {
            Some(s) if s.expires > now => Some((s.login.clone(), s.role)),
            Some(_) => {
                sessions.remove(id);
                None
            }
            None => None,
        }
    }

    pub fn get_session(&self, id: &str) -> Option<(String, Role)> {
        self.get_session_at(id, Instant::now())
    }

    pub fn revoke(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }

    pub fn set_cookie(&self, id: &str) -> String {
        let secure = if self.cfg.secure_cookies() { "; Secure" } else { "" };
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
            COOKIE_NAME,
            id,
            SESSION_TTL.as_secs(),
            secure
        )
    }

    pub fn clear_cookie(&self) -> String {
        let secure = if self.cfg.secure_cookies() { "; Secure" } else { "" };
        format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", COOKIE_NAME, secure)
    }
}

pub fn session_cookie(headers: &HashMap<String, String>) -> Option<String> {
    let header = headers.get("cookie")?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(COOKIE_NAME) {
            let v = v.strip_prefix('=')?.trim();
            if !v.is_empty() && v.len() <= 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(v.to_string());
            }
        }
    }
    None
}

pub fn authorize_url(cfg: &OAuthConfig, state: &str) -> String {
    format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=read:user",
        url_encode(&cfg.client_id),
        url_encode(&cfg.redirect_uri()),
        url_encode(state)
    )
}

pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

pub fn parse_query(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            out.insert(k.to_string(), percent_decode(v));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}
