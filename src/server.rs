use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::auth::{self, Auth, OAuthConfig};
use crate::config::{Config, Role, Status, AUTO_ALIAS};
use crate::redact::redact_payload;
use crate::sse::SseRewriter;

const ALIAS: &str = AUTO_ALIAS;
const MAX_BODY: usize = 1_000_000;
const MAX_RESPONSE: usize = 4_000_000; // hard cap on bytes sent to a client, stream or not
// request fields forwarded upstream; everything else is dropped, including
// "user" (a friend identity must not leave the gateway)
const PARAM_WHITELIST: &[&str] = &[
    "messages", "temperature", "top_p", "max_tokens", "stop", "n", "response_format",
    "seed", "presence_penalty", "frequency_penalty", "tools", "tool_choice",
];

struct Quota {
    day: String,
    reserved: u32,
    in_flight: u32,
}

// passive provider health, account scope: a 429 on one model of an account
// means the account's quota is exhausted - hammering its other models burns
// latency and can trip provider-side abuse limits. `hard` marks evidence of
// a real limit (a Retry-After the provider sent): hard-cooled accounts are
// never retried until the cooldown lapses, even as a last resort. Soft
// cooldowns only deprioritize.
#[derive(Clone, Copy)]
struct Cooldown {
    until: Instant,
    hard: bool,
}

struct Shared {
    config: Config,
    agent: ureq::Agent,
    auth: Auth,
    quotas: Mutex<HashMap<String, Quota>>,
    // Standard Z.AI account limit is one active inference, across all models.
    zai_in_flight: AtomicBool,
    auth_failures: Mutex<HashMap<String, (u32, Instant)>>,
    health: Mutex<HashMap<String, Cooldown>>,
    spend: Mutex<crate::spend::Store>,
    unknown_owner_requests: Mutex<u64>,
}

pub struct Server {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Server {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub fn bind(config: Config) -> std::io::Result<Server> {
    bind_addr("127.0.0.1:0", config)
}

pub fn bind_addr(addr: &str, config: Config) -> std::io::Result<Server> {
    let listener = TcpListener::bind(addr)?;
    let port = listener.local_addr()?.port();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(300)))
        .build()
        .into();
    let spend = crate::spend::Store::open(config.spend.path.clone())?;
    let shared = Arc::new(Shared {
        spend: Mutex::new(spend),
        unknown_owner_requests: Mutex::new(0),
        auth: Auth::new(config.oauth.clone()),
        config,
        agent,
        quotas: Mutex::new(HashMap::new()),
        zai_in_flight: AtomicBool::new(false),
        auth_failures: Mutex::new(HashMap::new()),
        health: Mutex::new(HashMap::new()),
    });
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(stream) = stream {
                let shared = shared.clone();
                thread::spawn(move || {
                    let _ = handle(stream, shared);
                });
            }
        }
    });
    Ok(Server { port, shutdown, handle: Some(handle) })
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, &'static str> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut tmp).map_err(|_| "read")?;
        if n == 0 {
            return Err("closed");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if p > 64 * 1024 {
                return Err("headers too large");
            }
            break p;
        }
        if buf.len() > 64 * 1024 {
            return Err("headers too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next().ok_or("bad request")?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let raw_target = parts.next().unwrap_or("");
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_target.to_string(), String::new()),
    };
    let mut headers = HashMap::new();
    let mut len = 0usize;
    let mut seen_len = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            if k == "transfer-encoding" {
                return Err("chunked"); // chunked bodies unsupported: reject, never guess framing
            }
            if k == "content-length" {
                if seen_len {
                    return Err("bad request"); // duplicate Content-Length: ambiguous framing, reject
                }
                seen_len = true;
                len = v.trim().parse().map_err(|_| "bad length")?;
            }
            headers.insert(k, v.trim().to_string());
        }
    }
    if len > MAX_BODY {
        return Err("too large");
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut tmp).map_err(|_| "read")?;
        if n == 0 {
            return Err("closed");
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Ok(Request { method, path, query, headers, body })
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn write_json(stream: &mut TcpStream, code: u16, body: &Value, cors: Option<&str>) -> std::io::Result<()> {
    let bytes = body.to_string();
    let cors_head = cors_headers(cors);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\nx-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
        code,
        status_text(code),
        bytes.len(),
        cors_head,
        bytes
    )
}

fn cors_headers(cors: Option<&str>) -> String {
    match cors {
        // credentials: the Pages console (aqua.goattech.us) calls the API host
        // (api.aqua.goattech.us) with fetch credentials:'include' for /auth/me and
        // /auth/logout. Same-site, so the host-only SameSite=Lax cookie still flows;
        // the browser only requires this header on the response.
        Some(origin) => format!(
            "access-control-allow-origin: {}\r\naccess-control-allow-credentials: true\r\nvary: origin\r\n",
            origin
        ),
        None => String::new(),
    }
}

fn write_html(stream: &mut TcpStream, body: &str, cors: Option<&str>) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\nx-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
        body.len(),
        cors_headers(cors),
        body
    )
}

fn write_redirect(stream: &mut TcpStream, location: &str, cookies: &[String]) -> std::io::Result<()> {
    let mut extra = String::new();
    for c in cookies {
        extra.push_str(&format!("set-cookie: {}\r\n", c));
    }
    write!(
        stream,
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n{}\r\n",
        location, extra
    )
}

fn write_no_content(stream: &mut TcpStream, cookies: &[String], cors: Option<&str>) -> std::io::Result<()> {
    let mut extra = String::new();
    for c in cookies {
        extra.push_str(&format!("set-cookie: {}\r\n", c));
    }
    write!(
        stream,
        "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n{}{}\r\n",
        cors_headers(cors),
        extra
    )
}

// the console pages are a public shell; every API call they make still needs a key
const PAGE_LANDING: &str = include_str!("../ui/landing.html");
const PAGE_CONSOLE: &str = include_str!("../ui/console.html");
const PAGE_PLAYGROUND: &str = include_str!("../ui/playground.html");

fn err_body(message: &str, ty: &str) -> Value {
    json!({ "error": { "message": message, "type": ty } })
}

fn bearer(req: &Request) -> String {
    req.headers
        .get("authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim()
        .to_string()
}

// host[:port] portion of an Origin value ("scheme://host[:port][/...]"), or "" when
// the value has no authority part - a malformed origin simply never matches.
fn origin_host(origin: &str) -> &str {
    match origin.split("://").nth(1) {
        Some(rest) => rest.split('/').next().unwrap_or(""),
        None => "",
    }
}

fn origin_host_matches(origin: &str, host_header: &str) -> bool {
    !host_header.is_empty() && origin_host(origin).eq_ignore_ascii_case(host_header)
}

fn handle(mut stream: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {
    let cfg = &shared.config;
    // bound downstream writes: a client that stops reading must not pin this
    // worker (and its in-flight quota slot) forever. Per write operation, so
    // healthy long streams are never cut; upstream IO carries its own
    // aggregate budget. No claim of a whole-request wall clock.
    let _ = stream.set_write_timeout(Some(shared.config.upstream_budget));
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err("too large") | Err("headers too large") => {
            return write_json(&mut stream, 413, &err_body("request too large", "invalid_request"), None)
        }
        Err("chunked") => {
            return write_json(&mut stream, 400, &err_body("chunked request bodies are not supported; send Content-Length", "invalid_request"), None)
        }
        Err("bad request") | Err("bad length") => {
            return write_json(&mut stream, 400, &err_body("malformed request", "invalid_request"), None)
        }
        Err(_) => return Ok(()),
    };

    // CORS: a single explicit allowed origin, nothing else gets headers
    let origin = req.headers.get("origin").map(String::as_str);
    let cors = if !cfg.allowed_origin.is_empty() && origin == Some(cfg.allowed_origin.as_str()) {
        Some(cfg.allowed_origin.as_str())
    } else {
        None
    };

    if req.method == "OPTIONS" {
        let extra = if cors.is_some() {
            "access-control-allow-headers: authorization, content-type\r\naccess-control-allow-methods: GET, POST, OPTIONS\r\n"
        } else {
            ""
        };
        write!(
            stream,
            "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n{}{}\r\n",
            cors_headers(cors),
            extra
        )?;
        return Ok(());
    }

    // static console pages (public shell, key still required for every API call)
    if req.method == "GET" {
        match req.path.as_str() {
            "/" | "/landing.html" => return write_html(&mut stream, PAGE_LANDING, cors),
            "/console.html" => return write_html(&mut stream, PAGE_CONSOLE, cors),
            "/playground.html" => return write_html(&mut stream, PAGE_PLAYGROUND, cors),
            _ => {}
        }
    }

    // console login: browser OAuth flow, separate from the bearer-key API below
    if req.method == "GET" && req.path == "/login/github" {
        if !shared.auth.cfg.enabled() {
            return write_json(&mut stream, 503, &err_body("github login is not configured on this deployment", "auth_error"), cors);
        }
        let state = shared.auth.new_state();
        return write_redirect(&mut stream, &auth::authorize_url(&shared.auth.cfg, &state), &[]);
    }
    if req.method == "GET" && req.path == "/auth/github/callback" {
        if !shared.auth.cfg.enabled() {
            return write_json(&mut stream, 503, &err_body("github login is not configured on this deployment", "auth_error"), cors);
        }
        let q = auth::parse_query(&req.query);
        let state_ok = q.get("state").map(|s| shared.auth.take_state(s)).unwrap_or(false);
        let code = q.get("code").cloned().unwrap_or_default();
        if !state_ok || code.is_empty() {
            return write_json(&mut stream, 400, &err_body("invalid or expired login state", "auth_error"), cors);
        }
        return match github_exchange(&shared.agent, &shared.auth.cfg, &code) {
            Ok(login) => match shared.auth.cfg.role_for(&login) {
                Some(role) => {
                    let id = shared.auth.create_session(&login, role);
                    write_redirect(&mut stream, &shared.auth.cfg.post_login_url(), &[shared.auth.set_cookie(&id)])
                }
                None => write_json(&mut stream, 403, &err_body("github account is not on the allowlist", "auth_error"), cors),
            },
            Err(e) => write_json(&mut stream, 502, &err_body(e, "upstream_error"), cors),
        };
    }
    if req.method == "GET" && req.path == "/auth/me" {
        match auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id)) {
            Some((login, role)) => {
                let role = match role {
                    Role::Owner => "owner",
                    Role::Friend => "friend",
                };
                return write_json(&mut stream, 200, &json!({ "login": login, "role": role }), cors);
            }
            None => return write_json(&mut stream, 401, &err_body("not signed in", "auth_error"), cors),
        }
    }
    if req.method == "POST" && req.path == "/auth/logout" {
        // CSRF, defense in depth against both cross-site pages and hostile same-site
        // siblings (any other *.goattech.us app): SameSite=Lax withholds the cookie
        // from cross-site POSTs but NOT from same-site siblings, so browser requests
        // must additionally carry either no Origin (non-browser client) or exactly the
        // one allowed console origin. Fetch metadata is a third wall, not the only one.
        if req.headers.get("sec-fetch-site").map(String::as_str) == Some("cross-site") {
            return write_json(&mut stream, 403, &err_body("cross-site request rejected", "auth_error"), cors);
        }
        if let Some(origin) = req.headers.get("origin") {
            // Allowed: exactly the configured console origin (the Pages host), or the
            // request's own same origin - a console served by this backend itself
            // (local dev, or the api host directly) sends Origin == its own host.
            // Host is the fetch target, so a browser attacker cannot pick it freely;
            // a non-browser client needs no CSRF protection. A hostile sibling
            // subdomain's Origin matches neither and stays 403.
            let allowed = (!cfg.allowed_origin.is_empty() && origin == &cfg.allowed_origin)
                || origin_host_matches(origin, req.headers.get("host").map(String::as_str).unwrap_or(""));
            if !allowed {
                return write_json(&mut stream, 403, &err_body("origin not allowed", "auth_error"), cors);
            }
        }
        if let Some(id) = auth::session_cookie(&req.headers) {
            shared.auth.revoke(&id);
        }
        return write_no_content(&mut stream, &[shared.auth.clear_cookie()], cors);
    }

    let token = bearer(&req);

    if matches!(req.path.as_str(), "/v1/admin/usage" | "/v1/admin/caps") {
        if auth_throttled(&shared, &token) { return write_json(&mut stream,429,&err_body("too many failed attempts","rate_limit_error"),cors); }
        return spend_admin(&mut stream,&shared,&req,&token,cors);
    }

    if req.method == "GET" && req.path == "/v1/admin/providers" {
        // Throttle check first: admin-key guessing must hit the same 429 wall as API keys.
        if auth_throttled(&shared, &token) {
            return write_json(&mut stream, 429, &err_body("too many failed attempts", "rate_limited"), cors);
        }
        if cfg.admin_key.is_empty() || cfg.admin_key.eq_ignore_ascii_case("change-me") || token != cfg.admin_key {
            record_auth_failure(&shared, &token);
            return write_json(&mut stream, 401, &err_body("invalid api key", "auth_error"), cors);
        }
        let providers: Vec<Value> = cfg
            .providers
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "status": p.status.as_str(),
                    "models": p.models.iter().map(|m| json!({ "public": m.public, "upstream": m.upstream })).collect::<Vec<Value>>(),
                    "configured": !p.api_key.is_empty(),
                })
            })
            .collect();
        return write_json(&mut stream, 200, &json!({ "providers": providers }), cors);
    }

    if auth_throttled(&shared, &token) {
        return write_json(&mut stream, 429, &err_body("too many failed attempts", "rate_limit_error"), cors);
    }
    let entry = match cfg.keys.get(&token).filter(|_| !token.is_empty() && !token.eq_ignore_ascii_case("change-me")) {
        Some(e) => e,
        None => {
            record_auth_failure(&shared, &token);
            return write_json(&mut stream, 401, &err_body("invalid api key", "auth_error"), cors);
        }
    };

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/models") => {
            // canonical models, deduplicated across provider bindings; the auto
            // alias is advertised only when a shortlist is actually configured
            let mut data = Vec::new();
            let mut seen = std::collections::HashSet::new();
            if !shared.config.auto_shortlist.is_empty() {
                data.push(json!({ "id": ALIAS, "object": "model", "created": 0, "owned_by": "aqua" }));
                seen.insert(ALIAS.to_string());
            }
            for p in &shared.config.providers {
                if p.status == Status::Off || p.api_key.is_empty() {
                    continue;
                }
                if p.status != Status::Friends && entry.role != Role::Owner {
                    continue;
                }
                for m in &p.models {
                    if entry.role != Role::Owner && cfg.spend.restricted(&m.public) { continue; }
                    if m.public == ALIAS || !seen.insert(m.public.clone()) {
                        continue;
                    }
                    let mut v = json!({ "id": m.public, "object": "model", "created": 0, "owned_by": "aqua" });
                    if let Some(c) = m.context {
                        v["context"] = json!(c);
                    }
                    data.push(v);
                }
            }
            write_json(&mut stream, 200, &json!({ "object": "list", "data": data }), cors)
        }
        ("POST", "/v1/chat/completions") => chat(&mut stream, &shared, &req, entry, &token, cors),
        _ => write_json(&mut stream, 404, &err_body("not found", "invalid_request"), cors),
    }
}

const AUTH_FAIL_LIMIT: u32 = 5; // per token per 60s window
const AUTH_FAIL_MAP_CAP: usize = 10_000;

// GitHub OAuth: exchange the callback code for the user's login. Errors are
// generic on purpose; the upstream body never reaches the client.
fn github_exchange(agent: &ureq::Agent, cfg: &OAuthConfig, code: &str) -> Result<String, &'static str> {
    let body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        auth::url_encode(&cfg.client_id),
        auth::url_encode(&cfg.client_secret),
        auth::url_encode(code),
        auth::url_encode(&cfg.redirect_uri())
    );
    let mut resp = agent
        .post("https://github.com/login/oauth/access_token")
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .send(body.into_bytes())
        .map_err(|_| "github token exchange failed")?;
    if resp.status().as_u16() != 200 {
        return Err("github token exchange rejected");
    }
    let tok: Value = resp.body_mut().read_json().map_err(|_| "github token exchange failed")?;
    let access = tok
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("github token exchange rejected")?;
    let mut uresp = agent
        .get("https://api.github.com/user")
        .header("authorization", &format!("Bearer {}", access))
        .header("user-agent", "aqua")
        .call()
        .map_err(|_| "github user lookup failed")?;
    if uresp.status().as_u16() != 200 {
        return Err("github user lookup rejected");
    }
    let user: Value = uresp.body_mut().read_json().map_err(|_| "github user lookup failed")?;
    user.get("login")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or("github user lookup failed")
}

fn record_auth_failure(shared: &Shared, token: &str) {
    let mut failures = shared.auth_failures.lock().unwrap();
    if failures.len() >= AUTH_FAIL_MAP_CAP {
        failures.retain(|_, v| v.1.elapsed() <= Duration::from_secs(60));
        if failures.len() >= AUTH_FAIL_MAP_CAP {
            failures.clear(); // last resort bound: counters reset, map cannot grow without limit
        }
    }
    let entry = failures.entry(token.to_string()).or_insert((0, Instant::now()));
    if entry.1.elapsed() > Duration::from_secs(60) {
        *entry = (0, Instant::now());
    }
    entry.0 += 1;
}

fn auth_throttled(shared: &Shared, token: &str) -> bool {
    let failures = shared.auth_failures.lock().unwrap();
    match failures.get(token) {
        Some((n, since)) => *n >= AUTH_FAIL_LIMIT && since.elapsed() <= Duration::from_secs(60),
        None => false,
    }
}

struct QuotaGuard<'a> {
    shared: &'a Shared,
    token: &'a str,
    dispatched: bool,
    day: String,
}

impl Drop for QuotaGuard<'_> {
    fn drop(&mut self) {
        release(self.shared, self.token);
        if !self.dispatched {
            if let Some(q) = self.shared.quotas.lock().unwrap().get_mut(self.token) {
                if q.day == self.day { q.reserved = q.reserved.saturating_sub(1); }
            }
        }
    }
}

fn reserve(shared: &Shared, token: &str) -> bool {
    let day = chrono_day();
    let mut quotas = shared.quotas.lock().unwrap();
    let q = quotas.entry(token.to_string()).or_insert(Quota { day: day.clone(), reserved: 0, in_flight: 0 });
    if q.day != day {
        q.day = day;
        q.reserved = 0;
    }
    if q.reserved >= shared.config.daily_limit {
        return false;
    }
    q.reserved += 1;
    q.in_flight += 1;
    true
}

fn release(shared: &Shared, token: &str) {
    let mut quotas = shared.quotas.lock().unwrap();
    if let Some(q) = quotas.get_mut(token) {
        q.in_flight = q.in_flight.saturating_sub(1);
    }
}

fn chrono_day() -> String {
    // UTC date from unix seconds, no chrono dependency
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    // civil-from-days algorithm
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn chat(stream: &mut TcpStream, shared: &Shared, req: &Request, entry: &crate::config::KeyEntry, token: &str, cors: Option<&str>) -> std::io::Result<()> {
    let payload: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return write_json(stream, 400, &err_body("invalid request body", "invalid_request"), cors),
    };
    if !payload.get("messages").map(Value::is_array).unwrap_or(false) {
        return write_json(stream, 400, &err_body("messages required", "invalid_request"), cors);
    }
    let want_stream = payload.get("stream") == Some(&Value::Bool(true));
    let requested = payload.get("model").and_then(Value::as_str).unwrap_or(ALIAS);
    let eligible = |p: &&crate::config::Provider| {
        p.status != Status::Off
            && !p.api_key.is_empty()
            && !p.base_url.is_empty()
            && !p.models.is_empty()
            && (p.status == Status::Friends || entry.role == Role::Owner)
    };
    // model first, then provider: a pinned name gathers every eligible provider
    // carrying that exact canonical model; "auto" walks the configured coding
    // shortlist model by model. Cross-model fallback happens only inside auto -
    // a pinned request can never drift to a different model.
    //
    // Passive health reorders providers WITHIN one canonical model only: an
    // account with a known hard limit (the provider sent Retry-After) is
    // deferred to the END of the candidate list - the dispatch-time recheck
    // skips it while the limit is active and tries it only if the limit has
    // lapsed by the time earlier candidates fail. Soft-cooled accounts are
    // tried after fresh ones, oldest cooldown first. Health never moves a
    // later shortlist model ahead of an earlier one.
    let known = |name: &str| {
        shared
            .config
            .providers
            .iter()
            .filter(eligible)
            .any(|p| p.models.iter().any(|m| m.public == name))
    };
    if requested != ALIAS && !known(requested) {
        return write_json(stream, 400, &err_body("unknown model", "invalid_request"), cors);
    }
    if requested != ALIAS && entry.role != Role::Owner && shared.config.spend.restricted(requested) {
        return write_json(stream,403,&spend_error("model restricted to the admin account","model_forbidden"),cors);
    }
    let mut hard_excluded = false;
    let mut immediate = 0usize;
    let mut candidates: Vec<(&crate::config::Provider, &crate::config::ModelEntry)> = Vec::new();
    {
        let health = shared.health.lock().unwrap();
        let now = Instant::now();
        let mut push_model = |name: &str| {
            let mut fresh: Vec<(&crate::config::Provider, &crate::config::ModelEntry)> = Vec::new();
            let mut cooled: Vec<(_, Instant)> = Vec::new();
            let mut deferred: Vec<(&crate::config::Provider, &crate::config::ModelEntry)> = Vec::new();
            for p in shared.config.providers.iter().filter(eligible) {
                for m in p.models.iter().filter(|m| m.public == name) {
                    if entry.role != Role::Owner && shared.config.spend.restricted(&m.public) { continue; }
                    match health.get(p.id.as_str()) {
                        Some(cd) if cd.until > now => {
                            if cd.hard {
                                hard_excluded = true;
                                deferred.push((p, m));
                            } else {
                                cooled.push(((p, m), cd.until));
                            }
                        }
                        _ => fresh.push((p, m)),
                    }
                }
            }
            cooled.sort_by_key(|(_, until)| *until);
            immediate += fresh.len() + cooled.len();
            candidates.extend(fresh);
            candidates.extend(cooled.into_iter().map(|(c, _)| c));
            candidates.extend(deferred);
        };
        if requested == ALIAS {
            for name in &shared.config.auto_shortlist {
                push_model(name);
            }
        } else {
            push_model(requested);
        }
    }
    if immediate == 0 {
        // pinned here means every binding has a known hard limit (a merely
        // unknown model 400d above); auto with nothing routable 503s. The
        // all-hard-limited 429 fires before any quota is reserved.
        if hard_excluded {
            return write_json(stream, 429, &err_body("rate limit exceeded", "rate_limit_error"), cors);
        }
        return write_json(stream, 503, &err_body("no models available", "upstream_unavailable"), cors);
    }
    // the only sound local size check: a requested output budget larger than
    // the model's verified context window can never succeed. Prompt-side token
    // counts need a real tokenizer; nothing is estimated here.
    if let Some(mt) = payload.get("max_tokens").and_then(Value::as_u64) {
        candidates.retain(|(_, m)| m.context.map_or(true, |c| mt <= c as u64));
        if candidates.is_empty() && requested != ALIAS {
            return write_json(stream, 400, &err_body("max_tokens exceeds the model's context window", "invalid_request"), cors);
        }
        if candidates.is_empty() {
            return write_json(stream, 503, &err_body("no models available", "upstream_unavailable"), cors);
        }
    }
    // the context filter may have removed every non-hard candidate, leaving
    // only deferred (hard-limited) bindings the dispatch recheck will skip;
    // reserving quota for such a request would burn a daily slot with no
    // possible upstream attempt, so it 429s here instead
    {
        let health = shared.health.lock().unwrap();
        let now = Instant::now();
        let usable = candidates.iter().any(|(p, _)| {
            !matches!(health.get(p.id.as_str()), Some(cd) if cd.hard && cd.until > now)
        });
        if !usable {
            return write_json(stream, 429, &err_body("rate limit exceeded", "rate_limit_error"), cors);
        }
    }
    // quota is reserved only after the request is known-valid and routable
    if !reserve(shared, token) {
        return write_json(stream, 429, &err_body("rate limit exceeded", "rate_limit_error"), cors);
    }
    let mut guard = QuotaGuard { shared, token, dispatched: false, day: chrono_day() };

    // one aggregate deadline shared by every fallback attempt of this request:
    // a per-upstream timeout must not multiply across candidates
    let deadline = Instant::now()
        .checked_add(shared.config.upstream_budget)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(300));

    let mut saw_rate_limit = false;
    let mut tried: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (p, m) in candidates {
        // dispatch-time recheck: the snapshot above may be stale - a concurrent
        // request can cool this account while we walk. A hard limit found here
        // is always honored; soft only ever reorders, it never blocks dispatch.
        if let Some(cd) = shared.health.lock().unwrap().get(p.id.as_str()).copied() {
            if cd.hard && cd.until > Instant::now() {
                hard_excluded = true;
                continue;
            }
        }
        // one attempt per provider account per request: after any failure the
        // account is suspect, and a 429 on one of its models means the whole
        // account's quota is gone - trying its other models would hammer an
        // exhausted account
        if !tried.insert(p.id.as_str()) {
            continue;
        }
        // Nonblocking local account permit, acquired before spend admission.
        // Keep it for this whole attempt, including the full JSON/SSE body and
        // all early exits. Busy is not provider 429 evidence: no cooldown or
        // fabricated Retry-After, and exact-model fallback may still proceed.
        let _provider_slot = if p.id == "zai" {
            if shared.zai_in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
                continue;
            }
            Some(ProviderSlot(&shared.zai_in_flight))
        } else { None };
        let mut up_body = serde_json::Map::new();
        for k in PARAM_WHITELIST {
            if let Some(v) = payload.get(*k) {
                up_body.insert((*k).to_string(), v.clone());
            }
        }
        up_body.insert("model".into(), json!(m.upstream));
        up_body.insert("stream".into(), json!(want_stream));
        if want_stream && shared.config.spend.enabled {
            up_body.insert("stream_options".into(), json!({"include_usage":true}));
        }

        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break; // aggregate budget spent: no further fallback attempts
        };
        let attempt_agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(remaining))
            .build()
            .into();
        let url = format!("{}/chat/completions", p.base_url.trim_end_matches('/'));
        let mut spend = match reserve_spend(shared,entry,m,&payload) {
            Ok(guard) => guard,
            Err((status,message,code)) => return write_json(stream,status,&spend_error(message,code),cors),
        };
        guard.dispatched = true;
        let resp = attempt_agent
            .post(&url)
            .header("authorization", &format!("Bearer {}", p.api_key))
            .header("content-type", "application/json")
            .send_json(&Value::Object(up_body));
        let mut resp = match resp {
            Ok(r) => r,
            Err(_) => {
                set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
                continue; // network failure: try the next provider
            }
        };
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            if matches!(status,400|401|403|404|422|429) {
                if let Some(guard) = spend.as_mut() { guard.refund(); }
            }
            if status == 429 {
                saw_rate_limit = true;
                // a Retry-After is evidence of a real limit: honor it (bounded)
                // and do not retry this account until it lapses
                match parse_retry_after(&resp) {
                    Some(secs) => set_cooldown(shared, &p.id, secs, true),
                    None => set_cooldown(shared, &p.id, COOLDOWN_429_DEFAULT_SECS, false),
                }
            } else {
                set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
            }
            // drain the upstream error body without ever forwarding it
            let _ = resp.body_mut().as_reader().take(64 * 1024).read_to_end(&mut Vec::new());
            continue;
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        if !want_stream {
            let mut buf = Vec::new();
            if resp.body_mut().as_reader().take(MAX_RESPONSE as u64).read_to_end(&mut buf).is_err() {
                set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
                continue;
            }
            let Ok(json) = serde_json::from_slice::<Value>(&buf) else {
                set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
                continue;
            };
            if let Some(guard) = spend.as_mut() { guard.finish(crate::spend::usage(&json)); }
            clear_cooldown(shared, &p.id);
            println!(
                "{}",
                json!({ "ts": chrono_day(), "key": entry.name, "provider": p.id, "model": m.public, "stream": false })
            );
            return write_json(stream, 200, &redact_payload(&json, &m.public), cors);
        }

        // streaming requested: require a real SSE stream, else fail over cleanly
        if !content_type.starts_with("text/event-stream") {
            let _ = resp.body_mut().as_reader().take(64 * 1024).read_to_end(&mut Vec::new());
            set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
            continue;
        }
        clear_cooldown(shared, &p.id);
        println!(
            "{}",
            json!({ "ts": chrono_day(), "key": entry.name, "provider": p.id, "model": m.public, "stream": true })
        );
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\nconnection: close\r\n{}\r\n",
            cors_headers(cors)
        );
        stream.write_all(head.as_bytes())?;
        // shortcut: close-delimited stream (no chunked framing); HTTP/1.1 clients read to EOF
        let mut rewriter = SseRewriter::new(&m.public);
        let mut reader = resp.body_mut().as_reader();
        let mut sent = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut out = Vec::new();
                    if !rewriter.push(&chunk[..n], &mut out) {
                        // upstream sent an unbounded undelimited blob; the 200
                        // and stream headers are long committed, so never fail
                        // over mid-response: end the stream honestly (the
                        // client sees it terminate without [DONE])
                        set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
                        break;
                    }
                    if sent + out.len() > MAX_RESPONSE {
                        break; // hard cap: stream just ends
                    }
                    if stream.write_all(&out).is_err() {
                        return Ok(()); // client gone
                    }
                    let _ = stream.flush();
                    sent += out.len();
                }
                Err(_) => {
                    // upstream died mid-stream: cool it for future requests
                    set_cooldown(shared, &p.id, COOLDOWN_SOFT_SECS, false);
                    break;
                }
            }
        }
        if let Some(guard) = spend.as_mut() { guard.finish(rewriter.usage()); }
        return Ok(());
    }

    if saw_rate_limit || hard_excluded {
        write_json(stream, 429, &err_body("rate limit exceeded", "rate_limit_error"), cors)
    } else {
        write_json(stream, 503, &err_body("no models available", "upstream_unavailable"), cors)
    }
}

// RAII release also covers invalid responses, network errors and client exits.
struct ProviderSlot<'a>(&'a AtomicBool);
impl Drop for ProviderSlot<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

const COOLDOWN_SOFT_SECS: u64 = 15;
const COOLDOWN_429_DEFAULT_SECS: u64 = 60;
const RETRY_AFTER_MAX_SECS: u64 = 3600; // bound on provider-supplied Retry-After

// Monotonic under concurrency: an active cooldown is never shortened, soft
// evidence never softens or replaces a hard limit, and hard evidence only ever
// extends. A 429+Retry-After observed by one in-flight request must survive a
// concurrent request's success or plain failure on the same account.
fn set_cooldown(shared: &Shared, provider_id: &str, secs: u64, hard: bool) {
    let mut health = shared.health.lock().unwrap();
    let now = Instant::now();
    let until = now + Duration::from_secs(secs);
    match health.get_mut(provider_id) {
        Some(cd) if cd.until > now => {
            if hard {
                cd.hard = true;
                if until > cd.until {
                    cd.until = until;
                }
            } else if !cd.hard && until > cd.until {
                cd.until = until;
            }
        }
        _ => {
            health.insert(provider_id.to_string(), Cooldown { until, hard });
        }
    }
}

// A success proves reachability, never that a hard limit lifted: clear only
// soft cooldowns.
fn clear_cooldown(shared: &Shared, provider_id: &str) {
    let mut health = shared.health.lock().unwrap();
    if matches!(health.get(provider_id), Some(cd) if !cd.hard) {
        health.remove(provider_id);
    }
}

// Retry-After, clamped to (0, 1h]. Both RFC 9110 forms: delta seconds, and a
// STRICT IMF-fixdate (fixed-width fields, a real calendar date whose weekday
// actually matches). Obsolete formats, normalizable junk ("31 Feb"), loose
// widths and out-of-range values are treated as absent (soft default): a
// malformed untrusted header must never panic or silently become a limit.
fn parse_retry_after(resp: &ureq::http::Response<ureq::Body>) -> Option<u64> {
    let raw = resp.headers().get("retry-after")?.to_str().ok()?.trim();
    // RFC 9110 delta-seconds are digits only: a leading '+' (which
    // u64::from_str would accept) or any other junk is malformed and falls
    // through to the soft default rather than installing a hard limit
    if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(secs) = raw.parse::<u64>() {
            return Some(secs.clamp(1, RETRY_AFTER_MAX_SECS));
        }
        return None; // digit string overflowing u64: no usable evidence
    }
    let target = parse_imf_fixdate(raw)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let delta = target.checked_sub(now)?; // past date: no evidence of a future limit
    Some(delta.clamp(1, RETRY_AFTER_MAX_SECS))
}

// exactly n ASCII digits, no signs, no overflow surface
fn ndigits(s: &str, n: usize) -> Option<u64> {
    if s.len() == n && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

fn days_in_month(y: i64, m: u64) -> u64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn parse_imf_fixdate(raw: &str) -> Option<u64> {
    // "<wkday>, DD Mon YYYY HH:MM:SS GMT" - the only date form we accept
    let (wkday, rest) = raw.split_once(',')?;
    let wkday = wkday.trim();
    let mut parts = rest.trim().split_whitespace();
    let day = ndigits(parts.next()?, 2)?;
    let month = match parts.next()? {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };
    // fixed 4-digit year: extreme values can never reach the date arithmetic
    let year = ndigits(parts.next()?, 4)? as i64;
    let time = parts.next()?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    let mut t = time.split(':');
    let (h, m, s) = (ndigits(t.next()?, 2)?, ndigits(t.next()?, 2)?, ndigits(t.next()?, 2)?);
    if t.next().is_some() || h > 23 || m > 59 || s > 60 {
        return None;
    }
    // a real calendar date, never normalized (31 Feb is junk, not 3 Mar)
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    // the weekday must actually match the date
    let computed = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
    if wkday != computed {
        return None;
    }
    (days * 86_400 + (h * 3600 + m * 60 + s) as i64).try_into().ok()
}

// days from civil epoch (Hinnant), inverse of chrono_day above
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod reviewer_regressions {
    //! Independent watchdog regressions, RED on the rev2 diff, fixed in this
    //! revision: health-map concurrency monotonicity (stale success must not
    //! clear a live hard limit, stale soft failure must not replace it, a
    //! shorter hard limit must not shrink it) and strict untrusted-date
    //! parsing (malformed provider headers must be None, never a panic).
    use super::*;

    fn shared() -> Shared {
        let config = Config {
            keys: HashMap::new(),
            admin_key: String::new(),
            daily_limit: 200,
            allowed_origin: String::new(),
            providers: vec![],
            oauth: Default::default(), spend: Default::default(),
            auto_shortlist: vec![],
            upstream_budget: std::time::Duration::from_secs(300),
        };
        Shared {
            spend: Mutex::new(crate::spend::Store::open(None).unwrap()),
            unknown_owner_requests: Mutex::new(0),
            auth: Auth::new(config.oauth.clone()),
            config,
            agent: ureq::Agent::new_with_defaults(),
            quotas: Mutex::new(HashMap::new()),
            zai_in_flight: AtomicBool::new(false),
            auth_failures: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
        }
    }

    fn admin_request(shared: Arc<Shared>, method: &str, path: &str, cookie: &str, origin: &str, fetch_site: &str) -> String {
        use std::io::{Read,Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || handle(listener.accept().unwrap().0, shared).unwrap());
        let body = r#"{"name":"sam","daily":"2","monthly":"15"}"#;
        let mut client = TcpStream::connect(address).unwrap();
        write!(client,"{method} {path} HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\norigin: {origin}\r\nsec-fetch-site: {fetch_site}\r\ncontent-length: {}\r\n\r\n{body}",body.len()).unwrap();
        let mut out = String::new();client.read_to_string(&mut out).unwrap();worker.join().unwrap();out
    }

    #[test]
    fn spend_admin_cookie_route_requires_owner_and_explicit_csrf_safe_origin() {
        let mut state = shared();state.config.allowed_origin="https://aqua.test".into();
        let state=Arc::new(state);
        let owner=state.auth.create_session("luke",Role::Owner);
        let friend=state.auth.create_session("sam",Role::Friend);
        assert!(admin_request(state.clone(),"GET","/v1/admin/usage",&friend,"https://aqua.test","same-site").starts_with("HTTP/1.1 401"));
        assert!(admin_request(state.clone(),"GET","/v1/admin/usage",&owner,"https://aqua.test","same-site").starts_with("HTTP/1.1 200"));
        for (origin,site) in [("https://evil.test","cross-site"),("https://aqua.test","cross-site"),("","same-site")] {
            assert!(admin_request(state.clone(),"POST","/v1/admin/caps",&owner,origin,site).starts_with("HTTP/1.1 403"));
        }
        assert!(state.spend.lock().unwrap().ledger.caps.is_empty());
        assert!(admin_request(state.clone(),"POST","/v1/admin/caps",&owner,"https://aqua.test","same-site").starts_with("HTTP/1.1 200"));
        assert_eq!(state.spend.lock().unwrap().ledger.caps["sam"].daily,2_000_000_000);
    }

    #[test]
    fn reviewer_success_must_not_clear_live_hard_limit() {
        let s = shared();
        set_cooldown(&s, "same-account", 120, true);
        clear_cooldown(&s, "same-account");
        assert!(
            s.health.lock().unwrap().get("same-account").map(|c| c.hard && c.until > Instant::now()).unwrap_or(false),
            "inflight stale success erased live Retry-After"
        );
    }

    #[test]
    fn reviewer_soft_failure_must_not_replace_live_hard_limit() {
        let s = shared();
        set_cooldown(&s, "same-account", 120, true);
        let before = s.health.lock().unwrap()["same-account"].until;
        set_cooldown(&s, "same-account", 15, false);
        let h = s.health.lock().unwrap();
        let c = h.get("same-account").unwrap();
        assert!(c.hard && c.until >= before, "stale 500 weakened hard Retry-After");
    }

    #[test]
    fn reviewer_shorter_hard_must_not_shorten_existing_limit() {
        let s = shared();
        set_cooldown(&s, "same-account", 120, true);
        let before = s.health.lock().unwrap()["same-account"].until;
        set_cooldown(&s, "same-account", 1, true);
        assert!(
            s.health.lock().unwrap()["same-account"].until >= before,
            "shorter concurrent Retry-After truncated existing hard cooldown"
        );
    }

    #[test]
    fn reviewer_untrusted_date_must_not_panic() {
        let result = std::panic::catch_unwind(|| {
            parse_imf_fixdate("X, 01 Jan -9223372036854775808 00:00:00 GMT")
        });
        assert!(result.is_ok(), "provider header panicked arithmetic");
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn reviewer_invalid_calendar_date_not_normalized() {
        assert!(
            parse_imf_fixdate("X, 31 Feb 2030 00:00:00 GMT").is_none(),
            "junk date accepted as real hard cooldown"
        );
    }

    // addition on top of the reviewer set: a weekday that does not match the
    // date makes the header junk, and field-width/range abuse is rejected
    #[test]
    fn weekday_and_width_strictness() {
        assert_eq!(parse_imf_fixdate("Tue, 15 Nov 2027 00:00:00 GMT"), None, "2027-11-15 is a Monday");
        assert_eq!(parse_imf_fixdate("Mon, 5 Nov 2027 00:00:00 GMT"), None, "1-digit day");
        assert_eq!(parse_imf_fixdate("Mon, 15 Nov 27 00:00:00 GMT"), None, "2-digit year");
        assert_eq!(parse_imf_fixdate("Mon, 15 Nov 2027 24:00:00 GMT"), None, "hour 24");
        assert_eq!(parse_imf_fixdate("Mon, 00 Nov 2027 00:00:00 GMT"), None, "day 0");
        assert_eq!(parse_imf_fixdate("Mon, 29 Feb 2027 00:00:00 GMT"), None, "2027 not a leap year");
        assert!(parse_imf_fixdate("Tue, 29 Feb 2028 00:00:00 GMT").is_some(), "2028 is a leap year");
        assert!(parse_imf_fixdate("Mon, 15 Nov 2027 00:00:00 GMT").is_some(), "valid IMF-fixdate parses");
    }
}

fn spend_error(message: &str, code: &str) -> Value {
    json!({"error":{"message":message,"type":"spend_error","code":code}})
}

struct SpendGuard<'a> {
    shared: &'a Shared,
    id: u64,
    price: crate::spend::Price,
    done: bool,
}
impl SpendGuard<'_> {
    fn finish(&mut self, usage: Option<(u64, u64)>) {
        let actual = usage.and_then(|(i,o)| self.price.cost(i,o));
        if self.shared.spend.lock().unwrap().change(|l| l.settle(self.id, actual)).is_err() {
            eprintln!("spend settlement unavailable; reservation retained");
        }
        self.done = true;
    }
    fn refund(&mut self) { self.finish(Some((0,0))); }
}
impl Drop for SpendGuard<'_> {
    fn drop(&mut self) { if !self.done { self.finish(None); } }
}

fn reserve_spend<'a>(shared: &'a Shared, entry: &crate::config::KeyEntry, model: &crate::config::ModelEntry, payload: &Value) -> Result<Option<SpendGuard<'a>>, (u16, &'static str, &'static str)> {
    let settings = &shared.config.spend;
    if !settings.enabled { return Ok(None); }
    let price = settings.price(&model.public);
    let owner = entry.role == Role::Owner;
    if !owner && settings.error.is_some() { return Err((503, "spend configuration unavailable", "spend_config_error")); }
    let amount = if owner { 0 } else {
        // A verified context bound, not a prompt token estimate. Reserve both
        // full input and full output windows, multiplied by completion count.
        let context = model.context.ok_or((503, "model needs a verified accounting bound", "spend_bound_unavailable"))? as u64;
        let n = match payload.get("n") { None => 1, Some(v) => v.as_u64().filter(|n| *n > 0 && *n <= 8).ok_or((400, "n must be an integer from 1 to 8", "invalid_request"))? };
        let output = context.checked_mul(n).ok_or((503,"accounting overflow","spend_bound_unavailable"))?;
        price.cost(context, output).ok_or((503,"accounting overflow","spend_bound_unavailable"))?
    };
    let mut store = shared.spend.lock().unwrap();
    let cap = if owner { None } else { Some(settings.cap(&store.ledger, &entry.name)) };
    match store.change(|ledger| ledger.reserve(&entry.name, &model.public, &chrono_day(), amount, cap)) {
        Ok(id) => Ok(Some(SpendGuard { shared, id, price, done: false })),
        Err(_) if owner => { let mut unknown = shared.unknown_owner_requests.lock().unwrap(); *unknown = unknown.saturating_add(1); eprintln!("owner usage accounting unavailable; owner remains uncapped"); Ok(None) },
        Err(e) if e == "spend cap reached" => Err((429,"spend cap reached","spend_cap_exceeded")),
        Err(_) => Err((503,"spend accounting unavailable","spend_accounting_unavailable")),
    }
}

fn spend_admin(stream: &mut TcpStream, shared: &Shared, req: &Request, token: &str, cors: Option<&str>) -> std::io::Result<()> {
    let cfg = &shared.config;
    let key_ok = !cfg.admin_key.is_empty() && !cfg.admin_key.eq_ignore_ascii_case("change-me") && token == cfg.admin_key;
    let session_owner = auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id)).map(|(_,role)|role==Role::Owner).unwrap_or(false);
    if !key_ok && !session_owner {
        record_auth_failure(shared, token);
        return write_json(stream,401,&err_body("invalid api key","auth_error"),cors);
    }
    if req.method == "POST" && !key_ok {
        if req.headers.get("sec-fetch-site").map(String::as_str)==Some("cross-site") {
            return write_json(stream,403,&err_body("cross-site request rejected","auth_error"),cors);
        }
        // Cookie mutations require an explicit approved Origin, including on
        // non-browser clients. Bearer admin clients are not cookie-authorized.
        let valid_origin = req.headers.get("origin").map(|origin| {
            (!cfg.allowed_origin.is_empty() && origin==&cfg.allowed_origin) || origin_host_matches(origin,req.headers.get("host").map(String::as_str).unwrap_or(""))
        }).unwrap_or(false);
        if !valid_origin { return write_json(stream,403,&err_body("origin not allowed","auth_error"),cors); }
    }
    if req.method=="GET" && req.path=="/v1/admin/usage" {
        let store = shared.spend.lock().unwrap();
        let mut users = serde_json::Map::new();
        let day = chrono_day();
        for (name, value) in &store.ledger.users {
            let mut usage = value.clone();
            if usage.day.period != day { usage.day = crate::spend::Window { period: day.clone(), ..Default::default() }; }
            if usage.month.period != day[..7] { usage.month = crate::spend::Window { period: day[..7].into(), ..Default::default() }; }
            let owner = cfg.keys.values().any(|e|e.name==*name && e.role==Role::Owner) || cfg.oauth.owner_users.iter().any(|login|login==name);
            let cap = if owner { Value::Null } else { json!(cfg.spend.cap(&store.ledger,name)) };
            users.insert(name.clone(),json!({"day":usage.day,"month":usage.month,"cap":cap,"unknown_requests":usage.unknown_requests,"accounting_error":usage.accounting_error}));
        }
        return write_json(stream,200,&json!({"currency":"virtual USD","units_per_usd":crate::spend::USD,"users":users,"default_friend_caps":cfg.spend.default_caps,"configuration_error":cfg.spend.error,"accounting_available":store.available(),"unknown_owner_requests_since_startup":*shared.unknown_owner_requests.lock().unwrap(),"prices":cfg.spend.prices,"unknown_model_price":cfg.spend.price(""),"period_timezone":"UTC"}),cors);
    }
    if req.method=="POST" && req.path=="/v1/admin/caps" {
        let value: Value = match serde_json::from_slice(&req.body) { Ok(v)=>v,Err(_)=>return write_json(stream,400,&err_body("invalid request body","invalid_request"),cors) };
        let name = value.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || name.len()>128 { return write_json(stream,400,&err_body("account name required","invalid_request"),cors); }
        let owner = cfg.keys.values().any(|e|e.name==name && e.role==Role::Owner) || cfg.oauth.owner_users.iter().any(|login|login==name);
        if owner { return write_json(stream,400,&err_body("owner usage is uncapped","invalid_request"),cors); }
        let daily = value.get("daily").and_then(Value::as_str).and_then(crate::spend::usd);
        let monthly = value.get("monthly").and_then(Value::as_str).and_then(crate::spend::usd);
        let (Some(daily),Some(monthly))=(daily,monthly) else { return write_json(stream,400,&err_body("daily and monthly must be decimal USD strings","invalid_request"),cors); };
        let cap = crate::spend::Caps { daily,monthly };
        if shared.spend.lock().unwrap().change(|l| { l.caps.insert(name.into(),cap); Ok(()) }).is_err() {
            return write_json(stream,503,&err_body("cannot persist spend caps","spend_error"),cors);
        }
        return write_json(stream,200,&json!({"name":name,"cap":cap,"units_per_usd":crate::spend::USD}),cors);
    }
    write_json(stream,404,&err_body("not found","invalid_request"),cors)
}
