use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    in_flight: Arc<AtomicUsize>,
    read_budget_ms: AtomicU64,
    quotas: Mutex<HashMap<String, Quota>>,
    // Standard Z.AI account limit is one active inference, across all models.
    zai_in_flight: AtomicBool,
    openrouter_in_flight: AtomicBool,
    nim_in_flight: AtomicBool,
    radeon_in_flight: AtomicBool,
    logfare_in_flight: AtomicBool,
    trial_recent: Mutex<HashMap<String,Vec<Instant>>>,
    route_latency: Mutex<HashMap<(String,String),u64>>,
    observations: Mutex<crate::passive_health::Tracker>,
    auth_failures: Mutex<HashMap<String, (u32, Instant)>>,
    health: Mutex<HashMap<String, Cooldown>>,
    spend: Mutex<crate::spend::Store>,
    unknown_owner_requests: Mutex<u64>,
    keys: Mutex<crate::keys::Store>,
    images: crate::images::Switches,
}

pub struct Server {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    drain: Duration,
}

// How long drop waits for in-flight handlers before returning anyway. This
// window starts after the accept thread has been joined, so it bounds the
// drain phase, not total Drop time. A bound, not instant teardown: a handler
// stuck longer still finishes detached.
const DEFAULT_DRAIN: Duration = Duration::from_secs(2);

impl Server {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_drain_timeout(&mut self, drain: Duration) {
        self.drain = drain;
    }

    // Overall wall-clock budget for reading one request's head + body, for
    // tests that must not wait out the production 30s.
    pub fn set_request_read_budget(&self, budget: Duration) {
        self.shared.read_budget_ms.store(budget.as_millis() as u64, Ordering::SeqCst);
    }

    // Live handler count, for tests observing drain behavior.
    pub fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Wait for in-flight handlers to finish, bounded by the drain window,
        // so teardown ordering is deterministic. (A detached handler always
        // kept its stream; this bounds how long drop waits for it.)
        let deadline = Instant::now() + self.drain;
        while self.shared.in_flight.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

// Counts a live connection handler from accept to completion, including a
// panicking one (drop runs during unwind).
struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    fn enter(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        InFlight(counter.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn bind(config: Config) -> std::io::Result<Server> {
    bind_addr("127.0.0.1:0", config)
}

// GitHub login exchange bounds, per call (the exchange is two calls: token
// POST, user GET, so a fully hung github.com holds a login handler at most
// ~2x global, not the old flat 300s). The idle floor restarts per socket
// read, so a slow-but-progressing github.com survives. POLICY VALUES.
pub const GITHUB_CALL_GLOBAL: Duration = Duration::from_secs(15);
pub const GITHUB_CALL_IDLE: Duration = Duration::from_secs(10);
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";

fn github_agent(cfg: &OAuthConfig) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(cfg.exchange_global.unwrap_or(GITHUB_CALL_GLOBAL)))
        .timeout_per_read(Some(cfg.exchange_idle.unwrap_or(GITHUB_CALL_IDLE)))
        .build()
        .into()
}

pub fn bind_addr(addr: &str, config: Config) -> std::io::Result<Server> {
    let listener = TcpListener::bind(addr)?;
    let port = listener.local_addr()?.port();
    let agent: ureq::Agent = github_agent(&config.oauth);
    let spend = crate::spend::Store::open(config.spend.path.clone())?;
    let shared = Arc::new(Shared {
        keys: Mutex::new(crate::keys::Store::open(config.spend.path.clone())?),
        images: crate::images::Switches::from_env(),
        spend: Mutex::new(spend),
        unknown_owner_requests: Mutex::new(0),
        in_flight: Arc::new(AtomicUsize::new(0)),
        read_budget_ms: AtomicU64::new(REQUEST_READ_BUDGET.as_millis() as u64),
        auth: Auth::new(config.oauth.clone()),
        config,
        agent,
        quotas: Mutex::new(HashMap::new()),
        zai_in_flight: AtomicBool::new(false),
        openrouter_in_flight: AtomicBool::new(false),
        nim_in_flight: AtomicBool::new(false),
        radeon_in_flight: AtomicBool::new(false),
        logfare_in_flight: AtomicBool::new(false),
        trial_recent: Mutex::new(HashMap::new()),
        route_latency: Mutex::new(HashMap::new()),
        observations: Mutex::new(crate::passive_health::Tracker::default()),
        auth_failures: Mutex::new(HashMap::new()),
        health: Mutex::new(HashMap::new()),
    });
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    let accept_shared = shared.clone();
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(stream) = stream {
                spawn_handler(stream, accept_shared.clone());
            }
        }
    });
    Ok(Server { port, shutdown, handle: Some(handle), shared, drain: DEFAULT_DRAIN })
}

// The in-flight count is incremented synchronously, before the child spawns:
// when this returns, an accepted connection already counts even if its child
// has not been scheduled, so drop can never observe 0 for it.
fn spawn_handler(stream: TcpStream, shared: Arc<Shared>) {
    let in_flight = InFlight::enter(&shared.in_flight);
    thread::spawn(move || {
        let _in_flight = in_flight;
        let _ = handle(stream, shared);
    });
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

// Overall budget policy for reading one request's head + body. The per-read
// timeout bounds a single syscall; a client trickling a byte at a time stays
// under it, so an aggregate budget is what bounds a slow client. 30s is a new
// aggregate policy (chosen to match the per-read timeout's scale), not
// measured upload compatibility. Subject to OS scheduling and timer
// granularity: a policy bound, not a guaranteed wall-clock deadline.
const REQUEST_READ_BUDGET: Duration = Duration::from_secs(30);

#[cfg(test)]
fn read_request(stream: &mut TcpStream) -> Result<Request, &'static str> {
    read_request_within(stream, REQUEST_READ_BUDGET)
}

fn read_request_within(stream: &mut TcpStream, budget: Duration) -> Result<Request, &'static str> {
    let deadline = Instant::now() + budget;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // One read bounded by the remaining overall budget (never more than the
    // standing 30s per-read timeout), so the deadline bites mid-read instead
    // of only between reads. A trickling client resets nothing: the deadline
    // is fixed at entry.
    let header_end = loop {
        let n = read_within(stream, &mut tmp, deadline)?;
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
            // Authorization must be unambiguous. Cookie field lines are
            // combined before checking repeated exact session names.
            if k == "authorization" && headers.contains_key(&k) {
                return Err("bad request");
            }
            if k == "cookie" {
                let combined = headers.get(&k).map(|prior| format!("{prior}; {}", v.trim()))
                    .unwrap_or_else(|| v.trim().to_string());
                if combined.split(';').filter(|part| {
                    part.trim().split_once('=').map_or(part.trim(), |(name, _)| name.trim()) == "aqua_session"
                }).count() > 1 {
                    return Err("bad request");
                }
                headers.insert(k, combined);
                continue;
            }
            if k == "content-length" {
                if seen_len {
                    return Err("bad request"); // duplicate Content-Length: ambiguous framing, reject
                }
                seen_len = true;
                let raw = v.trim_matches(|c| c == ' ' || c == '\t');
                if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("bad length");
                }
                len = raw.parse().map_err(|_| "bad length")?;
            }
            headers.insert(k, v.trim().to_string());
        }
    }
    if len > MAX_BODY {
        return Err("too large");
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < len {
        let n = read_within(stream, &mut tmp, deadline)?;
        if n == 0 {
            return Err("closed");
        }
        body.extend_from_slice(&tmp[..n]);
    }
    // A read can return more than Content-Length promised; the handler sees
    // exactly the declared body, never trailing bytes.
    body.truncate(len);
    Ok(Request { method, path, query, headers, body })
}

fn read_within(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<usize, &'static str> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("timeout");
    }
    // If the timeout cannot be installed, fail the request rather than allow
    // an unbounded read.
    stream
        .set_read_timeout(Some(remaining.min(Duration::from_secs(30))))
        .map_err(|_| "read")?;
    match stream.read(buf) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => Err("timeout"),
        Err(_) => Err("read"),
    }
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
        405 => "Method Not Allowed",
        408 => "Request Timeout",
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
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
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
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\nx-frame-options: DENY\r\ncontent-security-policy: frame-ancestors 'none'\r\nx-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
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

fn write_method_not_allowed(stream: &mut TcpStream, allow: &str, cors: Option<&str>) -> std::io::Result<()> {
    let body = err_body("method not allowed", "invalid_request").to_string();
    write!(stream, "HTTP/1.1 405 Method Not Allowed\r\nallow: {}\r\ncontent-type: application/json\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}", allow, body.len(), cors_headers(cors), body)
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

// Landing is public; interactive embedded pages also require a browser session.
const PAGE_LANDING: &str = include_str!("../ui/landing.html");
const PAGE_CONSOLE: &str = include_str!("../ui/console.html");
const PAGE_PLAYGROUND: &str = include_str!("../ui/playground.html");
const PAGE_ADMIN: &str = include_str!("../ui/admin.html");
const PAGE_SETTINGS: &str = include_str!("../ui/settings.html");
const PAGE_KEYS: &str = include_str!("../ui/keys.html");

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

// An Origin is exactly scheme + authority, without a path, query, credentials
// or extra separators. A hostile sibling cannot match the target Host.
fn origin_host_matches(origin: &str, host_header: &str) -> bool {
    if host_header.is_empty() { return false; }
    let authority=origin.strip_prefix("https://").or_else(||origin.strip_prefix("http://"));
    authority.map(|host| !host.contains(['/', '?', '#', '@']) && host.eq_ignore_ascii_case(host_header)).unwrap_or(false)
}

fn handle(mut stream: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {
    let cfg = &shared.config;
    // bound downstream writes: a client that stops reading must not pin this
    // worker (and its in-flight quota slot) forever. Per write operation, so
    // healthy long streams are never cut; upstream IO carries its own
    // aggregate budget. No claim of a whole-request wall clock. If the timeout
    // cannot be installed, fail the request rather than allow unbounded writes.
    stream.set_write_timeout(Some(shared.config.upstream_budget))?;
    let budget = Duration::from_millis(shared.read_budget_ms.load(Ordering::SeqCst));
    let req = match read_request_within(&mut stream, budget) {
        Ok(r) => r,
        Err("timeout") => {
            return write_json(&mut stream, 408, &err_body("request took too long to arrive", "invalid_request"), None)
        }
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

    // Embedded page routes require sessions; bearer keys still protect API calls.
    if req.method == "GET" {
        match req.path.as_str() {
            "/" | "/landing.html" => return write_html(&mut stream, PAGE_LANDING, cors),
            "/admin" | "/admin.html" => {
                if !auth::session_cookie(&req.headers).and_then(|id|shared.auth.get_session(&id)).map(|(_,r)|r==Role::Owner).unwrap_or(false) {
                    return write_json(&mut stream,403,&err_body("owner access required","auth_error"),cors);
                }
                return write_html(&mut stream,PAGE_ADMIN,cors);
            }
            "/console.html" | "/console" | "/playground.html" | "/playground" | "/keys.html" | "/keys" | "/settings" | "/settings.html" => {
                if auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id)).is_none() {
                    return write_redirect(&mut stream, "/", &[]);
                }
                let page = if req.path.starts_with("/settings") {PAGE_SETTINGS} else if req.path.starts_with("/console") { PAGE_CONSOLE } else if req.path.starts_with("/keys") {PAGE_KEYS} else { PAGE_PLAYGROUND };
                return write_html(&mut stream, page, cors);
            }
            _ => {}
        }
    }

    // console login: browser OAuth flow, separate from the bearer-key API below
    if req.method == "GET" && req.path == "/login/github" {
        if !shared.auth.cfg.enabled() {
            return write_json(&mut stream, 503, &err_body("github login is not configured on this deployment", "auth_error"), cors);
        }
        let state = match shared.auth.new_state() {Ok(state)=>state,Err(_)=>return write_json(&mut stream,503,&err_body("secure login unavailable","auth_error"),cors)};
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
        return match github_exchange(&shared.agent, &shared.auth.cfg, &code, GITHUB_TOKEN_URL, GITHUB_USER_URL) {
            Ok(login) => match shared.auth.cfg.role_for(&login) {
                Some(role) => {
                    let id = match shared.auth.create_session(&login, role) {Ok(id)=>id,Err(_)=>return write_json(&mut stream,503,&err_body("secure login unavailable","auth_error"),cors)};
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

    // Key management is session-only. Bearer possession cannot mint keys.
    if req.path == "/v1/keys" || req.path.starts_with("/v1/keys/") {
        return manage_keys(&mut stream,&shared,&req,cors);
    }

    let token = bearer(&req);

    if matches!(req.path.as_str(), "/v1/admin/usage" | "/v1/admin/caps") {
        if auth_throttled(&shared, &token) { return write_json(&mut stream,429,&err_body("too many failed attempts","rate_limit_error"),cors); }
        return spend_admin(&mut stream,&shared,&req,&token,cors);
    }

    // Usage aggregates (summary/series) are not served by this gateway; usage
    // analytics live on the live-box lineage. Owner session or admin key only,
    // same guard shape as /v1/admin/providers: a present Authorization header
    // is authoritative, so a bad bearer stays 401 even with a valid cookie.
    // 501 (not 401) for authenticated callers so the usage page shows its
    // graceful empty state instead of a false "session expired".
    if req.method == "GET" && matches!(req.path.as_str(), "/v1/admin/usage/summary" | "/v1/admin/usage/series") {
        if auth_throttled(&shared, &token) { return write_json(&mut stream,429,&err_body("too many failed attempts","rate_limit_error"),cors); }
        let admin_ok = !cfg.admin_key.is_empty() && !cfg.admin_key.eq_ignore_ascii_case("change-me") && token == cfg.admin_key;
        let cookie_owner = !req.headers.contains_key("authorization")
            && auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id)).map(|(_,r)| r==Role::Owner).unwrap_or(false);
        if !admin_ok && !cookie_owner {
            record_auth_failure(&shared, &token);
            return write_json(&mut stream, 401, &err_body("invalid api key","auth_error"),cors);
        }
        return write_json(&mut stream, 501, &err_body("usage aggregates are not served by this gateway","not_implemented"),cors);
    }

    if req.method == "GET" && req.path == "/v1/admin/providers" {
        // Throttle check first: admin-key guessing must hit the same 429 wall as API keys.
        if auth_throttled(&shared, &token) {
            return write_json(&mut stream, 429, &err_body("too many failed attempts", "rate_limited"), cors);
        }
        if !( !cfg.admin_key.is_empty() && !cfg.admin_key.eq_ignore_ascii_case("change-me") && token == cfg.admin_key )
            && !( !req.headers.contains_key("authorization") && auth::session_cookie(&req.headers).and_then(|id|shared.auth.get_session(&id)).map(|(_,r)|r==Role::Owner).unwrap_or(false) ) {
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
                    "retention": crate::preferences::facts(&p.id),
                })
            })
            .collect();
        let mut models: Vec<Value> = Vec::new();
        for p in &cfg.providers {
            for m in &p.models {
                let route = json!({"provider":p.id,"upstream":m.upstream,"status":p.status.as_str(),"configured":!p.api_key.is_empty(),"retention":crate::preferences::facts(&p.id)});
                if let Some(row) = models.iter_mut().find(|row|row["id"].as_str()==Some(&m.public)) {
                    row["routes"].as_array_mut().unwrap().push(route);
                    row["binding_count"] = json!(row["routes"].as_array().unwrap().len());
                } else { models.push(json!({"id":m.public,"routes":[route],"binding_count":1})); }
            }
        }
        return write_json(&mut stream, 200, &json!({ "providers": providers, "models": models }), cors);
    }

    if req.path == "/v1/admin/resolve" {
        // Read-only owner diagnostic.
        if auth_throttled(&shared, &token) {
            return write_json(&mut stream, 429, &err_body("too many failed attempts", "rate_limit_error"), cors);
        }
        // Main's auth only (main's scope decision, reversing the A8 keep-both):
        // the admin key, or an owner session cookie. Legacy and generated
        // bearer keys are NOT accepted on this route.
        let admin_ok = !cfg.admin_key.is_empty() && !cfg.admin_key.eq_ignore_ascii_case("change-me") && token == cfg.admin_key;
        let cookie_login: Option<String> = if !req.headers.contains_key("authorization") {
            auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id))
                .and_then(|(name,role)| if role==Role::Owner { Some(name) } else { None })
        } else { None };
        let ops_login = cookie_login;
        if !admin_ok && ops_login.is_none() {
            // Anonymous traffic must not lock out valid cookie sessions.
            if req.headers.contains_key("authorization") && !token.is_empty() { record_auth_failure(&shared, &token); }
            return write_json(&mut stream, 401, &err_body("invalid api key", "auth_error"), cors);
        }
        if req.method != "GET" {
            return write_method_not_allowed(&mut stream, "GET", cors);
        }
        let query=auth::parse_query(&req.query);
        let Some(requested)=query.get("model").filter(|v|!v.is_empty() && v.len()<=256) else {
            return write_json(&mut stream,400,&err_body("model query required (max 256 bytes)","invalid_request"),cors);
        };
        let store=shared.spend.lock().unwrap();
        if !store.available(){return write_json(&mut stream,503,&err_body("settings unavailable","settings_unavailable"),cors);}
        // Resolve honors the same login preference for keys and cookies.
        let strict=ops_login.as_ref().is_some_and(|name|store.ledger.preferences.get(name).is_some_and(|p|p.zdr_only));
        drop(store);
        return write_json(&mut stream,200,&resolve_model(&shared,requested,strict,Role::Owner),cors);
    }

    // Unknown non-API GETs (favicon, webfont paths on hosts that do not serve
    // them, crawler probes) are not credential attempts: plain 404, recorded
    // nowhere, so they cannot spend the shared empty-bearer throttle and 429
    // legitimate cookie traffic. /v1/* and every method other than GET keep
    // the full gate below; this adds no route and bypasses no auth.
    if req.method == "GET" && !req.path.starts_with("/v1/") {
        return write_json(&mut stream, 404, &err_body("not found","not_found"), cors);
    }

    // A present Authorization header is authoritative, even if malformed.
    // Never silently downgrade an explicit bearer failure to cookie authority.
    // Only models/chat accept session API auth; admin routes above retain their
    // separate owner/admin checks. Session IDs and synthetic API keys never leave.
    let session_entry = if !req.headers.contains_key("authorization")
        && matches!((req.method.as_str(),req.path.as_str()),
            ("GET","/v1/models") | ("POST","/v1/chat/completions") | ("GET","/v1/settings") | ("POST","/v1/settings") | ("POST","/v1/images/generations") | ("GET","/v1/images/models")) {
        auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id))
            .map(|(login,role)| crate::config::KeyEntry {name:login.to_ascii_lowercase(),role})
    } else {None};
    let generated_entry = if token.starts_with("aqua_sk_") {
        // Current allowlist is authoritative, not a role frozen at key creation.
        shared.keys.lock().unwrap().resolve(&token).ok().flatten()
            .and_then(|login| cfg.oauth.role_for(&login).map(|role|crate::config::KeyEntry{name:login,role}))
    } else {None};
    let entry = if let Some(ref entry) = session_entry {
        if req.method == "POST" && !cookie_origin_ok(&req,cfg) {
            return write_json(&mut stream,403,&err_body("origin not allowed","auth_error"),cors);
        }
        entry
    } else {
        if auth_throttled(&shared, &token) {
            return write_json(&mut stream, 429, &err_body("too many failed attempts", "rate_limit_error"), cors);
        }
        if let Some(ref entry) = generated_entry {entry} else {
            if token.starts_with("aqua_sk_") {
                record_auth_failure(&shared,&token);
                return write_json(&mut stream,401,&err_body("invalid api key","auth_error"),cors);
            }
            match cfg.keys.get(&token).filter(|_| !token.is_empty() && !token.eq_ignore_ascii_case("change-me")) {
                Some(e) => e,
                None => {
                    record_auth_failure(&shared, &token);
                    return write_json(&mut stream, 401, &err_body("invalid api key", "auth_error"), cors);
                }
            }
        }
    };
    // Canonicalize BEFORE every quota/spend/account operation. Legacy labels
    // cannot create a second identity alongside a GitHub login. With OAuth
    // allowlists configured, an alias or role mismatch is rejected, not guessed.
    let canonical_name=entry.name.to_ascii_lowercase();
    if !cfg.oauth.owner_users.is_empty() || !cfg.oauth.friend_users.is_empty() {
        if cfg.oauth.role_for(&canonical_name)!=Some(entry.role) {
            return write_json(&mut stream,401,&err_body("key account is not an allowed login","auth_error"),cors);
        }
    }
    let canonical_entry=crate::config::KeyEntry{name:canonical_name,role:entry.role};
    let entry=&canonical_entry;
    // Re-logins and concurrent browser sessions share one daily request quota.
    // The spend/account ledgers below already use entry.name for all API paths.
    let quota_token = format!("login:{}",entry.name.to_ascii_lowercase());

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/images/models") | ("POST", "/v1/images/generations") => {
            if entry.role != Role::Owner {
                let (status,body)=crate::images::Failure::Owner.response();
                return write_json(&mut stream,status,&body,cors);
            }
            let store=shared.spend.lock().unwrap();
            if !store.available() {return write_json(&mut stream,503,&err_body("settings unavailable","settings_unavailable"),cors);}
            let strict=store.ledger.preferences.get(&entry.name).is_some_and(|p|p.zdr_only);
            drop(store);
            if req.method=="GET" {
                // No qualified route. Keep image aliases out of the text catalog.
                return write_json(&mut stream,200,&json!({"object":"list","data":[]}),cors);
            }
            let (status,body)=crate::images::unavailable(&req.body,true,strict,&shared.images);
            return write_json(&mut stream,status,&body,cors);
        }
        ("GET", "/v1/settings") => {
            let store=shared.spend.lock().unwrap();
            if !store.available() {return write_json(&mut stream,503,&err_body("settings unavailable","settings_unavailable"),cors);}
            let value=store.ledger.preferences.get(&entry.name).cloned().unwrap_or_default();
            return write_json(&mut stream,200,&json!(value),cors);
        }
        ("POST", "/v1/settings") => {
            let value=serde_json::from_slice::<crate::preferences::Preferences>(&req.body);
            let Ok(value)=value else {return write_json(&mut stream,400,&err_body("invalid settings","invalid_request"),cors);};
            if !value.valid() {return write_json(&mut stream,400,&err_body("invalid settings","invalid_request"),cors);}
            let mut store=shared.spend.lock().unwrap();
            if !store.durable() || store.change(|ledger|ledger.set_preferences(&entry.name,value.clone())).is_err() {
                return write_json(&mut stream,503,&err_body("settings could not be saved","settings_unavailable"),cors);
            }
            return write_json(&mut stream,200,&json!(value),cors);
        }
        ("GET", "/v1/models") => {
            // canonical models, deduplicated across provider bindings; the auto
            // alias is advertised only when a shortlist is actually configured
            let store=shared.spend.lock().unwrap();
            if !store.available() {return write_json(&mut stream,503,&err_body("settings unavailable","settings_unavailable"),cors);}
            let strict=store.ledger.preferences.get(&entry.name).is_some_and(|p|p.zdr_only);
            drop(store);
            let mut data = Vec::new();
            let mut seen = std::collections::HashSet::new();
            if !shared.config.auto_shortlist.is_empty() {
                data.push(json!({ "id": ALIAS, "object": "model", "created": 0, "owned_by": "aqua" }));
                seen.insert(ALIAS.to_string());
            }
            for p in &shared.config.providers {
                if p.status == Status::Off || p.api_key.is_empty() || (owner_trial(&p.id) && entry.role!=Role::Owner) || !crate::preferences::allows(&p.id,strict) {
                    continue;
                }
                if (p.status != Status::Friends || p.id == "zro") && entry.role != Role::Owner {
                    continue;
                }
                if p.id=="cloudflare" {continue;}
                if p.id=="openrouter" && (cfg.spend.account_verified_day!=chrono_day() || cfg.spend.openrouter_allowance==0 || !shared.spend.lock().unwrap().durable()) {continue;}
                for m in &p.models {
                    if owner_trial(&p.id) && !trial_model(&p.id,&m.upstream) {continue;}
                    if p.id=="openrouter" && !OPENROUTER_FREE.contains(&m.upstream.as_str()) {continue;}
                    if entry.role != Role::Owner && cfg.spend.restricted(&m.public) { continue; }
                    if m.public == ALIAS || !seen.insert(m.public.clone()) {
                        continue;
                    }
                    let mut v = json!({ "id": m.public, "object": "model", "created": 0, "owned_by": "aqua" });
                    v["maker_pricing"] = crate::maker_pricing::metadata(&m.public);
                    if let Some(c) = m.context {
                        v["context"] = json!(c);
                    }
                    data.push(v);
                }
            }
            for model in &mut data {
                model["health"] = model_health(&shared, model["id"].as_str().unwrap_or(""), strict, entry.role);
            }
            write_json(&mut stream, 200, &json!({ "object": "list", "data": data }), cors)
        }
        ("POST", "/v1/chat/completions") => chat(&mut stream, &shared, &req, entry, &quota_token, cors),
        _ => write_json(&mut stream, 404, &err_body("not found", "invalid_request"), cors),
    }
}

fn cookie_origin_ok(req:&Request,cfg:&Config)->bool {
    req.headers.get("sec-fetch-site").map(String::as_str)!=Some("cross-site") && req.headers.get("origin").map(|origin|
        (!cfg.allowed_origin.is_empty() && origin==&cfg.allowed_origin) || ((!cfg.oauth.secure_cookies() || origin.starts_with("https://")) && origin_host_matches(origin,req.headers.get("host").map(String::as_str).unwrap_or("")))
    ).unwrap_or(false)
}
fn manage_keys(stream:&mut TcpStream,shared:&Shared,req:&Request,cors:Option<&str>)->std::io::Result<()> {
    let login=match auth::session_cookie(&req.headers).and_then(|id|shared.auth.get_session(&id)) {Some((login,_))=>login.to_ascii_lowercase(),None=>return write_json(stream,401,&err_body("sign in required","auth_error"),cors)};
    if req.method=="POST" && !cookie_origin_ok(req,&shared.config) {return write_json(stream,403,&err_body("origin not allowed","auth_error"),cors);}
    let mut keys=shared.keys.lock().unwrap();
    match (req.method.as_str(),req.path.as_str()) {
        ("GET","/v1/keys")=>match keys.list(&login) {Ok(data)=>write_json(stream,200,&json!({"data":data}),cors),Err(_)=>write_json(stream,503,&err_body("key storage unavailable","storage_error"),cors)},
        ("POST","/v1/keys")=>{
            let body:Value=match serde_json::from_slice(&req.body){Ok(v)=>v,Err(_)=>return write_json(stream,400,&err_body("invalid JSON","invalid_request"),cors)};
            let name=body.get("name").and_then(Value::as_str).unwrap_or("");
            if name.trim().is_empty()||name.len()>64||name.chars().any(char::is_control){return write_json(stream,400,&err_body("key name must be 1-64 bytes without control characters","invalid_request"),cors);}
            match keys.create(&login,name){Ok(key)=>write_json(stream,201,&key,cors),Err(_)=>write_json(stream,503,&err_body("key creation unavailable or key limit reached","storage_error"),cors)}
        }
        ("POST",path) if path.starts_with("/v1/keys/") && path.ends_with("/revoke")=>{
            let id=match path.strip_prefix("/v1/keys/").and_then(|s|s.strip_suffix("/revoke")).filter(|id|id.len()==32&&id.bytes().all(|b|b.is_ascii_hexdigit())) {
                Some(id)=>id,None=>return write_json(stream,404,&err_body("key not found","invalid_request"),cors)
            };match keys.revoke(&login,id){Ok(true)=>write_json(stream,200,&json!({"revoked":true}),cors),Ok(false)=>write_json(stream,404,&err_body("key not found","invalid_request"),cors),Err(_)=>write_json(stream,503,&err_body("key storage unavailable","storage_error"),cors)}
        }
        _=>write_json(stream,404,&err_body("not found","invalid_request"),cors)
    }
}

const AUTH_FAIL_LIMIT: u32 = 5; // per token per 60s window
const AUTH_FAIL_MAP_CAP: usize = 10_000;

// GitHub OAuth: exchange the callback code for the user's login. Errors are
// generic on purpose; the upstream body never reaches the client.
fn github_exchange(agent: &ureq::Agent, cfg: &OAuthConfig, code: &str, token_url: &str, user_url: &str) -> Result<String, &'static str> {
    let body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        auth::url_encode(&cfg.client_id),
        auth::url_encode(&cfg.client_secret),
        auth::url_encode(code),
        auth::url_encode(&cfg.redirect_uri())
    );
    let mut resp = agent
        .post(token_url)
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
        .get(user_url)
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
    let entry = failures.entry(crate::keys::fingerprint(token)).or_insert((0, Instant::now()));
    if entry.1.elapsed() > Duration::from_secs(60) {
        *entry = (0, Instant::now());
    }
    entry.0 += 1;
}

fn auth_throttled(shared: &Shared, token: &str) -> bool {
    let failures = shared.auth_failures.lock().unwrap();
    match failures.get(&crate::keys::fingerprint(token)) {
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

// One nonmutating eligibility shared by the resolve walk and model health:
// held providers (cloudflare), stale, unfunded or undurable openrouter
// accounts, off or unconfigured routes, denied privacy and role-based
// restrictions all read as not serving. No requests, quotas, counters, or
// settings mutations occur in this diagnostics path.
fn openrouter_currently_serving(shared:&Shared) -> bool {
    let store=shared.spend.lock().unwrap();
    let ok=shared.config.spend.account_verified_day==chrono_day()
        && shared.config.spend.openrouter_allowance>0 && store.durable();
    drop(store);
    ok
}
fn route_serving(p:&crate::config::Provider, role:Role, strict:bool, openrouter_ok:bool) -> bool {
    p.status != Status::Off
        && crate::preferences::allows(&p.id,strict) && !p.api_key.is_empty()
        && !p.base_url.is_empty() && !p.models.is_empty()
        && (!owner_trial(&p.id) || role==Role::Owner)
        && (role==Role::Owner || (p.status==Status::Friends && p.id!="zro"))
        && p.id!="cloudflare"
        && (p.id!="openrouter" || openrouter_ok)
}
fn route_model_serving(cfg:&crate::config::Config, p:&crate::config::Provider, m:&crate::config::ModelEntry, role:Role) -> bool {
    chat_model_eligible(&p.id,&m.upstream)
        && (p.id!="openrouter" || OPENROUTER_FREE.contains(&m.upstream.as_str()))
        && (role==Role::Owner || !cfg.spend.restricted(&m.public))
}
fn chat_model_eligible(provider:&str,model:&str)->bool {
    !owner_trial(provider)||trial_model(provider,model)
}

// One candidate walk for read-only diagnostics, mirroring dispatch ordering.
// The 1017 snapshot stays failover-only here exactly as in chat().
fn route_candidates<'a>(shared: &'a Shared, requested: &str, strict: bool, role: Role)
    -> (Vec<(&'a crate::config::Provider, &'a crate::config::ModelEntry)>, usize, bool) {
    let openrouter_ok = openrouter_currently_serving(shared);
    let eligible = |p: &&crate::config::Provider| route_serving(p,role,strict,openrouter_ok);
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
                for m in p.models.iter().filter(|m| m.public == name && route_model_serving(&shared.config,p,m,role)) {
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
            let latency=shared.route_latency.lock().unwrap();
            fresh.sort_by_key(|(p,m)|latency.get(&(p.id.clone(),m.public.clone())).copied().unwrap_or(u64::MAX));
            drop(latency);
            immediate += fresh.len() + cooled.len();
            let start = candidates.len();
            candidates.extend(fresh);
            candidates.extend(cooled.into_iter().map(|(c, _)| c));
            candidates.extend(deferred);
            // The 1017 snapshot is failover, never a latency-promoted primary.
            if name == "deepseek-v4.1-flash" {
                candidates[start..].sort_by_key(|(_,m)|m.upstream == "deepseek-v4.1-flash-1017");
            }
        };
        if requested == ALIAS {
            for name in &shared.config.auto_shortlist {
                push_model(name);
            }
        } else {
            push_model(requested);
        }
    }
    (candidates, immediate, hard_excluded)
}

// Match actual catalog/dispatch eligibility. A configured route with a stale
// allowance, missing key, denied privacy or excluded model is not serving.
fn model_health(shared:&Shared, model:&str, strict:bool, role:Role) -> Value {
    let openrouter_ok=openrouter_currently_serving(shared);
    let routes=shared.config.providers.iter().filter(|p|route_serving(p,role,strict,openrouter_ok))
        .flat_map(|p|p.models.iter().filter(move |m|route_model_serving(&shared.config,p,m,role))
            .map(move |m|(p,m)))
        .filter(|(_,m)|if model==ALIAS {shared.config.auto_shortlist.contains(&m.public)}else{m.public==model})
        .map(|(p,m)|(p.id.as_str(),m.public.as_str(),m.upstream.as_str()));
    shared.observations.lock().unwrap().aggregate(routes)
}

fn resolve_model(shared: &Shared, requested: &str, strict: bool, role: Role) -> Value {
    let canonical = legacy_request_name(requested);
    let (candidates, _, _) = route_candidates(shared, canonical, strict, role);
    let health = shared.health.lock().unwrap();
    let now = Instant::now();
    let rows: Vec<Value> = candidates.iter().map(|(p,m)| json!({
        "provider":p.id,"upstream":m.upstream,"status":p.status.as_str(),
        "configured":!p.api_key.is_empty(),
        "deferred":health.get(&p.id).is_some_and(|cd|cd.hard && cd.until>now)
    })).collect();
    json!({"requested":requested,"canonical":canonical,"known":!rows.is_empty(),"candidates":rows})
}

// Hidden legacy request names map to the canonical model before access and
// spend checks. Shared by chat dispatch and the read-only resolve diagnostic.
// Request-side alias parity with the live lineage's canonical_model table
// (live config.rs, sha 407b2f3f verified): every alias live accepted resolves
// to the same canonical model here. deepseek-v4.1-flash-route-b is kept from
// this lineage; live mapped the -route-c spelling and the 1017 snapshot name.
// Alias coverage only: no catalog merge, no pricing reshape (A9b decision).
fn legacy_request_name(name:&str)->&str {
    match name {
        "deepseek-v4.1-flash-1017" | "deepseek-v4.1-flash-route-b" | "deepseek-v4.1-flash-route-c" => "deepseek-v4.1-flash",
        "deepseek-v4-flash:fp8" | "deepseek-v4-flash-route-b" => "deepseek-v4-flash",
        "glm-5.3-flash-route-b" | "glm-5.3-flash-route-c" => "glm-5.3-flash",
        "qwen-3.8-27b-route-b" => "qwen-3.8-27b",
        "nemotron-3-ultra-550b-a55b-route-b" => "nemotron-3-ultra-550b-a55b",
        "nemotron-3.5-super-vl-route-b" => "nemotron-3.5-super-vl",
        other => other,
    }
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
    // The reviewed runtime mappings must supply these canonical public bindings.
    let requested = legacy_request_name(requested);
    let store=shared.spend.lock().unwrap();
    if !store.available() {return write_json(stream,503,&err_body("settings unavailable","settings_unavailable"),cors);}
    let strict=store.ledger.preferences.get(&entry.name).is_some_and(|p|p.zdr_only);
    drop(store);
    let eligible = |p: &&crate::config::Provider| {
        p.status != Status::Off
            && (!owner_trial(&p.id) || entry.role==Role::Owner)
            && crate::preferences::allows(&p.id,strict)
            && !p.api_key.is_empty()
            && !p.base_url.is_empty()
            && !p.models.is_empty()
            && ((p.status == Status::Friends && p.id != "zro") || entry.role == Role::Owner)
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
            .any(|p| p.models.iter().any(|m| m.public == name && (!owner_trial(&p.id)||trial_model(&p.id,&m.upstream))))
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
                for m in p.models.iter().filter(|m| m.public == name && (!owner_trial(&p.id)||trial_model(&p.id,&m.upstream))) {
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
            let latency=shared.route_latency.lock().unwrap();
            fresh.sort_by_key(|(p,m)|latency.get(&(p.id.clone(),m.public.clone())).copied().unwrap_or(u64::MAX));
            drop(latency);
            immediate += fresh.len() + cooled.len();
            let start = candidates.len();
            candidates.extend(fresh);
            candidates.extend(cooled.into_iter().map(|(c, _)| c));
            candidates.extend(deferred);
            // The 1017 snapshot is failover, never a latency-promoted primary.
            if name == "deepseek-v4.1-flash" {
                candidates[start..].sort_by_key(|(_,m)|m.upstream == "deepseek-v4.1-flash-1017");
            }
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

    // Every fallback shares one start. Non-NIM routes retain the configured
    // aggregate window. Only an owner actually dispatching NIM may use 120s.
    let request_started = Instant::now();

    let mut saw_rate_limit = false;
    let mut tried: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (p, m) in candidates {
        // Re-read privacy at dispatch: a concurrent settings change must not let
        // a queued request escape through a route newly excluded by its owner.
        let store=shared.spend.lock().unwrap();
        if !store.available() {return write_json(stream,503,&err_body("settings unavailable","settings_unavailable"),cors);}
        let strict=store.ledger.preferences.get(&entry.name).is_some_and(|p|p.zdr_only);
        drop(store);
        if !crate::preferences::allows(&p.id,strict) {continue;}

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
        // Cloudflare stays closed until GLM full-input and total-output neuron
        // bounds are independently verified. Catalog presence is insufficient.
        if p.id=="cloudflare" { continue; }
        if owner_trial(&p.id) && (entry.role!=Role::Owner || !trial_model(&p.id,&m.upstream) || !bounded_text_messages(&payload)
            || serde_json::to_vec(&payload).map_or(true,|b|b.len()>8192) || payload.get("n").is_some_and(|v|v.as_u64()!=Some(1))) {continue;}
        let limited = if p.id=="openrouter" { Some(&shared.openrouter_in_flight) }
            else if p.id=="zai" { Some(&shared.zai_in_flight) }
            else if p.id=="nim" { Some(&shared.nim_in_flight) }
            else if p.id=="radeon" { Some(&shared.radeon_in_flight) }
            else if p.id=="logfare" { Some(&shared.logfare_in_flight) } else { None };
        let _provider_slot = if let Some(slot)=limited {
            if slot.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
                continue;
            }
            Some(ProviderSlot(slot))
        } else { None };
        let mut up_body = serde_json::Map::new();
        for k in PARAM_WHITELIST {
            if let Some(v) = payload.get(*k) {
                up_body.insert((*k).to_string(), v.clone());
            }
        }
        if p.id=="openrouter" {
            if !OPENROUTER_FREE.contains(&m.upstream.as_str()) {continue;}
            // Refuse multimodal/unknown input rather than guess token size.
            if !bounded_text_messages(&payload) {continue;}
            let output=payload.get("max_tokens").map(Value::as_u64).unwrap_or(Some(512));
            let Some(output)=output.filter(|n|*n>0 && *n<=1024) else {continue;};
            if payload.get("n").is_some_and(|n|n.as_u64()!=Some(1)) {continue;}
            up_body.insert("max_tokens".into(),json!(output));
            up_body.insert("n".into(),json!(1));
            up_body.insert("provider".into(),json!({"allow_fallbacks":false,"require_parameters":true,"max_price":{"prompt":0,"completion":0}}));
        }
        up_body.insert("model".into(), json!(m.upstream));
        up_body.insert("stream".into(), json!(want_stream));
        if want_stream && shared.config.spend.enabled {
            up_body.insert("stream_options".into(), json!({"include_usage":true}));
        }

        let Some(remaining) = provider_remaining_budget(&p.id, entry.role==Role::Owner,
            shared.config.upstream_budget, request_started.elapsed()) else {
            continue; // this route's shared window expired; NIM may still qualify
        };
        let attempt_agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(remaining))
            // idle floor: a stalled upstream read fails the attempt in
            // upstream_idle instead of holding it to the aggregate budget;
            // restarts per read, so steady drip-feeds survive
            .timeout_per_read(Some(shared.config.upstream_idle))
            .max_redirects(if owner_trial(&p.id) {0} else {10})
            .build()
            .into();
        let url = format!("{}/chat/completions", p.base_url.trim_end_matches('/'));
        if p.id=="openrouter" {
            let day=chrono_day();
            if shared.config.spend.account_verified_day!=day || shared.config.spend.openrouter_allowance==0 {continue;}
            let mut store=shared.spend.lock().unwrap();
            if !store.durable() || store.change(|ledger|ledger.admit_account("openrouter",&day,&entry.name,entry.role==Role::Owner,
                &m.upstream,1,shared.config.spend.openrouter_allowance,shared.config.spend.openrouter_allowance,3,10)).is_err() {continue;}
        }
        if owner_trial(&p.id) && !reserve_trial_rpm(shared,&p.id) {continue;}
        let mut spend = match reserve_spend(shared,entry,m,&payload) {
            Ok(guard) => guard,
            Err((status,message,code)) => return write_json(stream,status,&spend_error(message,code),cors),
        };
        guard.dispatched = true;
        shared.observations.lock().unwrap().attempt(&p.id,&m.public,&m.upstream);
        let attempt_started=Instant::now();
        let resp = attempt_agent
            .post(&url)
            .header("authorization", &format!("Bearer {}", p.api_key))
            .header("content-type", "application/json")
            .send_json(&Value::Object(up_body));
        let mut resp = match resp {
            Ok(r) => r,
            Err(_) => {
                shared.observations.lock().unwrap().transport_failure(&p.id,&m.public,&m.upstream);
                set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
                continue; // network failure: try the next provider
            }
        };
        let header_latency=attempt_started.elapsed();
        let status = resp.status().as_u16();
        shared.observations.lock().unwrap().header(&p.id,&m.public,&m.upstream,status);
        if !(200..300).contains(&status) {
            shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,false);
            if matches!(status,400|401|403|404|422|429) {
                if let Some(guard) = spend.as_mut() { guard.refund(); }
            }
            if status == 429 {
                saw_rate_limit = true;
                // Even absent/malformed Retry-After, an explicit 429 blocks
                // this provider account. Never soften it into ordering only.
                let secs = parse_retry_after(&resp)
                    .map(|n| shared.config.backoff.retry_after_secs(n))
                    .unwrap_or_else(|| shared.config.backoff.missing_429_secs());
                set_cooldown(shared, &p.id, secs, true);
            } else if status == 503 {
                match parse_retry_after(&resp) {
                    Some(secs) => set_cooldown(shared, &p.id,
                        shared.config.backoff.retry_after_secs(secs), true),
                    None => set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false),
                }
            } else {
                set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
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
                shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,false);
                set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
                continue;
            }
            let Ok(json) = serde_json::from_slice::<Value>(&buf) else {
                shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,false);
                set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
                continue;
            };
            // A parseable body is not yet a completion: providers answer 2xx
            // with error envelopes, nulls and empty objects. Only a real
            // completion (non-empty choices, no top-level error) may commit
            // downstream; anything else takes the same fail-closed path as an
            // unparseable body, so no success is recorded and a live cooldown
            // is preserved. This is a narrow envelope check, not full schema
            // validation of the completion, and it is not applied to SSE
            // streams (the SseRewriter validates streamed frames separately).
            if json.get("error").is_some()
                || json.get("choices").and_then(Value::as_array).is_none_or(|c| c.is_empty())
            {
                shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,false);
                set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
                continue;
            }
            shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,status==200);
            record_route_latency(shared,&p.id,&m.public,header_latency);
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
            shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,false);
            set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
            continue;
        }
        record_route_latency(shared,&p.id,&m.public,header_latency);
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
        let mut clean_eof=false;
        let mut upstream_failed=false;
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => {clean_eof=true;break;},
                Ok(n) => {
                    let mut out = Vec::new();
                    if !rewriter.push(&chunk[..n], &mut out) {
                        // upstream sent an unbounded undelimited blob; the 200
                        // and stream headers are long committed, so never fail
                        // over mid-response: end the stream honestly (the
                        // client sees it terminate without [DONE])
                        upstream_failed=true;
                        break;
                    }
                    if sent + out.len() > MAX_RESPONSE {
                        upstream_failed=true;
                        break; // hard cap: stream just ends
                    }
                    if stream.write_all(&out).is_err() {
                        return Ok(()); // client gone
                    }
                    let _ = stream.flush();
                    sent += out.len();
                }
                Err(_) => {
                    // upstream died mid-stream
                    upstream_failed=true;
                    break;
                }
            }
        }
        let completed=status==200 && clean_eof && !upstream_failed && rewriter.completed_for_health();
        shared.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,completed);
        if let Some(guard) = spend.as_mut() { guard.finish(rewriter.usage()); }
        // One accepted-completion predicate drives both health and the soft
        // cooldown: a stream clears only what it proved, and a stream that
        // fails after commit cools the route. clear_cooldown never removes a
        // hard limit, and set_cooldown never shortens one.
        if completed {
            clear_cooldown(shared, &p.id);
        } else {
            set_cooldown(shared, &p.id, shared.config.backoff.soft_secs(), false);
        }
        return Ok(());
    }

    if saw_rate_limit || hard_excluded {
        write_json(stream, 429, &err_body("rate limit exceeded", "rate_limit_error"), cors)
    } else {
        write_json(stream, 503, &err_body("no models available", "upstream_unavailable"), cors)
    }
}

// Personal status never permits these development/trial accounts to serve friends.
// Owner requested light local call/concurrency controls, not spend/token caps.
fn owner_trial(id: &str) -> bool { matches!(id,"nim"|"radeon"|"logfare") }
fn trial_model(provider:&str,model:&str)->bool {
    match provider {
        "logfare"=>matches!(model,"qwen-3.8-27b"|"deepseek-v4.1-flash-1017"|"glm-5.3-flash"|"glm-5.3"|"kimi-k2.6"|"kimi-k2.7-code"),
        "nim"=>matches!(model,"z-ai/glm-5.3-flash"|"minimaxai/minimax-m3.1-flash"|"mistralai/mistral-large-4-1t-a52b"|"stepfun-ai/step-5-preview"|"nvidia/nemotron-3-ultra-550b-a55b"|"nvidia/nemotron-3.5-super-vl-120b-a12b"|"nvidia/nemotron-3.5-lightning-30b-a3b"),
        "radeon"=>matches!(model,"GLM-5.3-Flash"|"MiMo-V2.6-Flash"|"DeepSeek-V4.1-Flash"|"DeepSeek-V4-Flash"|"Qwen3.8-27B"),
        _=>false,
    }
}
fn reserve_trial_rpm(shared:&Shared,provider:&str)->bool {
    if !owner_trial(provider) {return false;}
    let mut all=shared.trial_recent.lock().unwrap();
    let calls=all.entry(provider.into()).or_default();
    let now=Instant::now();calls.retain(|t|now.duration_since(*t)<Duration::from_secs(60));
    if calls.len()>=2 {return false;}
    calls.push(now);true
}
// Successful response-header latency, not token throughput or full answer time.
// EWMA weights the latest sample 1/4; unknown routes retain configuration order.
fn record_route_latency(shared:&Shared,provider:&str,model:&str,duration:Duration) {
    if provider.len()>128 || model.len()>256 {return;}
    let sample=duration.as_micros().min(u64::MAX as u128) as u64;
    let mut cache=shared.route_latency.lock().unwrap();let key=(provider.into(),model.into());
    if let Some(previous)=cache.get_mut(&key) { *previous=((*previous as u128*3+sample as u128)/4) as u64; }
    else if cache.len()<512 {cache.insert(key,sample);}
}
fn provider_remaining_budget(id:&str,owner:bool,configured:Duration,elapsed:Duration)->Option<Duration> {
    let window=if id=="nim" && owner {Duration::from_secs(120)} else {configured};
    window.checked_sub(elapsed).filter(|d|!d.is_zero())
}

// gemma stays OUT of the OpenRouter free gate: A9a is HELD for Luke, so no
// gemma upstream is admitted here until he decides. Scope: this removal is
// fail-closed for the OpenRouter provider only. It is NOT equivalent to the
// live lineage's family-wide exclusion (config.rs exclude_gemma, a policy
// this lineage does not have); A9a parity remains open.
const OPENROUTER_FREE: &[&str]=&[
    "cohere/north-mini-code:free", "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3.5-super-vl:free",
];
fn bounded_text_messages(payload: &Value)->bool {
    // This byte limit is a conservative transport restriction, not a tokenizer.
    // Cloudflare's neuron admission must not reuse it as a verified token bound.
    if payload.get("tools").is_some() || payload.get("tool_choice").is_some() {return false;}
    let Some(messages)=payload.get("messages").and_then(Value::as_array) else {return false;};
    if messages.is_empty() || messages.len()>64 {return false;}
    if messages.iter().any(|m| m.as_object().is_none_or(|m|m.keys().any(|k|!matches!(k.as_str(),"role"|"content")) )
        || !matches!(m.get("role").and_then(Value::as_str),Some("system"|"user"|"assistant"))
        || m.get("content").and_then(Value::as_str).is_none()) {return false;}
    serde_json::to_vec(messages).is_ok_and(|b|b.len()<=8192)
}

// RAII release also covers invalid responses, network errors and client exits.
struct ProviderSlot<'a>(&'a AtomicBool);
impl Drop for ProviderSlot<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

#[cfg(test)]
const COOLDOWN_SOFT_SECS: u64 = 15;
#[cfg(test)]
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
// widths and out-of-range values are treated as absent (status-specific default): a
// malformed untrusted header must never panic or silently become a limit.
fn parse_retry_after(resp: &ureq::http::Response<ureq::Body>) -> Option<u64> {
    let raw = resp.headers().get("retry-after")?.to_str().ok()?.trim();
    // RFC 9110 delta-seconds are digits only: a leading '+' (which
    // u64::from_str would accept) or any other junk is malformed and falls
    // through to the status-specific default
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
            backoff: Default::default(),
            keys: HashMap::new(),
            admin_key: String::new(),
            daily_limit: 200,
            allowed_origin: String::new(),
            providers: vec![],
            oauth: Default::default(), spend: Default::default(),
            auto_shortlist: vec![],
            upstream_budget: std::time::Duration::from_secs(300),
            upstream_idle: std::time::Duration::from_secs(60),
        };
        Shared {
            keys: Mutex::new(crate::keys::Store::open(None).unwrap()),
            images: crate::images::Switches::default(),
            spend: Mutex::new(crate::spend::Store::open(None).unwrap()),
            unknown_owner_requests: Mutex::new(0),
            in_flight: Arc::new(AtomicUsize::new(0)),
            read_budget_ms: AtomicU64::new(REQUEST_READ_BUDGET.as_millis() as u64),
            auth: Auth::new(config.oauth.clone()),
            config,
            agent: ureq::Agent::new_with_defaults(),
            quotas: Mutex::new(HashMap::new()),
            zai_in_flight: AtomicBool::new(false),
            openrouter_in_flight: AtomicBool::new(false),
        nim_in_flight: AtomicBool::new(false),
        radeon_in_flight: AtomicBool::new(false),
        logfare_in_flight: AtomicBool::new(false),
        trial_recent: Mutex::new(HashMap::new()),
        route_latency: Mutex::new(HashMap::new()),
            observations: Mutex::new(crate::passive_health::Tracker::default()),
            auth_failures: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn in_flight_guard_counts_a_panicking_handler() {
        let counter = Arc::new(AtomicUsize::new(0));
        let entered = counter.clone();
        let worker = thread::spawn(move || {
            let _guard = InFlight::enter(&entered);
            panic!("handler panic");
        });
        assert!(worker.join().is_err(), "the handler must have panicked");
        assert_eq!(counter.load(Ordering::SeqCst), 0, "unwind must still decrement");
    }

    #[test]
    fn accept_counts_a_connection_before_its_child_runs() {
        // Deterministic: spawn_handler's increment is sequenced before the
        // spawn within the calling thread, so on return the connection counts
        // even if its child was never scheduled. No yield, no sleep.
        let shared = Arc::new(shared());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (stream, _) = listener.accept().unwrap();
        spawn_handler(stream, shared.clone());
        assert_eq!(shared.in_flight.load(Ordering::SeqCst), 1,
            "the accepted connection must count before its child can run");
        drop(client); // lets the child's read fail so it exits
    }

    #[test]
    fn mutation_increment_in_child_leaves_an_accepted_connection_uncounted() {
        // Negative control for the ordering guarantee above. MUTANT: the
        // pre-fix placement, with the increment inside the child behind a
        // gate. While the gate is closed the child cannot have registered
        // (no scheduling assumption needed: it cannot pass the gate), so the
        // accepted connection is invisible to a drop observing the counter.
        let shared = Arc::new(shared());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let mutant_shared = shared.clone();
        let child = thread::spawn(move || {
            // MUTANT child: register only after the gate opens.
            gate_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let _in_flight = InFlight::enter(&mutant_shared.in_flight);
            let _ = handle(stream, mutant_shared);
        });
        assert_eq!(shared.in_flight.load(Ordering::SeqCst), 0,
            "mutant: an accepted but not-yet-run child is invisible to drop");
        drop(client); // so the child's read fails immediately once it runs
        gate_tx.send(()).unwrap();
        child.join().unwrap();
    }

    fn req_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn silent_client_hits_the_overall_read_deadline() {
        let (mut client, mut server) = req_pair();
        client.write_all(b"POST /v1/chat/completions HTTP/1.1\r\nhost: x\r\n").unwrap();
        let started = Instant::now();
        let err = read_request_within(&mut server, Duration::from_millis(200)).err().unwrap();
        assert_eq!(err, "timeout");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(200), "took {elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "must not wait out the per-read timeout, took {elapsed:?}");
    }

    #[test]
    fn trickling_client_hits_the_overall_read_deadline() {
        // One byte every 50ms: each read succeeds well under any per-read
        // timeout, so only the overall deadline can stop this.
        let (mut client, mut server) = req_pair();
        let trickler = thread::spawn(move || {
            for _ in 0..20 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let started = Instant::now();
        let err = read_request_within(&mut server, Duration::from_millis(220)).err().unwrap();
        assert_eq!(err, "timeout", "a trickle that beats per-read timeouts must still hit the overall deadline");
        assert!(started.elapsed() < Duration::from_secs(2));
        trickler.join().unwrap();
    }

    #[test]
    fn stalled_body_hits_the_overall_read_deadline() {
        let (mut client, mut server) = req_pair();
        client.write_all(b"POST /v1/chat/completions HTTP/1.1\r\nhost: x\r\ncontent-length: 10\r\n\r\n{\"me").unwrap();
        let started = Instant::now();
        let err = read_request_within(&mut server, Duration::from_millis(200)).err().unwrap();
        assert_eq!(err, "timeout");
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn healthy_request_reads_in_full_under_budget() {
        let (mut client, mut server) = req_pair();
        client.write_all(b"POST /v1/chat/completions?stream=1 HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\nx-extra: yes\r\n\r\n{\"a\":").unwrap();
        let req = read_request_within(&mut server, Duration::from_secs(5)).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/chat/completions");
        assert_eq!(req.query, "stream=1");
        assert_eq!(req.headers.get("x-extra").unwrap(), "yes");
        assert_eq!(req.body, b"{\"a\":");
    }

    #[test]
    fn body_is_trimmed_to_content_length_after_an_over_read() {
        let (mut client, mut server) = req_pair();
        client.write_all(b"POST /x HTTP/1.1\r\ncontent-length: 4\r\n\r\n{\"a\":1}EXTRA").unwrap();
        let req = read_request_within(&mut server, Duration::from_secs(5)).unwrap();
        assert_eq!(req.body, b"{\"a\"", "handler must see exactly content-length bytes");
    }

    fn write_async(mut client: TcpStream, bytes: Vec<u8>) -> thread::JoinHandle<()> {
        // bounded concurrent writer: fixtures larger than a socket buffer
        // must not depend on the server draining mid-write
        thread::spawn(move || {
            let _ = client.write_all(&bytes);
            let _ = client.flush();
        })
    }

    #[test]
    fn declared_body_at_the_cap_reads_in_full() {
        // boundary: len == the cap passes; the full body must arrive.
        // Literal value, not MAX_BODY, so a cap change fails this test.
        const CAP: usize = 1_000_000;
        assert_eq!(CAP, MAX_BODY, "fixture drifted from the standing cap");
        let (client, mut server) = req_pair();
        let mut bytes = format!("POST /x HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n", CAP).into_bytes();
        bytes.extend(std::iter::repeat(b'x').take(CAP));
        let writer = write_async(client, bytes);
        let req = read_request_within(&mut server, Duration::from_secs(10)).unwrap();
        assert_eq!(req.body.len(), CAP);
        writer.join().unwrap();
    }

    #[test]
    fn declared_body_one_over_the_cap_rejected_by_bytes_not_time() {
        // boundary: len == cap + 1 is refused on the header alone.
        // Literal value, not MAX_BODY, so a cap change fails this test.
        const CAP: usize = 1_000_000;
        assert_eq!(CAP, MAX_BODY, "fixture drifted from the standing cap");
        let (client, mut server) = req_pair();
        let writer = write_async(client, format!("POST /x HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n", CAP + 1).into_bytes());
        let started = Instant::now();
        let err = read_request_within(&mut server, Duration::from_millis(500)).err().unwrap();
        assert_eq!(err, "too large");
        assert!(started.elapsed() < Duration::from_millis(500), "rejection must come from the byte cap, not the deadline");
        drop(server);
        writer.join().unwrap();
    }

    fn head_with_terminator_at(p: usize) -> Vec<u8> {
        let prefix = "POST /x HTTP/1.1\r\nhost: x\r\nx-pad: ";
        let suffix = "\r\ncontent-length: 2\r\n\r\n";
        // terminator starts 4 bytes before the end of the suffix, so the pad
        // absorbs those 4 to land the terminator exactly at p
        let pad = p + 4 - prefix.len() - suffix.len();
        let mut bytes = format!("{}{}{}", prefix, "a".repeat(pad), suffix).into_bytes();
        bytes.extend_from_slice(b"{}");
        // fixture self-check: the terminator must sit exactly at p
        assert!(bytes.windows(4).position(|w| w == b"\r\n\r\n") == Some(p), "fixture math");
        bytes
    }

    #[test]
    fn head_terminator_at_the_cap_reads_in_full() {
        // boundary: terminator at exactly 64KiB passes (check is strict >)
        let (client, mut server) = req_pair();
        let writer = write_async(client, head_with_terminator_at(64 * 1024));
        let req = read_request_within(&mut server, Duration::from_secs(5)).unwrap();
        assert_eq!(req.body, b"{}");
        writer.join().unwrap();
    }

    #[test]
    fn head_terminator_one_past_the_cap_rejected_by_bytes_not_time() {
        // boundary: terminator at 64KiB + 1 is refused on arrival
        let (client, mut server) = req_pair();
        let writer = write_async(client, head_with_terminator_at(64 * 1024 + 1));
        let started = Instant::now();
        let err = read_request_within(&mut server, Duration::from_millis(500)).err().unwrap();
        assert_eq!(err, "headers too large");
        assert!(started.elapsed() < Duration::from_millis(500), "rejection must come from the byte cap, not the deadline");
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn large_headers_under_the_cap_read_in_full() {
        // mid-range passing control
        let (client, mut server) = req_pair();
        let big = format!("POST /x HTTP/1.1\r\nhost: x\r\nx-pad: {}\r\ncontent-length: 2\r\n\r\n{{}}", "a".repeat(32 * 1024));
        let writer = write_async(client, big.into_bytes());
        let req = read_request_within(&mut server, Duration::from_secs(5)).unwrap();
        assert_eq!(req.headers.get("x-pad").unwrap().len(), 32 * 1024);
        assert_eq!(req.body, b"{}");
        writer.join().unwrap();
    }

    #[test]
    fn in_flight_guard_counts_a_completed_handler() {
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let _guard = InFlight::enter(&counter);
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0);
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
    fn mixed_legacy_session_and_generated_keys_share_real_openrouter_account_cap(){
        let upstream=TcpListener::bind("127.0.0.1:0").unwrap();let url=format!("http://{}",upstream.local_addr().unwrap());
        let worker=thread::spawn(move|| {for _ in 0..3 {let(mut socket,_)=upstream.accept().unwrap();let _=read_request(&mut socket).unwrap();let body=r#"{"choices":[{"message":{"content":"ok"}}]}"#;write!(socket,"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",body.len()).unwrap();}});
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        let path=std::env::temp_dir().join(format!("aqua-mixed-budget-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        state.spend=Mutex::new(crate::spend::Store::open(Some(path.clone())).unwrap());state.config.spend.account_verified_day=chrono_day();state.config.spend.openrouter_allowance=40;
        let mut provider=browser_provider("openrouter",Status::Friends,"shared-model",&url);provider.models[0].upstream=OPENROUTER_FREE[0].into();state.config.providers=vec![provider];
        state.config.keys.insert("legacy-sam".into(),crate::config::KeyEntry{name:"Sam".into(),role:Role::Friend});
        let key=state.keys.get_mut().unwrap().create("sam","client").unwrap();let bearer=format!("Bearer {}",key["key"].as_str().unwrap());
        let state=Arc::new(state);let session=state.auth.create_session("sam",Role::Friend).unwrap();let body=r#"{"model":"shared-model","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(browser_api(state.clone(),"POST","/v1/chat/completions","",None,"none",Some("Bearer legacy-sam"),body).starts_with("HTTP/1.1 200"));
        assert!(browser_api(state.clone(),"POST","/v1/chat/completions",&session,Some("https://aqua.test"),"same-site",None,body).starts_with("HTTP/1.1 200"));
        assert!(browser_api(state.clone(),"POST","/v1/chat/completions","",None,"none",Some(&bearer),body).starts_with("HTTP/1.1 200"));worker.join().unwrap();
        let denied=browser_api(state.clone(),"POST","/v1/chat/completions","",None,"none",Some("Bearer legacy-sam"),body);assert!(denied.starts_with("HTTP/1.1 503"));
        let store=state.spend.lock().unwrap();let account=&store.ledger.accounts["openrouter"];assert_eq!(account.total,3);assert_eq!(account.users.len(),1);assert_eq!(account.users["sam"],3);assert_eq!(account.friends,3);drop(store);drop(state);let _=std::fs::remove_file(path);
    }

    pub(super) fn keys_shared()->Arc<Shared>{
        let path=std::env::temp_dir().join(format!("aqua-http-keys-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let mut state=shared();state.keys=Mutex::new(crate::keys::Store::open(Some(path)).unwrap());state.config.allowed_origin="https://aqua.test".into();state.config.oauth.owner_users=vec!["luke".into()];state.config.oauth.friend_users=vec!["sam".into(),"alex".into()];Arc::new(state)
    }
    fn response_body(response:&str)->Value{serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()}
    #[test]
    fn key_http_lifecycle_is_session_scoped_csrf_safe_and_never_retrieves_secret(){
        let state=keys_shared();let sam=state.auth.create_session("sam",Role::Friend).unwrap();let alex=state.auth.create_session("alex",Role::Friend).unwrap();
        for origin in [None,Some("null"),Some("https://evil.aqua.test"),Some("https://api.aqua.test/path"),Some("https://api.aqua.test?x"),Some("ftp://api.aqua.test")] {assert!(browser_api(state.clone(),"POST","/v1/keys",&sam,origin,"same-site",None,r#"{"name":"laptop"}"#).starts_with("HTTP/1.1 403"));}
        for path in ["/v1/keys/revoke","/v1/keys//revoke","/v1/keys/😄/revoke","/v1/keys/a/revoke"] {assert!(browser_api(state.clone(),"POST",path,&sam,Some("https://aqua.test"),"same-site",None,"{}").starts_with("HTTP/1.1 404"));}
        let response=browser_api(state.clone(),"POST","/v1/keys",&sam,Some("https://aqua.test"),"same-site",None,r#"{"name":"laptop"}"#);assert!(response.starts_with("HTTP/1.1 201"));assert!(response.contains("cache-control: no-store\r\n"));
        let created=response_body(&response);let token=created["key"].as_str().unwrap();let bearer=format!("Bearer {token}");let id=created["id"].as_str().unwrap();
        let list=browser_api(state.clone(),"GET","/v1/keys",&sam,None,"same-site",None,"");assert!(!list.contains(token));assert!(!list.contains("hash"));assert!(list.contains("laptop"));
        assert!(response_body(&browser_api(state.clone(),"GET","/v1/keys",&alex,None,"same-site",None,""))["data"].as_array().unwrap().is_empty());
        assert!(browser_api(state.clone(),"GET","/v1/keys","",None,"none",Some(&bearer),"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"GET","/v1/models","",None,"none",Some(&bearer),"").starts_with("HTTP/1.1 200"));
        let path=format!("/v1/keys/{id}/revoke");assert!(browser_api(state.clone(),"POST",&path,&alex,Some("https://aqua.test"),"same-site",None,"{}").starts_with("HTTP/1.1 404"));
        assert!(browser_api(state.clone(),"POST",&path,&sam,Some("https://aqua.test"),"same-site",None,"{}").starts_with("HTTP/1.1 200"));
        assert!(browser_api(state,"GET","/v1/models","",None,"none",Some(&bearer),"").starts_with("HTTP/1.1 401"));
    }
    #[test]
    fn generated_keys_inherit_request_limit_and_require_current_allowlist(){
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();state.config.daily_limit=0;state.config.providers=vec![browser_provider("inferbase",Status::Friends,"shared-model","http://127.0.0.1:1")];
        let key=state.keys.get_mut().unwrap().create("sam","one").unwrap();let second=state.keys.get_mut().unwrap().create("sam","two").unwrap();let gone=state.keys.get_mut().unwrap().create("removed-user","gone").unwrap();
        let state=Arc::new(state);let session=state.auth.create_session("sam",Role::Friend).unwrap();
        for key in [key,second] {let bearer=format!("Bearer {}",key["key"].as_str().unwrap());
            assert!(browser_api(state.clone(),"POST","/v1/chat/completions","",None,"none",Some(&bearer),r#"{"model":"shared-model","messages":[{"role":"user","content":"hi"}]}"#).starts_with("HTTP/1.1 429"));
        }
        assert!(browser_api(state.clone(),"POST","/v1/chat/completions",&session,Some("https://aqua.test"),"same-site",None,r#"{"model":"shared-model","messages":[{"role":"user","content":"hi"}]}"#).starts_with("HTTP/1.1 429"));
        let bearer=format!("Bearer {}",gone["key"].as_str().unwrap());assert!(browser_api(state,"GET","/v1/models","",None,"none",Some(&bearer),"").starts_with("HTTP/1.1 401"));
    }
    #[test]
    fn admin_document_and_provider_metadata_are_owner_only(){
        let mut state=shared();state.config.providers=vec![browser_provider("zro",Status::Friends,"private-model","http://localhost")];let state=Arc::new(state);let owner=state.auth.create_session("luke",Role::Owner).unwrap();let friend=state.auth.create_session("sam",Role::Friend).unwrap();
        for path in ["/admin","/admin.html"] {for cookie in ["",friend.as_str()] {let response=browser_api(state.clone(),"GET",path,cookie,None,"same-site",None,"");assert!(response.starts_with("HTTP/1.1 403"));assert!(!response.contains("<html"));}assert!(browser_api(state.clone(),"GET",path,&owner,None,"same-site",None,"").starts_with("HTTP/1.1 200"));}
        assert!(browser_api(state.clone(),"GET","/v1/admin/providers",&owner,None,"same-site",None,"").contains("private-model"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/providers",&friend,None,"same-site",None,"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/providers",&owner,None,"same-site",Some("Bearer bad"),"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state,"POST","/v1/chat/completions",&friend,Some("https://api.aqua.test"),"same-site",None,r#"{"model":"private-model","messages":[{"role":"user","content":"hi"}]}"#).starts_with("HTTP/1.1 400"));
    }

    pub(super) fn browser_api(state: Arc<Shared>,method:&str,path:&str,cookie:&str,origin:Option<&str>,site:&str,authorization:Option<&str>,body:&str)->String {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();let address=listener.local_addr().unwrap();
        let worker=thread::spawn(move||handle(listener.accept().unwrap().0,state).unwrap());
        let mut c=TcpStream::connect(address).unwrap();
        write!(c,"{method} {path} HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\nsec-fetch-site: {site}\r\ncontent-length: {}\r\n",body.len()).unwrap();
        if let Some(v)=origin {write!(c,"origin: {v}\r\n").unwrap();}
        if let Some(v)=authorization {write!(c,"authorization: {v}\r\n").unwrap();}
        write!(c,"\r\n{body}").unwrap();let mut out=String::new();c.read_to_string(&mut out).unwrap();worker.join().unwrap();out
    }
    fn browser_provider(id:&str,status:Status,model:&str,url:&str)->crate::config::Provider {
        crate::config::Provider{id:id.into(),status,api_key:"secret-not-client".into(),base_url:url.into(),models:vec![crate::config::ModelEntry{public:model.into(),upstream:format!("raw-{model}"),context:None}]}
    }
    #[test]
    fn session_models_reuses_roles_and_never_shares_zro_or_personal_bindings() {
        let mut state=shared();state.config.providers=vec![browser_provider("zro",Status::Friends,"zro-model","http://localhost"),browser_provider("test-personal",Status::Personal,"private-model","http://localhost"),browser_provider("inferbase",Status::Friends,"shared-model","http://localhost")];
        let state=Arc::new(state);let owner=state.auth.create_session("luke",Role::Owner).unwrap();let friend=state.auth.create_session("sam",Role::Friend).unwrap();
        let o=browser_api(state.clone(),"GET","/v1/models",&owner,None,"same-site",None,"");
        assert!(o.starts_with("HTTP/1.1 200"));assert!(o.contains("private-model")&&o.contains("zro-model")&&o.contains("shared-model"));assert!(!o.contains("secret-not-client")&&!o.contains("raw-"));
        let f=browser_api(state.clone(),"GET","/v1/models",&friend,None,"same-site",None,"");assert!(f.starts_with("HTTP/1.1 200"));assert!(f.contains("shared-model"));assert!(!f.contains("zro-model")&&!f.contains("private-model"));
        assert!(browser_api(state.clone(),"GET","/v1/models",&friend,None,"same-site",Some("Bearer bad"),"").starts_with("HTTP/1.1 401"));
        state.auth.revoke(&friend);assert!(browser_api(state,"GET","/v1/models",&friend,None,"same-site",None,"").starts_with("HTTP/1.1 401"));
    }
    #[test]
    fn cookie_chat_requires_explicit_approved_origin_even_for_same_site_siblings() {
        let mut state=shared();state.config.allowed_origin="https://aqua.test".into();let state=Arc::new(state);let id=state.auth.create_session("sam",Role::Friend).unwrap();
        let body=r#"{"model":"x","messages":[]}"#;
        for (origin,site) in [(None,"same-site"),(Some("https://evil.aqua.test"),"same-site"),(Some("null"),"same-origin"),(Some("https://aqua.test"),"cross-site")] {
            assert!(browser_api(state.clone(),"POST","/v1/chat/completions",&id,origin,site,None,body).starts_with("HTTP/1.1 403"));
        }
        for origin in ["https://aqua.test","https://api.aqua.test"] {assert!(browser_api(state.clone(),"POST","/v1/chat/completions",&id,Some(origin),"same-site",None,body).starts_with("HTTP/1.1 400"));}
        assert!(browser_api(state,"GET","/v1/admin/providers",&id,None,"same-site",None,"").starts_with("HTTP/1.1 401"));
    }
    #[test]
    fn separate_sessions_for_one_login_share_chat_quota_in_json_and_sse() {
        for streaming in [false,true] {
            let upstream=TcpListener::bind("127.0.0.1:0").unwrap();let url=format!("http://{}",upstream.local_addr().unwrap());
            let worker=thread::spawn(move|| {let(mut socket,_)=upstream.accept().unwrap();let _=read_request(&mut socket).unwrap();
                let body=if streaming {"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"}else{r#"{"choices":[{"message":{"content":"ok"}}]}"#};
                write!(socket,"HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",if streaming{"text/event-stream"}else{"application/json"},body.len()).unwrap();});
            let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();state.config.daily_limit=1;state.config.providers=vec![browser_provider("inferbase",Status::Friends,"shared-model",&url)];
            let key=state.keys.get_mut().unwrap().create("sam","client").unwrap();let bearer=format!("Bearer {}",key["key"].as_str().unwrap());
            state.config.keys.insert("legacy-sam".into(),crate::config::KeyEntry{name:"Sam".into(),role:Role::Friend});
            state.config.keys.insert("legacy-alias".into(),crate::config::KeyEntry{name:"my-friend".into(),role:Role::Friend});
            let state=Arc::new(state);let a=state.auth.create_session("Sam",Role::Friend).unwrap();let b=state.auth.create_session("sam",Role::Friend).unwrap();
            let payload=json!({"model":"shared-model","messages":[{"role":"user","content":"hi"}],"stream":streaming}).to_string();
            assert!(browser_api(state.clone(),"POST","/v1/chat/completions","",None,"none",Some("Bearer legacy-sam"),&payload).starts_with("HTTP/1.1 200"));worker.join().unwrap();
            assert!(browser_api(state.clone(),"POST","/v1/chat/completions",&a,Some("https://aqua.test"),"same-site",None,&payload).starts_with("HTTP/1.1 429"));
            assert!(browser_api(state.clone(),"GET","/v1/models","",None,"none",Some("Bearer legacy-alias"),"").starts_with("HTTP/1.1 401"));
            assert!(browser_api(state.clone(),"POST","/v1/chat/completions",&b,Some("https://aqua.test"),"same-site",None,&payload).starts_with("HTTP/1.1 429"));
            assert!(browser_api(state,"POST","/v1/chat/completions","",None,"none",Some(&bearer),&payload).starts_with("HTTP/1.1 429"));
        }
    }

    #[test]
    fn embedded_interactive_pages_require_session_not_bearer_key() {
        let state=Arc::new(shared());
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        let friend=state.auth.create_session("sam",Role::Friend).unwrap();
        for path in ["/console.html","/playground.html","/console","/playground","/keys.html","/keys"] {
            for cookie in ["", "invalid"] {
                let response=admin_request(state.clone(),"GET",path,cookie,"","");
                assert!(response.starts_with("HTTP/1.1 302"),"{path} admitted logged-out browser");
                assert!(response.contains("location: /\r\n"));
            }
            for cookie in [&owner,&friend] {
                assert!(admin_request(state.clone(),"GET",path,cookie,"","").starts_with("HTTP/1.1 200"));
            }
        }
        state.auth.revoke(&friend);
        assert!(admin_request(state.clone(),"GET","/console.html",&friend,"","").starts_with("HTTP/1.1 302"));
        for path in ["/","/landing.html"] {
            assert!(admin_request(state.clone(),"GET",path,"","","").starts_with("HTTP/1.1 200"));
        }
    }

    #[test]
    fn legacy_request_name_covers_the_full_live_alias_table() {
        // Parity with the live lineage canonical_model table (A9b request-side
        // decision): every live alias resolves to the same canonical name.
        for (alias, canonical) in [
            ("deepseek-v4.1-flash-1017", "deepseek-v4.1-flash"),
            ("deepseek-v4.1-flash-route-b", "deepseek-v4.1-flash"),
            ("deepseek-v4.1-flash-route-c", "deepseek-v4.1-flash"),
            ("deepseek-v4-flash:fp8", "deepseek-v4-flash"),
            ("deepseek-v4-flash-route-b", "deepseek-v4-flash"),
            ("glm-5.3-flash-route-b", "glm-5.3-flash"),
            ("glm-5.3-flash-route-c", "glm-5.3-flash"),
            ("qwen-3.8-27b-route-b", "qwen-3.8-27b"),
            ("nemotron-3-ultra-550b-a55b-route-b", "nemotron-3-ultra-550b-a55b"),
            ("nemotron-3.5-super-vl-route-b", "nemotron-3.5-super-vl"),
        ] {
            assert_eq!(legacy_request_name(alias), canonical, "{alias}");
        }
        // Canonical names and unknowns pass through untouched.
        for name in ["deepseek-v4.1-flash","glm-5.3-flash","auto","no-such-model"] {
            assert_eq!(legacy_request_name(name), name, "{name}");
        }
    }

    #[test]
    fn gemma_stays_out_of_the_openrouter_free_gate() {
        assert!(!OPENROUTER_FREE.iter().any(|m| m.to_ascii_lowercase().contains("gemma")));
    }

    #[test]
        fn usage_aggregates_are_guarded_and_501_when_authenticated() {
        let mut state = shared();state.config.allowed_origin="https://aqua.test".into();
        state.config.admin_key="admintest".into();
        let state=Arc::new(state);
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        let friend=state.auth.create_session("sam",Role::Friend).unwrap();
        for path in ["/v1/admin/usage/summary?hours=24","/v1/admin/usage/series?hours=24&bucket=hour"] {
            let admin=browser_api(state.clone(),"GET",path,"",None,"none",Some("Bearer admintest"),"");
            assert!(admin.starts_with("HTTP/1.1 501"),"{path} admin bearer: {}",&admin[..20]);
            let own=browser_api(state.clone(),"GET",path,&owner,None,"same-site",None,"");
            assert!(own.starts_with("HTTP/1.1 501"),"{path} owner session: {}",&own[..20]);
            assert!(browser_api(state.clone(),"GET",path,&friend,None,"same-site",None,"").starts_with("HTTP/1.1 401"),"{path} friend");
            // Explicit bearer is authoritative: bad bearer 401s even with an owner cookie.
            assert!(browser_api(state.clone(),"GET",path,&owner,None,"same-site",Some("Bearer wrong"),"").starts_with("HTTP/1.1 401"),"{path} bad bearer precedence");
        }
    }

    #[test]
    fn unknown_static_gets_are_404_and_never_spend_the_empty_token_throttle() {
        let mut state = shared();state.config.admin_key="admintest".into();
        let state=Arc::new(state);
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        // Well past AUTH_FAIL_LIMIT: anonymous probes of unknown static paths
        // must 404 without recording credential failures.
        for path in ["/favicon.ico","/fonts/f00.woff2","/fonts/f04.woff2","/favicon.ico","/fonts/f00.woff2","/favicon.ico","/robots.txt"] {
            assert!(browser_api(state.clone(),"GET",path,"",None,"none",None,"").starts_with("HTTP/1.1 404"),"{path}");
        }
        // Cookie traffic (empty bearer fingerprint) is untouched by those probes.
        assert!(browser_api(state.clone(),"GET","/v1/admin/providers",&owner,None,"same-site",None,"").starts_with("HTTP/1.1 200"));
        // The API gate is unchanged: unknown /v1 paths still 401 and still count.
        assert!(browser_api(state.clone(),"GET","/v1/nope","",None,"none",None,"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"GET","/v1/models","",None,"none",Some("Bearer bad"),"").starts_with("HTTP/1.1 401"));
        // POST to an unknown static path keeps the full gate (no bypass added).
        assert!(browser_api(state.clone(),"POST","/favicon.ico","",None,"none",None,"").starts_with("HTTP/1.1 401"));
    }

    #[test]
        fn spend_admin_cookie_route_requires_owner_and_explicit_csrf_safe_origin() {
        let mut state = shared();state.config.allowed_origin="https://aqua.test".into();
        let state=Arc::new(state);
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        let friend=state.auth.create_session("sam",Role::Friend).unwrap();
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
    let session_owner = !req.headers.contains_key("authorization") && auth::session_cookie(&req.headers).and_then(|id| shared.auth.get_session(&id)).map(|(_,role)|role==Role::Owner).unwrap_or(false);
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


#[cfg(test)]
mod owner_bounds_tests {
    use super::*;
    #[test]
    fn nim_owner_window_is_scoped_and_shared_with_fallback() {
        let base=Duration::from_secs(30);
        assert_eq!(provider_remaining_budget("nim",true,base,Duration::ZERO),Some(Duration::from_secs(120)));
        assert_eq!(provider_remaining_budget("nim",false,base,Duration::ZERO),Some(base));
        assert_eq!(provider_remaining_budget("logfare",true,base,Duration::ZERO),Some(base));
        // Non-NIM first (auto or pin) consumes time from both fixed windows.
        assert_eq!(provider_remaining_budget("nim",true,base,Duration::from_secs(29)),Some(Duration::from_secs(91)));
        assert_eq!(provider_remaining_budget("other",true,base,Duration::from_secs(29)),Some(Duration::from_secs(1)));
        // Slow NIM never gives a later non-NIM route a fresh window.
        assert_eq!(provider_remaining_budget("other",true,base,Duration::from_secs(31)),None);
        assert_eq!(provider_remaining_budget("nim",true,base,Duration::from_secs(119)),Some(Duration::from_secs(1)));
        assert_eq!(provider_remaining_budget("nim",true,base,Duration::from_secs(120)),None);
        assert_eq!(provider_remaining_budget("other",true,base,Duration::from_secs(30)),None);
        assert_eq!(provider_remaining_budget("other",false,Duration::from_millis(25),Duration::from_millis(24)),Some(Duration::from_millis(1)));
    }
}

#[cfg(test)]
mod preferences_auth_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api,keys_shared};
    #[test]
    fn settings_cookie_csrf_and_bad_bearer_fail_closed_and_cannot_target_another_user() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();let path=std::env::temp_dir().join(format!("aqua-settings-auth-{}.json",std::process::id()));state.spend=Mutex::new(crate::spend::Store::open(Some(path)).unwrap());let state=Arc::new(state);let id=state.auth.create_session("sam",Role::Friend).unwrap();
        let body=r#"{"zdr_only":true,"default_model":"auto","show_cost":false}"#;
        for origin in [None,Some("https://evil.test")] {
            assert!(browser_api(state.clone(),"POST","/v1/settings",&id,origin,"same-site",None,body).starts_with("HTTP/1.1 403"));
        }
        assert!(browser_api(state.clone(),"POST","/v1/settings",&id,Some("https://aqua.test"),"same-site",Some("Bearer bad"),body).starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"POST","/v1/settings",&id,Some("https://aqua.test"),"same-site",None,body).starts_with("HTTP/1.1 200"));
        assert!(state.spend.lock().unwrap().ledger.preferences["sam"].zdr_only);
        let attack=r#"{"user":"luke","zdr_only":false,"default_model":"auto","show_cost":true}"#;
        assert!(browser_api(state.clone(),"POST","/v1/settings",&id,Some("https://aqua.test"),"same-site",None,attack).starts_with("HTTP/1.1 400"));
        assert!(!state.spend.lock().unwrap().ledger.preferences.contains_key("luke"));
    }
}

#[cfg(test)]
mod fastest_route_tests {
    use super::*;
    use super::reviewer_regressions::keys_shared;
    #[test]
    fn observed_latency_is_per_model_bounded_and_uses_exact_ewma() {
        let state=keys_shared();
        record_route_latency(&state,"one","model-a",Duration::from_millis(100));
        record_route_latency(&state,"one","model-a",Duration::from_millis(20));
        record_route_latency(&state,"one","model-b",Duration::from_millis(10));
        let cache=state.route_latency.lock().unwrap();
        assert_eq!(cache[&("one".into(),"model-a".into())],80_000);
        assert_eq!(cache[&("one".into(),"model-b".into())],10_000);drop(cache);
        for n in 0..1000 {record_route_latency(&state,"one",&format!("m{n}"),Duration::from_millis(1));}
        assert_eq!(state.route_latency.lock().unwrap().len(),512);
    }
}

#[cfg(test)]
mod fastest_dispatch_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api,keys_shared};
    #[test]
    fn fastest_observed_binding_is_used_before_config_order_for_same_model() {
        let (tx,rx)=std::sync::mpsc::channel();let mut providers=vec![];
        for (id,millis) in [("slow",100),("fast",20)] {
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();let url=format!("http://{}",listener.local_addr().unwrap());let tx=tx.clone();
            thread::spawn(move||{let(mut socket,_)=listener.accept().unwrap();let _=read_request(&mut socket);tx.send(id).unwrap();let body=r#"{"model":"private","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}"#;write!(socket,"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",body.len()).unwrap();});
            providers.push(crate::config::Provider{id:id.into(),base_url:url,api_key:"fixture".into(),status:Status::Friends,models:vec![crate::config::ModelEntry{public:"same".into(),upstream:"private".into(),context:None}]});
            let _=millis;
        }
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();state.config.providers=providers;let state=Arc::new(state);
        record_route_latency(&state,"slow","same",Duration::from_millis(100));record_route_latency(&state,"fast","same",Duration::from_millis(20));
        let id=state.auth.create_session("sam",Role::Friend).unwrap();
        assert!(browser_api(state,"POST","/v1/chat/completions",&id,Some("https://aqua.test"),"same-site",None,r#"{"model":"same","messages":[]}"#).starts_with("HTTP/1.1 200"));
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(),"fast");
    }
}

#[cfg(test)]
mod live_port_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api,keys_shared};

    fn response_body(response:&str)->Value{serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()}

    fn bp(id:&str,status:Status,model:&str,url:&str)->crate::config::Provider {
        crate::config::Provider{id:id.into(),status,api_key:"secret-not-client".into(),base_url:url.into(),models:vec![crate::config::ModelEntry{public:model.into(),upstream:format!("raw-{model}"),context:None}]}
    }

    #[test]
    fn passive_health_counts_only_eligible_routes_and_auto_shortlist() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers=vec![
            bp("p1",Status::Personal,"model","http://127.0.0.1:1"),
            bp("off",Status::Off,"model","http://127.0.0.1:1"),
            bp("no-key",Status::Personal,"model","http://127.0.0.1:1"),
            bp("openrouter",Status::Personal,"model","http://127.0.0.1:1"),
            bp("other",Status::Personal,"other-model","http://127.0.0.1:1")];
        state.config.providers[2].api_key.clear();
        state.config.providers[3].models[0].upstream="cohere/north-mini-code:free".into();
        state.config.auto_shortlist=vec!["model".into()];
        let state=Arc::new(state);
        assert_eq!(model_health(&state,"model",false,Role::Owner)["eligible_routes"],1);
        assert_eq!(model_health(&state,"auto",false,Role::Owner)["eligible_routes"],1);
        let p=&state.config.providers[0];let m=&p.models[0];
        state.observations.lock().unwrap().header(&p.id,&m.public,&m.upstream,200);
        state.observations.lock().unwrap().finish(&p.id,&m.public,&m.upstream,true);
        assert_eq!(model_health(&state,"model",false,Role::Owner)["status"],"healthy");
        assert_eq!(model_health(&state,"other-model",false,Role::Owner)["status"],"unknown");
        assert!(state.quotas.lock().unwrap().is_empty());
        assert!(state.trial_recent.lock().unwrap().is_empty());
    }

    #[test]
    fn merged_snapshot_is_failover_even_when_faster_and_default_is_cooled() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        let mut snapshot=bp("snapshot",Status::Personal,"deepseek-v4.1-flash","http://127.0.0.1:1");
        snapshot.models[0].upstream="deepseek-v4.1-flash-1017".into();
        let default=bp("default",Status::Personal,"deepseek-v4.1-flash","http://127.0.0.1:1");
        state.config.providers=vec![snapshot,default];
        state.route_latency.get_mut().unwrap().insert(("snapshot".into(),"deepseek-v4.1-flash".into()),1);
        state.route_latency.get_mut().unwrap().insert(("default".into(),"deepseek-v4.1-flash".into()),999);
        let state=Arc::new(state);
        for cooled in [false,true] {
            if cooled {state.health.lock().unwrap().insert("default".into(),Cooldown{until:Instant::now()+Duration::from_secs(60),hard:false});}
            let result=resolve_model(&state,"deepseek-v4.1-flash",false,Role::Owner);
            assert_eq!(result["candidates"].as_array().unwrap().iter().map(|c|c["provider"].as_str().unwrap()).collect::<Vec<_>>(),vec!["default","snapshot"]);
        }
    }

    #[test]
    fn embedded_pages_send_frame_deny_headers_and_json_or_redirects_do_not() {
        let state=keys_shared();
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        for path in ["/","/landing.html","/console.html","/settings.html","/keys.html","/playground.html"] {
            let cookie=if path=="/"||path=="/landing.html" {""} else {owner.as_str()};
            let r=browser_api(state.clone(),"GET",path,cookie,None,"none",None,"");
            assert!(r.starts_with("HTTP/1.1 200 "),"{path}: {r}");
            assert!(r.contains("\r\nx-frame-options: DENY\r\n"),"{path}");
            assert!(r.contains("\r\ncontent-security-policy: frame-ancestors 'none'\r\n"),"{path}");
        }
        let r=browser_api(state.clone(),"GET","/v1/models","",None,"none",Some("Bearer bad"),"");
        assert!(!r.contains("x-frame-options:"));
        let r=browser_api(state.clone(),"GET","/console.html","",None,"none",None,"");
        assert!(r.starts_with("HTTP/1.1 302 "));
        assert!(!r.contains("x-frame-options:"));
    }

    #[test]
    fn resolve_gate_owner_paths_throttle_and_method_contract() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.keys.insert("owner-legacy".into(),crate::config::KeyEntry{name:"luke".into(),role:Role::Owner});
        let generated=state.keys.get_mut().unwrap().create("luke","ops").unwrap();
        let generated=format!("Bearer {}",generated["key"].as_str().unwrap());
        let state=Arc::new(state);
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        let friend=state.auth.create_session("sam",Role::Friend).unwrap();
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x",&owner,None,"same-site",None,"").starts_with("HTTP/1.1 200"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x",&friend,None,"same-site",None,"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x","",None,"none",None,"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x",&owner,None,"same-site",Some("Bearer bad"),"").starts_with("HTTP/1.1 401"));
        // Main's auth only: legacy and generated bearer keys are rejected.
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x","",None,"none",Some("Bearer owner-legacy"),"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x","",None,"none",Some(&generated),"").starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"POST","/v1/admin/resolve?model=x",&owner,None,"same-site",None,"{").starts_with("HTTP/1.1 405"));
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve",&owner,None,"same-site",None,"").starts_with("HTTP/1.1 400"));
        let overlong=format!("/v1/admin/resolve?model={}","x".repeat(257));
        assert!(browser_api(state.clone(),"GET",&overlong,&owner,None,"same-site",None,"").starts_with("HTTP/1.1 400"));
        for _ in 0..AUTH_FAIL_LIMIT {let _=browser_api(state.clone(),"GET","/v1/admin/resolve?model=x","",None,"none",Some("Bearer throttle-this"),"");}
        assert!(browser_api(state.clone(),"GET","/v1/admin/resolve?model=x","",None,"none",Some("Bearer throttle-this"),"").starts_with("HTTP/1.1 429"));
    }

    #[test]
    fn auth_failure_map_sweeps_expired_entries_without_clearing_fresh_ones() {
        // Sweep and clear-all must be distinguishable: a fresh survivor entry
        // proves the expired entries left via the sweep, not via clear().
        let state=keys_shared();
        {
            let mut failures=state.auth_failures.lock().unwrap();
            // Exactly CAP entries before the record: reachable even under a
            // strict insert-time cap, so the check at CAP is what triggers.
            for n in 0..AUTH_FAIL_MAP_CAP-3 {
                failures.insert(format!("stale-{n}"),(1,Instant::now()-Duration::from_secs(120)));
            }
            // 60s cutoff probes: 59s must be kept, 61s must be swept
            // (1s margins, never a race against the retain instant)
            failures.insert("edge-kept".into(),(1,Instant::now()-Duration::from_secs(59)));
            failures.insert("edge-dropped".into(),(1,Instant::now()-Duration::from_secs(61)));
            failures.insert("survivor".into(),(7,Instant::now()));
            assert_eq!(failures.len(),AUTH_FAIL_MAP_CAP,"fixture must sit exactly at the cap");
        }
        record_auth_failure(&state,"fresh-token");
        let failures=state.auth_failures.lock().unwrap();
        assert_eq!(failures.len(),3,"stale entries swept, fresh entries kept: {}",failures.len());
        assert_eq!(failures.get("survivor").map(|(n,_)|*n),Some(7),"a fresh entry must survive the sweep");
        assert!(failures.contains_key("edge-kept"),"59s-old entry is inside the window");
        assert!(!failures.contains_key("edge-dropped"),"61s-old entry is outside the window");
        assert!(!failures.contains_key("stale-0"),"120s-old entry must be swept");
        assert!(failures.contains_key(&crate::keys::fingerprint("fresh-token")));
    }

    #[test]
    fn auth_failure_map_clears_all_only_when_full_of_fresh_entries() {
        let state=keys_shared();
        {
            let mut failures=state.auth_failures.lock().unwrap();
            for n in 0..AUTH_FAIL_MAP_CAP {
                failures.insert(format!("f-{n}"),(1,Instant::now()));
            }
        }
        record_auth_failure(&state,"fresh-token");
        let failures=state.auth_failures.lock().unwrap();
        assert_eq!(failures.len(),1,"a full fresh map must clear, then hold only the new entry");
        assert_eq!(failures.get(&crate::keys::fingerprint("fresh-token")).map(|(n,_)|*n),Some(1));
    }

    #[test]
    fn resolve_privacy_and_eligibility_are_fail_closed() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        let mut empty=bp("empty",Status::Personal,"model","http://localhost");empty.api_key.clear();
        state.config.providers=vec![empty,bp("good",Status::Personal,"model","http://localhost"),bp("off",Status::Off,"model","http://localhost")];
        let mut pref=crate::preferences::Preferences::default();pref.zdr_only=true;
        state.spend.get_mut().unwrap().ledger.preferences.insert("luke".into(),pref);
        let state=Arc::new(state);
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        let response=browser_api(state.clone(),"GET","/v1/admin/resolve?model=model",&owner,None,"same-site",None,"");
        assert!(response.starts_with("HTTP/1.1 200"),"{response}");
        assert_eq!(response_body(&response)["known"],false);
        assert_eq!(resolve_model(&state,"model",false,Role::Owner)["candidates"].as_array().unwrap().len(),1);
        assert!(!response.contains("secret-not-client"));
    }

    #[test]
    fn resolve_and_health_never_count_held_cloudflare_routes() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers=vec![bp("cloudflare",Status::Personal,"model","http://127.0.0.1:1")];
        let state=Arc::new(state);
        assert_eq!(resolve_model(&state,"model",false,Role::Owner)["candidates"].as_array().unwrap().len(),0);
        assert_eq!(resolve_model(&state,"model",false,Role::Owner)["known"],false);
        assert_eq!(model_health(&state,"model",false,Role::Owner)["eligible_routes"],0);
    }

    #[test]
    fn resolve_and_health_hold_openrouter_until_verified_funded_durable_and_free() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        let mut p=bp("openrouter",Status::Personal,"model","http://127.0.0.1:1");
        p.models[0].upstream=OPENROUTER_FREE[0].into();
        state.config.providers=vec![p];
        let state=Arc::new(state);
        // unverified day: held
        assert_eq!(resolve_model(&state,"model",false,Role::Owner)["candidates"].as_array().unwrap().len(),0);
        assert_eq!(model_health(&state,"model",false,Role::Owner)["eligible_routes"],0);
        // verified day but zero allowance: held
        let mut state=Arc::try_unwrap(state).ok().unwrap();
        state.config.spend.account_verified_day=chrono_day();
        state.config.spend.openrouter_allowance=0;
        let state=Arc::new(state);
        assert_eq!(resolve_model(&state,"model",false,Role::Owner)["candidates"].as_array().unwrap().len(),0);
        // funded but a paid or unlisted upstream: held
        let mut state=Arc::try_unwrap(state).ok().unwrap();
        state.config.spend.openrouter_allowance=40;
        state.config.providers[0].models[0].upstream="paid-model".into();
        let state=Arc::new(state);
        assert_eq!(resolve_model(&state,"model",false,Role::Owner)["candidates"].as_array().unwrap().len(),0);
        assert_eq!(model_health(&state,"model",false,Role::Owner)["eligible_routes"],0);
        // verified, funded, durable store, free upstream: serving
        let mut state=Arc::try_unwrap(state).ok().unwrap();
        state.config.providers[0].models[0].upstream=OPENROUTER_FREE[0].into();
        let path=std::env::temp_dir().join(format!("aqua-openrouter-hold-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        state.spend=Mutex::new(crate::spend::Store::open(Some(path.clone())).unwrap());
        let state=Arc::new(state);
        let c=resolve_model(&state,"model",false,Role::Owner);
        assert_eq!(c["candidates"].as_array().unwrap().iter().map(|v|v["provider"].as_str().unwrap()).collect::<Vec<_>>(),vec!["openrouter"]);
        assert_eq!(model_health(&state,"model",false,Role::Owner)["eligible_routes"],1);
        drop(state);let _=std::fs::remove_file(path.with_extension("lock"));let _=std::fs::remove_file(path);
    }

    #[test]
    fn resolve_and_health_apply_role_restrictions() {
        let mut state=Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers=vec![
            bp("test-personal",Status::Personal,"shared-model","http://127.0.0.1:1"),
            bp("zro",Status::Friends,"shared-model","http://127.0.0.1:1"),
            bp("inferbase",Status::Friends,"shared-model","http://127.0.0.1:1"),
            bp("nim",Status::Personal,"shared-model","http://127.0.0.1:1")];
        state.config.providers[3].models[0].upstream="nvidia/nemotron-3-ultra-550b-a55b".into();
        let state=Arc::new(state);
        // owner sees personal, zro and the trial route; friend sees only inferbase
        assert_eq!(resolve_model(&state,"shared-model",false,Role::Owner)["candidates"].as_array().unwrap().len(),4);
        let f=resolve_model(&state,"shared-model",false,Role::Friend);
        assert_eq!(f["candidates"].as_array().unwrap().iter().map(|v|v["provider"].as_str().unwrap()).collect::<Vec<_>>(),vec!["inferbase"]);
        assert_eq!(model_health(&state,"shared-model",false,Role::Owner)["eligible_routes"],4);
        assert_eq!(model_health(&state,"shared-model",false,Role::Friend)["eligible_routes"],1);
    }

    #[test]
    fn resolve_maps_legacy_request_names_like_dispatch() {
        let state=keys_shared();
        let owner=state.auth.create_session("luke",Role::Owner).unwrap();
        let r=browser_api(state.clone(),"GET","/v1/admin/resolve?model=deepseek-v4-flash%3Afp8",&owner,None,"same-site",None,"");
        let body=response_body(&r);
        assert_eq!(body["requested"],"deepseek-v4-flash:fp8");
        assert_eq!(body["canonical"],"deepseek-v4-flash");
        assert_eq!(body["known"],false);
    }
}

#[cfg(test)]
mod image_core_http_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api,keys_shared};
    const BODY:&str=r#"{"model":"image-auto","prompt":"private prompt sentinel"}"#;
    #[test]
    fn image_owner_auth_csrf_bad_bearer_and_disabled_routes_are_closed(){
        let state=keys_shared();let owner=state.auth.create_session("luke",Role::Owner).unwrap();let friend=state.auth.create_session("sam",Role::Friend).unwrap();
        for origin in [None,Some("https://evil.test")]{let r=browser_api(state.clone(),"POST","/v1/images/generations",&owner,origin,"same-site",None,BODY);assert!(r.starts_with("HTTP/1.1 403"));assert!(r.contains("cache-control: no-store"));}
        assert!(browser_api(state.clone(),"POST","/v1/images/generations",&owner,Some("https://aqua.test"),"same-site",Some("Bearer bad"),BODY).starts_with("HTTP/1.1 401"));
        assert!(browser_api(state.clone(),"POST","/v1/images/generations",&friend,Some("https://aqua.test"),"same-site",None,BODY).starts_with("HTTP/1.1 403"));
        let r=browser_api(state.clone(),"POST","/v1/images/generations",&owner,Some("https://aqua.test"),"same-site",None,BODY);assert!(r.starts_with("HTTP/1.1 503"));assert!(!r.contains("private prompt sentinel"));assert!(r.contains("cache-control: no-store"));
        let cat=browser_api(state.clone(),"GET","/v1/images/models",&owner,None,"same-site",None,"");assert!(cat.starts_with("HTTP/1.1 200"));assert!(cat.contains("\"data\":[]"));
        assert!(state.quotas.lock().unwrap().is_empty());assert!(state.health.lock().unwrap().is_empty());assert!(state.route_latency.lock().unwrap().is_empty());
    }
    #[test]
    fn image_strict_privacy_and_generated_key_use_canonical_owner(){
        let mut s=Arc::try_unwrap(keys_shared()).ok().unwrap();let key=s.keys.get_mut().unwrap().create("luke","image fixture").unwrap();let bearer=format!("Bearer {}",key["key"].as_str().unwrap());s.spend.lock().unwrap().ledger.preferences.insert("luke".into(),crate::preferences::Preferences{zdr_only:true,default_model:"auto".into(),show_cost:true});let state=Arc::new(s);
        let r=browser_api(state.clone(),"POST","/v1/images/generations","",None,"none",Some(&bearer),BODY);assert!(r.starts_with("HTTP/1.1 403"));assert!(!r.contains(key["key"].as_str().unwrap()));assert!(r.contains("privacy_error"));
        // A missing/unknown model is never changed to flux or text auto.
        let r=browser_api(state,"POST","/v1/images/generations","",None,"none",Some(&bearer),r#"{"model":"flux","prompt":"x"}"#);assert!(r.starts_with("HTTP/1.1 400"));
    }
}

#[cfg(test)]
mod exchange_tests {
    //! GitHub login exchange bounds: github_agent's default resolution and
    //! stalled-endpoint behavior, moved in from tests/auth.rs so the agent
    //! builder and exchange stay private (lib.rs exports remain minimal).
    //! The old-style flat-300s agent below is the pre-patch configuration;
    //! it must land on a different outcome than the bounded agent.
    use super::*;
    use std::io::Read;

    fn json_listener(body: &'static str, stall: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            while let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let mut head = Vec::new();
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => head.extend_from_slice(&buf[..n]) }
                }
                std::thread::sleep(stall);
                let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", body.len(), body);
                let _ = socket.write_all(resp.as_bytes());
            }
        });
        url
    }

    fn exchange_cfg(global: Option<Duration>, idle: Option<Duration>) -> OAuthConfig {
        OAuthConfig { exchange_global: global, exchange_idle: idle, ..Default::default() }
    }

    // the pre-patch configuration: flat 300s global, no per-read floor
    fn old_style_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(300)))
            .build()
            .into()
    }

    #[test]
    fn github_agent_resolves_named_defaults_and_overrides() {
        let agent = github_agent(&exchange_cfg(None, None));
        assert_eq!(agent.config().timeouts().global, Some(GITHUB_CALL_GLOBAL));
        assert_eq!(agent.config().timeout_per_read(), Some(GITHUB_CALL_IDLE));
        let agent = github_agent(&exchange_cfg(Some(Duration::from_secs(7)), Some(Duration::from_secs(3))));
        assert_eq!(agent.config().timeouts().global, Some(Duration::from_secs(7)));
        assert_eq!(agent.config().timeout_per_read(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn github_exchange_completes_when_github_answers() {
        let tok = json_listener("{\"access_token\":\"tok\"}", Duration::ZERO);
        let user = json_listener("{\"login\":\"testuser\"}", Duration::ZERO);
        let cfg = exchange_cfg(None, None);
        let got = github_exchange(&github_agent(&cfg), &cfg, "code", &tok, &user);
        assert_eq!(got, Ok("testuser".to_string()), "healthy GitHub must log in: {got:?}");
    }

    #[test]
    fn github_exchange_stalled_token_endpoint_fails_fast() {
        let tok = json_listener("{\"access_token\":\"tok\"}", Duration::from_secs(3));
        let user = json_listener("{\"login\":\"testuser\"}", Duration::ZERO);
        let cfg = exchange_cfg(Some(Duration::from_secs(30)), Some(Duration::from_millis(300)));
        let started = Instant::now();
        let got = github_exchange(&github_agent(&cfg), &cfg, "code", &tok, &user);
        assert!(got.is_err(), "stalled token exchange must fail, got {got:?}");
        assert!(started.elapsed() < Duration::from_millis(2500), "stalled token exchange held the login: {:?}", started.elapsed());
        // mutant control: the old flat-300s agent rides out the 3s stall and completes
        let started = Instant::now();
        let got = github_exchange(&old_style_agent(), &cfg, "code", &tok, &user);
        assert_eq!(got, Ok("testuser".to_string()), "mutant control must differ: {got:?}");
        assert!(started.elapsed() >= Duration::from_secs(3));
    }

    #[test]
    fn github_exchange_stalled_user_endpoint_fails_fast() {
        let tok = json_listener("{\"access_token\":\"tok\"}", Duration::ZERO);
        let user = json_listener("{\"login\":\"testuser\"}", Duration::from_secs(3));
        let cfg = exchange_cfg(Some(Duration::from_secs(30)), Some(Duration::from_millis(300)));
        let started = Instant::now();
        let got = github_exchange(&github_agent(&cfg), &cfg, "code", &tok, &user);
        assert!(got.is_err(), "stalled user lookup must fail, got {got:?}");
        assert!(started.elapsed() < Duration::from_millis(2500), "stalled user lookup held the login: {:?}", started.elapsed());
        // mutant control: the old flat-300s agent rides out the 3s stall and completes
        let started = Instant::now();
        let got = github_exchange(&old_style_agent(), &cfg, "code", &tok, &user);
        assert_eq!(got, Ok("testuser".to_string()), "mutant control must differ: {got:?}");
        assert!(started.elapsed() >= Duration::from_secs(3));
    }
}

// Test-only priority-1 regression packet. All outbound sockets are loopback.
#[cfg(test)]
mod json_false_success_regressions {
    use super::*;
    use super::reviewer_regressions::{keys_shared, browser_api};

    fn stub(status: u16, body: &'static str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "stub received no dispatch");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("stub accept: {e}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = read_request(&mut socket).expect("stub requires real HTTP request");
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/chat/completions");
            write!(socket, "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        (url, worker)
    }

    fn provider(id: &str, url: String) -> crate::config::Provider {
        crate::config::Provider {
            id: id.into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-chat-upstream".into(), context: None,
            }],
        }
    }

    fn request(state: Arc<Shared>) -> String {
        let owner = state.auth.create_session("luke", Role::Owner).unwrap();
        browser_api(state, "POST", "/v1/chat/completions", &owner,
            Some("https://aqua.test"), "same-site", None,
            r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}],"stream":false}"#)
    }

    fn rejected_json(status: u16, body: &'static str) {
        let (url, worker) = stub(status, body);
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(3);
        state.config.providers = vec![provider("inferbase", url)];
        // Soft cooling must not block the attempt, but false success must not erase it.
        set_cooldown(&state, "inferbase", 60, false);
        let state = Arc::new(state);
        let response = request(state.clone());
        worker.join().expect("fixture server completed");
        let health = state.observations.lock().unwrap().aggregate(
            [("inferbase", "fixture-chat", "fixture-chat-upstream")].into_iter());
        let cooled = state.health.lock().unwrap().get("inferbase")
            .is_some_and(|c| c.until > Instant::now());
        // One assertion reports all three independent acceptance conditions.
        assert!(response.starts_with("HTTP/1.1 503")
            && health["healthy_routes"] == 0 && health["failed_routes"] == 1 && cooled,
            "invalid upstream result must fail closed, record failure, and retain cooldown: status={status}, response={response:?}, health={health}, cooled={cooled}");
        assert!(state.route_latency.lock().unwrap().is_empty(), "invalid output is not a successful latency sample");
    }

    macro_rules! rejection {
        ($name:ident, $status:expr, $body:expr) => {
            #[test] fn $name() { rejected_json($status, $body); }
        };
    }
    rejection!(json_200_error, 200, r#"{"error":{"message":"unavailable","code":429}}"#);
    rejection!(json_200_null, 200, "null");
    rejection!(json_200_empty_object, 200, "{}");
    rejection!(json_200_malformed, 200, "{");
    rejection!(json_201_error, 201, r#"{"error":{"message":"unavailable"}}"#);
    rejection!(json_201_null, 201, "null");
    rejection!(json_201_empty_object, 201, "{}");
    rejection!(json_201_malformed, 201, "{");
    rejection!(json_202_error, 202, r#"{"error":{"message":"unavailable"}}"#);
    rejection!(json_202_null, 202, "null");
    rejection!(json_202_empty_object, 202, "{}");
    rejection!(json_202_malformed, 202, "{");
    rejection!(json_206_error, 206, r#"{"error":{"message":"unavailable"}}"#);
    rejection!(json_206_null, 206, "null");
    rejection!(json_206_empty_object, 206, "{}");
    rejection!(json_206_malformed, 206, "{");
    rejection!(json_204_empty_body, 204, "");

    const VALID: &str = r#"{"id":"offline-chat","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"valid offline output"},"finish_reason":"stop"}]}"#;

    #[test]
    fn json_valid_positive_control() {
        let (url, worker) = stub(200, VALID);
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers = vec![provider("inferbase", url)];
        set_cooldown(&state, "inferbase", 60, false);
        let state = Arc::new(state);
        let response = request(state.clone());
        worker.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("valid offline output"));
        assert!(!state.health.lock().unwrap().contains_key("inferbase"));
        let health = state.observations.lock().unwrap().aggregate(
            [("inferbase", "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert_eq!(health["healthy_routes"], 1);
    }

    #[test]
    fn json_error_falls_back_before_downstream_commit() {
        let (bad_url, bad_worker) = stub(200, r#"{"error":{"message":"unavailable"}}"#);
        let (good_url, good_worker) = stub(200, VALID);
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(3);
        state.config.providers = vec![provider("inferbase", bad_url), provider("orcarouter", good_url)];
        let state = Arc::new(state);
        let response = request(state.clone());
        bad_worker.join().unwrap();
        // Join even when dispatch is missing: bounded stub timeout exposes missed fallback.
        let good_dispatched = good_worker.join().is_ok();
        assert!(good_dispatched && response.starts_with("HTTP/1.1 200")
            && response.contains("valid offline output"), "must discard error envelope then use valid exact-model fallback: {response:?}");
    }
}

// Envelope edge pins for the non-stream completion check: the check is a
// narrow envelope check, not full schema validation, and it is not applied
// to SSE streams.
#[cfg(test)]
mod json_envelope_edge_tests {
    use super::*;
    use super::reviewer_regressions::{keys_shared, browser_api};

    fn stub(body: &'static str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "stub received no dispatch");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("stub accept: {e}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = read_request(&mut socket).expect("stub requires real HTTP request");
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/chat/completions");
            write!(socket, "HTTP/1.1 200 Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        (url, worker)
    }

    fn edge_state(url: String) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(3);
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-chat-upstream".into(), context: None,
            }],
        }];
        set_cooldown(&state, "inferbase", 60, false);
        Arc::new(state)
    }

    fn request(state: Arc<Shared>) -> String {
        let owner = state.auth.create_session("luke", Role::Owner).unwrap();
        browser_api(state, "POST", "/v1/chat/completions", &owner,
            Some("https://aqua.test"), "same-site", None,
            r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}],"stream":false}"#)
    }

    fn rejected(body: &'static str) {
        let (url, worker) = stub(body);
        let state = edge_state(url);
        let response = request(state.clone());
        worker.join().expect("fixture server completed");
        let health = state.observations.lock().unwrap().aggregate(
            [("inferbase", "fixture-chat", "fixture-chat-upstream")].into_iter());
        let cooled = state.health.lock().unwrap().get("inferbase")
            .is_some_and(|c| c.until > Instant::now());
        assert!(response.starts_with("HTTP/1.1 503")
            && health["healthy_routes"] == 0 && health["failed_routes"] == 1 && cooled,
            "invalid envelope must fail closed, record failure, and retain cooldown: body={body}, response={response:?}, health={health}, cooled={cooled}");
        assert!(state.route_latency.lock().unwrap().is_empty(), "invalid output is not a successful latency sample");
    }

    #[test]
    fn json_200_empty_choices_rejected() { rejected(r#"{"choices":[]}"#); }

    #[test]
    fn json_200_null_choices_rejected() { rejected(r#"{"choices":null}"#); }

    #[test]
    fn json_200_non_array_choices_rejected() { rejected(r#"{"choices":"yes"}"#); }

    #[test]
    fn json_200_error_with_valid_choices_rejected() {
        rejected(r#"{"error":{"message":"x"},"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}"#);
    }

    #[test]
    fn json_200_tool_call_only_completion_accepted() {
        let body = r#"{"id":"offline-tc","object":"chat.completion","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#;
        let (url, worker) = stub(body);
        let state = edge_state(url);
        let response = request(state.clone());
        worker.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "tool-call-only completion must commit: {response:?}");
        assert!(response.contains("tool_calls"), "tool calls survive redaction: {response:?}");
        assert!(!state.health.lock().unwrap().contains_key("inferbase"), "accepted completion clears the soft cooldown");
        let health = state.observations.lock().unwrap().aggregate(
            [("inferbase", "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert_eq!(health["healthy_routes"], 1);
    }
}

// SSE commit-time health pins (providers-lane items 1+2, QA AMEND 8.7): one
// accepted-completion predicate drives both health and soft-cooldown clearing;
// an accepted finish_reason + clean EOF without [DONE] is healthy and clears.
#[cfg(test)]
mod sse_commit_health_tests {
    use super::*;
    use super::reviewer_regressions::keys_shared;
    use std::io::ErrorKind;
    use std::sync::mpsc::{channel, Receiver};

    const STREAM_BODY: &str = r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}],"stream":true}"#;
    const VALID_DELTA: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n";
    const TERMINAL: &str = "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n";
    const DONE: &str = "data: [DONE]\n\n";
    const ERROR_FRAME: &str = "data: {\"error\":{\"message\":\"blown\"}}\n\n";
    const EXTRA_FRAME: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"late\"}}]}\n\n";
    const MALFORMED_FRAME: &str = "data: {not-json\n\n";

    fn leaked(s: String) -> &'static str { Box::leak(s.into_boxed_str()) }

    fn sse_state(primary: String, fallback: Option<String>, idle: Duration) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(5);
        state.config.upstream_idle = idle;
        let mk = |id: &str, base_url: String| crate::config::Provider {
            id: id.into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-chat-upstream".into(), context: None }],
        };
        state.config.providers = vec![mk("inferbase", primary)];
        if let Some(url) = fallback { state.config.providers.push(mk("orcarouter", url)); }
        Arc::new(state)
    }

    fn health_of(state: &Arc<Shared>) -> Value {
        state.observations.lock().unwrap().aggregate(
            [("inferbase", "fixture-chat", "fixture-chat-upstream")].into_iter())
    }

    fn cooldown(state: &Arc<Shared>) -> Option<Cooldown> {
        state.health.lock().unwrap().get("inferbase").copied()
    }

    fn accept_one(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((s, _)) => return s,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "stub received no dispatch");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("stub accept: {e}"),
            }
        }
    }

    // Scripted SSE upstream: bounded accept, write head + phase1, wait for the
    // gate (bounded), write phase2, close. All writes carry a write timeout.
    fn sse_stub(phase1: &'static str, gate: Option<Receiver<()>>, phase2: &'static str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut socket = accept_one(&listener);
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let req = read_request(&mut socket).expect("stub requires real HTTP request");
            assert_eq!(req.method, "POST");
            assert_eq!(req.path, "/chat/completions");
            write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", phase1.len() + phase2.len()).expect("head write");
            socket.write_all(phase1.as_bytes()).expect("phase1 write");
            if let Some(g) = gate { g.recv_timeout(Duration::from_secs(5)).expect("gate release"); }
            socket.write_all(phase2.as_bytes()).expect("phase2 write");
        });
        (url, worker)
    }

    // Close-delimited stall variant (idle-timeout path): no content-length, or
    // the client stops at the promised byte count and the stall is invisible.
    fn sse_stall_stub(phase1: &'static str, stall: Duration) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut socket = accept_one(&listener);
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n").expect("head write");
            socket.write_all(phase1.as_bytes()).expect("phase1 write");
            thread::sleep(stall);
        });
        (url, worker)
    }

    // Over-cap variant: offers phase1, tolerates the peer closing at the cap,
    // and reports how many bytes were offered before any broken pipe/timeout.
    fn sse_offer_stub(phase1: &'static str, offered: Arc<AtomicUsize>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut socket = accept_one(&listener);
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", phase1.len()).expect("head write");
            let bytes = phase1.as_bytes();
            let mut written = 0usize;
            while written < bytes.len() {
                match socket.write(&bytes[written..]) {
                    Ok(0) => break,
                    Ok(n) => written += n,
                    Err(e) if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                    Err(e) => panic!("offer write: {e}"),
                }
            }
            offered.store(written, Ordering::SeqCst);
        });
        (url, worker)
    }

    // Bounded counting fallback: nonblocking accept until the stop flag or a
    // deadline. On stop it drains the accept backlog for a short window before
    // exiting, so a failover connection already queued by the kernel is still
    // counted; the test joins the worker before reading the final count.
    fn counting_stub(hits: Arc<AtomicUsize>, stop: Arc<AtomicBool>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match listener.accept() {
                    Ok((socket, _)) => { hits.fetch_add(1, Ordering::SeqCst); drop(socket); }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        if stop.load(Ordering::SeqCst) {
                            let drain_until = Instant::now() + Duration::from_millis(100);
                            while Instant::now() < drain_until {
                                match listener.accept() {
                                    Ok((socket, _)) => { hits.fetch_add(1, Ordering::SeqCst); drop(socket); }
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                                    Err(_) => break,
                                }
                            }
                            break;
                        }
                        assert!(Instant::now() < deadline, "counting stub outlived its deadline");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        (url, worker)
    }

    fn open_chat(state: Arc<Shared>, cookie: &str) -> (TcpStream, JoinHandle<std::io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || handle(listener.accept().unwrap().0, state));
        let mut c = TcpStream::connect(address).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(c, "POST /v1/chat/completions HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\nsec-fetch-site: same-site\r\norigin: https://aqua.test\r\ncontent-length: {}\r\n\r\n{STREAM_BODY}", STREAM_BODY.len()).unwrap();
        (c, worker)
    }

    fn read_head(c: &mut TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = c.read(&mut tmp).unwrap();
            assert!(n > 0, "server closed before the response head");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..p + 4]).into_owned();
                return (head, buf[p + 4..].to_vec());
            }
        }
    }

    // Read one complete SSE frame (through its blank-line terminator).
    fn read_frame(c: &mut TcpStream, rest: &mut Vec<u8>) -> String {
        let mut tmp = [0u8; 4096];
        loop {
            if let Some(p) = rest.windows(2).position(|w| w == b"\n\n") {
                let frame: Vec<u8> = rest.drain(..p + 2).collect();
                return String::from_utf8_lossy(&frame).into_owned();
            }
            let n = c.read(&mut tmp).expect("frame read");
            assert!(n > 0, "server closed before the first frame");
            rest.extend_from_slice(&tmp[..n]);
        }
    }

    fn read_body_to_eof(c: &mut TcpStream, rest: Vec<u8>) -> String {
        let mut body = rest;
        let mut tmp = [0u8; 8192];
        loop {
            match c.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(e) => panic!("downstream read: {e}"),
            }
        }
        String::from_utf8_lossy(&body).into_owned()
    }

    fn run_stream(state: Arc<Shared>) -> (String, String) {
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let (mut c, server) = open_chat(state, &cookie);
        let (head, rest) = read_head(&mut c);
        let body = read_body_to_eof(&mut c, rest);
        server.join().unwrap().unwrap();
        (head, body)
    }

    // Terminal frames are not transport completion: the upstream can still
    // stall or send invalid trailing data before EOF. A channel gate makes
    // the pre-EOF checkpoint deterministic, not a scheduler sleep.
    fn terminal_gate_regression(tail: &'static str, accepted: bool) {
        let (tx, rx) = channel();
        let (url, upstream) = sse_stub(
            leaked(format!("{VALID_DELTA}{TERMINAL}{DONE}")), Some(rx), tail);
        let state = sse_state(url, None, Duration::from_secs(5));
        set_cooldown(&state, "inferbase", 60, false);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let (mut c, server) = open_chat(state.clone(), &cookie);
        let (head, mut rest) = read_head(&mut c);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let delta = read_frame(&mut c, &mut rest);
        let terminal = read_frame(&mut c, &mut rest);
        let done = read_frame(&mut c, &mut rest);
        assert!(delta.contains("hi"), "{delta}");
        assert!(terminal.contains("stop"), "{terminal}");
        assert!(done.contains("[DONE]"), "{done}");
        // All terminal markers have reached the client, but the upstream is
        // still open behind the gate and may invalidate this completion.
        let before = cooldown(&state);
        let before_health = health_of(&state);
        let checkpoint = Instant::now();
        // Release/join before assertions so a failing mutant leaves no parked
        // fixture threads or writes that contaminate another test.
        tx.send(()).unwrap();
        let trailing = read_body_to_eof(&mut c, rest);
        server.join().unwrap().unwrap();
        upstream.join().unwrap();
        assert!(before.is_some_and(|cd| !cd.hard && cd.until > checkpoint),
            "DONE without EOF must not clear the soft cooldown");
        assert_eq!(before_health["healthy_routes"], 0,
            "DONE without EOF must not record successful generation");
        assert_eq!(before_health["failed_routes"], 0,
            "an open, still-valid stream is not an upstream failure");
        assert!(!trailing.contains("late"), "post-DONE output must not escape: {trailing}");
        if accepted {
            assert!(cooldown(&state).is_none(), "clean EOF accepts and clears soft cooling");
            assert_eq!(health_of(&state)["healthy_routes"], 1);
            assert_eq!(health_of(&state)["failed_routes"], 0);
        } else {
            assert!(cooldown(&state).is_some_and(|cd| cd.until > Instant::now()),
                "post-DONE data must leave the route cooled");
            assert_eq!(health_of(&state)["healthy_routes"], 0);
            assert_eq!(health_of(&state)["failed_routes"], 1);
        }
    }

    #[test]
    fn sse_done_before_eof_does_not_clear_cooldown_or_mark_healthy() {
        // A nonempty comment tail keeps Content-Length beyond phase1, so
        // ureq cannot report HTTP-body EOF while the gate is still closed.
        terminal_gate_regression(": transport still open\n\n", true);
    }

    #[test]
    fn sse_done_before_eof_followed_by_data_never_becomes_healthy() {
        terminal_gate_regression(EXTRA_FRAME, false);
    }

    #[test]
    fn sse_soft_cooldown_is_not_cleared_until_valid_completion() {
        let (tx, rx) = channel();
        let (url, upstream) = sse_stub(VALID_DELTA, Some(rx), leaked(format!("{TERMINAL}{DONE}")));
        let state = sse_state(url, None, Duration::from_secs(5));
        set_cooldown(&state, "inferbase", 60, false);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let (mut c, server) = open_chat(state.clone(), &cookie);
        let (head, mut rest) = read_head(&mut c);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let frame = read_frame(&mut c, &mut rest);
        assert!(frame.contains("data:"), "one delta parsed before commit state: {frame}");
        // Headers committed and one valid delta seen, stream parked: the soft
        // cooldown must still be standing and nothing healthy recorded yet.
        assert!(cooldown(&state).is_some_and(|cd| cd.until > Instant::now()),
            "soft cooldown must survive until the stream proves out");
        assert_eq!(health_of(&state)["healthy_routes"], 0);
        tx.send(()).unwrap();
        let body = read_body_to_eof(&mut c, rest);
        server.join().unwrap().unwrap();
        upstream.join().unwrap();
        assert!(body.contains("data: [DONE]"), "{body}");
        assert!(cooldown(&state).is_none(), "valid completion clears the soft cooldown");
        assert_eq!(health_of(&state)["healthy_routes"], 1);
    }

    #[test]
    fn sse_completion_never_clears_a_hard_cooldown_installed_mid_stream() {
        let (tx, rx) = channel();
        let (url, upstream) = sse_stub(VALID_DELTA, Some(rx), leaked(format!("{TERMINAL}{DONE}")));
        let state = sse_state(url, None, Duration::from_secs(5));
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let (mut c, server) = open_chat(state.clone(), &cookie);
        let (head, mut rest) = read_head(&mut c);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let frame = read_frame(&mut c, &mut rest);
        assert!(frame.contains("data:"), "one delta parsed before commit state: {frame}");
        set_cooldown(&state, "inferbase", 120, true);
        let installed = cooldown(&state).unwrap();
        assert!(installed.hard);
        tx.send(()).unwrap();
        let _ = read_body_to_eof(&mut c, rest);
        server.join().unwrap().unwrap();
        upstream.join().unwrap();
        let after = cooldown(&state).expect("a hard limit installed mid-stream must survive completion");
        assert!(after.hard && after.until == installed.until, "hard limit cleared or shortened by completion");
    }

    // QA AMEND 8.7: one predicate. Accepted finish_reason + clean EOF without
    // [DONE] is healthy AND clears the soft cooldown.
    #[test]
    fn sse_terminal_without_done_completes_and_clears_soft_cooldown() {
        let (url, upstream) = sse_stub(leaked(format!("{VALID_DELTA}{TERMINAL}")), None, "");
        let state = sse_state(url, None, Duration::from_secs(5));
        set_cooldown(&state, "inferbase", 60, false);
        let (head, body) = run_stream(state.clone());
        upstream.join().unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(!body.contains("[DONE]"), "no synthesized DONE: {body}");
        assert_eq!(health_of(&state)["healthy_routes"], 1);
        assert!(cooldown(&state).is_none(), "accepted terminal + clean EOF clears the soft cooldown");
    }

    // Framing negatives: a tainted stream is not accepted even with [DONE].
    #[test]
    fn sse_data_after_done_is_not_accepted_and_cools() {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (fb_url, fb) = counting_stub(hits.clone(), stop.clone());
        let (url, upstream) = sse_stub(leaked(format!("{VALID_DELTA}{TERMINAL}{DONE}{EXTRA_FRAME}")), None, "");
        let state = sse_state(url, Some(fb_url), Duration::from_secs(5));
        let (head, _body) = run_stream(state.clone());
        upstream.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        fb.join().unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no failover once the response is committed");
        let health = health_of(&state);
        assert!(health["healthy_routes"] == 0 && health["failed_routes"] == 1, "post-DONE data is not accepted: {health}");
        assert!(cooldown(&state).is_some_and(|cd| cd.until > Instant::now()), "tainted stream must cool the route");
    }

    #[test]
    fn sse_malformed_frame_is_not_rescued_by_done() {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (fb_url, fb) = counting_stub(hits.clone(), stop.clone());
        let (url, upstream) = sse_stub(leaked(format!("{MALFORMED_FRAME}{VALID_DELTA}{TERMINAL}{DONE}")), None, "");
        let state = sse_state(url, Some(fb_url), Duration::from_secs(5));
        let (head, _body) = run_stream(state.clone());
        upstream.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        fb.join().unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let health = health_of(&state);
        assert!(health["healthy_routes"] == 0 && health["failed_routes"] == 1, "malformed is not rescued by DONE: {health}");
        assert!(cooldown(&state).is_some_and(|cd| cd.until > Instant::now()), "tainted stream must cool the route");
    }

    // Item 2 failure matrix: after a committed 200, every failure ends the
    // downstream honestly (no failover, no synthesized DONE), records the
    // route failed, and leaves an active cooldown.
    fn failure_case(phase1: &'static str, stall: Option<Duration>, idle: Duration) -> (Arc<Shared>, String, String, usize) {
        let (url, upstream) = match stall {
            Some(d) => sse_stall_stub(phase1, d),
            None => sse_stub(phase1, None, ""),
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (fb_url, fb) = counting_stub(hits.clone(), stop.clone());
        let state = sse_state(url, Some(fb_url), idle);
        let (head, body) = run_stream(state.clone());
        upstream.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        fb.join().unwrap();
        let final_hits = hits.load(Ordering::SeqCst);
        (state, head, body, final_hits)
    }

    fn assert_failed_commit(state: &Arc<Shared>, head: &str, body: &str, final_hits: usize) {
        assert!(head.starts_with("HTTP/1.1 200"), "headers were committed: {head}");
        assert!(!body.contains("[DONE]"), "no synthesized DONE: {body}");
        assert_eq!(final_hits, 0, "no failover once the response is committed");
        let health = health_of(state);
        assert!(health["healthy_routes"] == 0 && health["failed_routes"] == 1, "route recorded failed: {health}");
        assert!(cooldown(state).is_some_and(|cd| cd.until > Instant::now()), "failure after commit must cool the route");
    }

    #[test]
    fn sse_immediate_eof_after_commit_cools_and_never_fails_over() {
        let (state, head, body, hits) = failure_case("", None, Duration::from_secs(5));
        assert!(body.is_empty(), "{body}");
        assert_failed_commit(&state, &head, &body, hits);
    }

    #[test]
    fn sse_unterminated_event_eof_cools_and_never_fails_over() {
        let (state, head, body, hits) = failure_case("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par", None, Duration::from_secs(5));
        assert_failed_commit(&state, &head, &body, hits);
    }

    #[test]
    fn sse_valid_delta_then_eof_without_terminal_cools_and_never_fails_over() {
        let (state, head, body, hits) = failure_case(VALID_DELTA, None, Duration::from_secs(5));
        assert!(body.contains("data:"), "the valid delta was forwarded: {body}");
        assert_failed_commit(&state, &head, &body, hits);
    }

    #[test]
    fn sse_error_envelope_cools_and_never_fails_over() {
        let (state, head, body, hits) = failure_case(ERROR_FRAME, None, Duration::from_secs(5));
        assert_failed_commit(&state, &head, &body, hits);
    }

    #[test]
    fn sse_idle_timeout_after_valid_delta_cools_and_never_fails_over() {
        let (state, head, body, hits) = failure_case(VALID_DELTA, Some(Duration::from_secs(1)), Duration::from_millis(100));
        assert!(body.contains("data:"), "the valid delta was forwarded: {body}");
        assert_failed_commit(&state, &head, &body, hits);
    }

    // Over-cap: 45 legal frames of ~100KB each (~4.5MB) against the literal
    // 4_000_000-byte response cap. The ample idle budget (5s against a writer
    // that finishes in milliseconds) plus the exact end-of-body window prove
    // the cap ended the stream, not a timeout; offered > CAP proves the
    // upstream still had bytes to give, so it was not an early EOF either.
    #[test]
    fn sse_over_cap_legal_events_cool_and_end_honestly() {
        const CAP: usize = 4_000_000;
        assert_eq!(CAP, MAX_RESPONSE, "fixture drifted from the standing cap");
        let big = format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", "a".repeat(100_000));
        let mut phase = String::new();
        for _ in 0..45 { phase.push_str(&big); }
        let offered = Arc::new(AtomicUsize::new(0));
        let (url, upstream) = sse_offer_stub(leaked(phase.clone()), offered.clone());
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (fb_url, fb) = counting_stub(hits.clone(), stop.clone());
        let state = sse_state(url, Some(fb_url), Duration::from_secs(5));
        let (head, body) = run_stream(state.clone());
        stop.store(true, Ordering::SeqCst);
        fb.join().unwrap();
        upstream.join().unwrap();
        let final_hits = hits.load(Ordering::SeqCst);
        assert!(body.len() <= CAP && body.len() + big.len() > CAP,
            "body stopped exactly at the cap window: {} of {CAP}", body.len());
        assert!(offered.load(Ordering::SeqCst) > CAP,
            "upstream still had bytes to give when the stream ended: {}", offered.load(Ordering::SeqCst));
        assert_failed_commit(&state, &head, &body, final_hits);
    }

    // Under-cap control: the same legal frames totalling just under the cap
    // with a proper terminal and DONE must stream in full, record healthy and
    // clear a standing soft cooldown, so size alone explains nothing above.
    #[test]
    fn sse_under_cap_stream_completes_healthy_and_clears_soft_cooldown() {
        const CAP: usize = 4_000_000;
        assert_eq!(CAP, MAX_RESPONSE, "fixture drifted from the standing cap");
        let big = format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", "a".repeat(100_000));
        let mut phase = String::new();
        for _ in 0..39 { phase.push_str(&big); }
        phase.push_str(TERMINAL);
        phase.push_str(DONE);
        assert!(phase.len() < CAP, "control fixture must stay under the cap: {}", phase.len());
        let offered = Arc::new(AtomicUsize::new(0));
        let (url, upstream) = sse_offer_stub(leaked(phase.clone()), offered.clone());
        let state = sse_state(url, None, Duration::from_secs(5));
        set_cooldown(&state, "inferbase", 60, false);
        let (head, body) = run_stream(state.clone());
        upstream.join().unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(body.contains("data: [DONE]"), "stream completed: {} bytes", body.len());
        // Offered counts bytes the stub wrote to its socket, not proof of downstream
        // consumption: it proves the server kept reading until the upstream finished.
        assert_eq!(offered.load(Ordering::SeqCst), phase.len(), "server read the upstream to the end, no early stop");
        let health = health_of(&state);
        assert!(health["healthy_routes"] == 1 && health["failed_routes"] == 0, "under-cap stream is healthy: {health}");
        assert!(cooldown(&state).is_none(), "valid completion clears the soft cooldown");
    }
}

// Transport deadline matrix (providers-lane item 4): one aggregate upstream
// budget per request, shared across attempts, with a per-read idle floor.
// The NIM owner 120s window is pinned purely at the provider_remaining_budget
// boundary (no 120s sleeps); live loopback pins use small configured windows.
#[cfg(test)]
mod transport_deadline_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api, keys_shared};
    use std::io::ErrorKind;

    // NIM + owner gets a 120s window regardless of the configured budget;
    // the window ends exactly at 120s of elapsed request time.
    #[test]
    fn nim_owner_window_is_120s_at_the_boundary() {
        let configured = Duration::from_secs(300);
        assert_eq!(provider_remaining_budget("nim", true, configured, Duration::ZERO),
            Some(Duration::from_secs(120)), "NIM owner window is 120s regardless of configured budget");
        assert_eq!(provider_remaining_budget("nim", true, configured, Duration::from_secs(119)),
            Some(Duration::from_secs(1)));
        assert_eq!(provider_remaining_budget("nim", true, configured, Duration::from_secs(120)), None);
        assert_eq!(provider_remaining_budget("nim", true, configured, Duration::from_secs(121)), None);
    }

    // Every other route (and NIM for a non-owner) gets the configured window,
    // ending exactly at the configured elapsed time.
    #[test]
    fn configured_window_boundaries_and_non_owner_nim_window() {
        let configured = Duration::from_secs(300);
        assert_eq!(provider_remaining_budget("nim", false, configured, Duration::ZERO), Some(configured),
            "non-owner NIM never gets the owner 120s window");
        assert_eq!(provider_remaining_budget("inferbase", true, configured, Duration::ZERO), Some(configured));
        assert_eq!(provider_remaining_budget("inferbase", true, configured, configured - Duration::from_millis(1)),
            Some(Duration::from_millis(1)));
        assert_eq!(provider_remaining_budget("inferbase", true, configured, configured), None);
        assert_eq!(provider_remaining_budget("inferbase", true, configured, configured + Duration::from_secs(1)), None);
    }

    const VALID: &str = r#"{"id":"offline-chat","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"valid offline output"},"finish_reason":"stop"}]}"#;

    fn leaked(s: String) -> &'static str { Box::leak(s.into_boxed_str()) }

    // Counting JSON stub: serves VALID to every accepted connection, bounded,
    // drains the accept backlog after the stop flag so a queued dispatch is
    // still counted; the test joins before reading the final count.
    fn counting_json_stub(hits: Arc<AtomicUsize>, stop: Arc<AtomicBool>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        let _ = read_request(&mut socket);
                        let _ = write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", VALID.len(), VALID);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        if stop.load(Ordering::SeqCst) {
                            let drain_until = Instant::now() + Duration::from_millis(100);
                            while Instant::now() < drain_until {
                                match listener.accept() {
                                    Ok((mut socket, _)) => {
                                        hits.fetch_add(1, Ordering::SeqCst);
                                        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                                        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                                        let _ = read_request(&mut socket);
                                        let _ = write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", VALID.len(), VALID);
                                    }
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                                    Err(_) => break,
                                }
                            }
                            break;
                        }
                        assert!(Instant::now() < deadline, "counting stub outlived its deadline");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        (url, worker)
    }

    // NIM with a trial-eligible upstream model; the only route configured.
    fn nim_state(url: String) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(5);
        state.config.upstream_idle = Duration::from_secs(5);
        state.config.providers = vec![crate::config::Provider {
            id: "nim".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "z-ai/glm-5.3-flash".into(), context: None,
            }],
        }];
        Arc::new(state)
    }

    fn chat_once(state: Arc<Shared>, role: Role) -> String {
        let cookie = state.auth.create_session("luke", role).unwrap();
        browser_api(state, "POST", "/v1/chat/completions", &cookie,
            Some("https://aqua.test"), "same-site", None,
            r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}],"stream":false}"#)
    }

    // Owner-trial accounts never serve friends: a non-owner request must not
    // even reach the NIM account.
    #[test]
    fn non_owner_never_dispatches_owner_trial_nim() {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (url, stub) = counting_json_stub(hits.clone(), stop.clone());
        let state = nim_state(url);
        let response = chat_once(state, Role::Friend);
        stop.store(true, Ordering::SeqCst);
        stub.join().unwrap();
        assert!(!response.starts_with("HTTP/1.1 200"), "a friend must not be served by an owner-trial account: {response:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "non-owner request must never reach the NIM account");
    }

    // Positive control: the same fixture is owner-eligible, so the pin above
    // targets the role gate and not a broken fixture.
// One failing route configured, budget/idle set small and explicit.
    fn deadline_state(providers: Vec<crate::config::Provider>, budget: Duration, idle: Duration) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = budget;
        state.config.upstream_idle = idle;
        state.config.providers = providers;
        Arc::new(state)
    }

    fn deadline_provider(id: &str, url: String) -> crate::config::Provider {
        crate::config::Provider {
            id: id.into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-chat-upstream".into(), context: None,
            }],
        }
    }

    fn failed_attempt(state: &Arc<Shared>, response: &str, provider: &str) {
        assert!(response.starts_with("HTTP/1.1 503"), "attempt must fail closed: {response:?}");
        let health = state.observations.lock().unwrap().aggregate(
            [(provider, "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert!(health["healthy_routes"] == 0 && health["failed_routes"] == 1, "route recorded failed: {health}");
        assert!(state.health.lock().unwrap().get(provider).is_some_and(|c| c.until > Instant::now()),
            "timed-out attempt must cool the route");
    }

    // Scripted single-connection stub: optional head first, a stall, then the
    // body. Writes tolerate the client having gone away (deadline fired).
    fn stall_stub(head: Option<String>, stall: Duration, body: &'static str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut socket = accept_one(&listener);
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            if let Some(h) = head { let _ = socket.write_all(h.as_bytes()); }
            thread::sleep(stall);
            let _ = socket.write_all(body.as_bytes());
        });
        (url, worker)
    }

    // Drip-feed stub: head, then one byte per interval for `rounds` (faster
    // than the idle floor, so per-read never fires), then the rest. Writes
    // tolerate the client having gone away.
    fn drip_stub(body: &'static str, interval: Duration, rounds: usize) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut socket = accept_one(&listener);
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            let _ = socket.write_all(json_head(body.len()).as_bytes());
            let bytes = body.as_bytes();
            for chunk in bytes[..rounds].chunks(1) {
                if socket.write_all(chunk).is_err() { return; }
                thread::sleep(interval);
            }
            let _ = socket.write_all(&bytes[rounds..]);
        });
        (url, worker)
    }

    fn json_head(len: usize) -> String {
        format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", len)
    }

    fn accept_one(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((s, _)) => return s,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "stub received no dispatch");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("stub accept: {e}"),
            }
        }
    }

    // No headers at all: the per-read idle floor kills the attempt before the
    // late body can arrive, even though the aggregate budget would allow it.
    #[test]
    fn no_headers_attempt_dies_on_idle_floor() {
        // silent 300ms, then a valid head and body; idle 100ms, aggregate 400ms
        let (url, stub) = stall_stub(None, Duration::from_millis(300), leaked(format!("{}{}", json_head(VALID.len()), VALID)));
        let state = deadline_state(vec![deadline_provider("inferbase", url)], Duration::from_millis(400), Duration::from_millis(100));
        let started = Instant::now();
        let response = chat_once(state.clone(), Role::Owner);
        let elapsed = started.elapsed();
        stub.join().unwrap();
        assert!(elapsed < Duration::from_millis(350),
            "died before the 400ms aggregate could fire, so the idle floor is the killer: {elapsed:?}");
        failed_attempt(&state, &response, "inferbase");
    }

    // Headers arrive, body stalls: the idle floor restarts per read and still
    // kills the attempt before the late body, under a wide aggregate budget.
    #[test]
    fn headers_then_stalled_body_dies_on_idle_floor() {
        // head now, body at 400ms; idle 100ms, aggregate 2s
        let (url, stub) = stall_stub(Some(json_head(VALID.len())), Duration::from_millis(400), VALID);
        let state = deadline_state(vec![deadline_provider("inferbase", url)], Duration::from_secs(2), Duration::from_millis(100));
        let started = Instant::now();
        let response = chat_once(state.clone(), Role::Owner);
        let elapsed = started.elapsed();
        stub.join().unwrap();
        assert!(elapsed < Duration::from_millis(1000),
            "died far inside the 2s aggregate, so the per-read idle floor is the killer: {elapsed:?}");
        failed_attempt(&state, &response, "inferbase");
    }

    // Aggregate-budget regression guard: a steady drip faster than the idle
    // floor dies inside the aggregate window, mid-stream.
    #[test]
    fn drip_faster_than_idle_dies_on_aggregate_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stub = thread::spawn(move || {
            let mut socket = accept_one(&listener);
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            let _ = socket.write_all(json_head(VALID.len()).as_bytes());
            let bytes = VALID.as_bytes();
            // 16 drips of 1 byte, 50ms apart: faster than the 100ms idle floor,
            // 800ms in total, past the 400ms aggregate budget.
            for chunk in bytes[..16].chunks(1) {
                if socket.write_all(chunk).is_err() { return; }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = socket.write_all(&bytes[16..]);
        });
        let state = deadline_state(vec![deadline_provider("inferbase", url)], Duration::from_millis(400), Duration::from_millis(100));
        let started = Instant::now();
        let response = chat_once(state.clone(), Role::Owner);
        let elapsed = started.elapsed();
        stub.join().unwrap();
        // Died inside the aggregate window, before the 800ms body completed.
        // A long scheduling pause could land in the same window, so this pins
        // the aggregate regression, not a unique attribution to it.
        assert!(elapsed >= Duration::from_millis(300) && elapsed < Duration::from_millis(750),
            "died inside the aggregate window, mid-stream: {elapsed:?}");
        failed_attempt(&state, &response, "inferbase");
    }

    // Healthy control: the same drip pattern completes when the whole body
    // lands inside the aggregate budget, isolating the kill above to the budget.
    #[test]
    fn drip_faster_than_idle_completes_within_budget() {
        let (url, stub) = drip_stub(VALID, Duration::from_millis(50), 4);
        let state = deadline_state(vec![deadline_provider("inferbase", url)], Duration::from_millis(400), Duration::from_millis(100));
        let response = chat_once(state.clone(), Role::Owner);
        stub.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200") && response.contains("valid offline output"),
            "a drip that lands inside the aggregate budget completes: {response:?}");
        let health = state.observations.lock().unwrap().aggregate(
            [("inferbase", "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert_eq!(health["healthy_routes"], 1, "route recorded healthy: {health}");
    }

    // The fallback attempt inherits only the remaining aggregate window: the
    // first attempt burns 300ms of the 1000ms budget on the idle floor, and
    // the fallback drips for 800ms (faster than the 300ms idle floor, so only
    // the aggregate budget can end it), outlasting the remaining ~700ms.
    #[test]
    fn fallback_gets_only_the_remaining_aggregate_budget() {
        let (a_url, a_stub) = stall_stub(Some(json_head(VALID.len())), Duration::from_millis(1200), VALID);
        let (b_url, b_stub) = drip_stub(VALID, Duration::from_millis(100), 8);
        let state = deadline_state(
            vec![deadline_provider("inferbase", a_url), deadline_provider("orcarouter", b_url)],
            Duration::from_millis(1000), Duration::from_millis(300));
        let started = Instant::now();
        let response = chat_once(state.clone(), Role::Owner);
        let elapsed = started.elapsed();
        a_stub.join().unwrap();
        b_stub.join().unwrap();
        // The fallback outlived its own 300ms idle floor and died near the
        // 1000ms aggregate: the attempt ran on the remaining window.
        assert!(elapsed >= Duration::from_millis(850) && elapsed < Duration::from_millis(1600),
            "fallback ran into the remaining aggregate window: {elapsed:?}");
        assert!(response.starts_with("HTTP/1.1 503"), "fallback inside only the remaining budget must fail: {response:?}");
        for p in ["inferbase", "orcarouter"] {
            let health = state.observations.lock().unwrap().aggregate(
                [(p, "fixture-chat", "fixture-chat-upstream")].into_iter());
            assert!(health["failed_routes"] == 1, "{p} recorded failed: {health}");
        }
    }

    #[test]
    fn owner_dispatches_eligible_nim_model() {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (url, stub) = counting_json_stub(hits.clone(), stop.clone());
        let state = nim_state(url);
        let response = chat_once(state, Role::Owner);
        stop.store(true, Ordering::SeqCst);
        stub.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "owner request on an eligible NIM model: {response:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "exactly one dispatch to the account");
    }
}

// Permit lifetime/release matrix (providers-lane item 3): the per-account
// slot is held for the whole attempt and released on every exit path. A busy
// account is skipped without 429 evidence or cooldown. JSON-bodied busy
// outcomes can be schedule-dependent (the first call may complete before the
// second arrives); the SSE mid-stream case is the decisive busy-skip
// observation.
#[cfg(test)]
mod permit_lifetime_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api, keys_shared};
    use std::io::ErrorKind;
    use std::sync::mpsc::channel;

    const VALID: &str = r#"{"id":"offline-chat","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"valid offline output"},"finish_reason":"stop"}]}"#;

    fn slot<'a>(state: &'a Arc<Shared>, provider: &str) -> &'a AtomicBool {
        match provider {
            "zai" => &state.zai_in_flight,
            "openrouter" => &state.openrouter_in_flight,
            "nim" => &state.nim_in_flight,
            "radeon" => &state.radeon_in_flight,
            "logfare" => &state.logfare_in_flight,
            _ => panic!("not a slot-limited provider: {provider}"),
        }
    }

    fn slot_state(provider: &str, upstream_model: &str, url: String) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(5);
        state.config.upstream_idle = Duration::from_secs(5);
        state.config.providers = vec![crate::config::Provider {
            id: provider.into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: upstream_model.into(), context: None,
            }],
        }];
        Arc::new(state)
    }

    fn chat(state: Arc<Shared>) -> String {
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        browser_api(state, "POST", "/v1/chat/completions", &cookie,
            Some("https://aqua.test"), "same-site", None,
            r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}],"stream":false}"#)
    }

    // Counting gated stub: the first connection gets the head, a report-in,
    // then parks on the gate before the body. Any further connection is only
    // counted (a busy-skip violation reaches the account at TCP level even if
    // nobody answers it), and the backlog is drained after the stop flag so a
    // queued connection is still counted; the test joins before the count.
    fn counting_gated_stub(body: &'static str) -> (String, JoinHandle<()>, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let extra = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = channel();
        let (gate_tx, gate_rx) = channel();
        let extra2 = extra.clone();
        let stop2 = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "stub received no dispatch");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("stub accept: {e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()).expect("head write");
            in_tx.send(()).unwrap();
            gate_rx.recv_timeout(Duration::from_secs(10)).expect("gate release");
            socket.write_all(body.as_bytes()).expect("body write");
            drop(socket);
            while !stop2.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((s, _)) => { extra2.fetch_add(1, Ordering::SeqCst); drop(s); }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
            let drain_until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < drain_until {
                match listener.accept() {
                    Ok((s, _)) => { extra2.fetch_add(1, Ordering::SeqCst); drop(s); }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        });
        (url, worker, in_rx, gate_tx, extra, stop)
    }

const STREAM_BODY: &str = r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}],"stream":true}"#;
    const VALID_DELTA: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n";
    const TERMINAL: &str = "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n";
    const DONE: &str = "data: [DONE]\n\n";

    // Counting gated SSE stub: first connection gets an SSE head + phase1,
    // parks on the gate, then phase2. Further connections are only counted,
    // with a backlog drain after the stop flag; the test joins before counting.
    fn counting_gated_sse_stub(phase1: &'static str, phase2: &'static str) -> (String, JoinHandle<()>, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let extra = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = channel();
        let (gate_tx, gate_rx) = channel();
        let extra2 = extra.clone();
        let stop2 = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "stub received no dispatch");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("stub accept: {e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut socket);
            write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", phase1.len() + phase2.len()).expect("head write");
            socket.write_all(phase1.as_bytes()).expect("phase1 write");
            in_tx.send(()).unwrap();
            gate_rx.recv_timeout(Duration::from_secs(10)).expect("gate release");
            socket.write_all(phase2.as_bytes()).expect("phase2 write");
            drop(socket);
            while !stop2.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((s, _)) => { extra2.fetch_add(1, Ordering::SeqCst); drop(s); }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
            let drain_until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < drain_until {
                match listener.accept() {
                    Ok((s, _)) => { extra2.fetch_add(1, Ordering::SeqCst); drop(s); }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        });
        (url, worker, in_rx, gate_tx, extra, stop)
    }

    // Raw streaming client on a worker thread: reads the response head and one
    // SSE frame, reports in, waits for the release, then reads to EOF.
    fn streaming_client(state: Arc<Shared>, framed: std::sync::mpsc::Sender<()>, release: std::sync::mpsc::Receiver<()>) -> JoinHandle<String> {
        thread::spawn(move || {
            let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || handle(listener.accept().unwrap().0, state));
            let mut c = TcpStream::connect(address).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(c, "POST /v1/chat/completions HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\nsec-fetch-site: same-site\r\norigin: https://aqua.test\r\ncontent-length: {}\r\n\r\n{STREAM_BODY}", STREAM_BODY.len()).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let mut frames = 0;
            loop {
                let n = c.read(&mut tmp).unwrap();
                assert!(n > 0, "server closed before the first frame");
                buf.extend_from_slice(&tmp[..n]);
                frames = buf.windows(2).filter(|w| *w == b"\n\n").count();
                if frames >= 1 && buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            framed.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(10)).expect("release");
            loop {
                match c.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(e) => panic!("downstream read: {e}"),
                }
            }
            server.join().unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        })
    }

    // While a streaming attempt holds the account (downstream has provably
    // consumed the head and one frame), a second call must busy-skip: it never
    // reaches the account, fails closed, and leaves no cooldown. This
    // interleaving is what catches a slot released at header commit.
    #[test]
    fn busy_account_is_skipped_mid_stream_zai() {
        let (url, worker, _accepted, gate, extra, stop) = counting_gated_sse_stub(VALID_DELTA, leaked(format!("{TERMINAL}{DONE}")));
        let state = slot_state("zai", "fixture-chat-upstream", url);
        let (framed_tx, framed_rx) = channel();
        let (release_tx, release_rx) = channel();
        let first = streaming_client(state.clone(), framed_tx, release_rx);
        framed_rx.recv_timeout(Duration::from_secs(5)).expect("first stream delivered a frame");
        assert!(slot(&state, "zai").load(Ordering::SeqCst), "slot held while the stream is open");
        let second = chat(state.clone());
        assert!(second.starts_with("HTTP/1.1 503"), "busy account skipped, no other route: {second:?}");
        assert!(state.health.lock().unwrap().get("zai").is_none(), "busy-skip adds no cooldown");
        gate.send(()).unwrap();
        release_tx.send(()).unwrap();
        let body = first.join().unwrap();
        assert!(body.contains("data: [DONE]"), "first stream completes: {}", body.len());
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(!slot(&state, "zai").load(Ordering::SeqCst), "slot released after completion");
        assert_eq!(extra.load(Ordering::SeqCst), 0, "no second connection ever reached the account");
        let health = state.observations.lock().unwrap().aggregate(
            [("zai", "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert!(health["healthy_routes"] == 1 && health["failed_routes"] == 0, "only the first, completed stream counts: {health}");
    }

    fn leaked(s: String) -> &'static str { Box::leak(s.into_boxed_str()) }

    // Same busy-skip contract for every slot-limited provider, with its actual
    // eligible upstream model and owner role. OpenRouter needs its spend gate
    // enabled (verified day, allowance, durable store) like the existing
    // fixtures.
    fn busy_state(provider: &str, upstream_model: &str, url: String) -> (Arc<Shared>, Option<std::path::PathBuf>) {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(5);
        state.config.upstream_idle = Duration::from_secs(5);
        let mut spend_path = None;
        if provider == "openrouter" {
            let path = std::env::temp_dir().join(format!("aqua-permit-busy-{}-{}.json",
                std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            state.spend = Mutex::new(crate::spend::Store::open(Some(path.clone())).unwrap());
            state.config.spend.account_verified_day = chrono_day();
            state.config.spend.openrouter_allowance = 40;
            spend_path = Some(path);
        }
        state.config.providers = vec![crate::config::Provider {
            id: provider.into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: upstream_model.into(), context: None,
            }],
        }];
        (Arc::new(state), spend_path)
    }

    fn busy_account_is_skipped(provider: &str, upstream_model: &str) {
        let (url, worker, accepted, gate, extra, stop) = counting_gated_stub(VALID);
        let (state, spend_path) = busy_state(provider, upstream_model, url);
        let first = { let s = state.clone(); thread::spawn(move || chat(s)) };
        accepted.recv_timeout(Duration::from_secs(5)).expect("first call reached the account");
        assert!(slot(&state, provider).load(Ordering::SeqCst), "slot held once the account is engaged");
        let second = chat(state.clone());
        assert!(second.starts_with("HTTP/1.1 503"), "busy account skipped, no other route: {second:?}");
        assert!(state.health.lock().unwrap().get(provider).is_none(), "busy-skip adds no cooldown");
        gate.send(()).unwrap();
        assert!(first.join().unwrap().starts_with("HTTP/1.1 200"), "first call completes");
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(!slot(&state, provider).load(Ordering::SeqCst), "slot released after completion");
        assert_eq!(extra.load(Ordering::SeqCst), 0, "no second connection ever reached the account");
        if let Some(path) = spend_path { let _ = std::fs::remove_file(path); }
    }

    #[test]
    fn busy_account_is_skipped_nim() { busy_account_is_skipped("nim", "z-ai/glm-5.3-flash"); }

    #[test]
    fn busy_account_is_skipped_radeon() { busy_account_is_skipped("radeon", "GLM-5.3-Flash"); }

    #[test]
    fn busy_account_is_skipped_logfare() { busy_account_is_skipped("logfare", "qwen-3.8-27b"); }

    #[test]
    fn busy_account_is_skipped_openrouter() { busy_account_is_skipped("openrouter", "cohere/north-mini-code:free"); }

    // Release matrix: after every exit path the account slot must be free, so
    // a follow-up call reaches the account and succeeds. Each stub serves the
    // scripted failure to connection 1 and VALID to connection 2. Cooldowns
    // from the failure are soft (no Retry-After), which never blocks dispatch,
    // so dispatch on call 2 isolates the slot. A hard 429+Retry-After
    // cooldown would block call 2 before the slot check, so that shape cannot
    // observe the slot and is intentionally not used here.
    enum Behavior { Raw(&'static str), Close, Stall(Duration) }

    fn sequence_stub(behaviors: Vec<Behavior>, hits: Arc<AtomicUsize>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            for behavior in behaviors {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "stub received no dispatch");
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("stub accept: {e}"),
                    }
                };
                hits.fetch_add(1, Ordering::SeqCst);
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let _ = read_request(&mut socket);
                match behavior {
                    Behavior::Raw(response) => { let _ = socket.write_all(response.as_bytes()); }
                    Behavior::Close => drop(socket),
                    Behavior::Stall(d) => {
                        // Never respond, but notice the peer going away: probe
                        // with a short-timeout read (FIN shows as Ok(0)) so the
                        // stub is ready for the next connection promptly while
                        // the client still fails purely on its idle floor.
                        socket.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
                        let until = Instant::now() + d;
                        let mut probe = [0u8; 1];
                        loop {
                            match socket.read(&mut probe) {
                                Ok(0) => break,
                                _ => assert!(Instant::now() < until, "stall probe outlived its deadline"),
                            }
                        }
                    }
                }
            }
        });
        (url, worker)
    }

    fn raw_json(status: u16, body: &str) -> String {
        format!("HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", status, body.len(), body)
    }

    fn leaked_raw(response: String) -> &'static str { Box::leak(response.into_boxed_str()) }

    fn release_state(url: String, idle: Duration) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.upstream_budget = Duration::from_secs(5);
        state.config.upstream_idle = idle;
        state.config.providers = vec![crate::config::Provider {
            id: "zai".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-chat-upstream".into(), context: None,
            }],
        }];
        Arc::new(state)
    }

    // Core: path shapes connection 1, then call 2 must reach the account.
    fn released_after(behaviors: Vec<Behavior>, idle: Duration, first_expect: &str) {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, worker) = sequence_stub(behaviors, hits.clone());
        let state = release_state(url, idle);
        let first = chat(state.clone());
        assert!(first.starts_with(first_expect), "first call takes the scripted path: {first:?}");
        assert!(!slot(&state, "zai").load(Ordering::SeqCst), "slot released after the attempt ended");
        if first_expect == "HTTP/1.1 429" {
            // Release is independent of account backoff. First prove the
            // permit is free but hard cooling still prevents dispatch, then
            // expire only test state to exercise a second acquired permit.
            let blocked = chat(state.clone());
            assert!(blocked.starts_with("HTTP/1.1 429"), "429 fallback remains blocked: {blocked:?}");
            assert_eq!(hits.load(Ordering::SeqCst), 1, "released permit is not permission to bypass backoff");
            let mut health = state.health.lock().unwrap();
            let cd = health.get_mut("zai").expect("429 installs backoff");
            assert!(cd.hard);
            cd.until = Instant::now() - Duration::from_secs(1);
        }
        let second = chat(state.clone());
        worker.join().unwrap();
        assert!(second.starts_with("HTTP/1.1 200") && second.contains("valid offline output"),
            "follow-up call must reach the account after the slot is released: {second:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "both calls reached the account");
    }

    #[test]
    fn slot_released_after_429_zai() {
        released_after(vec![
            Behavior::Raw(leaked_raw(raw_json(429, r#"{"error":{"message":"slow down"}}"#))),
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], Duration::from_secs(5), "HTTP/1.1 429");
    }

    #[test]
    fn slot_released_after_500_zai() {
        released_after(vec![
            Behavior::Raw(leaked_raw(raw_json(500, r#"{"error":{"message":"blown"}}"#))),
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], Duration::from_secs(5), "HTTP/1.1 503");
    }

    #[test]
    fn slot_released_after_malformed_json_zai() {
        released_after(vec![
            Behavior::Raw(leaked_raw(raw_json(200, "{"))),
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], Duration::from_secs(5), "HTTP/1.1 503");
    }

    #[test]
    fn slot_released_after_transport_close_zai() {
        released_after(vec![
            Behavior::Close,
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], Duration::from_secs(5), "HTTP/1.1 503");
    }

    #[test]
    fn slot_released_after_idle_timeout_zai() {
        released_after(vec![
            Behavior::Stall(Duration::from_millis(1200)),
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], Duration::from_millis(100), "HTTP/1.1 503");
    }

    #[test]
    fn slot_released_after_normal_json_zai() {
        released_after(vec![
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], Duration::from_secs(5), "HTTP/1.1 200");
    }

    // Streaming completion: the slot must be free once the SSE stream ends.
    #[test]
    fn slot_released_after_normal_sse_zai() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, worker) = sequence_stub(vec![
            Behavior::Raw(leaked(format!("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{VALID_DELTA}{TERMINAL}{DONE}", VALID_DELTA.len() + TERMINAL.len() + DONE.len()))),
            Behavior::Raw(leaked_raw(raw_json(200, VALID))),
        ], hits.clone());
        let state = release_state(url, Duration::from_secs(5));
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let first = browser_api(state.clone(), "POST", "/v1/chat/completions", &cookie,
            Some("https://aqua.test"), "same-site", None, STREAM_BODY);
        assert!(first.starts_with("HTTP/1.1 200") && first.contains("data: [DONE]"), "stream completes: {first:?}");
        assert!(!slot(&state, "zai").load(Ordering::SeqCst), "slot released after the stream ended");
        let second = chat(state.clone());
        worker.join().unwrap();
        assert!(second.starts_with("HTTP/1.1 200"), "follow-up reaches the account: {second:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    // Downstream disconnect: the client goes away mid-stream on an explicit
    // close command. The test proves slot release across the close
    // interleaving: the joined handler result carries no error, no
    // upstream-failure evidence is recorded (the healthy-observation outcome
    // of the abandoned stream is timing-dependent and not pinned), and a
    // follow-up call reaches the account on a live second listener
    // connection, returning 200.
    #[test]
    fn slot_released_after_downstream_disconnect_zai() {
        let (url, worker, gate, hits) = disconnect_stub();
        let state = slot_state("zai", "fixture-chat-upstream", url);
        let (framed_tx, framed_rx) = channel();
        let (close_tx, close_rx) = channel();
        let client = disconnecting_client(state.clone(), framed_tx, close_rx);
        framed_rx.recv_timeout(Duration::from_secs(5)).expect("stream delivered a frame");
        assert!(slot(&state, "zai").load(Ordering::SeqCst), "slot held while the stream is open");
        close_tx.send(()).unwrap(); // explicit client close
        gate.send(()).unwrap();     // upstream bytes give the handler a write to fail on
        let handler_result = client.join().unwrap();
        assert!(handler_result.is_ok(), "client-gone path ends without a handler error: {handler_result:?}");
        assert!(!slot(&state, "zai").load(Ordering::SeqCst), "slot released after the client went away");
        // No upstream-failure evidence: whether the abandoned stream records a
        // healthy observation depends on when the kernel reports the close, so
        // the pinned guarantee is failure-side only.
        let health = state.observations.lock().unwrap().aggregate(
            [("zai", "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert_eq!(health["failed_routes"], 0,
            "client disconnect records no upstream failure: {health}");
        assert!(state.health.lock().unwrap().get("zai").is_none(),
            "client disconnect is not upstream-failure evidence: no cooldown");
        // The follow-up call must run before the stub join: connection 2 is
        // what the stub is waiting for.
        let second = chat(state.clone());
        worker.join().unwrap();
        assert!(second.starts_with("HTTP/1.1 200") && second.contains("valid offline output"),
            "follow-up call must reach the account after the slot is released: {second:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "both calls reached the account");
    }

    // Two-connection stub for the disconnect pin: connection 1 is a gated SSE
    // stream, connection 2 serves VALID JSON. hits counts accepted connections.
    fn disconnect_stub() -> (String, JoinHandle<()>, std::sync::mpsc::Sender<()>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (gate_tx, gate_rx) = channel();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        let worker = thread::spawn(move || {
            let mut first = take_one(&listener);
            hits2.fetch_add(1, Ordering::SeqCst);
            first.set_nonblocking(false).unwrap();
            first.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            first.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut first);
            let phase2 = format!("{TERMINAL}{DONE}");
            write!(first, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", VALID_DELTA.len() + phase2.len()).expect("head write");
            first.write_all(VALID_DELTA.as_bytes()).expect("delta write");
            gate_rx.recv_timeout(Duration::from_secs(10)).expect("gate release");
            // The client is gone by now: tolerate the failed write.
            let _ = first.write_all(phase2.as_bytes());
            drop(first);
            let mut second = take_one(&listener);
            hits2.fetch_add(1, Ordering::SeqCst);
            second.set_nonblocking(false).unwrap();
            second.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            second.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request(&mut second);
            let _ = second.write_all(leaked_raw(raw_json(200, VALID)).as_bytes());
        });
        (url, worker, gate_tx, hits)
    }

    fn take_one(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((s, _)) => return s,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "stub received no dispatch");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("stub accept: {e}"),
            }
        }
    }

    // Streaming client that closes on command: reads the head and one frame,
    // reports in, waits for the close command, drops its socket, and returns
    // the joined handler result.
    fn disconnecting_client(state: Arc<Shared>, framed: std::sync::mpsc::Sender<()>, close: std::sync::mpsc::Receiver<()>) -> JoinHandle<std::io::Result<()>> {
        thread::spawn(move || {
            let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || handle(listener.accept().unwrap().0, state));
            let mut c = TcpStream::connect(address).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(c, "POST /v1/chat/completions HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\nsec-fetch-site: same-site\r\norigin: https://aqua.test\r\ncontent-length: {}\r\n\r\n{STREAM_BODY}", STREAM_BODY.len()).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = c.read(&mut tmp).unwrap();
                assert!(n > 0, "server closed before the first frame");
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(2).any(|w| w == b"\n\n") && buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            framed.send(()).unwrap();
            close.recv_timeout(Duration::from_secs(10)).expect("close command");
            let _ = c.shutdown(std::net::Shutdown::Both);
            drop(c);
            server.join().unwrap()
        })
    }

    // While one attempt holds the account mid-body, a second call must skip
    // the busy account: it never reaches the stub, fails closed with no
    // cooldown and no 429 evidence.
    #[test]
    fn busy_account_is_skipped_without_cooldown_zai() {
        let (url, worker, accepted, gate, extra, stop) = counting_gated_stub(VALID);
        let state = slot_state("zai", "fixture-chat-upstream", url);
        let first = { let s = state.clone(); thread::spawn(move || chat(s)) };
        accepted.recv_timeout(Duration::from_secs(5)).expect("first call reached the account");
        // Pinned interleaving: the second call runs while the first attempt is
        // parked after the upstream sent its response headers but before the
        // body completes, where the slot is unconditionally held. Whether the
        // attempt thread has consumed those headers is not observable at this
        // checkpoint; a slot released at header commit is caught by the
        // downstream-observable SSE variant below.
        assert!(slot(&state, "zai").load(Ordering::SeqCst), "slot held once the account is engaged");
        let second = chat(state.clone());
        assert!(second.starts_with("HTTP/1.1 503"), "busy account skipped, no other route: {second:?}");
        assert!(state.health.lock().unwrap().get("zai").is_none(), "busy-skip adds no cooldown");
        let health = state.observations.lock().unwrap().aggregate(
            [("zai", "fixture-chat", "fixture-chat-upstream")].into_iter());
        assert!(health["healthy_routes"] == 0 && health["failed_routes"] == 0, "busy-skip records no attempt outcome: {health}");
        gate.send(()).unwrap();
        assert!(first.join().unwrap().starts_with("HTTP/1.1 200"), "first call completes");
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(!slot(&state, "zai").load(Ordering::SeqCst), "slot released after completion");
        assert_eq!(extra.load(Ordering::SeqCst), 0, "no second connection ever reached the account");
    }
}

// Cooldown / 429 hard-limit lock (providers-lane item 5): pin the current
// behavior so a regression trips a test. A Retry-After on a 429 is a hard
// limit: the account is skipped across ALL its models with no extra
// admission until it lifts. Hard deadlines are never shortened; soft
// evidence never touches a hard limit. Selected policy: missing/invalid
// Retry-After on429 blocks60s; usable503 Retry-After blocks its bounded
// delay.503 without usable header remains soft15s. Defaults are configurable. Client disconnect is never upstream-failure
// evidence (pinned in permit_lifetime_tests). Backoff policy changed under the parent decision.
#[cfg(test)]
mod cooldown_lock_tests {
    use super::*;
    use super::reviewer_regressions::{browser_api, keys_shared};
    use std::io::ErrorKind;

    const ERR: &str = r#"{"error":{"message":"fixture limited","type":"rate_limit"}}"#;

    // Literal pins with drift guards: these durations are the locked policy.
    #[test]
    fn cooldown_constants_match_the_locked_policy() {
        assert_eq!(COOLDOWN_SOFT_SECS, 15, "generic failure cooldown is 15s");
        assert_eq!(COOLDOWN_429_DEFAULT_SECS, 60, "429 without usable Retry-After is 60s");
        assert_eq!(RETRY_AFTER_MAX_SECS, 3600, "Retry-After is clamped at 1h");
        let cfg = crate::config::Backoff::default();
        assert_eq!(cfg.missing_429_secs(), COOLDOWN_429_DEFAULT_SECS);
        assert_eq!(cfg.soft_secs(), COOLDOWN_SOFT_SECS);
        assert_eq!(cfg.retry_after_secs(u64::MAX), RETRY_AFTER_MAX_SECS);
    }

    // IMF-fixdate parsing: exact epoch for the classic RFC example, junk
    // rejected (weekday must match the date, fields exact-width).
    #[test]
    fn imf_fixdate_parsing_is_exact() {
        assert_eq!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784111777));
        assert_eq!(parse_imf_fixdate("Mon, 06 Nov 1994 08:49:37 GMT"), None, "wrong weekday rejected");
        assert_eq!(parse_imf_fixdate("06 Nov 1994 08:49:37 GMT"), None, "missing weekday rejected");
        assert_eq!(parse_imf_fixdate("garbage"), None);
    }

    fn remaining_secs(state: &Arc<Shared>, provider: &str) -> u64 {
        state.health.lock().unwrap().get(provider).unwrap().until
            .saturating_duration_since(Instant::now()).as_secs()
    }

    fn is_hard(state: &Arc<Shared>, provider: &str) -> bool {
        state.health.lock().unwrap().get(provider).unwrap().hard
    }

    // Sequential state-transition coverage of the monotonic rules (not a
    // concurrency proof): an active cooldown is never shortened, soft
    // evidence never softens/extends a hard limit, hard evidence only ever
    // extends.
    #[test]
    fn cooldowns_are_monotonic_and_never_shortened() {
        let state = keys_shared();
        set_cooldown(&state, "zai", 60, false);
        assert!(!is_hard(&state, "zai"));
        assert!((58..=60).contains(&remaining_secs(&state, "zai")), "fresh soft insert: {}", remaining_secs(&state, "zai"));
        set_cooldown(&state, "zai", 10, false);
        assert!((58..=60).contains(&remaining_secs(&state, "zai")), "earlier soft evidence must not shorten");
        set_cooldown(&state, "zai", 90, false);
        assert!((88..=90).contains(&remaining_secs(&state, "zai")), "later soft evidence extends");
        set_cooldown(&state, "zai", 30, true);
        assert!(is_hard(&state, "zai"), "hard evidence upgrades the flag");
        assert!((88..=90).contains(&remaining_secs(&state, "zai")), "hard upgrade keeps the longer deadline");
        set_cooldown(&state, "zai", 500, false);
        assert!(is_hard(&state, "zai"), "soft evidence never softens a hard limit");
        assert!((88..=90).contains(&remaining_secs(&state, "zai")), "soft evidence never extends a hard limit");
        set_cooldown(&state, "zai", 300, true);
        assert!((298..=300).contains(&remaining_secs(&state, "zai")), "later hard evidence extends");
        set_cooldown(&state, "zai", 20, true);
        assert!((298..=300).contains(&remaining_secs(&state, "zai")), "earlier hard evidence must not shorten");
    }

    #[test]
    fn clear_cooldown_removes_soft_but_keeps_hard() {
        let state = keys_shared();
        set_cooldown(&state, "zai", 60, false);
        set_cooldown(&state, "inferbase", 60, true);
        clear_cooldown(&state, "zai");
        clear_cooldown(&state, "inferbase");
        let health = state.health.lock().unwrap();
        assert!(health.get("zai").is_none(), "soft cooldown clears on success");
        assert!(health.get("inferbase").is_some_and(|cd| cd.hard), "a hard limit survives success");
    }

    // Serves `count` scripted status responses (optional Retry-After header,
    // JSON error body), counting accepted connections.
    fn status_stub(status: u16, retry_after: Option<&'static str>, count: usize, hits: Arc<AtomicUsize>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut served = 0;
            while served < count {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        socket.set_nonblocking(false).unwrap();
                        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        let _ = read_request(&mut socket);
                        let ra = retry_after.map(|v| format!("retry-after: {v}\r\n")).unwrap_or_default();
                        let _ = write!(socket, "HTTP/1.1 {status} Limited\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{ra}connection: close\r\n\r\n{ERR}", ERR.len());
                        served += 1;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "status stub outlived its deadline");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("stub accept: {e}"),
                }
            }
        });
        (url, worker)
    }


    const VALID_OK: &str = r#"{"id":"offline-chat","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"valid offline output"},"finish_reason":"stop"}]}"#;

    // Sets the stub stop flag even when the test panics mid-assertion, so
    // the responder never spins to its deadline after a failure.
    struct StopGuard(Arc<AtomicBool>);
    impl Drop for StopGuard {
        fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
    }

    // Live responder: connection 1 gets 429 + Retry-After 120, every later
    // connection gets a 200 VALID body. Accepts until the stop flag, then
    // drains the backlog so a queued dispatch is still counted; the test
    // joins before reading the final count.
    fn live_limited_stub(hits: Arc<AtomicUsize>, stop: Arc<AtomicBool>) -> (String, JoinHandle<()>) {
        live_status_stub(429, "120", hits, stop)
    }

    // Parameterized status fixture for baseline policy tests. Later calls
    // always get a healthy response while the listener remains live.
    fn live_status_stub(status: u16, retry_after: &'static str, hits: Arc<AtomicUsize>, stop: Arc<AtomicBool>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut served = 0usize;
            loop {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        socket.set_nonblocking(false).unwrap();
                        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        let _ = read_request(&mut socket);
                        if served == 0 {
                            let _ = write!(socket, "HTTP/1.1 {status} Limited\r\ncontent-type: application/json\r\ncontent-length: {}\r\nretry-after: {retry_after}\r\nconnection: close\r\n\r\n{ERR}", ERR.len());
                        } else {
                            let _ = write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{VALID_OK}", VALID_OK.len());
                        }
                        served += 1;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        if stop.load(Ordering::SeqCst) {
                            let drain_until = Instant::now() + Duration::from_millis(100);
                            while Instant::now() < drain_until {
                                match listener.accept() {
                                    Ok((mut socket, _)) => {
                                        hits.fetch_add(1, Ordering::SeqCst);
                                        socket.set_nonblocking(false).unwrap();
                                        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                                        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                                        let _ = read_request(&mut socket);
                                        let _ = write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{VALID_OK}", VALID_OK.len());
                                    }
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                                    Err(_) => break,
                                }
                            }
                            break;
                        }
                        assert!(Instant::now() < deadline, "live limited stub outlived its deadline");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("stub accept: {e}"),
                }
            }
        });
        (url, worker)
    }

    fn lock_state(url: String, models: &[&str]) -> Arc<Shared> {
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers = vec![crate::config::Provider {
            id: "zai".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: url, models: models.iter().map(|m| crate::config::ModelEntry {
                public: (*m).to_string(), upstream: format!("{m}-upstream"), context: None,
            }).collect(),
        }];
        Arc::new(state)
    }

    fn call(state: Arc<Shared>, model: &str) -> String {
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        browser_api(state, "POST", "/v1/chat/completions", &cookie,
            Some("https://aqua.test"), "same-site", None,
            &format!(r#"{{"model":"{model}","messages":[{{"role":"user","content":"offline fixture"}}],"stream":false}}"#))
    }

    // One limited call with the given Retry-After, then inspect the installed
    // cooldown. The gateway forwards the upstream 429 status to the client.
    fn limited_once(retry_after: Option<&'static str>, status: u16) -> (Arc<Shared>, String) {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, stub) = status_stub(status, retry_after, 1, hits);
        let state = lock_state(url, &["fixture-chat"]);
        let response = call(state.clone(), "fixture-chat");
        stub.join().unwrap();
        let expected = format!("HTTP/1.1 {status}");
        assert!(response.starts_with(&expected), "limited call returns the upstream status: {response:?}");
        (state, response)
    }

    // Retry-After: 120 installs a hard limit: the account is skipped across
    // every one of its models, with no extra admission while it is cooled.
    // The responder stays LIVE across the cooled calls (bounded accept
    // window), so a regression that dispatched would be counted and served;
    // a healthy uncooled control call proves the listener still answers.
    #[test]
    fn retry_after_120_hard_skips_all_models_with_no_extra_admission() {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (url, stub) = live_limited_stub(hits.clone(), stop.clone());
        let _stop_guard = StopGuard(stop.clone());
        let state = lock_state(url, &["fixture-chat", "fixture-alt"]);
        let first = call(state.clone(), "fixture-chat");
        assert!(first.starts_with("HTTP/1.1 429"), "first call forwards the upstream 429: {first:?}");
        assert!(is_hard(&state, "zai"), "Retry-After installs a hard limit");
        assert!((115..=120).contains(&remaining_secs(&state, "zai")), "hard limit honors 120s: {}", remaining_secs(&state, "zai"));
        for model in ["fixture-chat", "fixture-alt"] {
            let again = call(state.clone(), model);
            assert!(again.starts_with("HTTP/1.1 429"),
                "cooled account is skipped on {model} with a synthesized 429 before any admission: {again:?}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1,
            "no extra admission while the hard limit stands (responder live and counting)");
        // Healthy control: lift the limit, the live listener must answer 200.
        state.health.lock().unwrap().remove("zai");
        let ok = call(state.clone(), "fixture-chat");
        stop.store(true, Ordering::SeqCst);
        stub.join().unwrap();
        assert!(ok.starts_with("HTTP/1.1 200") && ok.contains("valid offline output"),
            "uncooled control call reaches the live responder: {ok:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "exactly the first call and the control reached the account");
    }

    // Parent-selected reversible replacement policy. The responder stays live across blocked
    // requests, then proves post-expiry dispatch with a valid completion.
    fn approved_block(status: u16, header: &'static str, seconds: u64) {
        approved_configured_block(status, header, seconds, None);
    }
    fn approved_configured_block(status: u16, header: &'static str, seconds: u64,
        configured: Option<crate::config::Backoff>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (url, worker) = live_status_stub(status, header, hits.clone(), stop.clone());
        let _stop_guard = StopGuard(stop.clone());
        let mut owned = Arc::try_unwrap(lock_state(url, &["fixture-chat", "fixture-alt"])).ok().unwrap();
        if let Some(configured) = configured { owned.config.backoff = configured; }
        let state = Arc::new(owned);
        let first = call(state.clone(), "fixture-chat");
        let installed = state.health.lock().unwrap().get("zai").copied();
        let checkpoint = Instant::now();
        let ledger_before = serde_json::to_value(&state.spend.lock().unwrap().ledger).unwrap();
        let quota_before = state.quotas.lock().unwrap().values().map(|q| (q.reserved, q.in_flight)).collect::<Vec<_>>();
        let blocked = call(state.clone(), "fixture-alt");
        let blocked_hits = hits.load(Ordering::SeqCst);
        let ledger_after = serde_json::to_value(&state.spend.lock().unwrap().ledger).unwrap();
        let quota_after = state.quotas.lock().unwrap().values().map(|q| (q.reserved, q.in_flight)).collect::<Vec<_>>();
        // Expire only test state. No real-time 60s/120s wait.
        if let Some(cd) = state.health.lock().unwrap().get_mut("zai") {
            cd.until = Instant::now() - Duration::from_secs(1);
        }
        let resumed = call(state.clone(), "fixture-alt");
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        let expected = if status == 429 { "HTTP/1.1 429" } else { "HTTP/1.1 503" };
        assert!(first.starts_with(expected), "first failure: {first:?}");
        let cd = installed.expect("failure installs cooldown");
        assert!(cd.hard, "approved status/header policy must block the account: {status}/{header:?}");
        let remaining = cd.until.saturating_duration_since(checkpoint);
        assert!(remaining > Duration::from_secs(seconds.saturating_sub(5)) && remaining <= Duration::from_secs(seconds), "expected {seconds}s, got {remaining:?}");
        assert!(blocked.starts_with("HTTP/1.1 429"), "hard-cooled account must not dispatch: {blocked:?}");
        assert_eq!(blocked_hits, 1, "no dispatch across other account models while blocked");
        assert_eq!(ledger_before, ledger_after, "blocked request must not reserve spend");
        assert_eq!(quota_before, quota_after, "blocked request must not reserve quota");
        assert!(resumed.starts_with("HTTP/1.1 200") && resumed.contains("valid offline output"), "expired deadline must allow dispatch: {resumed:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "only failure and post-expiry control reach provider");
    }

    #[test]
    fn approved_backoff_configured_429_default_is_used_by_dispatch() {
        approved_configured_block(429, "soon", 17, Some(crate::config::Backoff {
            missing_429_secs:17, ..Default::default()
        }));
    }
    #[test]
    fn approved_backoff_configured_503_ceiling_is_used_by_dispatch() {
        approved_configured_block(503, "120", 42, Some(crate::config::Backoff {
            retry_after_max_secs:42, ..Default::default()
        }));
    }
    #[test]
    fn approved_backoff_configured_429_ceiling_is_used_by_dispatch() {
        approved_configured_block(429, "120", 42, Some(crate::config::Backoff {
            retry_after_max_secs:42, ..Default::default()
        }));
    }
    #[test]
    fn approved_backoff_configured_soft_503_stays_soft() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, worker) = status_stub(503, Some("soon"), 1, hits);
        let mut owned = Arc::try_unwrap(lock_state(url, &["fixture-chat"])).ok().unwrap();
        owned.config.backoff.soft_secs = 9;
        let state = Arc::new(owned);
        let first = call(state.clone(), "fixture-chat");
        worker.join().unwrap();
        assert!(first.starts_with("HTTP/1.1 503"));
        assert!(!is_hard(&state, "zai"));
        assert!((5..=9).contains(&remaining_secs(&state, "zai")));
    }

    #[test] fn approved_backoff_429_empty_blocks_60s() { approved_block(429, "", 60); }
    #[test] fn approved_backoff_429_invalid_blocks_60s() { approved_block(429, "soon", 60); }
    #[test] fn approved_backoff_429_overflow_blocks_60s() { approved_block(429, "99999999999999999999999999", 60); }
    #[test] fn approved_backoff_503_numeric_blocks_delay() { approved_block(503, "120", 120); }
    #[test] fn approved_backoff_503_future_date_blocks_ceiling() { approved_block(503, "Wed, 01 Jan 2042 00:00:00 GMT", 3600); }
    #[test] fn approved_backoff_503_long_delay_blocks_ceiling() { approved_block(503, "7200", 3600); }

    #[test]
    fn plain_429_without_retry_after_blocks_60s() {
        let (state, _) = limited_once(None, 429);
        assert!(is_hard(&state, "zai"), "429 fallback blocks even without usable Retry-After");
        assert!((55..=60).contains(&remaining_secs(&state, "zai")), "hard 60s fallback: {}", remaining_secs(&state, "zai"));
    }

    #[test]
    fn invalid_retry_after_blocks_60s() {
        let (state, _) = limited_once(Some("soon"), 429);
        assert!(is_hard(&state, "zai"), "429 fallback blocks even without usable Retry-After");
        assert!((55..=60).contains(&remaining_secs(&state, "zai")), "hard 60s fallback: {}", remaining_secs(&state, "zai"));
    }

    #[test]
    fn overflowing_retry_after_blocks_60s() {
        let (state, _) = limited_once(Some("99999999999999999999999999"), 429);
        assert!(is_hard(&state, "zai"), "429 fallback blocks even without usable Retry-After");
        assert!((55..=60).contains(&remaining_secs(&state, "zai")), "hard 60s fallback: {}", remaining_secs(&state, "zai"));
    }

    #[test]
    fn zero_retry_after_is_a_hard_minimum() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, stub) = status_stub(429, Some("0"), 1, hits);
        let state = lock_state(url, &["fixture-chat"]);
        let before = Instant::now();
        let response = call(state.clone(), "fixture-chat");
        let after = Instant::now();
        stub.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 429"), "limited call forwards the 429: {response:?}");
        let until = state.health.lock().unwrap().get("zai").unwrap().until;
        assert!(is_hard(&state, "zai"), "Retry-After 0 is hard-limit evidence");
        assert!(until >= before + Duration::from_secs(1) && until <= after + Duration::from_secs(1),
            "exactly the 1s floor, pinned against the pre-call instant");
    }

    // Exercise the parser itself, before any configured use-site ceiling.
    // Literal3600 is independent of RETRY_AFTER_MAX_SECS, so raising that
    // constant cannot be hidden by Backoff's second cap.
    fn direct_parser_ceiling(header: &'static str) {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, worker) = status_stub(429, Some(header), 1, hits.clone());
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .max_redirects(0).build().into();
        let response = agent.get(&url).call().expect("loopback response");
        let parsed = parse_retry_after(&response);
        worker.join().unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(parsed, Some(3600), "parser absolute ceiling, independent of configured dispatch cap");
    }
    #[test]
    fn direct_parse_retry_after_numeric_absolute_ceiling() {
        direct_parser_ceiling("7200");
    }
    #[test]
    fn direct_parse_retry_after_future_date_absolute_ceiling() {
        direct_parser_ceiling("Wed, 01 Jan 2042 00:00:00 GMT");
    }

    #[test]
    fn large_retry_after_clamps_at_one_hour() {
        let (state, _) = limited_once(Some("7200"), 429);
        assert!(is_hard(&state, "zai"));
        assert!((3595..=3600).contains(&remaining_secs(&state, "zai")), "clamped at 1h: {}", remaining_secs(&state, "zai"));
    }

    #[test]
    fn past_date_retry_after_blocks_60s() {
        let (state, _) = limited_once(Some("Sun, 06 Nov 1994 08:49:37 GMT"), 429);
        assert!(is_hard(&state, "zai"), "429 fallback blocks even without usable Retry-After");
        assert!((55..=60).contains(&remaining_secs(&state, "zai")), "hard 60s fallback: {}", remaining_secs(&state, "zai"));
    }

    #[test]
    fn future_date_retry_after_is_hard_and_clamped() {
        let (state, _) = limited_once(Some("Wed, 01 Jan 2042 00:00:00 GMT"), 429);
        assert!(is_hard(&state, "zai"), "a future date is hard-limit evidence");
        assert!((3595..=3600).contains(&remaining_secs(&state, "zai")), "far future clamps at 1h: {}", remaining_secs(&state, "zai"));
    }

    #[test]
    fn plain_503_is_soft_15s() {
        let (state, _) = limited_once(None, 503);
        assert!(!is_hard(&state, "zai"), "503 is soft evidence");
        assert!((10..=15).contains(&remaining_secs(&state, "zai")), "soft 15s default: {}", remaining_secs(&state, "zai"));
    }
    // Dispatcher baseline only: soft cooldowns reorder, not block. Inspect
    // the installed policy before the healthy response clears soft evidence.
    // Keep the responder live for call two and join before asserting counts.
    fn baseline_soft_dispatch(status: u16, header: &'static str, seconds: u64) {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (url, worker) = live_status_stub(status, header, hits.clone(), stop.clone());
        let _stop_guard = StopGuard(stop.clone());
        let state = lock_state(url, &["fixture-chat"]);
        let first = call(state.clone(), "fixture-chat");
        let observed = state.health.lock().unwrap().get("zai").copied();
        let checkpoint = Instant::now();
        let second = call(state.clone(), "fixture-chat");
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        let expected = if status == 429 { "HTTP/1.1 429" } else { "HTTP/1.1 503" };
        assert!(first.starts_with(expected), "initial failure: {first:?}");
        let cd = observed.expect("failure installs cooldown");
        assert!(!cd.hard, "status {status}, header {header:?} must remain soft");
        let remaining = cd.until.saturating_duration_since(checkpoint);
        assert!(remaining > Duration::from_secs(seconds - 5) && remaining <= Duration::from_secs(seconds),
            "status {status}, header {header:?}: expected soft {seconds}s, got {remaining:?}");
        assert!(second.starts_with("HTTP/1.1 200") && second.contains("valid offline output"),
            "healthy control must dispatch despite soft cooldown: {second:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "both calls reached the live account");
        assert!(state.health.lock().unwrap().get("zai").is_none(), "healthy completion clears soft cooldown");
    }

    #[test]
    fn policy_503_numeric_retry_after_blocks() {
        approved_block(503, "120", 120);
    }

    #[test]
    fn policy_503_date_retry_after_blocks() {
        approved_block(503, "Wed, 01 Jan 2042 00:00:00 GMT", 3600);
    }

    #[test]
    fn baseline_503_invalid_retry_after_stays_soft_and_dispatches() {
        baseline_soft_dispatch(503, "soon", 15);
    }

    #[test]
    fn policy_429_plus_signed_header_blocks() {
        approved_block(429, "+120", 60);
    }

    #[test]
    fn policy_429_negative_header_blocks() {
        approved_block(429, "-120", 60);
    }

    #[test]
    fn baseline_expired_hard_limit_dispatches_to_live_account() {
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (url, worker) = live_status_stub(429, "120", hits.clone(), stop.clone());
        let _stop_guard = StopGuard(stop.clone());
        let state = lock_state(url, &["fixture-chat", "fixture-alt"]);
        let first = call(state.clone(), "fixture-chat");
        let installed = state.health.lock().unwrap().get("zai").copied();
        let blocked = call(state.clone(), "fixture-alt");
        let before_expiry_hits = hits.load(Ordering::SeqCst);
        // Explicit state boundary, no 120s sleep: keep hard=true but expire it.
        state.health.lock().unwrap().get_mut("zai").unwrap().until =
            Instant::now() - Duration::from_secs(1);
        let resumed = call(state.clone(), "fixture-alt");
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(first.starts_with("HTTP/1.1 429"));
        assert!(installed.is_some_and(|cd| cd.hard), "initial response installs a hard limit");
        assert!(blocked.starts_with("HTTP/1.1 429"), "live hard limit blocks: {blocked:?}");
        assert_eq!(before_expiry_hits, 1, "no admission before expiry, responder still live");
        assert!(resumed.starts_with("HTTP/1.1 200") && resumed.contains("valid offline output"),
            "expired hard limit allows healthy dispatch on another account model: {resumed:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "initial and post-expiry calls only");
    }

}

// Request-framing regression matrix. Current parser policy only, not a
// general HTTP conformance claim and not an auth/throttle policy change.
#[cfg(test)]
mod framing_matrix_tests {
    use super::*;
    use super::reviewer_regressions::keys_shared;
    use std::io::ErrorKind;
    use std::net::Shutdown;

    const BODY: &str = r#"{"model":"fixture-chat","messages":[{"role":"user","content":"offline fixture"}]}"#;
    const VALID: &str = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"framing healthy control"},"finish_reason":"stop"}]}"#;

    // Own the responder until all malformed and healthy calls finish.
    // Drop also stops/joins it on assertion panic; all sockets are bounded.
    struct Responder {
        url: String,
        hits: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }
    impl Responder {
        fn start() -> Self { Self::start_status(None) }
        fn start_status(first_status: Option<u16>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let h = hits.clone();
            let done = stop.clone();
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    // After every gateway call has joined, no further dispatch
                    // can be initiated. Drain already queued connections first.
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            let hit = h.fetch_add(1, Ordering::SeqCst);
                            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                            if read_request_within(&mut socket, Duration::from_secs(2)).is_ok() {
                                if let Some(status) = first_status.filter(|_| hit == 0) {
                                    let private = r#"{"error":{"message":"private-upstream-body-sentinel"}}"#;
                                    let _ = write!(socket, "HTTP/1.1 {status} Failure\r\ncontent-type: application/json\r\ncontent-length: {}\r\nx-private-upstream: private-header-sentinel\r\nwww-authenticate: Bearer private-challenge\r\nretry-after: 120\r\nconnection: close\r\n\r\n{private}", private.len());
                                } else {
                                    let _ = write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{VALID}", VALID.len());
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            if done.load(Ordering::SeqCst) { break; }
                            assert!(Instant::now() < deadline, "responder exceeded bounded window");
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("accept failed: {e}"),
                    }
                }
            });
            Self { url, hits, stop, worker: Some(worker) }
        }
        fn finish(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.worker.take().unwrap().join().unwrap();
        }
    }
    impl Drop for Responder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() { let _ = worker.join(); }
        }
    }

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for socket in [&client, &server] {
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        }
        (client, server)
    }

    fn request(cookie: &str, framing: &str) -> String {
        format!("POST /v1/chat/completions HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\norigin: https://aqua.test\r\nsec-fetch-site: same-site\r\ncontent-type: application/json\r\n{framing}\r\n{BODY} ")
    }

    fn gateway_call(state: Arc<Shared>, bytes: String) -> String {
        let (mut client, server) = pair();
        let worker = thread::spawn(move || handle(server, state));
        client.write_all(bytes.as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        let read_result = client.read_to_string(&mut response);
        let handler_result = worker.join().unwrap();
        assert!(handler_result.is_ok(), "handler error: {handler_result:?}");
        // Rejection may close with unread request bytes. A reset is allowed
        // only after a response was captured; status/body pins remain below.
        assert!(read_result.is_ok() || (read_result.is_err_and(|e| e.kind() == ErrorKind::ConnectionReset) && !response.is_empty()));
        response
    }

    fn rejects(framing: String, expected: &str) {
        // Parser-level pin distinguishes rejection from later JSON/auth errors.
        let (mut client, mut server) = pair();
        client.write_all(request("unused", &framing).as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let parse_error = read_request_within(&mut server, Duration::from_secs(2)).err();

        let mut upstream = Responder::start();
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal,
            api_key: "offline-synthetic".into(), base_url: upstream.url.clone(),
            models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let bad = gateway_call(state.clone(), request(&cookie, &framing));
        let bad_hits = upstream.hits.load(Ordering::SeqCst);
        // A healthy request on the SAME state and still-live listener proves
        // the route/auth fixture can dispatch, not just reject everything.
        let good = gateway_call(state, request(&cookie, &format!("CoNtEnT-LeNgTh: {}\r\n", BODY.len() + 1)));
        upstream.finish();
        assert_eq!(parse_error, Some(expected), "parser rejection category");
        assert!(bad.starts_with("HTTP/1.1 400"), "rejection: {bad:?}");
        assert!(bad.contains("invalid_request"), "standard error envelope: {bad:?}");
        assert_eq!(bad_hits, 0, "malformed framing must not dispatch");
        assert!(good.starts_with("HTTP/1.1 200") && good.contains("framing healthy control"), "healthy control: {good:?}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1, "only the healthy control reached upstream");
    }

    #[test]
    fn framing_equal_duplicate_lengths_rejected() {
        rejects(format!("content-length: {}\r\nCoNtEnT-LeNgTh: {}\r\n", BODY.len(), BODY.len()), "bad request");
    }
    #[test]
    fn framing_conflicting_lengths_rejected_both_orders() {
        for (a, b) in [(BODY.len(), BODY.len()+1), (BODY.len()+1, BODY.len())] {
            rejects(format!("Content-Length: {a}\r\ncOnTeNt-LeNgTh: {b}\r\n"), "bad request");
        }
    }
    #[test]
    fn framing_transfer_encoding_with_length_rejected_both_orders() {
        for head in [format!("TrAnSfEr-EnCoDiNg: chunked\r\ncontent-length: {}\r\n", BODY.len()),
                     format!("content-length: {}\r\nTrAnSfEr-EnCoDiNg: chunked\r\n", BODY.len())] {
            rejects(head, "chunked");
        }
    }
    #[test]
    fn framing_nonchunked_transfer_encoding_still_rejected() {
        rejects(format!("transfer-encoding: identity\r\ncontent-length: {}\r\n", BODY.len()), "chunked");
    }
    #[test]
    fn framing_malformed_and_overflow_lengths_rejected() {
        for value in ["", "-1", "1x", "2, 2", "99999999999999999999999999999999"] {
            rejects(format!("content-length: {value}\r\n"), "bad length");
        }
    }
    // CORS baseline tests share the bounded, owned live responder above.
    // These pin response headers, not browser enforcement or CSRF policy.
    fn cors_headers_of(response: &str) -> HashMap<String, Vec<String>> {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        for line in response.split("\r\n\r\n").next().unwrap().split("\r\n").skip(1) {
            let (key, value) = line.split_once(':').expect("response header");
            headers.entry(key.to_ascii_lowercase()).or_default().push(value.trim().to_string());
        }
        headers
    }

    fn cors_single_header(headers: &HashMap<String, Vec<String>>, key: &str, value: &str) {
        assert_eq!(headers.get(key).map(Vec::as_slice), Some([value.to_string()].as_slice()),
            "exactly one {key} field with the expected value");
    }

    #[test]
    fn cors_baseline_collector_preserves_conflicting_duplicates() {
        let parsed = cors_headers_of("HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\naccess-control-allow-origin: https://aqua.test\r\nVary: accept\r\nvary: origin\r\nAccess-Control-Allow-Credentials: false\r\naccess-control-allow-credentials: true\r\n\r\n");
        for key in ["access-control-allow-origin", "access-control-allow-credentials", "vary"] {
            assert_eq!(parsed[key].len(), 2, "collector must preserve both {key} lines");
        }
        assert_eq!(parsed["access-control-allow-origin"], vec!["*", "https://aqua.test"]);
    }

    fn cors_baseline_case(configured: &str, origin: Option<&str>, allowed: bool) {
        let mut upstream = Responder::start();
        let mut shared = Arc::try_unwrap(keys_shared()).ok().unwrap();
        shared.config.allowed_origin = configured.into();
        shared.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal,
            api_key: "offline-synthetic".into(), base_url: upstream.url.clone(),
            models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let shared = Arc::new(shared);
        let cookie = shared.auth.create_session("luke", Role::Owner).unwrap();
        let origin_line = origin.map(|o| format!("origin: {o}\r\n")).unwrap_or_default();
        // No session on preflight: no authentication or upstream work needed.
        let options = gateway_call(shared.clone(), format!(
            "OPTIONS /v1/chat/completions HTTP/1.1\r\nhost: api.aqua.test\r\n{origin_line}access-control-request-method: POST\r\naccess-control-request-headers: authorization, content-type\r\ncontent-length: 0\r\n\r\n"));
        let actual = gateway_call(shared.clone(), format!(
            "GET /v1/models HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\n{origin_line}content-length: 0\r\n\r\n"));
        let pre_control_hits = upstream.hits.load(Ordering::SeqCst);
        // Same-host session origin is accepted independently of configured
        // CORS, so this control also works with CORS disabled.
        let healthy_request = request(&cookie, &format!("content-length: {}\r\n", BODY.len()+1))
            .replace("origin: https://aqua.test", "origin: https://api.aqua.test");
        let healthy = gateway_call(shared, healthy_request);
        upstream.finish();
        assert!(options.starts_with("HTTP/1.1 204"), "preflight: {options:?}");
        assert!(options.split_once("\r\n\r\n").unwrap().1.is_empty(), "204 has no body");
        assert!(actual.starts_with("HTTP/1.1 200"), "actual GET: {actual:?}");
        assert_eq!(pre_control_hits, 0, "OPTIONS and catalog GET never reached upstream");
        assert!(healthy.starts_with("HTTP/1.1 200") && healthy.contains("framing healthy control"), "healthy control: {healthy:?}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1, "only healthy control dispatched");
        let preflight_headers = cors_headers_of(&options);
        let actual_headers = cors_headers_of(&actual);
        for headers in [&preflight_headers, &actual_headers] {
            if allowed {
                cors_single_header(headers, "access-control-allow-origin", configured);
                cors_single_header(headers, "access-control-allow-credentials", "true");
                cors_single_header(headers, "vary", "origin");
            } else {
                for key in ["access-control-allow-origin", "access-control-allow-credentials", "vary"] {
                    assert!(!headers.contains_key(key), "disallowed origin must not get {key}: {headers:?}");
                }
            }
        }
        if allowed {
            cors_single_header(&preflight_headers, "access-control-allow-methods", "GET, POST, OPTIONS");
            cors_single_header(&preflight_headers, "access-control-allow-headers", "authorization, content-type");
        } else {
            assert!(!preflight_headers.contains_key("access-control-allow-methods"));
            assert!(!preflight_headers.contains_key("access-control-allow-headers"));
        }
        assert!(!actual_headers.contains_key("access-control-allow-methods"), "actual response is not preflight");
        assert!(!actual_headers.contains_key("access-control-allow-headers"));
    }

    #[test]
    fn cors_baseline_exact_origin() { cors_baseline_case("https://aqua.test", Some("https://aqua.test"), true); }
    #[test]
    fn cors_baseline_missing_origin() { cors_baseline_case("https://aqua.test", None, false); }
    #[test]
    fn cors_baseline_null_origin() { cors_baseline_case("https://aqua.test", Some("null"), false); }
    #[test]
    fn cors_baseline_scheme_mismatch() { cors_baseline_case("https://aqua.test", Some("http://aqua.test"), false); }
    #[test]
    fn cors_baseline_port_mismatch() { cors_baseline_case("https://aqua.test", Some("https://aqua.test:444"), false); }
    #[test]
    fn cors_baseline_suffix_lookalike() { cors_baseline_case("https://aqua.test", Some("https://aqua.test.evil.invalid"), false); }
    #[test]
    fn cors_baseline_unrelated_origin() { cors_baseline_case("https://aqua.test", Some("https://other.invalid"), false); }
    #[test]
    fn cors_baseline_disabled_config() { cors_baseline_case("", Some("https://aqua.test"), false); }
    #[test]
    fn cors_baseline_disabled_empty_origin() { cors_baseline_case("", Some(""), false); }

    // Handler-level body-size baseline. JSON is parsed and rewritten before
    // upstream dispatch, so exact byte preservation is a parser-level pin,
    // not an assertion about the rewritten upstream representation.
    fn body_size_baseline(size: usize, accepted: bool) {
        const CAP: usize = 1_000_000;
        assert_eq!(MAX_BODY, CAP, "literal policy drift guard");
        let mut body = BODY.to_string();
        body.extend(std::iter::repeat(' ').take(size - BODY.len()));
        assert_eq!(body.len(), size);
        // Healthy parser boundaries must consume the whole declared body.
        // Large writes run concurrently with the reader, never before it.
        if accepted {
            let (mut client, mut server) = pair();
            let input = format!("POST /x HTTP/1.1\r\ncontent-length: {size}\r\n\r\n{body}");
            let writer = thread::spawn(move || {
                let result = client.write_all(input.as_bytes());
                let _ = client.shutdown(Shutdown::Write);
                result
            });
            let parsed = read_request_within(&mut server, Duration::from_secs(3));
            drop(server);
            let written = writer.join().unwrap();
            assert!(written.is_ok(), "bounded writer: {written:?}");
            let parsed = parsed.expect("body at or under cap parses");
            assert_eq!(parsed.body, body.as_bytes(), "declared request bytes consumed without truncation");
        }
        let mut upstream = Responder::start();
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: upstream.url.clone(), models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        // For oversized input send only its declaration. Rejection must not
        // depend on receiving or parsing the advertised oversized body.
        let sent_body = if accepted { body.as_str() } else { "" };
        let response = gateway_call(state.clone(), format!(
            "POST /v1/chat/completions HTTP/1.1\r\nhost: api.aqua.test\r\ncookie: aqua_session={cookie}\r\norigin: https://aqua.test\r\nsec-fetch-site: same-site\r\ncontent-type: application/json\r\ncontent-length: {size}\r\n\r\n{sent_body}"));
        let boundary_hits = upstream.hits.load(Ordering::SeqCst);
        let control = gateway_call(state, request(&cookie, &format!("content-length: {}\r\n", BODY.len()+1)));
        upstream.finish();
        assert!(control.starts_with("HTTP/1.1 200") && control.contains("framing healthy control"), "live healthy control: {control:?}");
        if accepted {
            assert!(response.starts_with("HTTP/1.1 200") && response.contains("framing healthy control"), "accepted size {size}: {response:?}");
            assert_eq!(boundary_hits, 1, "boundary request dispatched");
            assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
        } else {
            assert!(response.starts_with("HTTP/1.1 413"), "oversized declaration: {response:?}");
            let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body, json!({"error":{"message":"request too large","type":"invalid_request"}}));
            assert_eq!(boundary_hits, 0, "oversized declaration never dispatches");
            assert_eq!(upstream.hits.load(Ordering::SeqCst), 1, "only healthy control dispatched");
        }
    }
    #[test]
    fn body_size_baseline_one_below_cap() { body_size_baseline(999_999, true); }
    #[test]
    fn body_size_baseline_exact_cap() { body_size_baseline(1_000_000, true); }
    #[test]
    fn body_size_baseline_one_above_cap() { body_size_baseline(1_000_001, false); }

    fn upstream_status_baseline(status: u16) {
        let mut upstream = Responder::start_status(Some(status));
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: upstream.url.clone(), models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let framing = format!("content-length: {}\r\n", BODY.len()+1);
        let failed = gateway_call(state.clone(), request(&cookie, &framing));
        let failure_hits = upstream.hits.load(Ordering::SeqCst);
        let cooldown = state.health.lock().unwrap().get("inferbase").copied();
        let checkpoint = Instant::now();
        let blocked = if status == 503 {
            let blocked = gateway_call(state.clone(), request(&cookie, &framing));
            assert_eq!(upstream.hits.load(Ordering::SeqCst), 1,
                "503 Retry-After blocks while preserving framing/sanitization checks");
            state.health.lock().unwrap().get_mut("inferbase").unwrap().until =
                Instant::now() - Duration::from_secs(1);
            Some(blocked)
        } else { None };
        let healthy = gateway_call(state.clone(), request(&cookie, &framing));
        upstream.finish();
        assert!(failed.starts_with("HTTP/1.1 503"), "upstream {status} becomes generic gateway503: {failed:?}");
        let (head, body) = failed.split_once("\r\n\r\n").unwrap();
        let body: Value = serde_json::from_str(body).unwrap();
        assert_eq!(body, json!({"error":{"message":"no models available","type":"upstream_unavailable"}}));
        for sentinel in ["private-upstream-body-sentinel", "private-header-sentinel", "private-challenge"] {
            assert!(!failed.contains(sentinel), "upstream {status} must not forward {sentinel}");
        }
        let headers = cors_headers_of(&failed);
        for (key, value) in [("content-type", "application/json"), ("cache-control", "no-store"),
                             ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer")] {
            cors_single_header(&headers, key, value);
        }
        for key in ["x-private-upstream", "www-authenticate", "retry-after"] {
            assert!(!headers.contains_key(key), "non429 upstream header must not be forwarded: {head}");
        }
        let cd = cooldown.expect("failed attempt installs cooldown");
        let remaining = cd.until.saturating_duration_since(checkpoint);
        if status == 503 {
            assert!(cd.hard, "503 usable Retry-After must block");
            assert!(remaining > Duration::from_secs(115) && remaining <= Duration::from_secs(120), "hard120s: {remaining:?}");
            assert!(blocked.unwrap().starts_with("HTTP/1.1 429"), "blocked request has no provider attempt");
        } else {
            assert!(!cd.hard, "other non429 statuses remain soft");
            assert!(remaining > Duration::from_secs(10) && remaining <= Duration::from_secs(15), "soft15s: {remaining:?}");
        }
        assert_eq!(failure_hits, 1, "the failure was actually dispatched");
        assert!(healthy.starts_with("HTTP/1.1 200") && healthy.contains("framing healthy control"), "healthy follow-up: {healthy:?}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 2, "failure and healthy control both dispatched");
    }
    #[test] fn upstream_status_baseline_400() { upstream_status_baseline(400); }
    #[test] fn upstream_status_baseline_401() { upstream_status_baseline(401); }
    #[test] fn upstream_status_baseline_403() { upstream_status_baseline(403); }
    #[test] fn upstream_status_baseline_404() { upstream_status_baseline(404); }
    #[test] fn upstream_status_baseline_422() { upstream_status_baseline(422); }
    #[test] fn upstream_status_baseline_503() { upstream_status_baseline(503); }
    #[test] fn upstream_status_baseline_504() { upstream_status_baseline(504); }

    // Present Authorization overrides session fallback, including malformed
    // values. Fresh state per case keeps throttle policy outside this pin.
    fn auth_precedence_baseline(header: Option<&str>, accepted: bool) {
        let mut upstream = Responder::start();
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.keys.insert("offline-owner-key".into(), crate::config::KeyEntry { name: "luke".into(), role: Role::Owner });
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: upstream.url.clone(), models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let auth_line = header.map(|value| format!("aUtHoRiZaTiOn: {value}\r\n")).unwrap_or_default();
        let framing = format!("content-length: {}\r\n", BODY.len()+1);
        let candidate = gateway_call(state.clone(), request(&cookie, &format!("{auth_line}{framing}")));
        let candidate_hits = upstream.hits.load(Ordering::SeqCst);
        // Cookie-only control proves the SAME session is valid after rejection.
        let cookie_control = gateway_call(state.clone(), request(&cookie, &framing));
        // Independent bearer-only control proves the configured key works and
        // no hidden cookie authority is responsible for bearer acceptance.
        let bearer_control = gateway_call(state, request("", &format!("Authorization: Bearer offline-owner-key\r\n{framing}")));
        upstream.finish();
        if accepted {
            assert!(candidate.starts_with("HTTP/1.1 200") && candidate.contains("framing healthy control"), "accepted header {header:?}: {candidate:?}");
        } else {
            assert!(candidate.starts_with("HTTP/1.1 401"), "present invalid header must not use session: {header:?}, {candidate:?}");
            let body: Value = serde_json::from_str(candidate.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body, json!({"error":{"message":"invalid api key","type":"auth_error"}}));
            assert!(!candidate.contains("offline-owner-key"));
        }
        let expected = if accepted { 1 } else { 0 };
        assert_eq!(candidate_hits, expected, "candidate dispatch count");
        for control in [&cookie_control, &bearer_control] {
            assert!(control.starts_with("HTTP/1.1 200") && control.contains("framing healthy control"), "healthy auth control: {control:?}");
        }
        assert_eq!(upstream.hits.load(Ordering::SeqCst), expected + 2, "only accepted candidate and healthy controls dispatch");
    }
    #[test] fn auth_precedence_baseline_absent_header() { auth_precedence_baseline(None, true); }
    #[test] fn auth_precedence_baseline_empty_header() { auth_precedence_baseline(Some(""), false); }
    #[test] fn auth_precedence_baseline_basic_header() { auth_precedence_baseline(Some("Basic offline-owner-key"), false); }
    #[test] fn auth_precedence_baseline_lowercase_scheme() { auth_precedence_baseline(Some("bearer offline-owner-key"), false); }
    #[test] fn auth_precedence_baseline_tab_separator() { auth_precedence_baseline(Some("Bearer\toffline-owner-key"), false); }
    #[test] fn auth_precedence_baseline_invalid_key() { auth_precedence_baseline(Some("Bearer not-the-key"), false); }
    #[test] fn auth_precedence_baseline_valid_bearer() { auth_precedence_baseline(Some("Bearer offline-owner-key"), true); }

    // Deliberate hardening after the historical characterization: ambiguous
    // Authorization field lines and repeated session names are rejected
    // before credential selection. Healthy single-field controls still work.
    fn duplicate_auth_rejection(kind: &str, valid_first: bool) {
        let mut upstream = Responder::start();
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.keys.insert("offline-owner-key".into(), crate::config::KeyEntry { name: "luke".into(), role: Role::Owner });
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: upstream.url.clone(), models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let stale = "00000000000000000000000000000000";
        assert!(state.auth.get_session(stale).is_none(), "stale fixture must not resolve");
        let (first, second) = if valid_first { (cookie.as_str(), stale) } else { (stale, cookie.as_str()) };
        let framing = format!("content-length: {}\r\n", BODY.len()+1);
        let bytes = match kind {
            "authorization" => {
                let (a,b) = if valid_first { ("Bearer offline-owner-key", "Bearer not-the-key") }
                            else { ("Bearer not-the-key", "Bearer offline-owner-key") };
                request(&cookie, &format!("Authorization: {a}\r\naUtHoRiZaTiOn: {b}\r\n{framing}"))
            }
            "cookie-lines" => {
                request(first, &format!("CoOkIe: aqua_session={second}\r\n{framing}"))
            }
            "cookie-tokens" => {
                let value = format!("aqua_session={first}; aqua_session={second}");
                request(value.strip_prefix("aqua_session=").unwrap(), &framing)
            }
            "authorization-equal" => request(&cookie, &format!("Authorization: Bearer offline-owner-key\r\nauthorization: Bearer offline-owner-key\r\n{framing}")),
            "cookie-lines-equal" => request(&cookie, &format!("Cookie: aqua_session={cookie}\r\n{framing}")),
            "cookie-tokens-equal" => request(&format!("{cookie}; aqua_session={cookie}"), &framing),
            "cookie-bare" => {
                if valid_first { request(&format!("{cookie}; aqua_session"), &framing) }
                else { request("", &framing).replace("cookie: aqua_session=", &format!("cookie: aqua_session; aqua_session={cookie}")) }
            }
            "cookie-empty" | "cookie-malformed" => {
                let invalid = if kind == "cookie-empty" { "" } else { "not-hex" };
                let (a,b) = if valid_first { (cookie.as_str(), invalid) } else { (invalid, cookie.as_str()) };
                request(&format!("{a}; aqua_session={b}"), &framing)
            }
            _ => panic!("unknown rejection fixture"),
        };
        let (mut client, mut server) = pair();
        client.write_all(bytes.as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let parse_error = read_request_within(&mut server, Duration::from_secs(2)).err();
        let candidate = gateway_call(state.clone(), bytes);
        let candidate_hits = upstream.hits.load(Ordering::SeqCst);
        let healthy = gateway_call(state.clone(), request(&cookie, &framing));
        let unrelated_cookie = gateway_call(state, request(&format!("{cookie}; theme=dark; unrelated=x"), &framing));
        upstream.finish();
        assert_eq!(parse_error, Some("bad request"), "ambiguous credentials fail at parser");
        assert!(candidate.starts_with("HTTP/1.1 400"), "{kind}, valid_first={valid_first}: {candidate:?}");
        let body: Value = serde_json::from_str(candidate.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body, json!({"error":{"message":"malformed request","type":"invalid_request"}}));
        assert_eq!(candidate_hits, 0, "ambiguous credentials never dispatch");
        assert!(healthy.starts_with("HTTP/1.1 200") && healthy.contains("framing healthy control"), "same-session healthy control: {healthy:?}");
        assert!(unrelated_cookie.starts_with("HTTP/1.1 200"), "unrelated cookie names remain supported: {unrelated_cookie:?}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
    }
    #[test] fn duplicate_auth_rejection_valid_then_invalid() { duplicate_auth_rejection("authorization", true); }
    #[test] fn duplicate_auth_rejection_invalid_then_valid() { duplicate_auth_rejection("authorization", false); }
    #[test] fn duplicate_cookie_rejection_valid_then_stale_lines() { duplicate_auth_rejection("cookie-lines", true); }
    #[test] fn duplicate_cookie_rejection_stale_then_valid_lines() { duplicate_auth_rejection("cookie-lines", false); }
    #[test] fn duplicate_cookie_rejection_valid_then_stale_tokens() { duplicate_auth_rejection("cookie-tokens", true); }
    #[test] fn duplicate_cookie_rejection_stale_then_valid_tokens() { duplicate_auth_rejection("cookie-tokens", false); }

    #[test] fn duplicate_cookie_rejection_empty_then_valid() { duplicate_auth_rejection("cookie-empty", false); }
    #[test] fn duplicate_cookie_rejection_valid_then_empty() { duplicate_auth_rejection("cookie-empty", true); }
    #[test] fn duplicate_cookie_rejection_malformed_then_valid() { duplicate_auth_rejection("cookie-malformed", false); }
    #[test] fn duplicate_cookie_rejection_valid_then_malformed() { duplicate_auth_rejection("cookie-malformed", true); }

    #[test] fn duplicate_cookie_rejection_bare_then_valid() { duplicate_auth_rejection("cookie-bare", false); }
    #[test] fn duplicate_cookie_rejection_valid_then_bare() { duplicate_auth_rejection("cookie-bare", true); }

    #[test] fn duplicate_auth_rejection_equal_values() { duplicate_auth_rejection("authorization-equal", true); }
    #[test] fn duplicate_cookie_rejection_equal_fields() { duplicate_auth_rejection("cookie-lines-equal", true); }
    #[test] fn duplicate_cookie_rejection_equal_tokens() { duplicate_auth_rejection("cookie-tokens-equal", true); }

    fn split_cookie_control(bearer_only: bool, session_first: bool) {
        let mut upstream = Responder::start();
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.keys.insert("offline-owner-key".into(), crate::config::KeyEntry { name: "luke".into(), role: Role::Owner });
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: upstream.url.clone(), models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let framing = format!("content-length: {}\r\n", BODY.len()+1);
        let mut bytes = request(&cookie, &framing);
        let field = if bearer_only {
            "cookie: theme=dark\r\nCoOkIe: other=x\r\nAuthorization: Bearer offline-owner-key".to_string()
        } else if session_first {
            format!("cookie: aqua_session={cookie}\r\nCoOkIe: theme=dark")
        } else {
            format!("cookie: theme=dark\r\nCoOkIe: aqua_session={cookie}")
        };
        bytes = bytes.replace(&format!("cookie: aqua_session={cookie}"), &field);
        let (mut client, mut server) = pair();
        client.write_all(bytes.as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let parsed = read_request_within(&mut server, Duration::from_secs(2));
        let response = gateway_call(state, bytes);
        upstream.finish();
        let parsed = parsed.expect("disjoint Cookie fields combine");
        let expected = if bearer_only { "theme=dark; other=x".to_string() }
            else if session_first { format!("aqua_session={cookie}; theme=dark") }
            else { format!("theme=dark; aqua_session={cookie}") };
        assert_eq!(parsed.headers.get("cookie"), Some(&expected), "wire order preserved with semicolon-space join");
        assert!(response.starts_with("HTTP/1.1 200") && response.contains("framing healthy control"), "healthy split-cookie response: {response:?}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    }
    #[test] fn split_cookie_session_first_control() { split_cookie_control(false, true); }
    #[test] fn split_cookie_session_last_control() { split_cookie_control(false, false); }
    #[test] fn split_cookie_bearer_only_control() { split_cookie_control(true, false); }

    #[test]
    fn content_length_plus_rejected() {
        let (mut client, mut server) = pair();
        client.write_all(b"POST /x HTTP/1.1\r\ncontent-length: +2\r\n\r\n{}").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(read_request_within(&mut server, Duration::from_secs(2)).err(), Some("bad length"));
        rejects(format!("content-length: +{}\r\n", BODY.len()), "bad length");
    }

    #[test]
    fn content_length_decimal_controls() {
        for raw in ["0", "000", "2", "0002", " \t2\t "] {
            let len = if raw.trim().parse::<usize>().unwrap() == 0 { 0 } else { 2 };
            let (mut client, mut server) = pair();
            write!(client, "POST /x HTTP/1.1\r\ncontent-length: {raw}\r\n\r\n{{}}").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let parsed = read_request_within(&mut server, Duration::from_secs(2)).unwrap();
            assert_eq!(parsed.body, &b"{}"[..len], "valid decimal {raw:?}");
        }
    }
    #[test]
    fn content_length_leading_zero_http_control() {
        let mut upstream = Responder::start();
        let mut state = Arc::try_unwrap(keys_shared()).ok().unwrap();
        state.config.providers = vec![crate::config::Provider {
            id: "inferbase".into(), status: Status::Personal, api_key: "offline-synthetic".into(),
            base_url: upstream.url.clone(), models: vec![crate::config::ModelEntry {
                public: "fixture-chat".into(), upstream: "fixture-upstream".into(), context: None,
            }],
        }];
        let state = Arc::new(state);
        let cookie = state.auth.create_session("luke", Role::Owner).unwrap();
        let response = gateway_call(state, request(&cookie, &format!("content-length: \t000{}\t \r\n", BODY.len()+1)));
        upstream.finish();
        assert!(response.starts_with("HTTP/1.1 200") && response.contains("framing healthy control"), "valid decimal HTTP control: {response:?}");
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn content_length_overflow_and_nondigits_rejected() {
        for raw in ["99999999999999999999999999999999", "-2", "2x", "2,2", "２", ""] {
            rejects(format!("content-length: {raw}\r\n"), "bad length");
        }
    }

    #[test]
    fn content_length_non_ows_whitespace_rejected() {
        for raw in ["\u{a0}2\u{a0}", "\u{2003}2\u{2003}", "\u{b}2\u{b}", "\u{c}2\u{c}"] {
            let (mut client, mut server) = pair();
            write!(client, "POST /x HTTP/1.1\r\ncontent-length: {raw}\r\n\r\n{{}}").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let parse_error = read_request_within(&mut server, Duration::from_secs(2)).err();
            rejects(format!("content-length: {raw}\r\n"), "bad length");
            assert_eq!(parse_error, Some("bad length"));
        }
    }

}
