use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use aqua::{Auth, OAuthConfig, Role};

fn oauth_cfg() -> OAuthConfig {
    OAuthConfig {
        client_id: "client123".into(),
        client_secret: "secret456".into(),
        public_url: "https://aqua.test".into(),
        console_url: String::new(),
        owner_users: vec!["luke".into()],
        friend_users: vec!["sam".into(), "alex".into()],
    }
}

fn cfg_with(oauth: OAuthConfig) -> aqua::Config {
    aqua::Config {
        keys: HashMap::new(),
        admin_key: "adminsecret".into(),
        daily_limit: 200,
        allowed_origin: String::new(),
        providers: vec![],
        oauth,
        auto_shortlist: vec![],
        upstream_budget: Duration::from_secs(300),
    }
}

fn raw(base: &str, req: &str) -> String {
    let addr = base.trim_start_matches("http://");
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn state_is_single_use() {
    let a = Auth::new(oauth_cfg());
    let s = a.new_state();
    assert!(a.take_state(&s));
    assert!(!a.take_state(&s), "replayed state must fail");
    assert!(!a.take_state("does-not-exist"));
}

#[test]
fn session_lifecycle() {
    let a = Auth::new(oauth_cfg());
    let id = a.create_session("luke", Role::Owner);
    let got = a.get_session(&id).expect("fresh session must resolve");
    assert_eq!(got.0, "luke");
    assert_eq!(got.1, Role::Owner);
    a.revoke(&id);
    assert!(a.get_session(&id).is_none(), "revoked session must not resolve");
}

#[test]
fn expired_session_is_dropped() {
    let a = Auth::new(oauth_cfg());
    let live = a.create_session("sam", Role::Friend);
    let doomed = a.create_session("sam", Role::Friend);
    let future = Instant::now() + aqua::auth::SESSION_TTL + Duration::from_secs(1);
    assert!(a.get_session_at(&doomed, future).is_none(), "expired session must not resolve");
    assert!(a.get_session(&live).is_some(), "live session must resolve");
}

#[test]
fn role_matching_is_case_insensitive_and_closed() {
    let cfg = oauth_cfg();
    assert_eq!(cfg.role_for("LUKE"), Some(Role::Owner));
    assert_eq!(cfg.role_for("Sam"), Some(Role::Friend));
    assert_eq!(cfg.role_for("mallory"), None);
    assert_eq!(cfg.role_for(""), None);
}

#[test]
fn cookie_roundtrip_and_rejects_garbage() {
    let a = Auth::new(oauth_cfg());
    let id = a.create_session("luke", Role::Owner);
    let cookie = a.set_cookie(&id);
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"), "https public_url must set Secure");
    let mut headers = HashMap::new();
    headers.insert("cookie".to_string(), format!("other=1; aqua_session={}; x=y", id));
    assert_eq!(aqua::auth::session_cookie(&headers), Some(id));
    // a same-prefix cookie name without '=' must not abort parsing of later parts
    let mut headers2 = HashMap::new();
    let id2 = a.create_session("sam", Role::Friend);
    headers2.insert("cookie".to_string(), format!("aqua_sessionfoo=1; aqua_session={}", id2));
    assert_eq!(aqua::auth::session_cookie(&headers2), Some(id2));
    headers.insert("cookie".to_string(), "aqua_session=<script>alert(1)</script>".to_string());
    assert_eq!(aqua::auth::session_cookie(&headers), None);
    headers.insert("cookie".to_string(), "aqua_session=".to_string());
    assert_eq!(aqua::auth::session_cookie(&headers), None);
    let headers: HashMap<String, String> = HashMap::new();
    assert_eq!(aqua::auth::session_cookie(&headers), None);
}

#[test]
fn authorize_url_encodes_and_targets_github() {
    let cfg = oauth_cfg();
    let url = aqua::auth::authorize_url(&cfg, "state123");
    assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
    assert!(url.contains("client_id=client123"));
    assert!(url.contains("redirect_uri=https%3A%2F%2Faqua.test%2Fauth%2Fgithub%2Fcallback"));
    assert!(url.contains("state=state123"));
    assert!(url.contains("scope=read:user"));
}

#[test]
fn query_parsing_decodes() {
    let q = aqua::auth::parse_query("code=abc%20def&state=xyz");
    assert_eq!(q.get("code").unwrap(), "abc def");
    assert_eq!(q.get("state").unwrap(), "xyz");
    let q = aqua::auth::parse_query("code=%zz&state=x");
    assert_eq!(q.get("code").unwrap(), "%zz"); // bad escapes pass through untouched
}

#[test]
fn login_disabled_returns_503_when_unconfigured() {
    let r = aqua::bind(cfg_with(OAuthConfig::default())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "GET /login/github HTTP/1.1\r\nhost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 503"), "unconfigured login must fail closed, got: {}", &resp[..resp.len().min(80)]);
    assert!(resp.contains("not configured"));
}

#[test]
fn login_redirects_to_github_when_configured() {
    let r = aqua::bind(cfg_with(oauth_cfg())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "GET /login/github HTTP/1.1\r\nhost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 302"), "got: {}", &resp[..resp.len().min(80)]);
    assert!(resp.contains("location: https://github.com/login/oauth/authorize?"));
    assert!(resp.contains("client_id=client123"));
}

#[test]
fn callback_rejects_bad_state_before_any_network() {
    let r = aqua::bind(cfg_with(oauth_cfg())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "GET /auth/github/callback?code=x&state=forged HTTP/1.1\r\nhost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 400"), "forged state must be rejected, got: {}", &resp[..resp.len().min(80)]);
}

#[test]
fn auth_me_requires_session() {
    let r = aqua::bind(cfg_with(oauth_cfg())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "GET /auth/me HTTP/1.1\r\nhost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 401"));
    let resp = raw(&base, "GET /auth/me HTTP/1.1\r\nhost: x\r\ncookie: aqua_session=deadbeef\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 401"), "unknown session must stay 401");
}

#[test]
fn logout_clears_cookie() {
    let r = aqua::bind(cfg_with(oauth_cfg())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "got: {}", &resp[..resp.len().min(80)]);
    assert!(resp.contains("Max-Age=0"));
}

#[test]
fn static_pages_are_served_and_api_still_closed() {
    let r = aqua::bind(cfg_with(OAuthConfig::default())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    for path in ["/", "/landing.html", "/console.html", "/playground.html"] {
        let resp = raw(&base, &format!("GET {} HTTP/1.1\r\nhost: x\r\n\r\n", path));
        assert!(resp.starts_with("HTTP/1.1 200"), "{} must be served", path);
        assert!(resp.contains("content-type: text/html"));
    }
    let resp = raw(&base, "GET /v1/models HTTP/1.1\r\nhost: x\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 401"), "API stays key-gated alongside public pages");
}

fn cfg_with_origin(origin: &str) -> aqua::Config {
    let mut c = cfg_with(OAuthConfig::default());
    c.allowed_origin = origin.to_string();
    c
}

#[test]
fn cors_echoes_only_the_allowed_origin_and_allows_credentials() {
    // the Pages console calls the API host with credentials:'include'; without
    // allow-credentials on the response the browser hides every answer from it
    let r = aqua::bind(cfg_with_origin("https://aqua.goattech.us")).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "GET /auth/me HTTP/1.1\r\nhost: x\r\norigin: https://aqua.goattech.us\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 401"));
    assert!(resp.contains("access-control-allow-origin: https://aqua.goattech.us"));
    assert!(resp.contains("access-control-allow-credentials: true"), "credentialed console fetches need allow-credentials");
    let resp = raw(&base, "GET /auth/me HTTP/1.1\r\nhost: x\r\norigin: https://evil.example\r\n\r\n");
    assert!(!resp.contains("access-control-allow-origin"), "other origins get no CORS headers");
    assert!(!resp.contains("access-control-allow-credentials"));
}

#[test]
fn preflight_allows_credentials_and_key_headers() {
    let r = aqua::bind(cfg_with_origin("https://aqua.goattech.us")).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "OPTIONS /auth/me HTTP/1.1\r\nhost: x\r\norigin: https://aqua.goattech.us\r\naccess-control-request-method: GET\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"));
    assert!(resp.contains("access-control-allow-credentials: true"), "credentialed preflight needs allow-credentials");
    assert!(resp.contains("access-control-allow-headers: authorization, content-type"));
}

#[test]
fn logout_rejects_cross_site_fetch_metadata() {
    // a cross-site page must not be able to sign a user out; SameSite=Lax is the
    // first wall, fetch metadata the second
    let r = aqua::bind(cfg_with(OAuthConfig::default())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nsec-fetch-site: cross-site\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 403"), "cross-site logout must be rejected, got: {}", &resp[..resp.len().min(80)]);
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nsec-fetch-site: same-site\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "same-site console logout must pass");
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "clients without fetch metadata rely on SameSite=Lax");
}

#[test]
fn logout_rejects_same_site_sibling_origin_and_accepts_exact_console() {
    // a hostile app on another *.goattech.us subdomain is same-SITE, so SameSite=Lax
    // and Sec-Fetch-Site both wave its credentialed POST through; only the exact
    // Origin check stops it
    let r = aqua::bind(cfg_with_origin("https://aqua.goattech.us")).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nsec-fetch-site: same-site\r\norigin: https://crafty.goattech.us\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 403"), "sibling-subdomain origin must be rejected, got: {}", &resp[..resp.len().min(80)]);
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nsec-fetch-site: same-site\r\norigin: https://evil.example\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 403"), "cross-site origin must be rejected");
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nsec-fetch-site: same-site\r\norigin: https://aqua.goattech.us\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "exact console origin must pass");
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "non-browser clients without Origin stay allowed");
}

#[test]
fn logout_allows_same_origin_console_without_allowed_origin() {
    // default local config: the backend serves the console itself, so the browser's
    // Origin IS the backend's own host - the reviewer caught this returning 403
    let r = aqua::bind(cfg_with(OAuthConfig::default())).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: localhost:8080\r\ncontent-length: 0\r\norigin: http://localhost:8080\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "same-origin console logout must pass, got: {}", &resp[..resp.len().min(80)]);
}

#[test]
fn logout_allows_console_served_on_the_api_host_itself() {
    // the split deployment keeps the pages reachable on the api host; a console
    // loaded from api.aqua.goattech.us posts back to its own origin
    let r = aqua::bind(cfg_with_origin("https://aqua.goattech.us")).unwrap();
    let base = format!("http://127.0.0.1:{}", r.port());
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: api.aqua.goattech.us\r\ncontent-length: 0\r\nsec-fetch-site: same-origin\r\norigin: https://api.aqua.goattech.us\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "api-host same-origin console logout must pass, got: {}", &resp[..resp.len().min(80)]);
    // ...while a same-site sibling on another host stays rejected
    let resp = raw(&base, "POST /auth/logout HTTP/1.1\r\nhost: api.aqua.goattech.us\r\ncontent-length: 0\r\nsec-fetch-site: same-site\r\norigin: https://crafty.goattech.us\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 403"), "sibling origin must stay rejected");
               }
