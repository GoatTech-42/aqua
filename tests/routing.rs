// Model-first routing tests: shortlist auto, same-model provider failover,
// passive account-scope cooldowns, sound context rejection.
// Self-contained harness (mirrors tests/proxy.rs fixtures).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aqua::{Config, KeyEntry, ModelEntry, Provider, Status};

// ---------- mock upstream ----------

#[derive(Clone)]
struct Recorded {
    body: serde_json::Value,
}

struct MockReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn read_request(stream: &mut std::net::TcpStream) -> (HashMap<String, String>, String) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = find(&buf, b"\r\n\r\n") { break p; }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut headers = HashMap::new();
    let mut len = 0usize;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            if k == "content-length" { len = v.trim().parse().unwrap_or(0); }
            headers.insert(k, v.trim().to_string());
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut tmp).unwrap();
        body.extend_from_slice(&tmp[..n]);
    }
    (headers, String::from_utf8_lossy(&body).to_string())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

struct Mock {
    url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    hits: Arc<AtomicUsize>,
}

fn mock_upstream<F: Fn(&Recorded) -> MockReply + Send + Sync + 'static>(handler: F) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    // one thread per connection: a gated/slow handler must not block the
    // listener, or concurrent-request tests deadlock against their own mock
    let handler = Arc::new(handler);
    let (rq0, ht0) = (requests.clone(), hits.clone());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            let (rq, ht, h) = (rq0.clone(), ht0.clone(), handler.clone());
            thread::spawn(move || {
                let (headers, body) = read_request(&mut stream);
                let _ = headers;
                let rec = Recorded {
                    body: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                };
                rq.lock().unwrap().push(rec.clone());
                ht.fetch_add(1, Ordering::SeqCst);
                let reply = h(&rec);
                let head = format!(
                    "HTTP/1.1 {}\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n",
                    reply.status,
                    reply.body.len(),
                    reply.headers.iter().map(|(k, v)| format!("{}: {}\r\n", k, v)).collect::<String>()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(reply.body.as_bytes()).unwrap();
            });
        }
    });
    Mock { url, requests, hits }
}

fn json_reply(body: serde_json::Value) -> MockReply {
    MockReply { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: body.to_string() }
}

fn chat_json(model: &str, content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-real", "object": "chat.completion", "created": 1, "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    })
}

fn error_reply(status: u16, extra_headers: Vec<(&str, &str)>) -> MockReply {
    MockReply {
        status,
        headers: std::iter::once(("content-type", "application/json"))
            .chain(extra_headers)
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: "{\"error\":\"upstream failure\"}".into(),
    }
}

// ---------- server fixture ----------

// models: (public name, upstream id, verified context)
fn provider(id: &str, url: &str, status: Status, models: Vec<(&str, &str, Option<u32>)>) -> Provider {
    Provider {
        id: id.into(),
        base_url: url.into(),
        api_key: format!("upstream-key-{}", id),
        models: models
            .into_iter()
            .map(|(public, upstream, context)| ModelEntry {
                public: public.into(),
                upstream: upstream.into(),
                context,
            })
            .collect(),
        status,
    }
}

fn config(providers: Vec<Provider>, auto_shortlist: Vec<&str>) -> Config {
    let mut keys = HashMap::new();
    keys.insert("ownerkey".into(), KeyEntry { name: "luke".into(), role: aqua::Role::Owner });
    keys.insert("friendkey".into(), KeyEntry { name: "sam".into(), role: aqua::Role::Friend });
    Config {
        keys,
        admin_key: "adminsecret".into(),
        daily_limit: 200,
        allowed_origin: String::new(),
        providers,
        oauth: Default::default(), spend: Default::default(),
        auto_shortlist: auto_shortlist.into_iter().map(|s| s.to_string()).collect(),
        upstream_budget: Duration::from_secs(300),
        upstream_idle: Duration::from_secs(60),
    }
}

struct Running { base: String, _h: aqua::Server }
fn serve(cfg: Config) -> Running {
    let s = aqua::bind(cfg).unwrap();
    Running { base: format!("http://127.0.0.1:{}", s.port()), _h: s }
}

// Restart on the same state path: Server::drop joins only the accept loop, so a
// busy handler thread can still hold the state lock file briefly after drop.
// A real restart waits for the old process to exit; poll the bind the same way.
fn serve_restart(cfg: Config) -> Running {
    serve_restart_within(cfg, Duration::from_secs(5), &mut |_| {}).unwrap_or_else(|e| panic!("bind after restart failed: {e}"))
}

// on_error observes every failed bind attempt so the controls below can count
// attempts and gate a lock release on observed contention instead of sleeps.
fn serve_restart_within(cfg: Config, timeout: Duration, on_error: &mut dyn FnMut(&std::io::Error)) -> std::io::Result<Running> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match aqua::bind(cfg.clone()) {
            Ok(s) => return Ok(Running { base: format!("http://127.0.0.1:{}", s.port()), _h: s }),
            Err(e) if is_state_lock_contention(&e) && std::time::Instant::now() < deadline => {
                on_error(&e);
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                on_error(&e);
                return Err(e);
            }
        }
    }
}

// The state stores guard their lock files with File::try_lock (src/spend.rs,
// src/keys.rs), whose contention reaches bind's caller as Error::other wrapping
// std::fs::TryLockError::WouldBlock. Only that positively identified contention
// is retried; permission, corrupt-state, or any other failure is not.
fn is_state_lock_contention(e: &std::io::Error) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = e.get_ref().map(|r| r as _);
    while let Some(err) = cur {
        if let Some(tle) = err.downcast_ref::<std::fs::TryLockError>() {
            return matches!(tle, std::fs::TryLockError::WouldBlock);
        }
        cur = err.source();
    }
    false
}

fn client() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).build().into()
}

fn chat(agent: &ureq::Agent, base: &str, key: &str, payload: serde_json::Value) -> ureq::http::Response<ureq::Body> {
    agent.post(&format!("{}/v1/chat/completions", base))
        .header("authorization", &format!("Bearer {}", key))
        .send_json(&payload)
        .unwrap()
}

fn auto_msg() -> serde_json::Value {
    serde_json::json!({"model": "auto", "messages": [{"role": "user", "content": "hi"}]})
}

fn pin_msg(model: &str) -> serde_json::Value {
    serde_json::json!({"model": model, "messages": [{"role": "user", "content": "hi"}]})
}

// ---------- model-first candidacy ----------

#[test]
fn auto_walks_shortlist_model_first_then_provider() {
    // P1 carries coder-a (fails) and coder-b; P2 carries coder-a (healthy).
    // shortlist [coder-a, coder-b]: P1/coder-a fails, then P2/coder-a must win
    // before P1/coder-b is even considered - and P1 must not be retried for
    // coder-b after failing (one attempt per account per request).
    let p1 = mock_upstream(|_| error_reply(500, vec![]));
    let p2 = mock_upstream(|_| json_reply(chat_json("real-p2-model", "ok")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None), ("coder-b", "p1/b", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a", "coder-b"],
    ));
    let mut res = chat(&client(), &srv.base, "ownerkey", auto_msg());
    assert_eq!(res.status(), 200);
    assert_eq!(res.body_mut().read_json::<serde_json::Value>().unwrap()["model"], "coder-a");
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1, "failed account tried once, never for its other model");
    assert_eq!(p2.hits.load(Ordering::SeqCst), 1);
    assert_eq!(p2.requests.lock().unwrap()[0].body["model"], "p2/a");
}

#[test]
fn auto_with_empty_shortlist_is_disabled_not_delegated() {
    // no shortlist: auto resolves nothing (it must never fall through to a
    // provider-side router); a pinned model still works
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![provider("p1", &up.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec![],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 503);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", pin_msg("coder-a")).status(), 200);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn pinned_model_fails_over_across_providers_carrying_it() {
    let bad = mock_upstream(|_| error_reply(500, vec![]));
    let good = mock_upstream(|_| json_reply(chat_json("real-good", "ok")));
    let srv = serve(config(
        vec![
            provider("bad", &bad.url, Status::Friends, vec![("coder-a", "bad/a", None)]),
            provider("good", &good.url, Status::Friends, vec![("coder-a", "good/a", None)]),
        ],
        vec!["coder-a"],
    ));
    let mut res = chat(&client(), &srv.base, "friendkey", pin_msg("coder-a"));
    assert_eq!(res.status(), 200);
    assert_eq!(res.body_mut().read_json::<serde_json::Value>().unwrap()["model"], "coder-a");
    assert_eq!(good.requests.lock().unwrap()[0].body["model"], "good/a");
}

#[test]
fn pinned_model_never_drifts_to_another_model() {
    let bad = mock_upstream(|_| error_reply(500, vec![]));
    let other = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![
            provider("bad", &bad.url, Status::Friends, vec![("coder-a", "bad/a", None)]),
            provider("other", &other.url, Status::Friends, vec![("writer-b", "other/b", None)]),
        ],
        vec!["coder-a", "writer-b"],
    ));
    let res = chat(&client(), &srv.base, "ownerkey", pin_msg("coder-a"));
    assert_eq!(res.status(), 503, "pinned model that fails everywhere must fail, not drift");
    assert_eq!(other.hits.load(Ordering::SeqCst), 0, "a different model was never tried");
}

// ---------- passive account-scope cooldowns ----------

#[test]
fn retry_after_marks_account_hard_limited_until_lapse() {
    // P1 429s with Retry-After: 120. The same request must not try P1's other
    // model; the NEXT request must not call P1 at all, even with nothing else
    // healthy - a known hard limit is not retried as a last resort.
    let p1 = mock_upstream(|_| error_reply(429, vec![("retry-after", "120")]));
    let p2_fail = Arc::new(AtomicBool::new(false));
    let flag = p2_fail.clone();
    let p2 = mock_upstream(move |_| {
        if flag.load(Ordering::SeqCst) { error_reply(500, vec![]) } else { json_reply(chat_json("m", "ok")) }
    });
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None), ("coder-b", "p1/b", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a", "coder-b"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1, "429 on one model: account's other model not tried");
    // now P2 also fails; P1 has a known hard limit and must stay untouched
    p2_fail.store(true, Ordering::SeqCst);
    let mut res = chat(&agent, &srv.base, "ownerkey", auto_msg());
    assert_eq!(res.status(), 429, "a known hard-limited account in the mix reports rate-limited, not generic failure");
    assert!(!res.body_mut().read_to_string().unwrap().contains("p1"));
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1, "hard-limited account never retried as last resort");
}

#[test]
fn huge_retry_after_is_bounded_but_still_hard() {
    let p1 = mock_upstream(|_| error_reply(429, vec![("retry-after", "99999999")]));
    let p2 = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1, "clamped Retry-After still excludes the account");
}

#[test]
fn plain_429_deprioritizes_but_allows_last_resort_retry() {
    // no Retry-After: soft cooldown. A sole provider is retried (stale blips
    // must not cause a false 503) and recovers.
    let failing = Arc::new(AtomicBool::new(true));
    let flag = failing.clone();
    let p1 = mock_upstream(move |_| {
        if flag.load(Ordering::SeqCst) { error_reply(429, vec![]) } else { json_reply(chat_json("m", "recovered")) }
    });
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 429);
    failing.store(false, Ordering::SeqCst);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200, "soft-cooled sole provider retried");
    assert_eq!(p1.hits.load(Ordering::SeqCst), 2);
}

#[test]
fn http_date_retry_after_is_hard_when_future_soft_when_past() {
    // future IMF-fixdate: real limit evidence, account excluded until lapse
    let p1 = mock_upstream(|_| error_reply(429, vec![("retry-after", "Mon, 15 Nov 2027 00:00:00 GMT")]));
    let p2 = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1, "future HTTP-date is a hard limit, account excluded");
}

#[test]
fn past_http_date_retry_after_is_no_evidence() {
    // a date in the past says nothing about the current limit: soft default
    let failing = Arc::new(AtomicBool::new(true));
    let flag = failing.clone();
    let p1 = mock_upstream(move |_| {
        if flag.load(Ordering::SeqCst) {
            error_reply(429, vec![("retry-after", "Sun, 15 Nov 2020 00:00:00 GMT")])
        } else {
            json_reply(chat_json("m", "recovered"))
        }
    });
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 429);
    failing.store(false, Ordering::SeqCst);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200, "past date treated as absent, last-resort retry allowed");
}

#[test]
fn signed_retry_after_delta_is_malformed_soft_not_hard() {
    // RFC 9110 delta-seconds are digits only: "+3600" must not become a
    // one-hour hard limit; malformed values get the soft default instead.
    let failing = Arc::new(AtomicBool::new(true));
    let flag = failing.clone();
    let p1 = mock_upstream(move |_| {
        if flag.load(Ordering::SeqCst) { error_reply(429, vec![("retry-after", "+3600")]) } else { json_reply(chat_json("m", "recovered")) }
    });
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 429);
    failing.store(false, Ordering::SeqCst);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200, "malformed Retry-After is a soft blip: sole provider is retried");
    assert_eq!(p1.hits.load(Ordering::SeqCst), 2);
}

#[test]
fn lapsed_hard_limit_is_retried_within_the_same_request() {
    // P1 hard-limited for 4s, then healthy. P2 answers slowly and fails. The
    // deferred dispatch-time recheck must try P1 after its limit lapses
    // instead of failing the request.
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    let p1 = mock_upstream(move |_| {
        if n.fetch_add(1, Ordering::SeqCst) == 0 { error_reply(429, vec![("retry-after", "4")]) } else { json_reply(chat_json("m", "recovered")) }
    });
    let p2 = mock_upstream(|_| {
        thread::sleep(Duration::from_millis(2500));
        error_reply(500, vec![])
    });
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a"],
    ));
    let agent = client();
    // first request: P1 installs its 4s hard limit, slow P2 fails -> 429
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 429);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1);
    // second request ~2.5s later: P1's limit is still active at candidacy so
    // it is deferred behind P2; P2 fails after another 2.5s, the limit has
    // lapsed by then, and the recheck tries P1 successfully
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200, "post-lapse hard-limited account is retried in the same request");
    assert_eq!(p1.hits.load(Ordering::SeqCst), 2);
}

#[test]
fn client_429_never_carries_a_fabricated_retry_after() {
    let p1 = mock_upstream(|_| error_reply(429, vec![("retry-after", "120")]));
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let res = chat(&client(), &srv.base, "ownerkey", auto_msg());
    assert_eq!(res.status(), 429);
    assert!(res.headers().get("retry-after").is_none(), "no upstream header forwarded, no duration promised");
}

#[test]
fn junk_retry_after_is_soft_not_hard() {
    let failing = Arc::new(AtomicBool::new(true));
    let flag = failing.clone();
    let p1 = mock_upstream(move |_| {
        if flag.load(Ordering::SeqCst) {
            error_reply(429, vec![("retry-after", "tomorrow-ish")])
        } else {
            json_reply(chat_json("m", "recovered"))
        }
    });
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 429);
    failing.store(false, Ordering::SeqCst);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200, "unparseable Retry-After never becomes a hard exclusion");
}

#[test]
fn soft_failure_deprioritizes_on_the_next_request() {
    // P1 500s once; on the next request healthy P2 is tried first even though
    // P1 sorts first in config order.
    let p1 = mock_upstream(|_| error_reply(500, vec![]));
    let p2 = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1, "soft-cooled account skipped while a fresh route exists");
    assert_eq!(p2.hits.load(Ordering::SeqCst), 2);
}

// ---------- model-priority regression (watchdog rev2 finding) ----------

#[test]
fn soft_health_never_moves_a_later_shortlist_model_ahead() {
    // auto [coder-a, coder-b]; P1 (sole carrier of coder-a) 500s once, then
    // recovers. The next request must try preferred coder-a again - the soft
    // cooldown reorders providers WITHIN a model, never across models.
    let recovering = Arc::new(AtomicBool::new(false));
    let f = recovering.clone();
    let p1 = mock_upstream(move |_| {
        if f.load(Ordering::SeqCst) { json_reply(chat_json("a", "recovered")) } else { error_reply(500, vec![]) }
    });
    let p2 = mock_upstream(|_| json_reply(chat_json("b", "fallback")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-b", "b", None)]),
        ],
        vec!["coder-a", "coder-b"],
    ));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200);
    recovering.store(true, Ordering::SeqCst);
    let mut res = chat(&agent, &srv.base, "ownerkey", auto_msg());
    assert_eq!(
        res.body_mut().read_json::<serde_json::Value>().unwrap()["model"],
        "coder-a",
        "soft account ordering moved lower-shortlist model ahead of preferred model"
    );
    assert_eq!(p2.hits.load(Ordering::SeqCst), 1, "fallback model used only while preferred was down");
}

// ---------- concurrency regression (watchdog rev1 findings) ----------

#[test]
fn concurrent_success_does_not_clear_a_hard_limit() {
    // call 1 is held in flight and eventually succeeds; call 2 429s with
    // Retry-After while call 1 is in flight. call 1's success must NOT clear
    // the hard limit call 2 established.
    let (gate_tx, gate_rx) = channel::<()>();
    let gate_rx = Mutex::new(Some(gate_rx));
    let first = Arc::new(AtomicBool::new(true));
    let f = first.clone();
    let p1 = mock_upstream(move |_| {
        if f.swap(false, Ordering::SeqCst) {
            let rx = gate_rx.lock().unwrap().take().unwrap();
            let _ = rx.recv_timeout(Duration::from_secs(5));
            json_reply(chat_json("m", "slow ok"))
        } else {
            error_reply(429, vec![("retry-after", "120")])
        }
    });
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let base = srv.base.clone();
    let t1 = thread::spawn(move || chat(&client(), &base, "ownerkey", auto_msg()).status().as_u16());
    for _ in 0..50 {
        if p1.hits.load(Ordering::SeqCst) == 1 { break; }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(chat(&client(), &srv.base, "ownerkey", auto_msg()).status(), 429);
    gate_tx.send(()).unwrap();
    assert_eq!(t1.join().unwrap(), 200);
    assert_eq!(chat(&client(), &srv.base, "ownerkey", auto_msg()).status(), 429);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 2, "hard limit survived the concurrent success");
}

#[test]
fn concurrent_soft_failure_does_not_overwrite_a_hard_limit() {
    // call 1 is held in flight and eventually 500s; call 2 sets a hard limit
    // first. call 1's soft failure must NOT shorten or soften it.
    let (gate_tx, gate_rx) = channel::<()>();
    let gate_rx = Mutex::new(Some(gate_rx));
    let first = Arc::new(AtomicBool::new(true));
    let f = first.clone();
    let p1 = mock_upstream(move |_| {
        if f.swap(false, Ordering::SeqCst) {
            let rx = gate_rx.lock().unwrap().take().unwrap();
            let _ = rx.recv_timeout(Duration::from_secs(5));
            error_reply(500, vec![])
        } else {
            error_reply(429, vec![("retry-after", "120")])
        }
    });
    let srv = serve(config(
        vec![provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let base = srv.base.clone();
    let t1 = thread::spawn(move || chat(&client(), &base, "ownerkey", auto_msg()).status().as_u16());
    for _ in 0..50 {
        if p1.hits.load(Ordering::SeqCst) == 1 { break; }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(chat(&client(), &srv.base, "ownerkey", auto_msg()).status(), 429);
    gate_tx.send(()).unwrap();
    assert_eq!(t1.join().unwrap(), 503);
    assert_eq!(chat(&client(), &srv.base, "ownerkey", auto_msg()).status(), 429);
    assert_eq!(p1.hits.load(Ordering::SeqCst), 2, "soft failure never overwrote the hard limit");
}

#[test]
fn dispatch_time_recheck_skips_a_freshly_hard_limited_account() {
    // X walks candidates [P1, P2] from a clean snapshot. While X's P1 attempt
    // is in flight, Y pins a different model on P2 and gets 429+Retry-After.
    // X's P1 fails; X must skip P2 at dispatch time, not call it.
    let (gate_tx, gate_rx) = channel::<()>();
    let gate_rx = Mutex::new(Some(gate_rx));
    let p1 = mock_upstream(move |_| {
        let rx = gate_rx.lock().unwrap().take().unwrap();
        let _ = rx.recv_timeout(Duration::from_secs(5));
        error_reply(500, vec![])
    });
    let p2 = mock_upstream(|_| error_reply(429, vec![("retry-after", "120")]));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None), ("coder-b", "p2/b", None)]),
        ],
        vec!["coder-a"],
    ));
    let base = srv.base.clone();
    let tx = thread::spawn(move || chat(&client(), &base, "ownerkey", auto_msg()).status().as_u16());
    for _ in 0..50 {
        if p1.hits.load(Ordering::SeqCst) == 1 { break; }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(chat(&client(), &srv.base, "ownerkey", pin_msg("coder-b")).status(), 429);
    gate_tx.send(()).unwrap();
    assert_eq!(tx.join().unwrap(), 429, "P1 failed and P2 was hard-limited: truthful 429");
    assert_eq!(p2.hits.load(Ordering::SeqCst), 1, "X never dispatched to the freshly-limited account");
}

// ---------- bounded SSE buffer + aggregate deadline (inherited-risk fix) ----------

#[test]
fn delimiterless_upstream_blob_is_cut_not_buffered_forever() {
    // one endless data: line with no event delimiter: the pending buffer is
    // capped, the committed stream ends honestly (no [DONE]), never a failover
    let blob = format!("data: {}", "x".repeat(1024 * 1024));
    let p1 = mock_upstream(move |_| MockReply {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into())],
        body: blob.clone(),
    });
    let p2 = mock_upstream(|_| json_reply(chat_json("m", "must not be reached")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a"],
    ));
    let payload = serde_json::json!({"model": "auto", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut res = chat(&client(), &srv.base, "ownerkey", payload);
    assert_eq!(res.status(), 200, "headers were committed before the blob arrived");
    let mut received = Vec::new();
    res.body_mut().as_reader().read_to_end(&mut received).unwrap();
    assert!(received.len() <= 256 * 1024 + 8192, "bounded: got {} bytes", received.len());
    assert!(!received.windows(12).any(|w| w == b"data: [DONE]"), "honest truncation: no fake clean end");
    assert_eq!(p2.hits.load(Ordering::SeqCst), 0, "no failover once stream headers are committed");
    assert_eq!(p1.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn aggregate_deadline_bounds_fallback_accumulation() {
    // both providers hang past the budget: the first attempt consumes it and
    // the second is never dispatched (per-upstream timeout must not multiply)
    let hang = |_: &Recorded| {
        thread::sleep(Duration::from_secs(10));
        json_reply(chat_json("m", "too late"))
    };
    let p1 = mock_upstream(hang);
    let p2 = mock_upstream(hang);
    let mut cfg = config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", None)]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", None)]),
        ],
        vec!["coder-a"],
    );
    cfg.upstream_budget = Duration::from_secs(1);
    let srv = serve(cfg);
    let start = Instant::now();
    let res = chat(&client(), &srv.base, "ownerkey", auto_msg());
    let elapsed = start.elapsed();
    assert_eq!(res.status(), 503);
    assert!(elapsed < Duration::from_secs(8), "aggregate budget spent, not multiplied: took {:?}", elapsed);
    assert_eq!(p2.hits.load(Ordering::SeqCst), 0, "no second attempt once the budget is gone");
}

// ---------- sound context rejection ----------

#[test]
fn max_tokens_above_context_is_a_sound_400_without_burning_quota() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let mut cfg = config(
        vec![provider("p1", &up.url, Status::Friends, vec![("coder-a", "p1/a", Some(100))])],
        vec!["coder-a"],
    );
    cfg.daily_limit = 1;
    let srv = serve(cfg);
    let agent = client();
    let too_big = serde_json::json!({"model": "coder-a", "max_tokens": 150, "messages": [{"role": "user", "content": "hi"}]});
    let res = chat(&agent, &srv.base, "ownerkey", too_big);
    assert_eq!(res.status(), 400, "output budget larger than the window can never succeed");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
    // the 400 burned nothing: the one daily slot still routes
    let ok = serde_json::json!({"model": "coder-a", "max_tokens": 50, "messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(chat(&agent, &srv.base, "ownerkey", ok).status(), 200);
}

#[test]
fn context_filter_leaving_only_hard_limited_bindings_429s_without_burning_quota() {
    // p1 fresh but tiny context; p2 big context. First request soft-fails p1
    // then hard-limits p2. A later request whose max_tokens filters p1 out
    // leaves only the deferred hard-limited binding: it must 429 before
    // reserving quota, not burn a daily slot it can never use.
    let p1_calls = Arc::new(AtomicUsize::new(0));
    let n1 = p1_calls.clone();
    let p1 = mock_upstream(move |_| {
        if n1.fetch_add(1, Ordering::SeqCst) == 0 { error_reply(429, vec![]) } else { json_reply(chat_json("m", "small ctx ok")) }
    });
    let p2 = mock_upstream(|_| error_reply(429, vec![("retry-after", "120")]));
    let mut cfg = config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", Some(100))]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", Some(8000))]),
        ],
        vec!["coder-a"],
    );
    cfg.daily_limit = 2;
    let srv = serve(cfg);
    let agent = client();
    // r1: p1 soft-fails, p2 429s with Retry-After -> hard limit installed
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 429);
    assert_eq!(p2.hits.load(Ordering::SeqCst), 1);
    // r2: max_tokens filters p1 (ctx 100) out; only hard-limited p2 remains.
    // 429 before any quota reservation.
    let too_big = serde_json::json!({"model": "coder-a", "max_tokens": 150, "messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(chat(&agent, &srv.base, "ownerkey", too_big).status(), 429);
    assert_eq!(p2.hits.load(Ordering::SeqCst), 1, "hard-limited account is never attempted");
    // the leaked-reservation check: r1 burned one of two daily slots; had r2
    // burned the other, r3 could not route
    assert_eq!(chat(&agent, &srv.base, "ownerkey", auto_msg()).status(), 200, "r2 burned no quota: the second daily slot still routes");
}

#[test]
fn auto_skips_models_whose_context_cannot_hold_the_budget() {
    let p1 = mock_upstream(|_| json_reply(chat_json("m", "small ctx")));
    let p2 = mock_upstream(|_| json_reply(chat_json("m", "big ctx")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-small", "p1/s", Some(100))]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-big", "p2/b", Some(200_000))]),
        ],
        vec!["coder-small", "coder-big"],
    ));
    let payload = serde_json::json!({"model": "auto", "max_tokens": 150, "messages": [{"role": "user", "content": "hi"}]});
    let mut res = chat(&client(), &srv.base, "ownerkey", payload);
    assert_eq!(res.status(), 200);
    assert_eq!(res.body_mut().read_json::<serde_json::Value>().unwrap()["model"], "coder-big");
    assert_eq!(p1.hits.load(Ordering::SeqCst), 0, "too-small window skipped without an upstream call");
}

#[test]
fn unknown_context_means_no_size_rejection() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![provider("p1", &up.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec!["coder-a"],
    ));
    let payload = serde_json::json!({"model": "coder-a", "max_tokens": 999_999, "messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(chat(&client(), &srv.base, "ownerkey", payload).status(), 200, "no metadata: nothing estimated, upstream decides");
}

// ---------- models listing ----------

#[test]
fn models_list_dedupes_canonical_names_and_exposes_context() {
    let p1 = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let p2 = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![
            provider("p1", &p1.url, Status::Friends, vec![("coder-a", "p1/a", Some(128_000))]),
            provider("p2", &p2.url, Status::Friends, vec![("coder-a", "p2/a", Some(128_000)), ("writer-b", "p2/b", None)]),
        ],
        vec!["coder-a"],
    ));
    let mut res = client().get(&format!("{}/v1/models", srv.base)).header("authorization", "Bearer friendkey").call().unwrap();
    let body: serde_json::Value = res.body_mut().read_json().unwrap();
    let data = body["data"].as_array().unwrap();
    let ids: Vec<&str> = data.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(ids.iter().filter(|i| **i == "coder-a").count(), 1, "canonical model listed once");
    assert!(ids.contains(&"writer-b"));
    assert!(ids.contains(&"auto"), "shortlist configured: auto advertised");
    let entry = data.iter().find(|m| m["id"] == "coder-a").unwrap();
    assert_eq!(entry["context"], 128_000);
    assert!(!body.to_string().contains("p1"));
    assert!(!body.to_string().contains("p2"));
}

#[test]
fn models_list_hides_auto_without_a_shortlist() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(
        vec![provider("p1", &up.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec![],
    ));
    let mut res = client().get(&format!("{}/v1/models", srv.base)).header("authorization", "Bearer friendkey").call().unwrap();
    let body: serde_json::Value = res.body_mut().read_json().unwrap();
    let ids: Vec<&str> = body["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(!ids.contains(&"auto"), "unroutable alias must not be advertised");
    assert!(ids.contains(&"coder-a"));
}

// ---------- config intake (pure) ----------

#[test]
fn shortlist_and_meta_parsing_reject_junk_and_reserved_names() {
    let shortlist = aqua::parse_shortlist(Some(" coder-a ,,auto,coder-b ".into()));
    assert_eq!(shortlist, vec!["coder-a".to_string(), "coder-b".to_string()], "the reserved alias can never be a shortlist entry");
    let meta = aqua::parse_model_meta(Some("coder-a=128000,bad=,junk,coder-b=0,coder-c=64000,auto=1".into()));
    assert_eq!(meta.get("coder-a"), Some(&128_000));
    assert_eq!(meta.get("coder-c"), Some(&64_000));
    assert_eq!(meta.len(), 2, "zero, junk and reserved entries dropped");
}

#[test]
fn sanitize_drops_reserved_duplicate_and_provider_named_entries() {
    let meta: HashMap<String, u32> = [("coder-a".to_string(), 128_000u32)].into_iter().collect();
    let entries = vec![
        ModelEntry { public: "coder-a".into(), upstream: "real/a".into(), context: None },
        ModelEntry { public: "coder-a".into(), upstream: "real/a-dup".into(), context: None },
        ModelEntry { public: "auto".into(), upstream: "secretp/free".into(), context: None },
        ModelEntry { public: "secretp-special".into(), upstream: "real/x".into(), context: None },
        ModelEntry { public: " ".into(), upstream: "real/y".into(), context: None },
    ];
    let out = aqua::sanitize_models("secretp", entries, &meta);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].public, "coder-a");
    assert_eq!(out[0].context, Some(128_000), "verified metadata attaches by public name");
}

fn spend_cfg(up: &str) -> Config {
    let mut cfg = config(vec![provider("p1", up, Status::Friends, vec![("coder-a", "p1/a", Some(10))])], vec!["coder-a"]);
    cfg.spend.enabled = true;
    cfg.spend.prices.insert("coder-a".into(), aqua::ModelPrice { input: 1_000_000_000, output: 1_000_000_000 });
    cfg.spend.default_caps = aqua::SpendCaps { daily: 20_000, monthly: 40_000 };
    cfg
}

#[test]
fn spend_friend_cap_stops_at_boundary_but_owner_is_uncapped_and_usage_visible() {
    let up = mock_upstream(|_| json_reply(serde_json::json!({"model":"m", "choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}], "usage":{"prompt_tokens":10,"completion_tokens":10}})));
    let srv = serve(spend_cfg(&up.url));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "friendkey", pin_msg("coder-a")).status(), 200);
    let mut denied = chat(&agent, &srv.base, "friendkey", pin_msg("coder-a"));
    assert_eq!(denied.status(), 429);
    assert_eq!(denied.body_mut().read_json::<serde_json::Value>().unwrap()["error"]["code"], "spend_cap_exceeded");
    for _ in 0..3 { assert_eq!(chat(&agent, &srv.base, "ownerkey", pin_msg("coder-a")).status(), 200); }
    let mut usage = agent.get(&format!("{}/v1/admin/usage", srv.base)).header("authorization", "Bearer adminsecret").call().unwrap();
    assert_eq!(usage.status(), 200);
    let data = usage.body_mut().read_json::<serde_json::Value>().unwrap();
    assert!(data["users"]["luke"]["cap"].is_null());
    assert_eq!(data["users"]["luke"]["day"]["models"]["coder-a"]["confirmed"], 60_000);
    assert_eq!(agent.get(&format!("{}/v1/admin/usage", srv.base)).header("authorization", "Bearer friendkey").call().unwrap().status(), 401);
}

#[test]
fn spend_expensive_tier_is_hidden_and_forbidden_for_friends_not_owner() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let mut cfg = spend_cfg(&up.url);
    cfg.spend.prices.insert("coder-a".into(), aqua::ModelPrice { input: 1_000_000_000, output: 10_000_000_000 });
    let srv = serve(cfg);
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "friendkey", pin_msg("coder-a")).status(), 403);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", pin_msg("coder-a")).status(), 200);
    let mut models = agent.get(&format!("{}/v1/models", srv.base)).header("authorization", "Bearer friendkey").call().unwrap();
    let data = models.body_mut().read_json::<serde_json::Value>().unwrap();
    assert!(!data["data"].as_array().unwrap().iter().any(|m|m["id"]=="coder-a"));
}

#[test]
fn spend_missing_usage_keeps_hold_and_missing_context_fails_closed_for_friend() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(spend_cfg(&up.url));
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "friendkey", pin_msg("coder-a")).status(), 200);
    assert_eq!(chat(&agent, &srv.base, "friendkey", pin_msg("coder-a")).status(), 429);
    let mut cfg = spend_cfg(&up.url);
    cfg.providers[0].models[0].context = None;
    let srv2 = serve(cfg);
    assert_eq!(chat(&agent, &srv2.base, "friendkey", pin_msg("coder-a")).status(), 503);
    assert_eq!(chat(&agent, &srv2.base, "ownerkey", pin_msg("coder-a")).status(), 200);
}

#[test]
fn spend_admin_can_persist_caps_and_friends_cannot_change_them() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(spend_cfg(&up.url));
    let agent = client();
    let endpoint = format!("{}/v1/admin/caps", srv.base);
    let body = serde_json::json!({"name":"sam", "daily":"0", "monthly":"0"});
    assert_eq!(agent.post(&endpoint).header("authorization", "Bearer friendkey").send_json(&body).unwrap().status(), 401);
    assert_eq!(agent.post(&endpoint).header("authorization", "Bearer adminsecret").send_json(&body).unwrap().status(), 200);
    assert_eq!(chat(&agent, &srv.base, "friendkey", pin_msg("coder-a")).status(), 429);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", pin_msg("coder-a")).status(), 200);
}

#[test]
fn spend_denial_does_not_burn_request_quota() {
    let up = mock_upstream(|_| json_reply(serde_json::json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}})));
    let mut cfg = spend_cfg(&up.url);
    cfg.daily_limit = 1;
    cfg.spend.default_caps = aqua::SpendCaps { daily:0, monthly:0 };
    let srv = serve(cfg);
    let agent = client();
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),429);
    assert_eq!(up.hits.load(Ordering::SeqCst),0);
    assert_eq!(agent.post(&format!("{}/v1/admin/caps",srv.base)).header("authorization","Bearer adminsecret").send_json(serde_json::json!({"name":"sam","daily":"2","monthly":"15"})).unwrap().status(),200);
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),200);
}

#[test]
fn spend_stream_requests_usage_and_settles_only_a_terminal_report() {
    let up = mock_upstream(|rec| {
        assert_eq!(rec.body["stream_options"]["include_usage"],true);
        MockReply { status:200, headers:vec![("content-type".into(),"text/event-stream".into())], body:"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\ndata: [DONE]\n\n".into() }
    });
    let srv=serve(spend_cfg(&up.url));
    let agent=client();
    let mut body=pin_msg("coder-a"); body["stream"]=serde_json::json!(true);
    let mut res=chat(&agent,&srv.base,"friendkey",body);
    assert!(res.body_mut().read_to_string().unwrap().contains("[DONE]"));
    let data:serde_json::Value=agent.get(&format!("{}/v1/admin/usage",srv.base)).header("authorization","Bearer adminsecret").call().unwrap().body_mut().read_json().unwrap();
    assert_eq!(data["users"]["sam"]["day"]["models"]["coder-a"]["confirmed"],2000);
    assert_eq!(data["users"]["sam"]["day"]["models"]["coder-a"]["held"],0);
}

#[test]
fn spend_stream_truncated_after_partial_usage_retains_the_full_hold() {
    let up=mock_upstream(|_|MockReply {status:200,headers:vec![("content-type".into(),"text/event-stream".into())],body:"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n".into()});
    let srv=serve(spend_cfg(&up.url)); let agent=client();
    let mut body=pin_msg("coder-a"); body["stream"]=serde_json::json!(true);
    let _=chat(&agent,&srv.base,"friendkey",body).body_mut().read_to_string().unwrap();
    let data:serde_json::Value=agent.get(&format!("{}/v1/admin/usage",srv.base)).header("authorization","Bearer adminsecret").call().unwrap().body_mut().read_json().unwrap();
    assert_eq!(data["users"]["sam"]["day"]["models"]["coder-a"]["held"],20000);
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),429);
}

#[test]
fn spend_parallel_http_requests_share_one_atomic_account_budget() {
    let gate=Arc::new((Mutex::new(false),std::sync::Condvar::new())); let g=gate.clone();
    let up=mock_upstream(move |_| { let(lock,cv)=&*g;let mut open=lock.lock().unwrap();while !*open {open=cv.wait(open).unwrap();} json_reply(serde_json::json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":10}})) });
    let srv=serve(spend_cfg(&up.url)); let base=srv.base.clone();
    let first=thread::spawn(move ||chat(&client(),&base,"friendkey",pin_msg("coder-a")).status());
    let deadline=Instant::now()+Duration::from_secs(2);
    while up.hits.load(Ordering::SeqCst)==0 { assert!(Instant::now()<deadline);thread::yield_now(); }
    assert_eq!(chat(&client(),&srv.base,"friendkey",pin_msg("coder-a")).status(),429);
    {let(lock,cv)=&*gate;*lock.lock().unwrap()=true;cv.notify_all();}
    assert_eq!(first.join().unwrap(),200);
    assert_eq!(up.hits.load(Ordering::SeqCst),1);
}

// ---------- shutdown drain ----------

#[test]
fn server_drop_lets_an_in_flight_request_finish() {
    let (entered_tx, entered_rx) = channel();
    let (release_tx, release_rx) = channel();
    let release_rx = Mutex::new(Some(release_rx));
    let up = mock_upstream(move |_| {
        entered_tx.send(()).unwrap();
        release_rx.lock().unwrap().take().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        json_reply(chat_json("real", "ok"))
    });
    let srv = serve(config(
        vec![provider("p1", &up.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec![],
    ));
    let expected_body = chat_json("real", "ok").to_string();
    let base = srv.base.clone();
    let client_thread = thread::spawn(move || {
        let mut res = chat(&client(), &base, "ownerkey", pin_msg("coder-a"));
        (res.status(), res.body_mut().read_to_string().unwrap())
    });
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let drop_thread = thread::spawn(move || drop(srv));
    thread::sleep(Duration::from_millis(100));
    assert!(!drop_thread.is_finished(), "drop must wait for the in-flight handler");
    release_tx.send(()).unwrap();
    let (status, body) = client_thread.join().unwrap();
    assert_eq!(status, 200);
    // The gateway rewrites id/model/created, so assert the complete body
    // field-wise: valid JSON in full (no truncation) with the upstream's
    // choices and usage carried through intact.
    let sent: serde_json::Value = serde_json::from_str(&expected_body).unwrap();
    let got: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(got["choices"], sent["choices"]);
    assert_eq!(got["usage"], sent["usage"]);
    assert_eq!(got["model"], "coder-a");
    assert!(got["created"].as_u64().unwrap() > 0);
    drop_thread.join().unwrap();
}

#[test]
fn server_drop_waits_for_a_counted_blocked_handler() {
    // Counting test: a raw connection that never sends a byte keeps its
    // handler blocked in read_request while counted, and drop waits out the
    // drain window for it. The increment-before-spawn ordering itself is
    // covered by the synchronous unit tests in src/server.rs, not here.
    let mut srv = serve(config(vec![], vec![]));
    srv._h.set_drain_timeout(Duration::from_millis(300));
    let raw = TcpStream::connect(srv.base.trim_start_matches("http://")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while srv._h.in_flight() != 1 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(srv._h.in_flight(), 1, "the accepted connection must be counted");
    let started = Instant::now();
    drop(srv);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "drop must wait out the drain window for the counted handler, took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "drop must still be bounded, took {elapsed:?}");
    drop(raw);
}

#[test]
fn slow_client_gets_408_connection_close_and_burns_no_state() {
    let up=mock_upstream(|_|json_reply(chat_json("real","ok")));
    let srv=serve(spend_cfg(&up.url));
    srv._h.set_request_read_budget(Duration::from_millis(300));
    let mut raw=TcpStream::connect(srv.base.trim_start_matches("http://")).unwrap();
    // Fixture-side cap so a regression hangs this read for seconds, not forever.
    raw.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    raw.write_all(b"POST /v1/chat/completions HTTP/1.1\r\nauthorization: Bearer friendkey\r\ncontent-length: 50\r\n\r\n{}").unwrap();
    // read_to_string only returns at EOF: the server must close after the 408
    // (responses already carry connection: close; there is no keep-alive).
    let mut resp=String::new();
    raw.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 408"),"got: {resp:?}");
    assert!(resp.contains("connection: close"),"got: {resp:?}");
    assert_eq!(up.hits.load(Ordering::SeqCst),0,"a timed-out request must never reach a provider");
    let agent=client();
    let usage:serde_json::Value=agent.get(&format!("{}/v1/admin/usage",srv.base)).header("authorization","Bearer adminsecret").call().unwrap().body_mut().read_json().unwrap();
    assert!(usage["users"].as_object().unwrap().is_empty(),"a timed-out request must not record usage: {usage}");
}

#[test]
fn server_drop_returns_within_the_drain_window_when_a_handler_is_stuck() {
    let (entered_tx, entered_rx) = channel();
    let (release_tx, release_rx) = channel();
    let release_rx = Mutex::new(Some(release_rx));
    let up = mock_upstream(move |_| {
        entered_tx.send(()).unwrap();
        release_rx.lock().unwrap().take().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        json_reply(chat_json("real", "ok"))
    });
    let mut srv = serve(config(
        vec![provider("p1", &up.url, Status::Friends, vec![("coder-a", "p1/a", None)])],
        vec![],
    ));
    srv._h.set_drain_timeout(Duration::from_millis(200));
    let base = srv.base.clone();
    let client_thread = thread::spawn(move || chat(&client(), &base, "ownerkey", pin_msg("coder-a")).status());
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let started = std::time::Instant::now();
    drop(srv);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(200), "drop must wait out the drain window, took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "a stuck handler must not block drop past the window, took {elapsed:?}");
    // The detached handler still completes its response after drop returned.
    release_tx.send(()).unwrap();
    assert_eq!(client_thread.join().unwrap(), 200);
}

#[test]
fn spend_http_cap_edit_and_usage_survive_server_restart() {
    let up=mock_upstream(|_|json_reply(serde_json::json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":10}})));
    let path=std::env::temp_dir().join(format!("aqua-http-ledger-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let mut cfg=spend_cfg(&up.url);cfg.spend.path=Some(path.clone());
    {
        let srv=serve(cfg.clone());let agent=client();
        assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),200);
        assert_eq!(agent.post(&format!("{}/v1/admin/caps",srv.base)).header("authorization","Bearer adminsecret").send_json(serde_json::json!({"name":"sam","daily":"0.00003","monthly":"0.00003"})).unwrap().status(),200);
    }
    let srv=serve_restart(cfg);let agent=client();
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),429);
    let data:serde_json::Value=agent.get(&format!("{}/v1/admin/usage",srv.base)).header("authorization","Bearer adminsecret").call().unwrap().body_mut().read_json().unwrap();
    assert_eq!(data["users"]["sam"]["cap"]["daily"],30000);
    assert_eq!(data["users"]["sam"]["day"]["models"]["coder-a"]["confirmed"],20000);
    drop(srv);let _=std::fs::remove_file(path);
}

// Deterministic controls for serve_restart's lock-contention polling. No
// sleeps decide outcomes: a lock is released only after a contended attempt is
// observed through on_error, and attempt counts assert the poll behavior.
fn restart_ctl_cfg(up_url: &str) -> (Config, std::path::PathBuf) {
    let path=std::env::temp_dir().join(format!("aqua-restart-ctl-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let mut cfg=spend_cfg(up_url);cfg.spend.path=Some(path.clone());
    (cfg,path)
}

fn hold_state_lock(path: &std::path::Path) -> std::fs::File {
    let held=std::fs::OpenOptions::new().read(true).write(true).create(true).open(path.with_extension("lock")).unwrap();
    held.try_lock().unwrap();
    held
}

#[test]
fn serve_restart_succeeds_when_held_state_lock_releases_mid_poll() {
    let up=mock_upstream(|_|json_reply(chat_json("real","ok")));
    let (cfg,path)=restart_ctl_cfg(&up.url);
    let held=hold_state_lock(&path);
    let (observed_tx,observed_rx)=channel();
    let releaser=thread::spawn(move || { observed_rx.recv_timeout(Duration::from_secs(5)).unwrap(); drop(held); });
    let mut observed=Some(observed_tx);
    let mut contended=0u64;
    let mut on_error=|e: &std::io::Error| {
        if is_state_lock_contention(e) {
            contended+=1;
            if let Some(tx)=observed.take() { let _=tx.send(()); }
        }
    };
    let srv=serve_restart_within(cfg,Duration::from_secs(5),&mut on_error).unwrap();
    assert!(contended>=1,"the lock must be released only after at least one observed contended attempt");
    assert_eq!(chat(&client(),&srv.base,"friendkey",pin_msg("coder-a")).status(),200);
    releaser.join().unwrap();
    drop(srv);let _=std::fs::remove_file(&path);let _=std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn serve_restart_persistent_lock_fails_at_deadline_with_contention_error() {
    let up=mock_upstream(|_|json_reply(chat_json("real","ok")));
    let (cfg,path)=restart_ctl_cfg(&up.url);
    let _held=hold_state_lock(&path);
    let started=std::time::Instant::now();
    let mut attempts=0u64;
    let err=serve_restart_within(cfg,Duration::from_millis(400),&mut |_: &std::io::Error| attempts+=1).err().expect("persistent lock must fail the bind");
    assert!(started.elapsed()>=Duration::from_millis(400),"contention must be retried until the deadline");
    assert!(attempts>=2,"persistent contention must be polled, got {attempts} attempt(s)");
    assert!(is_state_lock_contention(&err),"final error must be the lock contention, got {err:?}");
    let _=std::fs::remove_file(&path);let _=std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn serve_restart_does_not_retry_non_lock_errors() {
    let up=mock_upstream(|_|json_reply(chat_json("real","ok")));
    let missing_dir=std::env::temp_dir().join(format!("aqua-restart-ctl-missing-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let mut cfg=spend_cfg(&up.url);cfg.spend.path=Some(missing_dir.join("state.json"));
    let mut attempts=0u64;
    let err=serve_restart_within(cfg,Duration::from_millis(400),&mut |_: &std::io::Error| attempts+=1).err().expect("missing state dir must fail the bind");
    assert_eq!(attempts,1,"non-lock error must be attempted exactly once, never polled");
    assert_eq!(err.kind(),std::io::ErrorKind::NotFound,"got {err:?}");
    assert!(!is_state_lock_contention(&err),"non-lock error must not be classified as contention, got {err:?}");
}

// Mutation controls: each mutant is a one-line behavior change to the poll
// loop, and the named control kills it.
fn mutant_no_retry(cfg: Config) -> std::io::Result<Running> {
    // MUTANT: never retries, so the mid-poll release control's success fails.
    aqua::bind(cfg).map(|s| Running { base: format!("http://127.0.0.1:{}", s.port()), _h: s })
}

fn mutant_broad_retry(cfg: Config, timeout: Duration, on_error: &mut dyn FnMut(&std::io::Error)) -> std::io::Result<Running> {
    // MUTANT: retries every bind error, so the non-lock control's
    // single-attempt assertion fails.
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match aqua::bind(cfg.clone()) {
            Ok(s) => return Ok(Running { base: format!("http://127.0.0.1:{}", s.port()), _h: s }),
            Err(e) if std::time::Instant::now() < deadline => {
                on_error(&e);
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
}

#[test]
fn mutation_no_retry_is_killed_by_the_mid_poll_release_control() {
    let up=mock_upstream(|_|json_reply(chat_json("real","ok")));
    let (cfg,path)=restart_ctl_cfg(&up.url);
    let held=hold_state_lock(&path);
    // Same scenario as the release control: the mutant errors out while the
    // lock is still held, where the control asserts success. Mutant killed.
    let err=mutant_no_retry(cfg.clone()).err().expect("mutant must fail while the lock is held");
    assert!(is_state_lock_contention(&err));
    drop(held);
    let srv=serve_restart(cfg);
    assert_eq!(chat(&client(),&srv.base,"friendkey",pin_msg("coder-a")).status(),200);
    drop(srv);let _=std::fs::remove_file(&path);let _=std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn mutation_broad_retry_is_killed_by_the_non_lock_control() {
    let up=mock_upstream(|_|json_reply(chat_json("real","ok")));
    let missing_dir=std::env::temp_dir().join(format!("aqua-restart-ctl-mutant-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let mut cfg=spend_cfg(&up.url);cfg.spend.path=Some(missing_dir.join("state.json"));
    // Same scenario as the non-lock control: the mutant polls a non-lock
    // error past one attempt, where the control asserts attempts == 1. Mutant
    // killed.
    let mut attempts=0u64;
    let err=mutant_broad_retry(cfg,Duration::from_millis(300),&mut |_: &std::io::Error| attempts+=1).err().expect("missing state dir must fail the bind");
    assert!(attempts>1,"mutant must poll the non-lock error, got {attempts} attempt(s)");
    assert_eq!(err.kind(),std::io::ErrorKind::NotFound,"got {err:?}");
}

#[test]
fn spend_owner_stays_uncapped_on_storage_failure_but_usage_gap_is_visible() {
    let up=mock_upstream(|_|json_reply(serde_json::json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}})));
    let dir=std::env::temp_dir().join(format!("aqua-storage-fault-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));std::fs::create_dir(&dir).unwrap();
    let mut cfg=spend_cfg(&up.url);cfg.spend.path=Some(dir.join("state.json"));let srv=serve(cfg);
    std::fs::remove_file(dir.join("state.lock")).unwrap();std::fs::remove_file(dir.join("state.keys.lock")).unwrap();std::fs::remove_dir(&dir).unwrap();
    let agent=client();assert_eq!(chat(&agent,&srv.base,"ownerkey",pin_msg("coder-a")).status(),200);
    let data:serde_json::Value=agent.get(&format!("{}/v1/admin/usage",srv.base)).header("authorization","Bearer adminsecret").call().unwrap().body_mut().read_json().unwrap();
    assert_eq!(data["accounting_available"],false);
    assert_eq!(data["unknown_owner_requests_since_startup"],1);
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),503);
}

#[test]
fn spend_upstream_server_error_is_ambiguous_and_keeps_the_hold() {
    let up=mock_upstream(|_|MockReply{status:500,headers:vec![],body:"failure".into()});let srv=serve(spend_cfg(&up.url));let agent=client();
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("coder-a")).status(),503);
    let data:serde_json::Value=agent.get(&format!("{}/v1/admin/usage",srv.base)).header("authorization","Bearer adminsecret").call().unwrap().body_mut().read_json().unwrap();
    assert_eq!(data["users"]["sam"]["day"]["models"]["coder-a"]["held"],20000);
}

// Intake adapter limits must be account-wide and last through response consumption.
#[test]
fn zai_parallel_models_share_one_slot_and_release_after_json() {
    let (entered_tx, entered_rx) = channel();
    let (release_tx, release_rx) = channel();
    let release_rx = Mutex::new(Some(release_rx));
    let first = AtomicBool::new(true);
    let up = mock_upstream(move |_| {
        if first.swap(false, Ordering::SeqCst) {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().take().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        }
        json_reply(chat_json("glm-4.7-flash", "ok"))
    });
    let mut cfg=config(vec![provider("zai", &up.url, Status::Personal, vec![("glm-4.7-flash", "glm-4.7-flash", None), ("glm-4.5-flash", "glm-4.5-flash", None)])],vec![]);
    cfg.daily_limit=2; // first + third succeed; local busy must refund request quota.
    let srv = serve(cfg);
    let base=srv.base.clone();
    let first=thread::spawn(move || chat(&client(),&base,"ownerkey",pin_msg("glm-4.7-flash")).status());
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let second=chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.5-flash"));
    release_tx.send(()).unwrap();
    assert_eq!(second.status(),503,"busy account must not receive a parallel request for another model");
    assert!(second.headers().get("retry-after").is_none(),"local busy state supplies no made-up Retry-After");
    assert_eq!(first.join().unwrap(),200);
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.7-flash")).status(),200);
    assert_eq!(up.hits.load(Ordering::SeqCst),2,"blocked request must not reach the provider");
}

#[test]
fn zai_stream_slot_lasts_until_upstream_body_finishes() {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    let (entered_tx,entered_rx)=channel();
    let (release_tx,release_rx)=channel();
    let release_rx=Arc::new(Mutex::new(Some(release_rx)));
    let hits=Arc::new(AtomicUsize::new(0));let h=hits.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream=stream.unwrap();let h=h.clone();let entered_tx=entered_tx.clone();let gate=release_rx.clone();
            thread::spawn(move || {
                read_request(&mut stream);
                if h.fetch_add(1,Ordering::SeqCst)==0 {
                    stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n").unwrap();stream.flush().unwrap();
                    entered_tx.send(()).unwrap();
                    gate.lock().unwrap().take().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
                    stream.write_all(b"data: [DONE]\n\n").unwrap();
                } else {
                    let body=chat_json("glm-4.7-flash","ok").to_string();
                    write!(stream,"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",body.len(),body).unwrap();
                }
            });
        }
    });
    let srv=serve(config(vec![provider("zai",&url,Status::Personal,vec![("glm-4.7-flash","glm-4.7-flash",None)])],vec![]));
    let mut payload=pin_msg("glm-4.7-flash");payload["stream"]=true.into();
    let mut first=chat(&client(),&srv.base,"ownerkey",payload);assert_eq!(first.status(),200);
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let second=chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.7-flash"));
    release_tx.send(()).unwrap();
    assert_eq!(second.status(),503,"headers alone must not release the slot");
    assert!(first.body_mut().read_to_string().unwrap().contains("[DONE]"));
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.7-flash")).status(),200);
    assert_eq!(hits.load(Ordering::SeqCst),2);
}

#[test]
fn zai_failed_attempt_releases_slot_for_next_request() {
    let first=AtomicBool::new(true);
    let up=mock_upstream(move |_| if first.swap(false,Ordering::SeqCst){error_reply(500,vec![])}else{json_reply(chat_json("glm-4.7-flash","ok"))});
    let srv=serve(config(vec![provider("zai",&up.url,Status::Personal,vec![("glm-4.7-flash","glm-4.7-flash",None)])],vec![]));
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.7-flash")).status(),503);
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.7-flash")).status(),200);
}

#[test]
fn intake_model_sanitizer_rejects_unqualified_and_paid_routes() {
    let model=|public:&str,upstream:&str|ModelEntry{public:public.into(),upstream:upstream.into(),context:None};
    let meta=HashMap::new();
    let zai=aqua::sanitize_models("zai",vec![model("glm-4.7-flash","glm-4.7-flash"),model("glm-4.5-flash","glm-4.5-flash"),model("glm-4.7-flashx","glm-4.7-flashx"),model("glm-5.3-flash","glm-5.3-flash")],&meta);
    assert_eq!(zai.len(),2,"only the exact free standard API models may be configured");
    let orca=aqua::sanitize_models("orcarouter",vec![model("deepseek-v4.1-flash","deepseek/deepseek-v4.1-flash-free"),model("paid","deepseek/deepseek-v4.1-flash"),model("untested","tencent/hy4-preview-free")],&meta);
    assert_eq!(orca.len(),1);
    let infer=aqua::sanitize_models("inferbase",vec![model("deepseek-v4-flash:fp8","deepseek-v4-flash"),model("other","deepseek-v4-pro")],&meta);
    assert_eq!(infer.len(),1);assert_eq!(infer[0].public,"deepseek-v4-flash:fp8","returned build stays distinct from unsuffixed model");
}

#[test]
fn zai_busy_uses_only_exact_model_fallback_without_waiting_or_retrying() {
    let (entered_tx,entered_rx)=channel();let (release_tx,release_rx)=channel();
    let release_rx=Mutex::new(Some(release_rx));let first=AtomicBool::new(true);
    let up=mock_upstream(move |_| {
        if first.swap(false,Ordering::SeqCst) {
            entered_tx.send(()).unwrap();release_rx.lock().unwrap().take().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        }
        json_reply(chat_json("glm-4.7-flash","ok"))
    });
    let fallback=mock_upstream(|_|json_reply(chat_json("same-model","ok")));
    let srv=serve(config(vec![provider("zai",&up.url,Status::Personal,vec![("glm-4.7-flash","glm-4.7-flash",None)]),provider("fallback",&fallback.url,Status::Personal,vec![("glm-4.7-flash","same-model",None)])],vec![]));
    let base=srv.base.clone();let first=thread::spawn(move ||chat(&client(),&base,"ownerkey",pin_msg("glm-4.7-flash")).status());
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let second=chat(&client(),&srv.base,"ownerkey",pin_msg("glm-4.7-flash"));release_tx.send(()).unwrap();
    assert_eq!(second.status(),200);assert_eq!(fallback.hits.load(Ordering::SeqCst),1);assert_eq!(up.hits.load(Ordering::SeqCst),1);
    assert_eq!(first.join().unwrap(),200);
}



#[test]
fn wave2_cloudflare_unknown_token_bound_never_dispatches() {
    let up=mock_upstream(|_|json_reply(chat_json("raw","ok")));
    let srv=serve(config(vec![provider("cloudflare",&up.url,Status::Friends,vec![("glm","@cf/zai-org/glm-4.7-flash",None)])],vec![]));
    let r=chat(&client(),&srv.base,"ownerkey",pin_msg("glm"));
    assert_eq!(r.status(),503);
    assert_eq!(up.hits.load(Ordering::SeqCst),0);
}

#[test]
fn wave2_openrouter_paid_or_unlisted_route_never_dispatches() {
    for model in ["paid/model","openrouter/free","other/model:free"] {
        let up=mock_upstream(|_|json_reply(chat_json("raw","ok")));
        let srv=serve(config(vec![provider("openrouter",&up.url,Status::Friends,vec![("candidate",model,None)])],vec![]));
        let r=chat(&client(),&srv.base,"ownerkey",pin_msg("candidate"));
        assert_eq!(r.status(),503);
        assert_eq!(up.hits.load(Ordering::SeqCst),0);
    }
}

#[test]
fn wave2_openrouter_missing_current_remote_allowance_never_dispatches() {
    let up=mock_upstream(|_|json_reply(chat_json("raw","ok")));
    let srv=serve(config(vec![provider("openrouter",&up.url,Status::Friends,vec![("candidate","cohere/north-mini-code:free",None)])],vec![]));
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("candidate")).status(),503);
    assert_eq!(up.hits.load(Ordering::SeqCst),0);
}

fn wave2_config(up:&Mock,path:&std::path::Path)->Config {
    let mut cfg=config(vec![provider("openrouter",&up.url,Status::Friends,vec![("candidate","cohere/north-mini-code:free",None)])],vec![]);
    cfg.spend.path=Some(path.into());
    cfg.spend.account_verified_day=String::from_utf8(std::process::Command::new("date").args(["-u","+%Y-%m-%d"]).output().unwrap().stdout).unwrap().trim().into();
    cfg.spend.openrouter_allowance=4;
    cfg
}
fn wave2_path()->std::path::PathBuf {
    std::env::temp_dir().join(format!("aqua-account-{}-{}.json",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))
}
#[test]
fn wave2_shared_calls_survive_restart_and_errors_without_usage() {
    let up=mock_upstream(|_|error_reply(400,vec![]));
    let path=wave2_path();
    for key in ["ownerkey","friendkey","ownerkey","ownerkey","ownerkey"] {
        let srv=serve_restart(wave2_config(&up,&path));
        assert_eq!(chat(&client(),&srv.base,key,pin_msg("candidate")).status(),503);
    }
    assert_eq!(up.hits.load(Ordering::SeqCst),4);
    let _=std::fs::remove_file(&path);let _=std::fs::remove_file(path.with_extension("lock"));
}
#[test]
fn wave2_free_route_forces_zero_price_defaults_and_rejects_output_bounds() {
    let up=mock_upstream(|_|json_reply(chat_json("raw","ok")));let path=wave2_path();
    let srv=serve(wave2_config(&up,&path));
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("candidate")).status(),200);
    let body=up.requests.lock().unwrap()[0].body.clone();
    assert_eq!(body["provider"],serde_json::json!({"allow_fallbacks":false,"require_parameters":true,"max_price":{"prompt":0,"completion":0}}));
    assert_eq!(body["max_tokens"],512);assert_eq!(body["n"],1);
    for extra in [serde_json::json!({"max_tokens":1025}),serde_json::json!({"n":2}),serde_json::json!({"tools":[]})] {
        let mut payload=pin_msg("candidate");payload.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        assert_eq!(chat(&client(),&srv.base,"ownerkey",payload).status(),503);
    }
    assert_eq!(up.hits.load(Ordering::SeqCst),1);
    drop(srv);let _=std::fs::remove_file(&path);let _=std::fs::remove_file(path.with_extension("lock"));
}
#[test]
fn wave2_concurrent_last_slot_is_reserved_before_upstream_and_streams_count() {
    let (tx,rx)=channel();let rx=Arc::new(Mutex::new(rx));let gate=rx.clone();
    let up=mock_upstream(move |_| {gate.lock().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();MockReply {status:200,headers:vec![("content-type".into(),"text/event-stream".into())],body:"data: {\"choices\":[]}\n\ndata: [DONE]\n\n".into()}});
    let path=wave2_path();let mut cfg=wave2_config(&up,&path);cfg.spend.openrouter_allowance=1;
    let srv=serve(cfg);let base=srv.base.clone();
    let worker=thread::spawn(move|| {let mut payload=pin_msg("candidate");payload["stream"]=true.into();let mut r=chat(&client(),&base,"ownerkey",payload);let status=r.status().as_u16();let _=r.body_mut().read_to_string();status});
    let deadline=Instant::now()+Duration::from_secs(3);while up.hits.load(Ordering::SeqCst)==0 {assert!(Instant::now()<deadline);thread::yield_now();}
    assert_eq!(chat(&client(),&srv.base,"friendkey",pin_msg("candidate")).status(),503);
    tx.send(()).unwrap();assert_eq!(worker.join().unwrap(),200);
    assert_eq!(chat(&client(),&srv.base,"ownerkey",pin_msg("candidate")).status(),503);
    assert_eq!(up.hits.load(Ordering::SeqCst),1);
    drop(srv);let _=std::fs::remove_file(&path);let _=std::fs::remove_file(path.with_extension("lock"));
}
#[test]
fn wave2_stale_allowance_and_held_cloudflare_are_not_advertised() {
    let up=mock_upstream(|_|json_reply(chat_json("raw","ok")));let path=wave2_path();
    let mut cfg=wave2_config(&up,&path);cfg.spend.account_verified_day="2026-01-01".into();
    cfg.providers.push(provider("cloudflare",&up.url,Status::Friends,vec![("glm","@cf/zai-org/glm-4.7-flash",None)]));
    let srv=serve(cfg);let mut r=client().get(&format!("{}/v1/models",srv.base)).header("authorization","Bearer friendkey").call().unwrap();
    let body=r.body_mut().read_json::<serde_json::Value>().unwrap();assert_eq!(body["data"],serde_json::json!([]));
    assert_eq!(up.hits.load(Ordering::SeqCst),0);
}

// These break if display prices are omitted, guessed for unknown models, or use
// the internal accounting fallback instead of a sourced maker tariff.
#[test]
fn catalog_exposes_sourced_maker_prices_without_route_identity() {
    let up = mock_upstream(|_| panic!("catalog must not invoke upstream"));
    let srv = serve(config(vec![provider("private-lane", &up.url, Status::Friends, vec![
        ("glm-4.7-flash", "secret-route", None),
        ("deepseek-v4.1-flash-1017", "secret-snapshot", None),
        ("unknown-model", "secret-unknown", None),
    ])], vec![]));
    let mut res = client().get(&format!("{}/v1/models",srv.base)).header("authorization","Bearer ownerkey").call().unwrap();
    let body=res.body_mut().read_json::<serde_json::Value>().unwrap();
    let rows=body["data"].as_array().unwrap();
    let free=&rows[0]["maker_pricing"];
    assert_eq!(free["status"],"verified");
    assert_eq!(free["input_nano_usd_per_million"],0);
    assert_eq!(free["output_nano_usd_per_million"],0);
    assert_eq!(free["source_url"],"https://docs.z.ai/guides/overview/pricing");
    let ds=&rows[1]["maker_pricing"];
    assert_eq!(ds["input_nano_usd_per_million"],300000000u64);
    assert_eq!(ds["output_nano_usd_per_million"],1200000000u64);
    assert_eq!(ds["basis"],"standard online, uncached input, peak list rate; virtual USD");
    let unknown=&rows[2]["maker_pricing"];
    assert_eq!(unknown["status"],"unavailable");
    assert!(unknown.get("input_nano_usd_per_million").is_none());
    let raw=body.to_string();
    assert!(!raw.contains("secret-route") && !raw.contains("private-lane"));
    assert_eq!(up.hits.load(Ordering::SeqCst),0);
}

#[test]
fn maker_prices_do_not_guess_snapshot_or_quantized_variant() {
    let srv=serve(config(vec![provider("private-lane","http://127.0.0.1:1",Status::Friends,vec![
        ("deepseek-v4.1-flash","x",None),("deepseek-v4-flash","y",None),
        ("deepseek-v4-flash:fp8","z",None),("nemotron-3-ultra-550b-a55b","n",None),
    ])],vec![]));
    let mut res=client().get(&format!("{}/v1/models",srv.base)).header("authorization","Bearer ownerkey").call().unwrap();
    for row in res.body_mut().read_json::<serde_json::Value>().unwrap()["data"].as_array().unwrap() {
        assert_eq!(row["maker_pricing"]["status"],"unavailable", "must not guess price for {}",row["id"]);
        assert!(row["maker_pricing"].get("input_nano_usd_per_million").is_none());
    }
}

#[test]
fn legacy_flash_alias_uses_one_canonical_pool_and_response_name() {
    let bad=mock_upstream(|_|error_reply(500,vec![]));
    let good=mock_upstream(|_|json_reply(chat_json("vendor-build","OK")));
    let srv=serve(config(vec![
        provider("zro",&bad.url,Status::Personal,vec![("deepseek-v4.1-flash","deepseek-v4.1-flash",None)]),
        provider("orcarouter",&good.url,Status::Personal,vec![("deepseek-v4.1-flash","deepseek/deepseek-v4.1-flash-free",None)]),
    ],vec![]));
    let agent=client();
    let mut list=agent.get(&format!("{}/v1/models",srv.base)).header("authorization","Bearer ownerkey").call().unwrap();
    let body=list.body_mut().read_json::<serde_json::Value>().unwrap();
    assert_eq!(body["data"].as_array().unwrap().len(),1);
    assert_eq!(body["data"][0]["id"],"deepseek-v4.1-flash");
    let mut res=chat(&agent,&srv.base,"ownerkey",pin_msg("deepseek-v4.1-flash-route-b"));
    assert_eq!(res.status(),200);
    assert_eq!(res.body_mut().read_json::<serde_json::Value>().unwrap()["model"],"deepseek-v4.1-flash");
    assert_eq!(bad.hits.load(Ordering::SeqCst),1);
    assert_eq!(good.requests.lock().unwrap()[0].body["model"],"deepseek/deepseek-v4.1-flash-free");
    assert_ne!(chat(&agent,&srv.base,"friendkey",pin_msg("deepseek-v4.1-flash-route-b")).status(),200);
    assert_eq!(good.hits.load(Ordering::SeqCst),1,"legacy alias cannot expand personal access");
}

#[test]
fn legacy_fp8_name_resolves_to_v4_not_v41() {
    let up=mock_upstream(|_|json_reply(chat_json("deepseek-v4-flash:fp8","OK")));
    let srv=serve(config(vec![provider("inferbase",&up.url,Status::Personal,vec![("deepseek-v4-flash","deepseek-v4-flash",None)])],vec![]));
    let mut res=chat(&client(),&srv.base,"ownerkey",pin_msg("deepseek-v4-flash:fp8"));
    assert_eq!(res.status(),200);
    assert_eq!(res.body_mut().read_json::<serde_json::Value>().unwrap()["model"],"deepseek-v4-flash");
    assert_eq!(up.requests.lock().unwrap()[0].body["model"],"deepseek-v4-flash");
}

#[test]
fn legacy_flash_streams_use_canonical_name_without_provider_leak() {
    let up=mock_upstream(|_|MockReply { status:200,headers:vec![("content-type".into(),"text/event-stream".into())],
        body:"data: {\"model\":\"vendor-private\",\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n".into() });
    let srv=serve(config(vec![provider("orcarouter",&up.url,Status::Personal,vec![("deepseek-v4.1-flash","deepseek/deepseek-v4.1-flash-free",None)])],vec![]));
    let mut payload=pin_msg("deepseek-v4.1-flash-route-b"); payload["stream"]=true.into();
    let mut res=chat(&client(),&srv.base,"ownerkey",payload);assert_eq!(res.status(),200);
    let body=res.body_mut().read_to_string().unwrap();
    assert!(body.contains("deepseek-v4.1-flash"));
    assert!(!body.contains("vendor-private") && !body.contains("route-b") && !body.contains("orcarouter"));
}

#[test]
fn owner_trial_adapters_fail_closed_without_exact_model_allowlist() {
    for id in ["nim","radeon","logfare"] {
        let up=mock_upstream(|_|json_reply(chat_json("private-build","must not dispatch")));
        let srv=serve(config(vec![provider(id,&up.url,Status::Personal,vec![("candidate","private-build",None)])],vec!["candidate"]));
        let mut res=client().get(&format!("{}/v1/models",srv.base)).header("authorization","Bearer ownerkey").call().unwrap();
        let body=res.body_mut().read_json::<serde_json::Value>().unwrap();
        assert!(!body["data"].as_array().unwrap().iter().any(|m|m["id"]=="candidate"),"{id} unknown model must not be advertised");
        assert_ne!(chat(&client(),&srv.base,"ownerkey",pin_msg("candidate")).status(),200);
        assert_ne!(chat(&client(),&srv.base,"ownerkey",pin_msg("auto")).status(),200);
        assert_eq!(up.hits.load(Ordering::SeqCst),0,"{id} absent exact allowlist must not dispatch");
    }
}

#[test]
fn owner_trial_adapters_never_inherit_friend_access_from_status() {
    for id in ["nim","radeon","logfare"] {
        let up=mock_upstream(|_|json_reply(chat_json("private-build","must not dispatch")));
        let srv=serve(config(vec![provider(id,&up.url,Status::Friends,vec![("candidate","private-build",None)])],vec![]));
        assert_ne!(chat(&client(),&srv.base,"friendkey",pin_msg("candidate")).status(),200);
        assert_eq!(up.hits.load(Ordering::SeqCst),0,"{id} friend misconfiguration must stay closed");
    }
}

#[test]
fn strict_zdr_setting_filters_unknown_routes_for_pin_auto_and_catalog() {
    let up=mock_upstream(|_|json_reply(chat_json("private","must not dispatch")));
    let mut cfg=config(vec![provider("unverified-route",&up.url,Status::Friends,vec![("candidate","private",None)])],vec!["candidate"]);cfg.spend.path=Some(wave2_path());let srv=serve(cfg);
    let agent=client();
    let mut saved=agent.post(&format!("{}/v1/settings",srv.base)).header("authorization","Bearer ownerkey")
        .send_json(serde_json::json!({"zdr_only":true,"default_model":"auto","show_cost":false})).unwrap();
    assert_eq!(saved.status(),200);
    assert_eq!(saved.body_mut().read_json::<serde_json::Value>().unwrap()["zdr_only"],true);
    assert_ne!(chat(&agent,&srv.base,"ownerkey",pin_msg("candidate")).status(),200);
    assert_ne!(chat(&agent,&srv.base,"ownerkey",pin_msg("auto")).status(),200);
    let mut list=agent.get(&format!("{}/v1/models",srv.base)).header("authorization","Bearer ownerkey").call().unwrap();
    let rows=list.body_mut().read_json::<serde_json::Value>().unwrap();
    assert!(!rows["data"].as_array().unwrap().iter().any(|m|m["id"]=="candidate"));
    assert_eq!(up.hits.load(Ordering::SeqCst),0);
    assert_eq!(chat(&agent,&srv.base,"friendkey",pin_msg("candidate")).status(),200,"another account's settings are isolated");
}

#[test]
fn trial_routes_allow_only_owner_exact_text_and_two_calls_per_account_minute() {
    for (id,upstream) in [("logfare","qwen-3.8-27b"),("radeon","MiMo-V2.6-Flash"),("nim","minimaxai/minimax-m3.1-flash")] {
        let up=mock_upstream(|_|json_reply(chat_json("private","OK")));
        let srv=serve(config(vec![provider(id,&up.url,Status::Friends,vec![("one",upstream,None),("two",upstream,None)])],vec![]));let agent=client();
        assert_ne!(chat(&agent,&srv.base,"friendkey",pin_msg("one")).status(),200);
        let mut bad=pin_msg("one");bad["tools"]=serde_json::json!([]);assert_ne!(chat(&agent,&srv.base,"ownerkey",bad).status(),200);
        let mut bad=pin_msg("one");bad["messages"]=serde_json::json!([{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid"}}]}]);assert_ne!(chat(&agent,&srv.base,"ownerkey",bad).status(),200);
        assert_eq!(up.hits.load(Ordering::SeqCst),0);
        let mut first=chat(&agent,&srv.base,"ownerkey",pin_msg("one"));assert_eq!(first.status(),200);let _=first.body_mut().read_to_string();
        // Header receipt can precede the server dropping its completed-body permit.
        let limit=Instant::now()+Duration::from_secs(2);
        loop {let mut second=chat(&agent,&srv.base,"ownerkey",pin_msg("two"));if second.status()==200 {let _=second.body_mut().read_to_string();break;}assert!(Instant::now()<limit,"completed-body permit did not release");thread::yield_now();}
        assert_ne!(chat(&agent,&srv.base,"ownerkey",pin_msg("one")).status(),200);
        assert_eq!(up.hits.load(Ordering::SeqCst),2,"{id} RPM shared across models");
    }
}

#[test]
fn trial_account_concurrency_permit_lasts_through_complete_sse_body() {
    let (entered_tx,entered_rx)=channel();let (release_tx,release_rx)=channel();let gate=Arc::new(Mutex::new(Some(release_rx)));let entered=Arc::new(Mutex::new(Some(entered_tx)));
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();let url=format!("http://{}",listener.local_addr().unwrap());
    thread::spawn(move||{let(mut socket,_)=listener.accept().unwrap();read_request(&mut socket);socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\ndata: {\"choices\":[]}\n\n").unwrap();socket.flush().unwrap();entered.lock().unwrap().take().unwrap().send(()).unwrap();gate.lock().unwrap().take().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();socket.write_all(b"data: [DONE]\n\n").unwrap();});
    let srv=serve(config(vec![provider("logfare",&url,Status::Personal,vec![("one","qwen-3.8-27b",None)])],vec![]));let base=srv.base.clone();
    let first=thread::spawn(move||{let mut payload=pin_msg("one");payload["stream"]=true.into();let mut response=chat(&client(),&base,"ownerkey",payload);let status=response.status().as_u16();let _=response.body_mut().read_to_string();status});
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_ne!(chat(&client(),&srv.base,"ownerkey",pin_msg("one")).status(),200);
    release_tx.send(()).unwrap();assert_eq!(first.join().unwrap(),200);
}

#[test]
fn trial_rejects_oversize_multiple_choices_and_does_not_follow_redirects() {
    let next=mock_upstream(|_|json_reply(chat_json("private","must not follow")));
    let target=format!("{}/chat/completions",next.url);
    let first=mock_upstream(move |_|MockReply{status:307,headers:vec![("location".into(),target.clone())],body:String::new()});
    let srv=serve(config(vec![provider("logfare",&first.url,Status::Personal,vec![("one","qwen-3.8-27b",None)])],vec![]));let agent=client();
    let mut bad=pin_msg("one");bad["n"]=2.into();assert_ne!(chat(&agent,&srv.base,"ownerkey",bad).status(),200);
    let mut bad=pin_msg("one");bad["messages"]=serde_json::json!([{"role":"user","content":"a".repeat(9000)}]);assert_ne!(chat(&agent,&srv.base,"ownerkey",bad).status(),200);
    assert_eq!(first.hits.load(Ordering::SeqCst),0);
    assert_ne!(chat(&agent,&srv.base,"ownerkey",pin_msg("one")).status(),200);
    assert_eq!(first.hits.load(Ordering::SeqCst),1);assert_eq!(next.hits.load(Ordering::SeqCst),0);
}

// -- upstream idle floor (upstream_idle) vs aggregate ceiling (upstream_budget) --
// The floor is ureq's per-read timeout on the attempt agent: it restarts on
// every successful socket read, so it cuts stalls without bounding healthy
// streams. The ceiling stays the pre-existing per-attempt timeout_global cut
// from the shared request budget. Headers are committed before any mid-stream
// cut, so a cut always ends the SSE body honestly (no [DONE]), never a 504.

fn raw_sse_listener(script: impl Fn(std::net::TcpStream) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        while let Ok((socket, _)) = listener.accept() {
            script(socket);
        }
    });
    url
}

#[test]
fn stalled_sse_upstream_cut_at_idle_floor() {
    let url = raw_sse_listener(|mut socket| {
        read_request(&mut socket);
        socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\ndata: {\"choices\":[]}\n\n").unwrap();
        socket.flush().unwrap();
        // stall far past the floor; the cleanup write may fail once the server gave up
        thread::sleep(Duration::from_secs(5));
        let _ = socket.write_all(b"data: [DONE]\n\n");
    });
    let mut cfg = config(vec![provider("logfare", &url, Status::Personal, vec![("one", "qwen-3.8-27b", None)])], vec![]);
    cfg.upstream_idle = Duration::from_millis(300);
    let srv = serve(cfg);
    let started = Instant::now();
    let mut payload = pin_msg("one"); payload["stream"] = true.into();
    let mut resp = chat(&client(), &srv.base, "ownerkey", payload);
    assert_eq!(resp.status(), 200, "headers commit before any mid-stream cut");
    let body = resp.body_mut().read_to_string().unwrap();
    assert!(started.elapsed() < Duration::from_secs(4), "stalled stream pinned the handler: {:?}", started.elapsed());
    assert!(!body.contains("[DONE]"), "cut must end the stream honestly, no fabricated DONE: {body:?}");
}

#[test]
fn dripping_sse_stream_survives_idle_floor() {
    let url = raw_sse_listener(|mut socket| {
        read_request(&mut socket);
        socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n").unwrap();
        socket.flush().unwrap();
        // steady progress under the floor: 10 chunks 50ms apart = 500ms total, past the 300ms floor
        for _ in 0..10 {
            socket.write_all(b"data: {\"choices\":[]}\n\n").unwrap(); socket.flush().unwrap();
            thread::sleep(Duration::from_millis(50));
        }
        socket.write_all(b"data: [DONE]\n\n").unwrap();
    });
    let mut cfg = config(vec![provider("logfare", &url, Status::Personal, vec![("one", "qwen-3.8-27b", None)])], vec![]);
    cfg.upstream_idle = Duration::from_millis(300);
    let srv = serve(cfg);
    let mut payload = pin_msg("one"); payload["stream"] = true.into();
    let mut resp = chat(&client(), &srv.base, "ownerkey", payload);
    assert_eq!(resp.status(), 200);
    let body = resp.body_mut().read_to_string().unwrap();
    assert!(body.contains("[DONE]"), "stream with steady progress must complete past the floor: {body:?}");
}

#[test]
fn stalled_nonstream_upstream_fails_over_to_503_within_budget() {
    let url = raw_sse_listener(|mut socket| {
        read_request(&mut socket);
        // never answer within the floor: each attempt must die on the idle
        // floor, not the client's patience; the cleanup write ends the mutant's wait
        thread::sleep(Duration::from_secs(5));
        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 14\r\n\r\n{\"choices\":[]}");
    });
    let mut cfg = config(vec![provider("logfare", &url, Status::Personal, vec![("one", "qwen-3.8-27b", None)])], vec![]);
    cfg.upstream_idle = Duration::from_millis(300);
    cfg.upstream_budget = Duration::from_secs(30);
    let srv = serve(cfg);
    let started = Instant::now();
    let resp = chat(&client(), &srv.base, "ownerkey", pin_msg("one"));
    assert_eq!(resp.status(), 503, "stalled upstream must fail over and exhaust as 503");
    assert!(started.elapsed() < Duration::from_secs(4), "non-stream stall pinned the handler: {:?}", started.elapsed());
}

#[test]
fn stalled_json_body_after_headers_cut_at_idle_floor() {
    let url = raw_sse_listener(|mut socket| {
        read_request(&mut socket);
        // headers commit, then the JSON body stalls mid-way past the floor
        socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 14\r\n\r\n{\"cho").unwrap();
        socket.flush().unwrap();
        thread::sleep(Duration::from_secs(5));
        let _ = socket.write_all(b"ices\":[]}");
    });
    let mut cfg = config(vec![provider("logfare", &url, Status::Personal, vec![("one", "qwen-3.8-27b", None)])], vec![]);
    cfg.upstream_idle = Duration::from_millis(300);
    cfg.upstream_budget = Duration::from_secs(30);
    let srv = serve(cfg);
    let started = Instant::now();
    let resp = chat(&client(), &srv.base, "ownerkey", pin_msg("one"));
    assert_eq!(resp.status(), 503, "stalled body must fail over and exhaust as 503");
    assert!(started.elapsed() < Duration::from_secs(4), "mid-body stall pinned the handler: {:?}", started.elapsed());
}

#[test]
fn dripping_stream_still_capped_by_aggregate_budget() {
    let url = raw_sse_listener(|mut socket| {
        read_request(&mut socket);
        socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n").unwrap();
        socket.flush().unwrap();
        // progress fast enough to beat the floor, long enough to cross the ceiling
        for _ in 0..30 {
            if socket.write_all(b"data: {\"choices\":[]}\n\n").is_err() { break; }
            let _ = socket.flush();
            thread::sleep(Duration::from_millis(50));
        }
        let _ = socket.write_all(b"data: [DONE]\n\n");
    });
    let mut cfg = config(vec![provider("logfare", &url, Status::Personal, vec![("one", "qwen-3.8-27b", None)])], vec![]);
    cfg.upstream_idle = Duration::from_millis(300);
    cfg.upstream_budget = Duration::from_millis(800);
    let srv = serve(cfg);
    let started = Instant::now();
    let mut payload = pin_msg("one"); payload["stream"] = true.into();
    let mut resp = chat(&client(), &srv.base, "ownerkey", payload);
    assert_eq!(resp.status(), 200);
    let body = resp.body_mut().read_to_string().unwrap();
    assert!(started.elapsed() < Duration::from_secs(4), "aggregate ceiling did not bind the drip: {:?}", started.elapsed());
    assert!(!body.contains("[DONE]"), "stream past the aggregate budget must be cut honestly: {body:?}");
}

// -- request byte caps -> 413 (read_request_within -> handle mapping) --
// The caps themselves are standing policy (64KB head, 1MB declared body);
// these pin the end-to-end 413 mapping at the HTTP layer.

fn raw_http(base: &str, req: &[u8]) -> String {
    let addr = base.trim_start_matches("http://");
    // connect, write and read all carry their own timeouts: a server that
    // never drains, never answers or hangs mid-response fails the test
    // instead of hanging it. The fixture content itself is still finite.
    let mut s = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5)).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req).expect("server did not drain the request within 5s");
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => panic!("server left the connection open past 5s: {e}"),
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn oversize_declared_body_gets_413() {
    let srv = serve(config(vec![], vec![]));
    let resp = raw_http(&srv.base, b"POST /v1/chat/completions HTTP/1.1\r\nhost: x\r\nauthorization: Bearer ownerkey\r\ncontent-length: 2000000\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 413"), "oversize declared body must map to 413: {:?}", &resp[..resp.len().min(120)]);
}

#[test]
fn oversize_headers_get_413() {
    let srv = serve(config(vec![], vec![]));
    let req = format!("POST /v1/chat/completions HTTP/1.1\r\nhost: x\r\nauthorization: Bearer ownerkey\r\nx-pad: {}\r\ncontent-length: 2\r\n\r\n{{}}", "a".repeat(70 * 1024));
    let resp = raw_http(&srv.base, req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 413"), "oversize headers must map to 413: {:?}", &resp[..resp.len().min(120)]);
}
