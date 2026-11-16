// Model-first routing tests: shortlist auto, same-model provider failover,
// passive account-scope cooldowns, sound context rejection.
// Self-contained harness (mirrors tests/proxy.rs fixtures).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
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
        oauth: Default::default(),
        auto_shortlist: auto_shortlist.into_iter().map(|s| s.to_string()).collect(),
        upstream_budget: Duration::from_secs(300),
    }
}

struct Running { base: String, _h: aqua::Server }
fn serve(cfg: Config) -> Running {
    let s = aqua::bind(cfg).unwrap();
    Running { base: format!("http://127.0.0.1:{}", s.port()), _h: s }
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
