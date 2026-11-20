use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use aqua::{Config, KeyEntry, Provider, Status};

// ---------- mock upstream ----------

#[derive(Clone)]
struct Recorded {
    auth: String,
    body: serde_json::Value,
}

struct MockReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    // when set, body[0..split] is written, then we wait for the gate, then the rest
    gate: Option<(usize, std::sync::mpsc::Receiver<()>)>,
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

fn mock_upstream<F: Fn(&Recorded) -> MockReply + Send + 'static>(handler: F) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let (rq, ht) = (requests.clone(), hits.clone());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            let (headers, body) = read_request(&mut stream);
            let rec = Recorded {
                auth: headers.get("authorization").cloned().unwrap_or_default(),
                body: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
            };
            rq.lock().unwrap().push(rec.clone());
            ht.fetch_add(1, Ordering::SeqCst);
            let reply = handler(&rec);
            let head = format!(
                "HTTP/1.1 {}\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n",
                reply.status,
                reply.body.len(),
                reply.headers.iter().map(|(k, v)| format!("{}: {}\r\n", k, v)).collect::<String>()
            );
            if let Some((split, gate)) = reply.gate {
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&reply.body.as_bytes()[..split]).unwrap();
                stream.flush().unwrap();
                let _ = gate.recv_timeout(Duration::from_secs(5));
                stream.write_all(&reply.body.as_bytes()[split..]).unwrap();
            } else {
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(reply.body.as_bytes()).unwrap();
            }
        }
    });
    Mock { url, requests, hits }
}

fn json_reply(body: serde_json::Value) -> MockReply {
    MockReply { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: body.to_string(), gate: None }
}

fn chat_json(model: &str, content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-real", "object": "chat.completion", "created": 1, "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    })
}

// ---------- server fixture ----------

fn provider(id: &str, url: &str, status: Status) -> Provider {
    Provider {
        id: id.into(),
        base_url: url.into(),
        api_key: format!("upstream-key-{}", id),
        models: vec![aqua::ModelEntry {
            public: "publicmodel-7b".into(),
            upstream: format!("real-{}-model", id),
            context: None,
        }],
        status,
    }
}

fn config(providers: Vec<Provider>) -> Config {
    let mut keys = HashMap::new();
    keys.insert("ownerkey".into(), KeyEntry { name: "luke".into(), role: aqua::Role::Owner });
    keys.insert("friendkey".into(), KeyEntry { name: "sam".into(), role: aqua::Role::Friend });
    Config { keys, admin_key: "adminsecret".into(), daily_limit: 200, allowed_origin: String::new(), providers, oauth: Default::default(), spend: Default::default(), auto_shortlist: vec!["publicmodel-7b".into()], upstream_budget: Duration::from_secs(300), upstream_idle: Duration::from_secs(60) }
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

fn msg(stream: bool) -> serde_json::Value {
    serde_json::json!({"model": "auto", "stream": stream, "messages": [{"role": "user", "content": "hi"}]})
}

// ---------- tests ----------

#[test]
fn rejects_unknown_key_without_calling_upstream() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let res = chat(&client(), &srv.base, "wrongkey", msg(false));
    assert_eq!(res.status(), 401);
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_and_placeholder_keys_fail_closed() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    // intake filtering: empty or placeholder keys are dropped at config build
    let mut m = std::collections::HashMap::new();
    aqua::parse_keys(Some("luke:,x:change-me,y:realkey-12345".into()), aqua::Role::Owner, &mut m);
    assert_eq!(m.len(), 1);
    assert!(m.contains_key("realkey-12345"));
    // and at request time those tokens are never honored
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let agent = client();
    let empty = agent.post(&format!("{}/v1/chat/completions", srv.base))
        .header("authorization", "Bearer ")
        .send_json(&msg(false)).unwrap();
    assert_eq!(empty.status(), 401);
    assert_eq!(chat(&agent, &srv.base, "change-me", msg(false)).status(), 401);
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn owner_completion_model_rewritten_provider_hidden() {
    let up = mock_upstream(|_| json_reply(chat_json("secretvendor/giant-9000", "hi there")));
    let srv = serve(config(vec![provider("hiddenvendor", &up.url, Status::Personal)]));
    let mut res = chat(&client(), &srv.base, "ownerkey", msg(false));
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.body_mut().read_json().unwrap();
    assert_eq!(body["model"], "publicmodel-7b");
    assert_eq!(body["choices"][0]["message"]["content"], "hi there");
    let raw = body.to_string();
    assert!(!raw.contains("secretvendor"));
    assert!(!raw.contains("hiddenvendor"));
    let reqs = up.requests.lock().unwrap();
    assert_eq!(reqs[0].auth, "Bearer upstream-key-hiddenvendor");
    assert_eq!(reqs[0].body["model"], "real-hiddenvendor-model");
}

#[test]
fn friend_refused_when_nothing_friends_eligible() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Personal)]));
    let mut res = chat(&client(), &srv.base, "friendkey", msg(false));
    assert_eq!(res.status(), 503);
    let raw = res.body_mut().read_to_string().unwrap();
    assert!(!raw.contains("p1"));
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn friend_works_with_friends_provider() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    assert_eq!(chat(&client(), &srv.base, "friendkey", msg(false)).status(), 200);
}

#[test]
fn off_provider_never_called_even_for_owner() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Off)]));
    assert_eq!(chat(&client(), &srv.base, "ownerkey", msg(false)).status(), 503);
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn failover_hides_failed_and_serving_provider() {
    let bad = mock_upstream(|_| MockReply {
        status: 500,
        headers: vec![("x-served-by".into(), "badvendor".into()), ("content-type".into(), "application/json".into())],
        body: "{\"error\":\"badvendor exploded\"}".into(),
        gate: None,
    });
    let good = mock_upstream(|_| json_reply(chat_json("m", "ok")));
    let srv = serve(config(vec![provider("badvendor", &bad.url, Status::Friends), provider("goodvendor", &good.url, Status::Friends)]));
    let mut res = chat(&client(), &srv.base, "ownerkey", msg(false));
    assert_eq!(res.status(), 200);
    assert!(res.headers().get("x-served-by").is_none());
    let raw: String = res.body_mut().read_json::<serde_json::Value>().unwrap().to_string();
    assert!(!raw.contains("badvendor"));
    assert!(!raw.contains("goodvendor"));
}

#[test]
fn all_upstreams_down_generic_error_no_leak() {
    let up = mock_upstream(|_| MockReply { status: 502, headers: vec![], body: "vendorname upstream is on fire".into(), gate: None });
    let srv = serve(config(vec![provider("vendorname", &up.url, Status::Friends)]));
    let mut res = chat(&client(), &srv.base, "ownerkey", msg(false));
    assert_eq!(res.status(), 503);
    let raw = res.body_mut().read_to_string().unwrap();
    assert!(!raw.contains("vendorname"));
    assert!(!raw.contains("on fire"));
}

#[test]
fn streaming_multiline_events_rewritten_nothing_leaks() {
    let frames = concat!(
        "event: message\nid: xyz\ndata: {\"id\":\"c1\",\"model\":\"vendorx/real\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"id\":\"c1\",\"model\":\"vendorx/real\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"}}]}\n",
        "data: {\"id\":\"c1\",\"model\":\"vendorx/real\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"}}]}\n\n",
        ": vendorx comment\n\n",
        "data: [DONE]\n\n"
    );
    let up = mock_upstream(move |_| MockReply {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into()), ("x-vendorx-ray".into(), "abc".into())],
        body: frames.into(),
        gate: None,
    });
    let srv = serve(config(vec![provider("vendorx", &up.url, Status::Friends)]));
    let mut res = chat(&client(), &srv.base, "ownerkey", msg(true));
    assert_eq!(res.status(), 200);
    assert!(res.headers().get("x-vendorx-ray").is_none());
    let text = res.body_mut().read_to_string().unwrap();
    assert!(text.contains("hello"));
    assert!(text.contains("data: [DONE]"));
    assert!(!text.contains("vendorx"));
    assert!(!text.contains("event:"));
    for line in text.lines().filter(|l| l.starts_with("data: {")) {
        let v: serde_json::Value = serde_json::from_str(&line[5..]).unwrap();
        assert_eq!(v["model"], "publicmodel-7b");
    }
}

#[test]
fn stream_requested_but_upstream_returns_json_is_clean_error_not_empty_200() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "no stream here"))); // JSON even though stream requested
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let mut res = chat(&client(), &srv.base, "ownerkey", msg(true));
    let status = res.status().as_u16();
    assert!(status >= 500, "expected clean 5xx, got {}", status);
    let raw = res.body_mut().read_to_string().unwrap();
    assert!(raw.contains("error"));
    assert!(!raw.contains("p1"));
}

#[test]
fn openai_parameter_whitelist_forwarded_unknown_dropped() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let payload = serde_json::json!({
        "model": "auto", "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 50, "top_p": 0.5, "stop": ["x"], "n": 1,
        "response_format": {"type": "text"}, "temperature": 0.2, "seed": 7,
        "user": "friend-identity-should-not-go-upstream",
        "evil_custom_field": "drop me"
    });
    assert_eq!(chat(&client(), &srv.base, "ownerkey", payload).status(), 200);
    let reqs = up.requests.lock().unwrap();
    let sent = &reqs[0].body;
    for k in ["max_tokens", "top_p", "stop", "n", "response_format", "temperature", "seed"] {
        assert!(sent.get(k).is_some(), "{} must be forwarded", k);
    }
    assert!(sent.get("user").is_none(), "user identity must not go upstream");
    assert!(sent.get("evil_custom_field").is_none(), "unknown fields dropped");
    assert_eq!(sent["model"], "real-p1-model");
}

#[test]
fn daily_cap_returns_generic_429() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let mut cfg = config(vec![provider("p1", &up.url, Status::Friends)]);
    cfg.daily_limit = 2;
    let srv = serve(cfg);
    let agent = client();
    assert_eq!(chat(&agent, &srv.base, "ownerkey", msg(false)).status(), 200);
    assert_eq!(chat(&agent, &srv.base, "ownerkey", msg(false)).status(), 200);
    let mut third = chat(&agent, &srv.base, "ownerkey", msg(false));
    assert_eq!(third.status(), 429);
    assert!(!third.body_mut().read_to_string().unwrap().contains("p1"));
    assert_eq!(up.hits.load(Ordering::SeqCst), 2);
}

#[test]
fn in_flight_request_reserves_quota_slot() {
    // stream that hangs until released; while it holds a slot the second request must 429
    let (gate_tx, gate_rx) = channel::<()>();
    let gate_rx = Mutex::new(Some(gate_rx));
    let up = mock_upstream(move |_| {
        let rx = gate_rx.lock().unwrap().take().unwrap();
        let body = "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\ndata: [DONE]\n\n".to_string();
        MockReply {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            gate: Some((10, rx)),
            body,
        }
    });
    let mut cfg = config(vec![provider("p1", &up.url, Status::Friends)]);
    cfg.daily_limit = 1;
    let srv = serve(cfg);
    let base = srv.base.clone();
    let first = thread::spawn(move || chat(&client(), &base, "ownerkey", msg(true)).status().as_u16());
    // wait until the upstream actually has the first request in flight
    for _ in 0..50 {
        if up.hits.load(Ordering::SeqCst) == 1 { break; }
        thread::sleep(Duration::from_millis(20));
    }
    let second = chat(&client(), &srv.base, "ownerkey", msg(false));
    assert_eq!(second.status(), 429, "in-flight stream must reserve the quota slot");
    gate_tx.send(()).unwrap();
    assert_eq!(first.join().unwrap(), 200);
}

#[test]
fn models_list_exposes_only_alias() {
    let srv = serve(config(vec![provider("p1", "http://127.0.0.1:1", Status::Friends)]));
    let mut res = client().get(&format!("{}/v1/models", srv.base)).header("authorization", "Bearer friendkey").call().unwrap();
    let body: serde_json::Value = res.body_mut().read_json().unwrap();
    let ids: Vec<&str> = body["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"auto"));
    assert!(ids.contains(&"publicmodel-7b"));
    assert!(!body.to_string().contains("p1"));
}

#[test]
fn admin_route_requires_admin_key() {
    let srv = serve(config(vec![provider("p1", "http://127.0.0.1:1", Status::Off)]));
    let agent = client();
    let denied = agent.get(&format!("{}/v1/admin/providers", srv.base)).header("authorization", "Bearer friendkey").call().unwrap();
    assert_eq!(denied.status(), 401);
    let mut ok = agent.get(&format!("{}/v1/admin/providers", srv.base)).header("authorization", "Bearer adminsecret").call().unwrap();
    assert_eq!(ok.status(), 200);
    let body: serde_json::Value = ok.body_mut().read_json().unwrap();
    assert_eq!(body["providers"][0]["id"], "p1");
    assert_eq!(body["providers"][0]["status"], "off");
}

#[test]
fn cors_is_narrow_and_configured_only() {
    let mut cfg = config(vec![provider("p1", "http://127.0.0.1:1", Status::Off)]);
    cfg.allowed_origin = "https://aqua.goattech.us".into();
    let srv = serve(cfg);
    let agent = client();
    let ok = agent.run(ureq::http::Request::options(&format!("{}/v1/chat/completions", srv.base))
        .header("origin", "https://aqua.goattech.us")
        .header("access-control-request-headers", "authorization,content-type")
        .body(()).unwrap()).unwrap();
    assert_eq!(ok.headers().get("access-control-allow-origin").unwrap(), "https://aqua.goattech.us");
    let evil = agent.run(ureq::http::Request::options(&format!("{}/v1/chat/completions", srv.base))
        .header("origin", "https://evil.example")
        .body(()).unwrap()).unwrap();
    assert!(evil.headers().get("access-control-allow-origin").is_none());
}

#[test]
fn many_bad_attempts_do_not_lock_out_valid_key() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let agent = client();
    // throttled after 5 failures in the window: further attempts get 429, not upstream work
    for i in 0..25 {
        let want = if i < 5 { 401 } else { 429 };
        assert_eq!(chat(&agent, &srv.base, "nope", msg(false)).status(), want, "attempt {}", i);
    }
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
    // throttling is per-token: a valid key is unaffected
    assert_eq!(chat(&agent, &srv.base, "ownerkey", msg(false)).status(), 200);
}

#[test]
fn explicit_model_name_selects_and_unknown_model_400s() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let agent = client();
    let mut ok = chat(&agent, &srv.base, "friendkey", serde_json::json!({"model": "publicmodel-7b", "messages": [{"role": "user", "content": "hi"}]}));
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.body_mut().read_json::<serde_json::Value>().unwrap()["model"], "publicmodel-7b");
    let bad = chat(&agent, &srv.base, "friendkey", serde_json::json!({"model": "nonexistent-model", "messages": [{"role": "user", "content": "hi"}]}));
    assert_eq!(bad.status(), 400);
}

#[test]
fn public_model_names_never_contain_provider_ids() {
    // misconfigured upstream id mentioning the provider must not surface as-is:
    // public name is what clients see, and the registry keeps it provider-free
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let mut p = provider("secretp", &up.url, Status::Friends);
    p.models[0].public = "deepseek-v4.1-flash".into();
    p.models[0].upstream = "secretp/deepseek-v4.1-flash".into();
    let srv = serve(config(vec![p]));
    let mut res = client().get(&format!("{}/v1/models", srv.base)).header("authorization", "Bearer friendkey").call().unwrap();
    let raw = res.body_mut().read_to_string().unwrap();
    assert!(raw.contains("deepseek-v4.1-flash"));
    assert!(!raw.contains("secretp"));
}

// ---------- reviewer regression tests (f1a9be5 findings) ----------

fn raw(base: &str, bytes: &[u8]) -> String {
    let mut s = std::net::TcpStream::connect(base.trim_start_matches("http://")).unwrap();
    s.write_all(bytes).unwrap();
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf
}

#[test]
fn malformed_request_does_not_burn_quota() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let mut cfg = config(vec![provider("p1", &up.url, Status::Friends)]);
    cfg.daily_limit = 1;
    let srv = serve(cfg);
    let agent = client();
    // invalid JSON: 400 and no quota consumed
    let bad = agent.post(&format!("{}/v1/chat/completions", srv.base))
        .header("authorization", "Bearer friendkey")
        .header("content-type", "application/json")
        .send("{not json").unwrap();
    assert_eq!(bad.status(), 400);
    // unknown model: 400 and no quota consumed
    let unk = chat(&agent, &srv.base, "friendkey", serde_json::json!({"model": "nope", "messages": [{"role": "user", "content": "hi"}]}));
    assert_eq!(unk.status(), 400);
    // the one valid request still succeeds
    let ok = chat(&agent, &srv.base, "friendkey", msg(false));
    assert_eq!(ok.status(), 200);
    // and the quota is now spent
    let over = chat(&agent, &srv.base, "friendkey", msg(false));
    assert_eq!(over.status(), 429);
}

#[test]
fn admin_placeholder_key_never_authenticates() {
    let mut cfg = config(vec![]);
    cfg.admin_key = "change-me".into();
    let srv = serve(cfg);
    let res = client().get(&format!("{}/v1/admin/providers", srv.base))
        .header("authorization", "Bearer change-me").call().unwrap();
    assert_eq!(res.status(), 401);
    // client-side placeholder tokens stay rejected too
    let res2 = client().get(&format!("{}/v1/models", srv.base))
        .header("authorization", "Bearer change-me").call().unwrap();
    assert_eq!(res2.status(), 401);
}

#[test]
fn oversized_headers_rejected_even_with_terminator() {
    let srv = serve(config(vec![]));
    let filler = "a".repeat(70 * 1024);
    let req = format!("GET /v1/models HTTP/1.1\r\nauthorization: Bearer ownerkey\r\nx-pad: {}\r\n\r\n", filler);
    let resp = raw(&srv.base, req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 413"), "got: {}", &resp[..resp.len().min(80)]);
}

#[test]
fn auth_failures_throttle_repeated_bad_tokens() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let agent = client();
    for i in 0..5 {
        let r = chat(&agent, &srv.base, "badtoken", msg(false));
        assert_eq!(r.status(), 401, "attempt {}", i);
    }
    let r = chat(&agent, &srv.base, "badtoken", msg(false));
    assert_eq!(r.status(), 429);
    // a different, valid key is unaffected
    let ok = chat(&agent, &srv.base, "friendkey", msg(false));
    assert_eq!(ok.status(), 200);
}

#[test]
fn chunked_request_body_explicitly_rejected() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let req = "POST /v1/chat/completions HTTP/1.1\r\nauthorization: Bearer friendkey\r\ntransfer-encoding: chunked\r\ncontent-type: application/json\r\n\r\n1a\r\n{\"messages\":[],\"x\":1}\r\n0\r\n\r\n";
    let resp = raw(&srv.base, req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 400"), "got: {}", &resp[..resp.len().min(80)]);
    assert!(resp.contains("chunked"));
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_content_length_rejected() {
    let srv = serve(config(vec![]));
    let req = "POST /v1/chat/completions HTTP/1.1\r\nauthorization: Bearer friendkey\r\ncontent-length: 20\r\ncontent-length: 40\r\ncontent-type: application/json\r\n\r\n{\"messages\":[],\"x\":1}";
    let resp = raw(&srv.base, req.as_bytes());
    assert!(resp.starts_with("HTTP/1.1 400"), "got: {}", &resp[..resp.len().min(80)]);
}

#[test]
fn admin_key_guessing_hits_the_same_throttle() {
    let up = mock_upstream(|_| json_reply(chat_json("m", "hi")));
    let srv = serve(config(vec![provider("p1", &up.url, Status::Friends)]));
    let agent = client();
    for i in 0..5 {
        let r = agent.get(format!("{}/v1/admin/providers", srv.base)).header("authorization", "Bearer wrongadmin").call().unwrap();
        assert_eq!(r.status(), 401, "attempt {}", i);
    }
    let r = agent.get(format!("{}/v1/admin/providers", srv.base)).header("authorization", "Bearer wrongadmin").call().unwrap();
    assert_eq!(r.status(), 429, "admin guessing must be throttled like API keys");
    // the real admin key still works
    let ok = agent.get(format!("{}/v1/admin/providers", srv.base)).header("authorization", "Bearer adminsecret").call().unwrap();
    assert_eq!(ok.status(), 200);
}

#[test]
fn unroutable_auto_does_not_burn_quota() {
    // no providers at all: auto has nothing to route to
    let srv = serve(config(vec![]));
    let agent = client();
    for _ in 0..3 {
        let r = chat(&agent, &srv.base, "friendkey", msg(false));
        assert_eq!(r.status(), 503, "unroutable auto must 503, not 429");
    }
}
