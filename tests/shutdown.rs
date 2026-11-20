use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn config() -> aqua::Config {
    aqua::Config {
        auth_throttle: Default::default(), backoff: Default::default(), connections: Default::default(),
        keys: HashMap::new(), admin_key: String::new(), daily_limit: 200,
        allowed_origin: String::new(), providers: vec![], oauth: Default::default(),
        spend: Default::default(), auto_shortlist: vec![],
        upstream_budget: Duration::from_secs(300), upstream_idle: Duration::from_secs(60),
    }
}

// Test-process fixture only. Never run a live deployment or change global limits.
#[test]
fn shutdown_child_fixture() {
    let Ok(bind) = std::env::var("AQUA_TEST_SHUTDOWN_BIND") else { return; };
    let mut server = aqua::bind_addr(&bind, config()).unwrap();
    server.set_drain_timeout(Duration::from_millis(50));
    let bound: std::net::SocketAddr = bind.parse().unwrap();
    let host = match bound.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    };
    let mut client = TcpStream::connect((host, server.port())).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
    let mut response = String::new(); client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "accept loop healthy before Drop");
    drop(client);
    drop(server);
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            // TERM-only, exact PID returned by this test's own spawn.
            let status = Command::new("kill").args(["-TERM", &self.0.id().to_string()]).status().unwrap();
            assert!(status.success(), "owned child TERM failed");
            let deadline = Instant::now() + Duration::from_secs(3);
            while self.0.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline, "TERM did not stop owned child PID {}", self.0.id());
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn shutdown_wakes_each_available_listener_family() {
    let mut cases = vec!["127.0.0.1:0", "127.0.0.2:0", "0.0.0.0:0"];
    match TcpListener::bind("[::1]:0") {
        Ok(probe) => { drop(probe); cases.extend(["[::1]:0", "[::]:0"]); }
        Err(error) => eprintln!("IPv6 unavailable, not exercised: {error}"),
    }
    let mut failed = Vec::new();
    for bind in cases {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "shutdown_child_fixture", "--nocapture"])
            .env("AQUA_TEST_SHUTDOWN_BIND", bind).spawn().unwrap();
        let mut owned = OwnedChild(child);
        let deadline = Instant::now() + Duration::from_secs(3);
        let outcome = loop {
            if let Some(status) = owned.0.try_wait().unwrap() { break Some(status); }
            if Instant::now() >= deadline { break None; }
            std::thread::sleep(Duration::from_millis(5));
        };
        eprintln!("shutdown case {bind}: {outcome:?}");
        if !outcome.is_some_and(|s|s.success()) { failed.push(bind); }
        drop(owned); // joins completion, or TERM+wait on timeout, before assertions
    }
    assert!(failed.is_empty(), "shutdown did not finish in owned child: {failed:?}");
}
