fn main() {
    // Default to loopback so a bare local run or test never exposes the port.
    // Deployment sets AQUA_BIND explicitly (e.g. 0.0.0.0:8080 behind TLS).
    let addr = std::env::var("AQUA_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let server = aqua::bind_addr(&addr, aqua::config::from_env()).expect("failed to bind");
    println!("aqua listening on {}", addr);
    loop {
        std::thread::park();
    }
}
