fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let server = aqua::bind_addr(&format!("0.0.0.0:{}", port), aqua::config::from_env())
        .expect("failed to bind");
    println!("aqua listening on :{}", server.port());
    loop {
        std::thread::park();
    }
}
