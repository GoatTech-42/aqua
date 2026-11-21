use std::sync::Mutex;
use std::time::{Duration,Instant};

// One process-wide lane, not one allowance per gateway key or model row.
static CLASSIC: Mutex<Lane> = Mutex::new(Lane { active:false, last:None });
#[derive(Default)]
struct Lane { active:bool, last:Option<Instant> }
struct Permit<'a>(&'a Mutex<Lane>);
impl Drop for Permit<'_> {
    fn drop(&mut self) { if let Ok(mut lane)=self.0.lock() {lane.active=false;} }
}
fn acquire_at(lane:&Mutex<Lane>, now:Instant)->Option<Permit<'_>> {
    let mut state=lane.lock().ok()?;
    if state.active || state.last.is_some_and(|last|now.saturating_duration_since(last)<Duration::from_secs(60)) {return None;}
    state.active=true;state.last=Some(now);
    Some(Permit(lane))
}
pub(crate) fn acquire()->Option<impl Drop> { acquire_at(&CLASSIC,Instant::now()) }
pub(crate) fn valid_response(value:&serde_json::Value)->bool {
    value.get("model").and_then(serde_json::Value::as_str)==Some("gpt-oss-20b")
}

// This request is intentionally separate from bearer-provider transport. It
// receives only a whitelisted body, never gateway headers or stored credentials.
pub(crate) fn send(agent:&ureq::Agent, url:&str, body:&serde_json::Value)
    -> Result<ureq::http::Response<ureq::Body>,ureq::Error> {
    agent.post(url).header("content-type","application/json")
        .config().max_redirects(0).build().send_json(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pollinations_spacing_is_shared_and_permit_survives_past_the_window() {
        let lane=Mutex::new(Lane::default());let now=Instant::now();
        let first=acquire_at(&lane,now).expect("first call admitted");
        assert!(acquire_at(&lane,now+Duration::from_secs(61)).is_none(),"body still in flight");
        drop(first);
        assert!(acquire_at(&lane,now+Duration::from_secs(59)).is_none(),"spacing survives release");
        let next=acquire_at(&lane,now+Duration::from_secs(60)).expect("boundary admitted");
        drop(next);
        assert!(acquire_at(&lane,now+Duration::from_secs(61)).is_none(),"second call recorded");
    }
    #[test]
    fn pollinations_never_accepts_alias_drift_to_another_model() {
        assert!(valid_response(&serde_json::json!({"model":"gpt-oss-20b"})));
        for bad in [serde_json::json!({}),serde_json::json!({"model":null}),serde_json::json!({"model":"gpt-oss-120b"}),serde_json::json!({"model":"openai-fast"})] {
            assert!(!valid_response(&bad));
        }
    }
    #[test]
    fn pollinations_transport_posts_json_without_authorization_or_cookies_and_refuses_redirects() {
        use std::io::{Read,Write};
        use std::net::TcpListener;
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let url=format!("http://{}/openai",listener.local_addr().unwrap());
        let redirect=TcpListener::bind("127.0.0.1:0").unwrap();
        let redirected_address=redirect.local_addr().unwrap();
        let worker=std::thread::spawn(move|| {
            let (mut stream,_)=listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut bytes=Vec::new();let mut one=[0;1];
            while !bytes.ends_with(b"\r\n\r\n") {stream.read_exact(&mut one).unwrap();bytes.push(one[0]);}
            let head=String::from_utf8(bytes).unwrap();
            let length=head.lines().find_map(|l|l.to_lowercase().strip_prefix("content-length:").and_then(|n|n.trim().parse::<usize>().ok())).unwrap();
            let mut body=vec![0;length];stream.read_exact(&mut body).unwrap();
            write!(stream,"HTTP/1.1 302 Found\r\nLocation: http://{}/paid\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",redirected_address).unwrap();
            (head,serde_json::from_slice::<serde_json::Value>(&body).unwrap())
        });
        let agent:ureq::Agent=ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(3))).build().into();
        let body=serde_json::json!({"model":"openai-fast","messages":[{"role":"user","content":"offline fixture"}],"stream":false});
        let response=send(&agent,&url,&body);
        let (head,sent)=worker.join().unwrap();
        redirect.set_nonblocking(true).unwrap();
        assert!(matches!(redirect.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock),"redirect target contacted");
        assert!(response.is_err() || response.unwrap().status()==302,"must not follow redirect");
        assert!(head.starts_with("POST /openai HTTP/1.1\r\n"));
        let head=head.to_ascii_lowercase();
        for denied in ["authorization:","cookie:","x-api-key:","x-forwarded-for:","x-aqua-key:"] {assert!(!head.contains(denied),"{head}");}
        assert_eq!(sent,body);
    }

}
