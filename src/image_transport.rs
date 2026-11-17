//! Qualification transport. Not wired to any image provider or API route.
use std::net::IpAddr;
use ureq::http::Uri;
#[derive(Debug,PartialEq,Eq)]
pub enum Rejected { Destination, Address, Transport, Response, Deadline }
fn checked_uri(url:&str)->Result<Uri,Rejected>{
    if url.bytes().any(|c|c<=32||c>=127)||url.contains(['#','\\']) {return Err(Rejected::Destination)}
    let uri:Uri=url.parse().map_err(|_|Rejected::Destination)?;
    let authority=uri.authority().ok_or(Rejected::Destination)?.as_str();
    if uri.scheme_str()!=Some("https") || !matches!(authority,"image.pollinations.ai"|"image.pollinations.ai:443"|"aihorde.net"|"aihorde.net:443") {return Err(Rejected::Destination)}
    Ok(uri)
}
fn public_ip(ip:IpAddr)->bool{
    match ip {
        IpAddr::V4(v)=>{let [a,b,c,_]=v.octets();
            !(a==0||a==10||a==127||a>=224||(a==100&&(64..=127).contains(&b))
              ||(a==169&&b==254)||(a==172&&(16..=31).contains(&b))
              ||(a==192&&(b==0||(b==168)||(b==88&&c==99)))
              ||(a==198&&(b==18||b==19||(b==51&&c==100)))||(a==203&&b==0&&c==113))
        },
        IpAddr::V6(v)=>{let s=v.segments();(s[0]&0xe000)==0x2000
            && !(s[0]==0x2001&&s[1]<0x200) && !(s[0]==0x2001&&s[1]==0x0db8) && s[0]!=0x2002 && !(s[0]==0x3fff&&(s[1]&0xf000)==0)}
    }
}
use std::io::Read;
use std::time::{Duration,Instant};
use ureq::unversioned::resolver::{Resolver,ResolvedSocketAddrs,DefaultResolver};
use ureq::unversioned::transport::{Connector,TcpConnector,RustlsConnector,NextTimeout,Transport,Buffers,ConnectionDetails};
use ureq::config::Config;
#[derive(Debug)]
struct Pinned { host:String, addresses:ResolvedSocketAddrs }
impl Pinned {
    fn new(uri:&Uri,addresses:ResolvedSocketAddrs)->Result<Self,Rejected>{
        checked_uri(&uri.to_string())?;
        if addresses.is_empty() || addresses.iter().any(|a|a.port()!=443||!public_ip(a.ip())) {return Err(Rejected::Address)}
        let mut one=DefaultResolver::default().empty();one.push(*addresses.iter().next().ok_or(Rejected::Address)?);
        Ok(Self{host:uri.host().ok_or(Rejected::Destination)?.into(),addresses:one})
    }
}
impl Resolver for Pinned {
    fn resolve(&self,uri:&Uri,_:&Config,_:NextTimeout)->Result<ResolvedSocketAddrs,ureq::Error>{
        if checked_uri(&uri.to_string()).is_err()||uri.host()!=Some(&self.host){return Err(ureq::Error::HostNotFound)}
        Ok(self.addresses.clone())
    }
}
#[derive(Debug)]
struct TransferBudget;
#[derive(Debug)]
struct Bounded<T:Transport>{inner:T,received:usize}
impl<T:Transport> Connector<T> for TransferBudget{
    type Out=Bounded<T>;
    fn connect(&self,_:&ConnectionDetails,chained:Option<T>)->Result<Option<Self::Out>,ureq::Error>{
        let inner=chained.ok_or_else(||ureq::Error::Io(std::io::Error::other("missing TLS transport")))?;
        if !inner.is_tls(){return Err(ureq::Error::Io(std::io::Error::other("TLS required")))}
        Ok(Some(Bounded{inner,received:0}))
    }
}
impl<T:Transport> Transport for Bounded<T>{
    fn buffers(&mut self)->&mut dyn Buffers{self.inner.buffers()}
    fn transmit_output(&mut self,n:usize,t:NextTimeout)->Result<(),ureq::Error>{self.inner.transmit_output(n,t)}
    fn await_input(&mut self,t:NextTimeout)->Result<bool,ureq::Error>{
        let before=self.inner.buffers().input().len();
        let progress=self.inner.await_input(t)?;
        let added=self.inner.buffers().input().len().saturating_sub(before);
        self.received=self.received.saturating_add(added);
        // Includes headers and HTTP framing, before transparent gzip decoding.
        if self.received>MAX_BYTES+16384{return Err(ureq::Error::Io(std::io::Error::other("image transfer limit")))}
        Ok(progress)
    }
    fn is_open(&mut self)->bool{self.inner.is_open()}
    fn is_tls(&self)->bool{self.inner.is_tls()}
}
fn pinned_agent(pin:Pinned,timeout:Duration,roots:ureq::tls::RootCerts)->ureq::Agent {
    let tls=ureq::tls::TlsConfig::builder().root_certs(roots).use_sni(true).disable_verification(false).build();
    let config=Config::builder().proxy(None).https_only(true).max_redirects(0)
        .http_status_as_error(false).max_response_header_size(16384)
        .timeout_global(Some(timeout)).tls_config(tls).build();
    let chain=().chain(TcpConnector::default()).chain(RustlsConnector::default()).chain(TransferBudget);
    ureq::Agent::with_parts(config,chain,pin)
}
const MAX_BYTES:usize=2*1024*1024;
fn get_bytes(agent:&ureq::Agent,uri:&Uri)->Result<Vec<u8>,Rejected>{
    let mut response=agent.get(uri.to_string()).header("accept-encoding","identity").call().map_err(|_|Rejected::Transport)?;
    if response.status().as_u16()!=200 {return Err(Rejected::Response)}
    // ureq strips known gzip headers when transparently decoding. TransferBudget
    // caps pre-decoding bytes; the reader below independently caps decoded bytes.
    let headers=response.headers();
    if headers.get_all("content-encoding").iter().any(|v|v.as_bytes()!=b"identity") {return Err(Rejected::Response)}
    if headers.get_all("content-length").iter().count()>1 {return Err(Rejected::Response)}
    if let Some(length)=headers.get("content-length"){
        let length:usize=length.to_str().map_err(|_|Rejected::Response)?.parse().map_err(|_|Rejected::Response)?;
        if length>MAX_BYTES{return Err(Rejected::Response)}
    }
    let mut bytes=Vec::new();
    response.body_mut().as_reader().take((MAX_BYTES+1)as u64).read_to_end(&mut bytes).map_err(|_|Rejected::Transport)?;
    if bytes.len()>MAX_BYTES{return Err(Rejected::Response)}
    Ok(bytes)
}
pub fn fetch(url:&str,deadline:Instant)->Result<Vec<u8>,Rejected>{
    let uri=checked_uri(url)?;
    let remaining=deadline.checked_duration_since(Instant::now()).ok_or(Rejected::Deadline)?;
    let config=Config::builder().proxy(None).build();
    let timeout=NextTimeout{after:ureq::unversioned::transport::time::Duration::Exact(remaining.min(Duration::from_secs(5))),reason:ureq::Timeout::Resolve,..Default::default()};
    let addresses=DefaultResolver::default().resolve(&uri,&config,timeout).map_err(|_|Rejected::Address)?;
    let pin=Pinned::new(&uri,addresses)?;
    let remaining=deadline.checked_duration_since(Instant::now()).ok_or(Rejected::Deadline)?;
    get_bytes(&pinned_agent(pin,remaining,ureq::tls::RootCerts::WebPki),&uri)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_https_hosts_accept_only_default_tls_authorities() {
        for url in ["https://image.pollinations.ai/prompt/x?width=512","https://aihorde.net/api/v2/generate/check/a","https://image.pollinations.ai:443/x"] {assert!(checked_uri(url).is_ok(),"{url}")}
    }
    #[test]
    fn unexpected_authorities_and_url_injection_never_reach_dns() {
        for url in ["http://image.pollinations.ai/x","https://image.pollinations.ai:444/x","https://image.pollinations.ai:0443/x","https://user@image.pollinations.ai/x","https://image.pollinations.ai.evil.test/x","https://image.pollinations.ai./x","https://IMAGE.POLLINATIONS.AI/x","https://127.0.0.1/x","https://2130706433/x","https://0x7f000001/x","https://[::ffff:127.0.0.1]/x","https://image%2epollinations.ai/x","https://image.pollinations.ai/x#f","https://image.pollinations.ai/x\r\nHost: evil","https://aihorde.net\\@127.0.0.1/x","https://storage.example/x"] {assert!(checked_uri(url).is_err(),"{url}")}
    }
    #[test]
    fn non_global_and_transition_addresses_are_rejected() {
        for ip in ["0.0.0.0","10.1.2.3","100.64.0.1","127.0.0.1","169.254.169.254","172.16.0.1","192.0.0.9","192.0.2.1","192.88.99.1","192.168.1.1","198.18.0.1","198.51.100.1","203.0.113.1","224.0.0.1","240.0.0.1","255.255.255.255","::","::1","::ffff:8.8.8.8","64:ff9b::808:808","100::1","2001::1","2001:db8::1","2002:0808:0808::1","3fff::1","fc00::1","fe80::1","ff02::1"] {assert!(!public_ip(ip.parse().unwrap()),"{ip}")}
        for ip in ["8.8.8.8","1.1.1.1","104.21.1.1","2606:4700:4700::1111"] {assert!(public_ip(ip.parse().unwrap()),"{ip}")}
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use std::{io::{Read,Write},sync::Arc,net::TcpListener};
    fn fixture(response:Vec<u8>,trusted:bool,host:&str)->(ureq::Agent,Uri,std::thread::JoinHandle<Option<(String,String)>>){
        fixture_timed(response,trusted,host,Duration::from_secs(2),Duration::ZERO)
    }
    fn fixture_timed(response:Vec<u8>, trusted:bool, host:&str,timeout:Duration,delay:Duration)->(ureq::Agent,Uri,std::thread::JoinHandle<Option<(String,String)>>) {
        let cert=ureq::tls::Certificate::from_pem(include_bytes!("../tests/fixtures/image-tls/server.pem")).unwrap();
        let key=ureq::tls::PrivateKey::from_pem(include_bytes!("../tests/fixtures/image-tls/server.key")).unwrap();
        let server=rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key.der().to_vec()))).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();let addr=listener.local_addr().unwrap();
        let thread=std::thread::spawn(move||{
            listener.set_nonblocking(true).unwrap();let start=Instant::now();
            let tcp=loop {match listener.accept(){Ok((s,_))=>break s,Err(_)=>{if start.elapsed()>Duration::from_secs(3){return None}std::thread::sleep(Duration::from_millis(2));}}};
            tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            let conn=rustls::ServerConnection::new(Arc::new(server)).unwrap();let mut stream=rustls::StreamOwned::new(conn,tcp);let mut request=Vec::new();let mut b=[0;1024];
            while !request.windows(4).any(|w|w==b"\r\n\r\n"){match stream.read(&mut b){Ok(0)|Err(_)=>return None,Ok(n)=>request.extend_from_slice(&b[..n])}}
            let sni=stream.conn.server_name().unwrap_or("").to_string();
            if !delay.is_zero(){let split=response.windows(4).position(|b|b==b"\r\n\r\n").unwrap()+4;let _=stream.write_all(&response[..split]);let _=stream.flush();std::thread::sleep(delay);let _=stream.write_all(&response[split..]);}else{let _=stream.write_all(&response);}let _=stream.flush();
            Some((sni,String::from_utf8(request).unwrap()))
        });
        let uri=checked_uri(&format!("https://{host}/private-sentinel")).unwrap();
        // Only the local TLS fixture bypasses public-address admission. The actual
        // TCP and TLS connectors are identical to production; no external network.
        let mut addresses=DefaultResolver::default().empty();addresses.push(addr);let pin=Pinned{host:host.into(),addresses};
        let mut roots=ureq::tls::RootCerts::WebPki;
        if trusted{let ca=ureq::tls::Certificate::from_pem(include_bytes!("../tests/fixtures/image-tls/ca.pem")).unwrap();roots=ureq::tls::RootCerts::new_with_certs(&[ca]);}
        (pinned_agent(pin,timeout,roots),uri,thread)
    }
    #[test]
    fn actual_socket_is_pinned_with_original_sni_certificate_and_host(){
        let (agent,uri,server)=fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),true,"image.pollinations.ai");
        assert_eq!(get_bytes(&agent,&uri).unwrap(),b"ok");let (sni,req)=server.join().unwrap().unwrap();assert_eq!(sni,"image.pollinations.ai");assert!(req.to_lowercase().contains("host: image.pollinations.ai\r\n"));assert!(!req.to_lowercase().contains("authorization:"));assert!(!req.to_lowercase().contains("cookie:"));
    }
    #[test]
    fn global_budget_also_bounds_waiting_for_response_body(){
        let (agent,uri,server)=fixture_timed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),true,"image.pollinations.ai",Duration::from_millis(100),Duration::from_millis(350));
        assert_eq!(get_bytes(&agent,&uri),Err(Rejected::Transport));let _=server.join().unwrap();
    }
    #[test]
    fn invalid_certificate_or_hostname_never_delivers_http(){
        for (trusted,host) in [(false,"image.pollinations.ai"),(true,"aihorde.net")]{let (agent,uri,server)=fixture(vec![],trusted,host);assert_eq!(get_bytes(&agent,&uri),Err(Rejected::Transport));assert!(server.join().unwrap().is_none());}
    }
    #[test]
    fn raw_transfer_cap_bounds_gzip_with_no_decoded_output(){
        let mut gzip=vec![31,139,8,0,0,0,0,0,0,255];
        for _ in 0..500_000{gzip.extend_from_slice(&[0,0,0,255,255]);}
        gzip.extend_from_slice(&[1,0,0,255,255]);gzip.extend_from_slice(&[0;8]);
        let mut response=format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",gzip.len()).into_bytes();response.extend(gzip);
        let (agent,uri,server)=fixture(response,true,"image.pollinations.ai");
        assert_eq!(get_bytes(&agent,&uri),Err(Rejected::Transport));assert!(server.join().unwrap().is_some());
    }
    #[test]
    fn redirects_and_unknown_length_oversized_bodies_are_rejected(){
        let redirect=b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let mut huge=b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();huge.extend(vec![b'x';MAX_BYTES+1]);
        for response in [redirect,huge]{let (agent,uri,server)=fixture(response,true,"image.pollinations.ai");assert_eq!(get_bytes(&agent,&uri),Err(Rejected::Response));assert!(server.join().unwrap().is_some());}
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    fn addresses(list:&[&str])->ResolvedSocketAddrs{let mut out=DefaultResolver::default().empty();for a in list{out.push(a.parse().unwrap())}out}
    #[test]
    fn pin_constructor_rejects_unexpected_host_even_with_public_address(){
        assert!(Pinned::new(&"https://evil.test/".parse().unwrap(),addresses(&["8.8.8.8:443"])).is_err());
    }
    #[test]
    fn mixed_private_answers_and_wrong_ports_are_never_connectable(){
        let uri=checked_uri("https://image.pollinations.ai/x").unwrap();
        for a in [vec!["8.8.8.8:443","127.0.0.1:443"],vec!["8.8.8.8:80"],vec![]]{assert!(matches!(Pinned::new(&uri,addresses(&a)),Err(Rejected::Address)))}
    }
    #[test]
    fn resolver_never_reresolves_or_accepts_another_host(){
        let uri=checked_uri("https://image.pollinations.ai/x").unwrap();let p=Pinned::new(&uri,addresses(&["8.8.8.8:443"])).unwrap();let cfg=Config::default();
        for _ in 0..2{assert_eq!(p.resolve(&uri,&cfg,NextTimeout::default()).unwrap().iter().next().unwrap().to_string(),"8.8.8.8:443")}
        assert!(p.resolve(&checked_uri("https://aihorde.net/x").unwrap(),&cfg,NextTimeout::default()).is_err());
    }
    #[test]
    fn one_request_pins_one_address_without_rotation(){
        let uri=checked_uri("https://image.pollinations.ai/x").unwrap();let p=Pinned::new(&uri,addresses(&["8.8.8.8:443","1.1.1.1:443"])).unwrap();assert_eq!(p.addresses.len(),1);assert_eq!(p.addresses.iter().next().unwrap().to_string(),"8.8.8.8:443");
    }
    #[test]
    fn elapsed_absolute_deadline_stops_before_resolution(){
        assert_eq!(fetch("https://image.pollinations.ai/private-sentinel",Instant::now()-Duration::from_secs(1)),Err(Rejected::Deadline));
    }
                                                                                                                                                                                                                                                }
