//! Per-login bearer keys. Cleartext exists only for the create response.
use std::{collections::BTreeMap, io::{Read, Write}, path::{Path, PathBuf}};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record { pub id:String,pub login:String,pub name:String,pub masked:String,pub created:u64,pub last_used:Option<u64>,hash:String }
impl Record {
    pub fn public(&self)->serde_json::Value {serde_json::json!({"id":self.id,"name":self.name,"masked":self.masked,"created":self.created,"last_used":self.last_used})}
}
pub struct Store {records:BTreeMap<String,Record>,path:Option<PathBuf>,failed:bool,_lock:Option<std::fs::File>}
fn now()->u64 {std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()}
fn random(bytes:usize)->std::io::Result<String> {let mut b=vec![0;bytes];std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;Ok(b.iter().map(|b|format!("{b:02x}")).collect())}
pub fn fingerprint(token:&str)->String {format!("{:x}",Sha256::digest(token.as_bytes()))}
impl Store {
    pub fn open(spend_path:Option<PathBuf>)->std::io::Result<Self> {
        // Separate from usage: older accounting writers cannot erase keys/revocations.
        let path=spend_path.map(|p|p.with_extension("keys.json"));
        let path=path.map(|p| {let parent=p.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            if std::fs::symlink_metadata(&p).map(|m|m.file_type().is_symlink()).unwrap_or(false) {return Err(std::io::Error::other("key store alias rejected"));}
            Ok(std::fs::canonicalize(parent)?.join(p.file_name().ok_or_else(||std::io::Error::other("key store filename"))?))}).transpose()?;
        let mut lock=None;let mut records=BTreeMap::new();
        if let Some(path)=&path {
            let mut o=std::fs::OpenOptions::new();o.read(true).write(true).create(true);
            #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;o.mode(0o600);}
            let f=o.open(path.with_extension("lock"))?;f.try_lock().map_err(std::io::Error::other)?;lock=Some(f);
            match std::fs::File::open(path) {Ok(f)=>{let mut bytes=Vec::new();f.take(4*1024*1024+1).read_to_end(&mut bytes)?;
                if bytes.len()>4*1024*1024{return Err(std::io::Error::other("key store too large"));}records=serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;},Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(e)}
        }
        let store=Self{records,path,failed:false,_lock:lock};
        if store.records.len()>4096 || store.records.iter().any(|(id,r)| id!=&r.id || r.hash.len()!=64 || !r.hash.bytes().all(|b|b.is_ascii_hexdigit()) || r.login.len()>39 || r.name.len()>64 || r.masked.len()>32) {return Err(std::io::Error::other("invalid key store"));}
        Ok(store)
    }
    fn persist(&mut self,next:BTreeMap<String,Record>)->Result<(),&'static str> {
        if self.failed{return Err("key store unavailable");}let path=self.path.as_ref().ok_or("key storage not configured")?;
        let result=(||->std::io::Result<()> {let bytes=serde_json::to_vec(&next)?;if bytes.len()>4*1024*1024{return Err(std::io::Error::other("key store too large"));}
            let temp=path.with_extension(format!("tmp-{}",random(16)?));let mut o=std::fs::OpenOptions::new();o.write(true).create_new(true);
            #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;o.mode(0o600);}
            let mut f=o.open(&temp)?;let result=(|| {f.write_all(&bytes)?;f.sync_all()?;std::fs::rename(&temp,path)?;std::fs::File::open(path.parent().unwrap())?.sync_all()})();
            if result.is_err(){let _=std::fs::remove_file(temp);}result})();
        if result.is_err(){self.failed=true;return Err("key store unavailable");}self.records=next;Ok(())
    }
    pub fn list(&self,login:&str)->Result<Vec<serde_json::Value>,&'static str> {if self.failed||self.path.is_none(){return Err("key storage unavailable");}Ok(self.records.values().filter(|r|r.login==login).map(Record::public).collect())}
    pub fn create(&mut self,login:&str,name:&str)->Result<serde_json::Value,&'static str> {
        let name=name.trim();if name.is_empty()||name.len()>64||name.chars().any(char::is_control){return Err("key name must be 1-64 bytes without control characters");}
        if self.records.len()>=4096||self.records.values().filter(|r|r.login==login).count()>=16{return Err("key limit reached");}
        let token=format!("aqua_sk_{}",random(32).map_err(|_|"secure randomness unavailable")?);let id=random(16).map_err(|_|"secure randomness unavailable")?;
        let r=Record{id:id.clone(),login:login.into(),name:name.into(),masked:format!("aqua_sk_...{}",&token[token.len()-4..]),created:now(),last_used:None,hash:fingerprint(&token)};
        let mut response=r.public();let mut next=self.records.clone();next.insert(id,r);self.persist(next)?;response["key"]=token.into();Ok(response)
    }
    pub fn resolve(&mut self,token:&str)->Result<Option<String>,&'static str> {
        if self.failed||self.path.is_none(){return Err("key storage unavailable");}
        if token.len()!=72||!token.starts_with("aqua_sk_")||!token[8..].bytes().all(|b|b.is_ascii_hexdigit()){return Ok(None);}
        let hash=fingerprint(token);let found=self.records.values().find(|r|r.hash==hash).map(|r|(r.id.clone(),r.login.clone()));
        if let Some((id,login))=found {let mut next=self.records.clone();next.get_mut(&id).unwrap().last_used=Some(now());self.persist(next)?;return Ok(Some(login));}Ok(None)
    }
    pub fn revoke(&mut self,login:&str,id:&str)->Result<bool,&'static str> {if !self.records.get(id).map(|r|r.login==login).unwrap_or(false){return Ok(false);}let mut next=self.records.clone();next.remove(id);self.persist(next)?;Ok(true)}
}
#[cfg(test)] mod tests {
    use super::*;
    fn path()->PathBuf{std::env::temp_dir().join(format!("aqua-key-test-{}-{}.json",std::process::id(),random(8).unwrap()))}
    #[test] fn keys_are_once_only_hashed_scoped_and_revoked_across_restart(){
        let p=path();let key_path=p.with_extension("keys.json");let mut s=Store::open(Some(p.clone())).unwrap();let created=s.create("sam","laptop").unwrap();let token=created["key"].as_str().unwrap();assert_eq!(token.len(),72);
        let disk=std::fs::read_to_string(&key_path).unwrap();assert!(!disk.contains(token));assert!(disk.contains(&fingerprint(token)));assert!(s.list("alex").unwrap().is_empty());assert!(!s.list("sam").unwrap()[0].to_string().contains("hash"));
        assert!(!s.revoke("alex",created["id"].as_str().unwrap()).unwrap());assert_eq!(s.resolve(token).unwrap(),Some("sam".into()));assert!(s.list("sam").unwrap()[0]["last_used"].is_u64());
        assert!(Store::open(Some(p.clone())).is_err());drop(s);let mut s=Store::open(Some(p.clone())).unwrap();assert_eq!(s.resolve(token).unwrap(),Some("sam".into()));assert!(s.revoke("sam",created["id"].as_str().unwrap()).unwrap());drop(s);assert!(Store::open(Some(p.clone())).unwrap().resolve(token).unwrap().is_none());
        let _=std::fs::remove_file(key_path);
    }
    #[test] fn key_limits_and_storage_fail_closed(){let p=path();let mut s=Store::open(Some(p)).unwrap();assert!(s.create("sam","").is_err());assert!(s.create("sam","\n").is_err());for _ in 0..16{s.create("sam","test").unwrap();}assert!(s.create("sam","17th").is_err());assert!(Store::open(None).unwrap().create("sam","test").is_err());s.path=Some(PathBuf::from("/does-not-exist/keys.json"));assert!(s.create("alex","fail").is_err());assert!(s.list("sam").is_err());}
}
