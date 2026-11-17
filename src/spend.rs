//! Virtual USD accounting. Amounts are integer nanodollars, never real charges.
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

pub const USD: u64 = 1_000_000_000;
pub const FRIEND_CAPS: Caps = Caps { daily: 2 * USD, monthly: 15 * USD };

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Price { pub input: u64, pub output: u64 }
impl Price {
    pub fn cost(self, input: u64, output: u64) -> Option<u64> {
        let amount = (input as u128).checked_mul(self.input as u128)?
            .checked_add((output as u128).checked_mul(self.output as u128)?)?;
        u64::try_from(amount.checked_add(999_999)? / 1_000_000).ok()
    }
}

// Strict decimal USD, up to nine fractional digits. No floats or exponent form.
pub fn usd(raw: &str) -> Option<u64> {
    let mut parts = raw.split('.');
    let whole = parts.next()?;
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) { return None; }
    let mut value = whole.parse::<u64>().ok()?.checked_mul(USD)?;
    if let Some(frac) = parts.next() {
        if frac.is_empty() || frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()) { return None; }
        value = value.checked_add(frac.parse::<u64>().ok()?.checked_mul(10u64.pow(9 - frac.len() as u32))?)?;
    }
    if parts.next().is_some() { return None; }
    Some(value)
}

pub fn admin_only(price: Price, explicit: Option<bool>) -> bool {
    explicit.unwrap_or(price.output >= 10 * USD)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Caps { pub daily: u64, pub monthly: u64 }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals { pub confirmed: u64, pub held: u64 }
impl Totals {
    fn combined(self) -> Option<u64> { self.confirmed.checked_add(self.held) }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Window { pub period: String, pub models: BTreeMap<String, Totals> }
impl Window {
    pub fn total(&self) -> Option<Totals> {
        self.models.values().try_fold(Totals::default(), |sum, v| Some(Totals {
            confirmed: sum.confirmed.checked_add(v.confirmed)?, held: sum.held.checked_add(v.held)?,
        }))
    }
    fn roll(&mut self, period: &str) {
        if self.period.as_str() < period { self.period = period.to_string(); self.models.clear(); }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserUsage { pub day: Window, pub month: Window, #[serde(default)] pub unknown_requests: u64, #[serde(default)] pub accounting_error: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Reservation { user: String, model: String, day: String, amount: u64, capped: bool }
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub users: BTreeMap<String, UserUsage>,
    pub caps: BTreeMap<String, Caps>,
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountUsage>,
    next_id: u64,
    reservations: BTreeMap<u64, Reservation>,
}

// Account resources are charged in full before dispatch. Unknown outcomes never
// refund an allowance. Neurons use integer micro-neurons; calls use whole units.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountUsage {
    pub day: String,
    pub total: u64,
    pub friends: u64,
    pub users: BTreeMap<String,u64>,
    pub models: BTreeMap<String,u64>,
}

impl Ledger {
    pub fn admit_account(&mut self, account: &str, day: &str, user: &str, owner: bool,
        model: &str, amount: u64, total_cap: u64, friend_cap: u64, user_cap: u64, model_cap: u64)
        -> Result<(), &'static str> {
        if !matches!(account,"cloudflare"|"openrouter") || amount == 0 || user.is_empty() || user.len()>128 || model.len()>256 {
            return Err("invalid account admission");
        }
        let mut next=self.accounts.get(account).cloned().unwrap_or_default();
        if next.day.as_str()>day { return Err("account clock moved backwards"); }
        if next.day!=day { next=AccountUsage {day:day.into(),..Default::default()}; }
        // Bound allocation at admission, not just serialized state size.
        if !next.users.contains_key(user) && next.users.len()>=1024 { return Err("account users full"); }
        if !next.models.contains_key(model) && next.models.len()>=32 { return Err("account models full"); }
        let total=next.total.checked_add(amount).ok_or("account overflow")?;
        let friends=next.friends.checked_add(if owner {0}else{amount}).ok_or("account overflow")?;
        let calls=next.users.get(user).copied().unwrap_or(0).checked_add(1).ok_or("account overflow")?;
        let model_calls=next.models.get(model).copied().unwrap_or(0).checked_add(1).ok_or("account overflow")?;
        if total>total_cap || friends>friend_cap || (!owner && calls>user_cap) || model_calls>model_cap {return Err("account cap reached");}
        next.total=total;next.friends=friends;next.users.insert(user.into(),calls);next.models.insert(model.into(),model_calls);
        self.accounts.insert(account.into(),next);Ok(())
    }

    pub fn reserve(&mut self, user: &str, model: &str, day: &str, amount: u64, cap: Option<Caps>) -> Result<u64, &'static str> {
        if day.len() != 10 || !day.is_ascii() || day.as_bytes()[4] != b'-' || day.as_bytes()[7] != b'-' { return Err("invalid accounting day"); }
        let month = &day[..7];
        let mut usage = self.users.get(user).cloned().unwrap_or_default();
        if cap.is_some() && usage.accounting_error { return Err("accounting bound was exceeded; admin repair required"); }
        // A backward wall-clock step must not reset an already active budget.
        if usage.day.period.as_str() > day || usage.month.period.as_str() > month { return Err("accounting clock moved backwards"); }
        usage.day.roll(day); usage.month.roll(month);
        let daily = usage.day.total().and_then(Totals::combined).ok_or("accounting overflow")?.checked_add(amount).ok_or("accounting overflow")?;
        let monthly = usage.month.total().and_then(Totals::combined).ok_or("accounting overflow")?.checked_add(amount).ok_or("accounting overflow")?;
        if let Some(c) = cap {
            if daily > c.daily || monthly > c.monthly || daily == 0 && (c.daily == 0 || c.monthly == 0) { return Err("spend cap reached"); }
        }
        let id = self.next_id.checked_add(1).ok_or("accounting overflow")?;
        for window in [&mut usage.day, &mut usage.month] {
            let totals = window.models.entry(model.to_string()).or_default();
            totals.held = totals.held.checked_add(amount).ok_or("accounting overflow")?;
        }
        self.next_id = id;
        self.users.insert(user.to_string(), usage);
        self.reservations.insert(id, Reservation { user: user.into(), model: model.into(), day: day.into(), amount, capped: cap.is_some() });
        Ok(id)
    }

    // None means unreported usage: retain the full hold, never record zero cost.
    // A late completion updates only its admission windows, not a new day's cap.
    pub fn settle(&mut self, id: u64, actual: Option<u64>) -> Result<(), &'static str> {
        let r = self.reservations.get(&id).ok_or("unknown reservation")?;
        let mut usage = self.users.get(&r.user).cloned().ok_or("missing accounting user")?;
        if matches!(actual, Some(n) if r.capped && n > r.amount) { usage.accounting_error = true; }
        if let Some(actual) = actual {
            for (window, period) in [(&mut usage.day, r.day.as_str()), (&mut usage.month, &r.day[..7])] {
                if window.period != period { continue; }
                let totals = window.models.get_mut(&r.model).ok_or("missing accounting model")?;
                totals.held = totals.held.checked_sub(r.amount).ok_or("accounting underflow")?;
                totals.confirmed = totals.confirmed.checked_add(actual).ok_or("accounting overflow")?;
            }
        }
        if actual.is_none() { usage.unknown_requests = usage.unknown_requests.checked_add(1).ok_or("accounting overflow")?; }
        self.users.insert(r.user.clone(), usage);
        self.reservations.remove(&id);
        Ok(())
    }
}

pub struct Store {
    pub ledger: Ledger,
    path: Option<std::path::PathBuf>,
    failed: bool,
    _lock: Option<std::fs::File>,
}
impl Store {
    pub fn open(path: Option<std::path::PathBuf>) -> std::io::Result<Self> {
        use std::io::Read;
        let path = path.map(|path| -> std::io::Result<std::path::PathBuf> {
            match std::fs::canonicalize(&path) {
                Ok(real) => Ok(real),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Reject dangling filename symlinks rather than creating a
                    // second identity before their target exists.
                    if std::fs::symlink_metadata(&path).is_ok() { return Err(std::io::Error::other("unresolved ledger alias")); }
                    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| std::path::Path::new("."));
                    let name = path.file_name().ok_or_else(|| std::io::Error::other("missing ledger filename"))?;
                    Ok(std::fs::canonicalize(parent)?.join(name))
                }
                Err(e) => Err(e),
            }
        }).transpose()?;
        let mut lock = None;
        if let Some(path) = &path {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true);
            #[cfg(unix)] {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(path.with_extension("lock"))?;
            file.try_lock().map_err(std::io::Error::other)?;
            lock = Some(file);
        }
        let mut ledger = Ledger::default();
        if let Some(path) = &path {
            match std::fs::File::open(path) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                    if bytes.len() > 4 * 1024 * 1024 { return Err(std::io::Error::other("spend state exceeds limit")); }
                    ledger = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        // No request survives a restart. Keep its held cost, discard only the
        // transient receipt so interrupted requests cannot reset the budget.
        for reservation in ledger.reservations.values() {
            let usage = ledger.users.get_mut(&reservation.user).ok_or_else(|| std::io::Error::other("missing reservation user"))?;
            usage.unknown_requests = usage.unknown_requests.checked_add(1).ok_or_else(|| std::io::Error::other("accounting overflow"))?;
        }
        ledger.reservations.clear();
        Ok(Self { ledger, path, failed: false, _lock: lock })
    }
    pub fn durable(&self) -> bool { self.path.is_some() && !self.failed }
    pub fn available(&self) -> bool { !self.failed }
    pub fn change<T>(&mut self, f: impl FnOnce(&mut Ledger) -> Result<T, &'static str>) -> Result<T, String> {
        if self.failed { return Err("spend state unavailable until restart".into()); }
        let mut next = self.ledger.clone();
        let result = f(&mut next).map_err(str::to_string)?;
        if let Some(path) = &self.path {
            if let Err(e) = save(path, &next) {
                self.failed = true;
                return Err(format!("cannot persist spend state: {e}"));
            }
        }
        self.ledger = next;
        Ok(result)
    }
}
fn save(path: &std::path::Path, ledger: &Ledger) -> std::io::Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(ledger)?;
    if bytes.len() > 4 * 1024 * 1024 { return Err(std::io::Error::other("spend state exceeds limit")); }
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(std::io::Error::other)?.as_nanos();
    let temp = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        #[cfg(unix)] {
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| std::path::Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() { let _ = std::fs::remove_file(&temp); }
    result
}

#[cfg(test)]
#[path = "spend_tests.rs"]
mod tests;

pub fn usage(json: &serde_json::Value) -> Option<(u64,u64)> {
    let usage = json.get("usage")?;
    Some((usage.get("prompt_tokens")?.as_u64()?, usage.get("completion_tokens")?.as_u64()?))
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub enabled: bool,
    pub account_verified_day: String,
    pub openrouter_allowance: u64,
    pub path: Option<std::path::PathBuf>,
    pub prices: BTreeMap<String, Price>,
    pub access: BTreeMap<String, bool>,
    pub caps: BTreeMap<String, Caps>,
    pub default_caps: Caps,
    pub error: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        let mut prices = BTreeMap::new();
        // List-price benchmark, USD per million tokens. Source/date in README.
        for (name, input, output) in [
            ("glm-5.3", 1_400_000_000, 4_400_000_000),
            ("glm-5.3-flash", 150_000_000, 500_000_000),
            ("glm-4.7-flash", 0, 0),
            ("deepseek-v4.1-flash-1017", 300_000_000, 1_200_000_000),
            ("qwen-3.8-27b", 500_000_000, 3_000_000_000),
        ] { prices.insert(name.into(), Price { input, output }); }
        Self { account_verified_day: String::new(), openrouter_allowance: 0, enabled: false, path: None, prices, access: BTreeMap::new(), caps: BTreeMap::new(), default_caps: FRIEND_CAPS, error: None }
    }
}
impl Settings {
    pub fn from_env() -> Self {
        let mut out = Self { enabled: true, path: Some(std::path::PathBuf::from("aqua-spend.json")), ..Self::default() };
        let result = (|| -> Result<(), String> {
            out.account_verified_day=std::env::var("AQUA_ACCOUNT_VERIFIED_UTC_DAY").unwrap_or_default();
            out.openrouter_allowance=match std::env::var("AQUA_OPENROUTER_VERIFIED_REMAINING") {
                Ok(raw)=>raw.parse::<u64>().ok().filter(|n|*n<=50).ok_or("invalid OpenRouter remaining")?.saturating_sub(10).min(40),
                Err(_)=>0,
            };
            if let Ok(path) = std::env::var("AQUA_SPEND_STATE_PATH") {
                if path.trim().is_empty() { return Err("empty AQUA_SPEND_STATE_PATH".into()); }
                out.path = Some(path.into());
            }
            if let Ok(raw) = std::env::var("AQUA_SPEND_DEFAULT_CAP") { out.default_caps = parse_caps(&raw).ok_or("invalid AQUA_SPEND_DEFAULT_CAP")?; }
            if let Ok(raw) = std::env::var("AQUA_SPEND_CAPS") {
                for pair in raw.split(',').filter(|p| !p.trim().is_empty()) {
                    let (name, value) = pair.split_once('=').ok_or("invalid AQUA_SPEND_CAPS")?;
                    if name.trim().is_empty() { return Err("empty cap account".into()); }
                    out.caps.insert(name.trim().into(), parse_caps(value).ok_or("invalid AQUA_SPEND_CAPS")?);
                }
            }
            if let Ok(raw) = std::env::var("AQUA_MODEL_PRICES") {
                for pair in raw.split(',').filter(|p| !p.trim().is_empty()) {
                    let (name, value) = pair.split_once('=').ok_or("invalid AQUA_MODEL_PRICES")?;
                    let (input, output) = value.split_once('/').ok_or("invalid AQUA_MODEL_PRICES")?;
                    if name.trim().is_empty() { return Err("empty price model".into()); }
                    out.prices.insert(name.trim().into(), Price { input: usd(input.trim()).ok_or("invalid price")?, output: usd(output.trim()).ok_or("invalid price")? });
                }
            }
            if let Ok(raw) = std::env::var("AQUA_MODEL_ACCESS") {
                for pair in raw.split(',').filter(|p| !p.trim().is_empty()) {
                    let (name, value) = pair.split_once('=').ok_or("invalid AQUA_MODEL_ACCESS")?;
                    if name.trim().is_empty() { return Err("empty access model".into()); }
                    let restricted = match value.trim() { "admin" => true, "all" => false, _ => return Err("invalid model access".into()) };
                    out.access.insert(name.trim().into(), restricted);
                }
            }
            Ok(())
        })();
        out.error = result.err();
        out
    }
    pub fn price(&self, model: &str) -> Price {
        self.prices.get(model).copied().unwrap_or(Price { input: 10 * USD, output: 30 * USD })
    }
    pub fn restricted(&self, model: &str) -> bool {
        self.enabled && admin_only(self.price(model), self.access.get(model).copied())
    }
    pub fn cap(&self, ledger: &Ledger, name: &str) -> Caps {
        ledger.caps.get(name).or_else(|| self.caps.get(name)).copied().unwrap_or(self.default_caps)
    }
}
pub fn parse_caps(raw: &str) -> Option<Caps> {
    let (daily, monthly) = raw.trim().split_once('/')?;
    Some(Caps { daily: usd(daily.trim())?, monthly: usd(monthly.trim())? })
}
