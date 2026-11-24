//! Repository storage on Azure Blob Storage, with version-level
//! immutability (design: docs/design/phase-4-storage.md §7).
//!
//! Plain HTTPS and the documented Blob service REST API; no SDK. Requests
//! are signed with Shared Key (the storage account key) or carry a shared
//! access signature (SAS).

#![forbid(unsafe_code)]

use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use core_format::backend::{validate_key, Backend, PutOutcome};
use core_format::error::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The REST API version used (version-level immutability needs 2020-06-12+).
pub const API_VERSION: &str = "2021-12-02";

/// Immutability for new blobs: `Locked` cannot be shortened or removed by
/// anyone (like S3 compliance mode); `Unlocked` can be by an account with
/// the right permission (like S3 governance mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Unlocked,
    Locked,
}

impl LockMode {
    fn header(self) -> &'static str {
        match self {
            LockMode::Unlocked => "Unlocked",
            LockMode::Locked => "Locked",
        }
    }
    /// The repository settings use S3's words: compliance and governance.
    pub fn parse(s: &str) -> Option<LockMode> {
        match s.to_ascii_lowercase().as_str() {
            "compliance" | "locked" => Some(LockMode::Locked),
            "governance" | "unlocked" => Some(LockMode::Unlocked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lock {
    pub mode: LockMode,
    pub days: u32,
}

/// How requests are authorised.
#[derive(Clone)]
pub enum Credential {
    /// The storage account key (base64), for Shared Key signing.
    AccountKey(String),
    /// A shared access signature query string (`sv=...&sig=...`).
    Sas(String),
}

#[derive(Clone)]
pub struct AzureConfig {
    /// `https://account.blob.core.windows.net`, or for the Azurite emulator
    /// `http://127.0.0.1:10000/devstoreaccount1` (account in the path).
    pub endpoint: String,
    pub account: String,
    pub container: String,
    /// Blob name prefix, without leading or trailing slash.
    pub prefix: String,
    pub credential: Credential,
    pub lock: Option<Lock>,
}

impl std::fmt::Debug for AzureConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureConfig")
            .field("endpoint", &self.endpoint)
            .field("account", &self.account)
            .field("container", &self.container)
            .field("prefix", &self.prefix)
            .field("credential", &"<hidden>")
            .field("lock", &self.lock)
            .finish()
    }
}

/// `azure://container/some/prefix` → ("container", "some/prefix").
pub fn parse_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("azure://")?;
    let (c, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    // Container names: 3-63 of lower-case letters, digits and single hyphens.
    let valid = (3..=63).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !c.starts_with('-')
        && !c.ends_with('-')
        && !c.contains("--");
    valid.then(|| (c.to_string(), prefix.trim_matches('/').to_string()))
}

/// The credential a share sign-in carries: `password` is the account key,
/// or a SAS token (starting with `sv=` or `?sv=`).
pub fn credential_from(password: &str) -> Credential {
    let p = password.trim();
    let q = p.strip_prefix('?').unwrap_or(p);
    if q.starts_with("sv=") || q.contains("&sig=") {
        Credential::Sas(q.to_string())
    } else {
        Credential::AccountKey(p.to_string())
    }
}

pub struct AzureBackend {
    cfg: AzureConfig,
    agent: ureq::Agent,
    scheme: String,
    host: String,
    /// Path before the container: empty, or `/devstoreaccount1` (Azurite).
    base_path: String,
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn error_code(&self) -> String {
        self.header("x-ms-error-code")
            .map(str::to_string)
            .or_else(|| tag(&String::from_utf8_lossy(&self.body), "Code"))
            .unwrap_or_default()
    }
}

fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(
        xml[s..e]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

fn io(msg: String) -> Error {
    Error::Io(std::io::Error::other(msg))
}

/// Percent-encode a blob path (unreserved characters and `/` kept).
pub fn encode_path(p: &str) -> String {
    let mut out = String::new();
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn encode_query(v: &str) -> String {
    encode_path(v).replace('/', "%2F")
}

/// RFC 1123 date, as Azure wants in `x-ms-date` and immutability headers.
pub fn http_date(unix: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = core_format::timefmt::civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// The Shared Key string to sign (Blob service, version 2009-09-19 and
/// later), from the request's method, headers, account and path, and query.
pub fn string_to_sign(
    method: &str,
    headers: &[(String, String)],
    account: &str,
    path: &str,
    query: &[(&str, &str)],
) -> String {
    let h = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    let len = match h("content-length") {
        "0" => "",
        v => v,
    };
    let mut s = format!(
        "{method}\n{}\n{}\n{len}\n{}\n{}\n\n{}\n{}\n{}\n{}\n{}\n",
        h("content-encoding"),
        h("content-language"),
        h("content-md5"),
        h("content-type"),
        h("if-modified-since"),
        h("if-match"),
        h("if-none-match"),
        h("if-unmodified-since"),
        h("range"),
    );
    let mut ms: Vec<(String, &str)> = headers
        .iter()
        .filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-ms-"))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim()))
        .collect();
    ms.sort();
    for (k, v) in ms {
        s.push_str(&format!("{k}:{v}\n"));
    }
    s.push_str(&format!("/{account}{path}"));
    let mut q: Vec<(String, &str)> = query
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), *v))
        .collect();
    q.sort();
    for (k, v) in q {
        s.push_str(&format!("\n{k}:{v}"));
    }
    s
}

pub fn sign(key_b64: &str, string_to_sign: &str) -> Result<String> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .map_err(|_| Error::InvalidArgument("the storage account key is not base64".into()))?;
    let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("any key length");
    m.update(string_to_sign.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes()))
}

impl AzureBackend {
    pub fn new(cfg: AzureConfig) -> Result<Self> {
        let (scheme, rest) = cfg.endpoint.split_once("://").ok_or_else(|| {
            Error::InvalidArgument(format!("endpoint {} needs https://", cfg.endpoint))
        })?;
        if scheme != "https" && scheme != "http" {
            return Err(Error::InvalidArgument(
                "endpoint must be http:// or https://".into(),
            ));
        }
        let rest = rest.trim_end_matches('/');
        let (host, base_path) = match rest.split_once('/') {
            Some((h, p)) => (h.to_string(), format!("/{p}")),
            None => (rest.to_string(), String::new()),
        };
        if host.is_empty() || cfg.account.is_empty() {
            return Err(Error::InvalidArgument(
                "an endpoint and an account name are needed".into(),
            ));
        }
        if let Some(l) = cfg.lock {
            if l.days == 0 || l.days > 36_500 {
                return Err(Error::InvalidArgument(
                    "lock days must be 1 to 36500".into(),
                ));
            }
        }
        if let Credential::AccountKey(k) = &cfg.credential {
            sign(k, "")?;
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(20))
            .timeout(Duration::from_secs(300))
            .try_proxy_from_env(protocol::net::use_env_proxy(
                &cfg.endpoint,
                &protocol::net::no_proxy_env(),
            ))
            .build();
        Ok(AzureBackend {
            scheme: scheme.to_string(),
            host,
            base_path,
            agent,
            cfg,
        })
    }

    fn blob(&self, key: &str) -> String {
        if self.cfg.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{key}", self.cfg.prefix)
        }
    }

    /// URL path of the container (`blob` empty) or of a blob.
    fn path(&self, blob: &str) -> String {
        let mut p = format!("{}/{}", self.base_path, self.cfg.container);
        if !blob.is_empty() {
            p.push('/');
            p.push_str(&encode_path(blob));
        }
        p
    }

    /// One authorised request, retried on network errors, 5xx and 429.
    fn request(
        &self,
        method: &str,
        blob: &str,
        query: &[(&str, &str)],
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<Resp> {
        let path = self.path(blob);
        let mut delay = Duration::from_millis(500);
        let mut last = String::new();
        for attempt in 0..4 {
            if attempt > 0 {
                std::thread::sleep(delay);
                delay *= 2;
            }
            let mut h: Vec<(String, String)> = headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            h.push((
                "x-ms-date".into(),
                http_date(core_format::timefmt::now_unix()),
            ));
            h.push(("x-ms-version".into(), API_VERSION.into()));
            if method == "PUT" || !body.is_empty() {
                h.push(("content-length".into(), body.len().to_string()));
            }
            let mut qs: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{k}={}", encode_query(v)))
                .collect();
            match &self.cfg.credential {
                Credential::AccountKey(key) => {
                    // The account in the signature is the real one; for
                    // Azurite, its path segment is the account too.
                    let canon_path = format!("{}{}", self.base_path, self.path_tail(blob));
                    let sts = string_to_sign(method, &h, &self.cfg.account, &canon_path, query);
                    h.push((
                        "authorization".into(),
                        format!("SharedKey {}:{}", self.cfg.account, sign(key, &sts)?),
                    ));
                }
                Credential::Sas(sas) => qs.push(sas.clone()),
            }
            let url = format!(
                "{}://{}{}{}{}",
                self.scheme,
                self.host,
                path,
                if qs.is_empty() { "" } else { "?" },
                qs.join("&")
            );
            let mut req = self.agent.request(method, &url);
            for (k, v) in &h {
                if !k.eq_ignore_ascii_case("content-length") {
                    req = req.set(k, v);
                }
            }
            let r = if body.is_empty() && method != "PUT" {
                req.call()
            } else {
                req.send_bytes(body)
            };
            let resp = match r {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r,
                Err(ureq::Error::Transport(t)) => {
                    last = t.to_string();
                    continue;
                }
            };
            let status = resp.status();
            let headers: Vec<(String, String)> = resp
                .headers_names()
                .into_iter()
                .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string())))
                .collect();
            let mut body = Vec::new();
            if let Err(e) = resp.into_reader().take(1 << 30).read_to_end(&mut body) {
                last = e.to_string();
                continue;
            }
            let out = Resp {
                status,
                headers,
                body,
            };
            if status >= 500 || status == 429 {
                last = format!("{status} {}", out.error_code());
                continue;
            }
            return Ok(out);
        }
        Err(io(format!("{} {}: {last}", self.describe(), blob)))
    }

    /// The path after the endpoint's own path (container and blob).
    fn path_tail(&self, blob: &str) -> String {
        self.path(blob)[self.base_path.len()..].to_string()
    }

    fn fail(&self, what: &str, blob: &str, r: &Resp) -> Error {
        let code = r.error_code();
        let hint = match (r.status, code.as_str()) {
            (403, "AuthenticationFailed") => " (check the account name and key, or the SAS token)",
            (403, "AuthorizationPermissionMismatch") | (403, "AuthorizationFailure") => {
                " (the key or SAS token is not allowed to do this)"
            }
            (404, "ContainerNotFound") => " (no such container)",
            _ => "",
        };
        io(format!("{what} {blob}: HTTP {} {code}{hint}", r.status))
    }

    fn lock_until(&self) -> i64 {
        let days = self.cfg.lock.map_or(0, |l| l.days) as i64;
        core_format::timefmt::now_unix() + days * 86_400
    }

    fn lock_headers(&self, until: i64) -> Vec<(&'static str, String)> {
        match self.cfg.lock {
            Some(l) => vec![
                ("x-ms-immutability-policy-until-date", http_date(until)),
                ("x-ms-immutability-policy-mode", l.mode.header().to_string()),
            ],
            None => vec![],
        }
    }

    /// Repository locks are short-lived and never made immutable.
    fn lockable(key: &str) -> bool {
        !key.starts_with("locks/")
    }

    /// Create the container (tests, and storage set up from scratch). With
    /// `immutability`, version-level immutability is enabled on it, which
    /// needs versioning on the storage account (Azure) and is set when the
    /// container is created.
    pub fn create_container(&self, immutability: bool) -> Result<()> {
        let mut h = Vec::new();
        if immutability {
            h.push((
                "x-ms-immutable-storage-with-versioning-enabled",
                "true".to_string(),
            ));
        }
        let r = self.request("PUT", "", &[("restype", "container")], &h, b"")?;
        match r.status {
            201 => Ok(()),
            409 if r.error_code() == "ContainerAlreadyExists" => Ok(()),
            _ => Err(self.fail("create container", &self.cfg.container, &r)),
        }
    }

    /// Create the container for a new repository unless it exists (with
    /// version-level immutability when the repository uses it). Returns true
    /// when it was created.
    pub fn ensure_container(&self) -> Result<bool> {
        if self.container_exists()? {
            return Ok(false);
        }
        self.create_container(self.cfg.lock.is_some())?;
        Ok(true)
    }

    /// Whether the container exists.
    pub fn container_exists(&self) -> Result<bool> {
        let r = self.request("HEAD", "", &[("restype", "container")], &[], b"")?;
        match r.status {
            200 => Ok(true),
            404 => Ok(false),
            _ => Err(self.fail("look up container", &self.cfg.container, &r)),
        }
    }

    /// True when nothing is stored under the prefix yet.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.list_blobs("", Some(1))?.is_empty())
    }

    /// Check access and, with immutability, that the container enforces it.
    pub fn check(&self) -> Result<String> {
        let key = format!("fenrir-access-test-{}", core_format::timefmt::now_unix());
        let blob = self.blob(&key);
        let mut h = vec![("x-ms-blob-type", "BlockBlob".to_string())];
        h.extend(self.lock_headers(core_format::timefmt::now_unix() + 86_400));
        let r = self.request("PUT", &blob, &[], &h, b"fenrir")?;
        if r.status != 201 {
            return Err(self.fail("write", &blob, &r));
        }
        let r = self.request("GET", &blob, &[], &[], b"")?;
        if r.status != 200 || r.body != b"fenrir" {
            return Err(self.fail("read", &blob, &r));
        }
        self.list_blobs("", Some(1))?;
        let mut note = String::from("write, read and list work");
        match self.cfg.lock {
            Some(l) => match self.delete(&key) {
                Err(Error::Retained(_)) => {
                    note += &format!(
                        "; immutability is enforced ({}; the 1-day test blob stays until it expires)",
                        l.mode.header().to_lowercase()
                    )
                }
                Ok(()) => {
                    return Err(io(
                        "the container accepted deleting an immutable blob: version-level immutability is not enabled on it".into(),
                    ))
                }
                Err(e) => return Err(e),
            },
            None => {
                let _ = self.delete(&key);
            }
        }
        Ok(note)
    }

    fn list_blobs(&self, prefix: &str, limit: Option<usize>) -> Result<Vec<String>> {
        let full = self.blob(prefix);
        let strip = if self.cfg.prefix.is_empty() {
            0
        } else {
            self.cfg.prefix.len() + 1
        };
        let mut out = Vec::new();
        let mut marker = String::new();
        loop {
            let mut q: Vec<(&str, &str)> = vec![
                ("restype", "container"),
                ("comp", "list"),
                ("prefix", &full),
            ];
            if !marker.is_empty() {
                q.push(("marker", &marker));
            }
            let r = self.request("GET", "", &q, &[], b"")?;
            if r.status != 200 {
                return Err(self.fail("list", &full, &r));
            }
            let xml = String::from_utf8_lossy(&r.body).to_string();
            let mut rest = xml.as_str();
            while let Some(i) = rest.find("<Blob>") {
                let end = rest[i..].find("</Blob>").map_or(rest.len(), |e| e + i);
                if let Some(n) = tag(&rest[i..end], "Name") {
                    if n.len() >= strip {
                        out.push(n[strip..].to_string());
                    }
                }
                rest = &rest[end..];
                if limit.is_some_and(|l| out.len() >= l) {
                    return Ok(out);
                }
            }
            match tag(&xml, "NextMarker") {
                Some(m) if !m.is_empty() => marker = m,
                _ => break,
            }
        }
        Ok(out)
    }

    fn head(&self, key: &str) -> Result<Option<Resp>> {
        let blob = self.blob(key);
        let r = self.request("HEAD", &blob, &[], &[], b"")?;
        match r.status {
            200 => Ok(Some(r)),
            404 => Ok(None),
            _ => Err(self.fail("check", &blob, &r)),
        }
    }
}

impl Backend for AzureBackend {
    fn put(&self, key: &str, data: &[u8]) -> Result<PutOutcome> {
        validate_key(key)?;
        let blob = self.blob(key);
        let mut h = vec![
            ("x-ms-blob-type", "BlockBlob".to_string()),
            ("if-none-match", "*".to_string()),
        ];
        if Self::lockable(key) {
            h.extend(self.lock_headers(self.lock_until()));
        }
        let r = self.request("PUT", &blob, &[], &h, data)?;
        match r.status {
            201 => Ok(PutOutcome::Created),
            409 | 412 => Ok(PutOutcome::AlreadyExists),
            _ => Err(self.fail("write", &blob, &r)),
        }
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        validate_key(key)?;
        let blob = self.blob(key);
        let r = self.request("GET", &blob, &[], &[], b"")?;
        match r.status {
            200 => Ok(r.body),
            404 => Err(Error::NotFound(key.to_string())),
            _ => Err(self.fail("read", &blob, &r)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        Ok(self.head(key)?.is_some())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_blobs(prefix, None)
    }

    fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        let blob = self.blob(key);
        let Some(h) = self.head(key)? else {
            return Ok(());
        };
        // With versioning, deleting the blob would keep its version: delete
        // the version itself, which Azure refuses while it is immutable.
        let version = h.header("x-ms-version-id").map(str::to_string);
        let q: Vec<(&str, &str)> = match &version {
            Some(v) => vec![("versionid", v.as_str())],
            None => vec![],
        };
        let r = self.request("DELETE", &blob, &q, &[], b"")?;
        match r.status {
            200 | 202 | 204 | 404 => Ok(()),
            409 | 403 if r.error_code().contains("Immutab") || r.error_code().contains("Legal") => {
                let until = h
                    .header("x-ms-immutability-policy-until-date")
                    .map(|d| format!("until {d}"))
                    .unwrap_or_else(|| "for now".into());
                Err(Error::Retained(format!("{key} {until}")))
            }
            _ => Err(self.fail("delete", &blob, &r)),
        }
    }

    fn size(&self, key: &str) -> Result<u64> {
        validate_key(key)?;
        match self.head(key)? {
            Some(r) => r
                .header("content-length")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| io(format!("no size for {key}"))),
            None => Err(Error::NotFound(key.to_string())),
        }
    }

    fn describe(&self) -> String {
        format!(
            "azure://{}/{} at {}",
            self.cfg.container, self.cfg.prefix, self.cfg.endpoint
        )
    }

    fn lock_days(&self) -> Option<u32> {
        self.cfg.lock.map(|l| l.days)
    }

    fn extend_lock(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        if self.cfg.lock.is_none() || !Self::lockable(key) {
            return Ok(false);
        }
        let blob = self.blob(key);
        let h = self.lock_headers(self.lock_until());
        let r = self.request("PUT", &blob, &[("comp", "immutabilityPolicies")], &h, b"")?;
        match r.status {
            200 | 204 => Ok(true),
            404 => Err(Error::NotFound(key.to_string())),
            _ => Err(self.fail("extend the immutability of", &blob, &r)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_credentials() {
        assert_eq!(
            parse_url("azure://backups/office"),
            Some(("backups".into(), "office".into()))
        );
        assert_eq!(parse_url("azure://Bad_Name"), None);
        assert_eq!(parse_url("azure://a--b"), None);
        assert_eq!(parse_url("s3://x"), None);
        assert!(
            matches!(credential_from("?sv=2021&sig=abc"), Credential::Sas(s) if s == "sv=2021&sig=abc")
        );
        assert!(matches!(credential_from("a2V5"), Credential::AccountKey(_)));
    }

    #[test]
    fn dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // 2026-11-23 19:58:01 UTC was a Monday.
        assert_eq!(http_date(1_795_463_881), "Mon, 23 Nov 2026 19:58:01 GMT");
    }

    #[test]
    fn shared_key_string_to_sign() {
        // Layout from the "Authorize with Shared Key" documentation (Blob
        // service, 2009-09-19 and later): 12 standard headers, the x-ms-
        // headers sorted, the account and path, the query sorted.
        let h = vec![
            ("x-ms-version".to_string(), "2021-12-02".to_string()),
            (
                "x-ms-date".to_string(),
                "Mon, 23 Nov 2026 19:58:01 GMT".to_string(),
            ),
            ("content-length".to_string(), "0".to_string()),
            ("If-None-Match".to_string(), "*".to_string()),
        ];
        let s = string_to_sign(
            "GET",
            &h,
            "acct",
            "/c",
            &[("restype", "container"), ("comp", "list")],
        );
        assert_eq!(
            s,
            "GET\n\n\n\n\n\n\n\n\n*\n\n\nx-ms-date:Mon, 23 Nov 2026 19:58:01 GMT\nx-ms-version:2021-12-02\n/acct/c\ncomp:list\nrestype:container"
        );
        assert!(sign("not base64!", &s).is_err());
        assert_eq!(sign("a2V5", "x").unwrap().len(), 44);
    }

    #[test]
    fn secrets_are_not_printed() {
        let c = AzureConfig {
            endpoint: "https://a.blob.core.windows.net".into(),
            account: "a".into(),
            container: "c".into(),
            prefix: String::new(),
            credential: Credential::AccountKey("very-secret".into()),
            lock: None,
        };
        assert!(!format!("{c:?}").contains("very-secret"));
    }
}
