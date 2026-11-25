//! Repository storage on S3-compatible object storage, with S3 Object Lock
//! (design: docs/design/phase-4-storage.md).
//!
//! Plain HTTPS and AWS Signature Version 4; no SDK. Works with AWS S3 and
//! S3-compatible services (MinIO, Wasabi, Backblaze B2, Cloudflare R2, ...).

#![forbid(unsafe_code)]

pub mod multipart;

use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use core_format::backend::{validate_key, Backend, PutOutcome};
use core_format::error::{Error, Result};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

pub mod sigv4;

/// Object Lock mode for new objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Users with `s3:BypassGovernanceRetention` can still remove objects.
    Governance,
    /// Nobody can remove an object before its lock expires.
    Compliance,
}

impl LockMode {
    fn header(self) -> &'static str {
        match self {
            LockMode::Governance => "GOVERNANCE",
            LockMode::Compliance => "COMPLIANCE",
        }
    }
    pub fn parse(s: &str) -> Option<LockMode> {
        match s.to_ascii_lowercase().as_str() {
            "governance" => Some(LockMode::Governance),
            "compliance" => Some(LockMode::Compliance),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lock {
    pub mode: LockMode,
    pub days: u32,
}

#[derive(Clone)]
pub struct S3Config {
    /// `https://s3.eu-west-2.amazonaws.com`, `http://minio.lan:9000`, ...
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Key prefix inside the bucket, without leading or trailing slash.
    pub prefix: String,
    /// `https://host/bucket/key` (MinIO, most self-hosted) instead of
    /// `https://bucket.host/key`.
    pub path_style: bool,
    pub access_key: String,
    pub secret_key: String,
    pub lock: Option<Lock>,
    /// Storage class for chunk objects (see `protocol::S3_STORAGE_CLASSES`).
    pub storage_class: Option<String>,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<hidden>")
            .field("lock", &self.lock)
            .finish()
    }
}

/// Chunk objects (`chunks/...`, also in a dedup group's shared store): the
/// bulk of a repository, and what an archive tier applies to.
pub fn is_chunk(key: &str) -> bool {
    key.starts_with("chunks/") || key.contains("/chunks/")
}

/// `s3://bucket/some/prefix` → ("bucket", "some/prefix").
pub fn parse_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("s3://")?;
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    let valid_bucket = (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    valid_bucket.then(|| (bucket.to_string(), prefix.trim_matches('/').to_string()))
}

pub struct S3Backend {
    cfg: S3Config,
    agent: ureq::Agent,
    host: String,
    scheme: String,
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
        tag(&String::from_utf8_lossy(&self.body), "Code").unwrap_or_default()
    }
}

/// The text of the first `<name>...</name>` in `xml`.
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(unescape(&xml[s..e]))
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn io(msg: String) -> Error {
    Error::Io(std::io::Error::other(msg))
}

impl S3Backend {
    pub fn new(cfg: S3Config) -> Result<Self> {
        let (scheme, rest) = cfg.endpoint.split_once("://").ok_or_else(|| {
            Error::InvalidArgument(format!(
                "endpoint {} needs http:// or https://",
                cfg.endpoint
            ))
        })?;
        if scheme != "https" && scheme != "http" {
            return Err(Error::InvalidArgument(
                "endpoint must be http:// or https://".into(),
            ));
        }
        let host = rest.trim_end_matches('/').to_string();
        if host.is_empty() || host.contains('/') {
            return Err(Error::InvalidArgument(format!(
                "endpoint {} must be a host, without a path",
                cfg.endpoint
            )));
        }
        if let Some(l) = cfg.lock {
            if l.days == 0 || l.days > 36_500 {
                return Err(Error::InvalidArgument(
                    "lock days must be 1 to 36500".into(),
                ));
            }
        }
        // The environment's proxy, except for loopback and NO_PROXY hosts.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(20))
            .timeout(Duration::from_secs(300))
            .try_proxy_from_env(protocol::net::use_env_proxy(
                &cfg.endpoint,
                &protocol::net::no_proxy_env(),
            ))
            .build();
        let host = if cfg.path_style {
            host
        } else {
            format!("{}.{host}", cfg.bucket)
        };
        Ok(S3Backend {
            scheme: scheme.to_string(),
            host,
            agent,
            cfg,
        })
    }

    fn object(&self, key: &str) -> String {
        if self.cfg.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{key}", self.cfg.prefix)
        }
    }

    /// Path part of the URL for an object (or the bucket when `object` is empty).
    fn path(&self, object: &str) -> String {
        let mut p = String::from("/");
        if self.cfg.path_style {
            p.push_str(&self.cfg.bucket);
            if object.is_empty() {
                return p;
            }
            p.push('/');
        }
        p.push_str(&sigv4::encode_path(object));
        p
    }

    /// One signed request, retried on network errors and 5xx/429.
    fn request(
        &self,
        method: &str,
        object: &str,
        query: &[(&str, &str)],
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<Resp> {
        let path = self.path(object);
        let mut delay = Duration::from_millis(500);
        let mut last = String::new();
        for attempt in 0..4 {
            if attempt > 0 {
                std::thread::sleep(delay);
                delay *= 2;
            }
            let now = core_format::timefmt::now_unix();
            let signed = sigv4::sign(&sigv4::Request {
                method,
                host: &self.host,
                path: &path,
                query,
                headers,
                payload: body,
                region: &self.cfg.region,
                access_key: &self.cfg.access_key,
                secret_key: &self.cfg.secret_key,
                unix_time: now,
            });
            let qs = sigv4::canonical_query(query);
            let url = format!(
                "{}://{}{}{}{}",
                self.scheme,
                self.host,
                path,
                if qs.is_empty() { "" } else { "?" },
                qs
            );
            let mut req = self.agent.request(method, &url);
            for (k, v) in &signed {
                if !k.eq_ignore_ascii_case("host") {
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
        Err(io(format!("{} {}: {last}", self.describe(), object)))
    }

    fn fail(&self, what: &str, object: &str, r: &Resp) -> Error {
        let code = r.error_code();
        let msg = tag(&String::from_utf8_lossy(&r.body), "Message").unwrap_or_default();
        let hint = match (r.status, code.as_str()) {
            (403, "SignatureDoesNotMatch") => " (check the secret key and the region)",
            (403, "InvalidAccessKeyId") => " (unknown access key)",
            (403, _) => " (the keys are not allowed to do this)",
            (404, "NoSuchBucket") => " (no such bucket)",
            _ => "",
        };
        io(format!(
            "{what} {object}: HTTP {} {code} {msg}{hint}",
            r.status
        ))
    }

    fn lock_headers(&self, until_unix: i64) -> Vec<(&'static str, String)> {
        match self.cfg.lock {
            Some(l) => vec![
                ("x-amz-object-lock-mode", l.mode.header().to_string()),
                (
                    "x-amz-object-lock-retain-until-date",
                    core_format::timefmt::rfc3339_utc(until_unix),
                ),
            ],
            None => vec![],
        }
    }

    fn lock_until(&self) -> i64 {
        let days = self.cfg.lock.map_or(0, |l| l.days) as i64;
        core_format::timefmt::now_unix() + days * 86_400
    }

    /// Objects under `locks/` are repository locks: short-lived, never
    /// object-locked.
    fn lockable(key: &str) -> bool {
        !key.starts_with("locks/")
    }

    /// Create the bucket (tests, and self-hosted storage set up from
    /// scratch). With `object_lock`, Object Lock (and versioning) is enabled
    /// on it, which S3 allows only when the bucket is created.
    pub fn create_bucket(&self, object_lock: bool) -> Result<()> {
        let mut h = Vec::new();
        if object_lock {
            h.push(("x-amz-bucket-object-lock-enabled", "true".to_string()));
        }
        let body = if self.cfg.region == "us-east-1" {
            String::new()
        } else {
            format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
                self.cfg.region
            )
        };
        let r = self.request("PUT", "", &[], &h, body.as_bytes())?;
        match r.status {
            200 => Ok(()),
            409 if r.error_code() == "BucketAlreadyOwnedByYou" => Ok(()),
            _ => Err(self.fail("create bucket", &self.cfg.bucket, &r)),
        }
    }

    /// Create the bucket for a new repository unless it exists (with Object
    /// Lock when the repository uses it). Returns true when it was created.
    pub fn ensure_bucket(&self) -> Result<bool> {
        if self.bucket_exists()? {
            return Ok(false);
        }
        self.create_bucket(self.cfg.lock.is_some())?;
        Ok(true)
    }

    /// Whether the bucket exists (and these keys may see it).
    pub fn bucket_exists(&self) -> Result<bool> {
        let r = self.request("HEAD", "", &[], &[], b"")?;
        match r.status {
            200 => Ok(true),
            404 => Ok(false),
            _ => Err(self.fail("look up bucket", &self.cfg.bucket, &r)),
        }
    }

    /// True when nothing is stored under the prefix yet (for `repo init`).
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.list_objects("", Some(1))?.is_empty())
    }

    /// Check access and, with a lock, that the bucket enforces it: write a
    /// test object, read it, try to delete it (must be refused while
    /// locked), list. Returns what was found, for "Test connection".
    pub fn check(&self) -> Result<String> {
        let key = format!("fenrir-access-test-{}", core_format::timefmt::now_unix());
        let obj = self.object(&key);
        let mut h = vec![("content-md5", md5_b64(b"fenrir"))];
        h.extend(self.lock_headers(core_format::timefmt::now_unix() + 86_400));
        let r = self.request("PUT", &obj, &[], &h, b"fenrir")?;
        if r.status != 200 {
            return Err(self.fail("write", &obj, &r));
        }
        let r = self.request("GET", &obj, &[], &[], b"")?;
        if r.status != 200 || r.body != b"fenrir" {
            return Err(self.fail("read", &obj, &r));
        }
        self.list_objects("", Some(1))?;
        let mut note = String::from("write, read and list work");
        match self.cfg.lock {
            Some(l) => match self.delete(&key) {
                Err(Error::Retained(_)) => {
                    note += &format!("; Object Lock is enforced ({} mode; the 1-day test object stays until it expires)", l.mode.header().to_lowercase())
                }
                Ok(()) => {
                    return Err(io(
                        "the bucket accepted deleting a locked object: Object Lock is not enabled on this bucket".into(),
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

    /// Full object names under `prefix` (relative to the repository), at
    /// most `limit`.
    fn list_objects(&self, prefix: &str, limit: Option<usize>) -> Result<Vec<String>> {
        let full = self.object(prefix);
        let strip = if self.cfg.prefix.is_empty() {
            0
        } else {
            self.cfg.prefix.len() + 1
        };
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut q: Vec<(&str, &str)> = vec![("list-type", "2"), ("prefix", &full)];
            if let Some(t) = &token {
                q.push(("continuation-token", t));
            }
            let r = self.request("GET", "", &q, &[], b"")?;
            if r.status != 200 {
                return Err(self.fail("list", &full, &r));
            }
            let xml = String::from_utf8_lossy(&r.body).to_string();
            let mut rest = xml.as_str();
            while let Some(i) = rest.find("<Contents>") {
                let end = rest[i..].find("</Contents>").map_or(rest.len(), |e| e + i);
                if let Some(k) = tag(&rest[i..end], "Key") {
                    if k.len() >= strip {
                        out.push(k[strip..].to_string());
                    }
                }
                rest = &rest[end..];
                if limit.is_some_and(|l| out.len() >= l) {
                    return Ok(out);
                }
            }
            if tag(&xml, "IsTruncated").as_deref() == Some("true") {
                token = tag(&xml, "NextContinuationToken");
                if token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(out)
    }

    fn head(&self, key: &str) -> Result<Option<Resp>> {
        let obj = self.object(key);
        let r = self.request("HEAD", &obj, &[], &[], b"")?;
        match r.status {
            200 => Ok(Some(r)),
            404 => Ok(None),
            _ => Err(self.fail("check", &obj, &r)),
        }
    }
}

fn md5_b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Md5::digest(data))
}

impl Backend for S3Backend {
    fn put(&self, key: &str, data: &[u8]) -> Result<PutOutcome> {
        validate_key(key)?;
        let obj = self.object(key);
        let mut h = vec![
            ("if-none-match", "*".to_string()),
            ("content-md5", md5_b64(data)),
        ];
        if Self::lockable(key) {
            h.extend(self.lock_headers(self.lock_until()));
        }
        if let Some(c) = self.cfg.storage_class.as_ref().filter(|_| is_chunk(key)) {
            h.push(("x-amz-storage-class", c.clone()));
        }
        let r = self.request("PUT", &obj, &[], &h, data)?;
        match r.status {
            200 => Ok(PutOutcome::Created),
            // Already there (or being written by another machine at this
            // moment): create-only, so the existing object stands.
            412 | 409 => Ok(PutOutcome::AlreadyExists),
            _ => Err(self.fail("write", &obj, &r)),
        }
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        validate_key(key)?;
        let obj = self.object(key);
        let r = self.request("GET", &obj, &[], &[], b"")?;
        match r.status {
            200 => Ok(r.body),
            404 => Err(Error::NotFound(key.to_string())),
            _ => Err(self.fail("read", &obj, &r)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        Ok(self.head(key)?.is_some())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_objects(prefix, None)
    }

    fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        let obj = self.object(key);
        let Some(h) = self.head(key)? else {
            return Ok(());
        };
        // A versioned bucket (Object Lock needs one) would only hide the
        // object behind a delete marker: delete the version itself, which
        // S3 refuses while it is locked.
        let version = h
            .header("x-amz-version-id")
            .filter(|v| *v != "null")
            .map(str::to_string);
        let q: Vec<(&str, &str)> = match &version {
            Some(v) => vec![("versionId", v.as_str())],
            None => vec![],
        };
        let r = self.request("DELETE", &obj, &q, &[], b"")?;
        match r.status {
            200 | 204 | 404 => Ok(()),
            403 if version.is_some() => {
                let until = h
                    .header("x-amz-object-lock-retain-until-date")
                    .map(|d| format!("until {d}"))
                    .unwrap_or_else(|| "for now".into());
                Err(Error::Retained(format!("{key} {until}")))
            }
            _ => Err(self.fail("delete", &obj, &r)),
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
            "s3://{}/{} at {}",
            self.cfg.bucket, self.cfg.prefix, self.cfg.endpoint
        )
    }

    fn lock_days(&self) -> Option<u32> {
        self.cfg.lock.map(|l| l.days)
    }

    fn extend_lock(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        let Some(l) = self.cfg.lock else {
            return Ok(false);
        };
        if !Self::lockable(key) {
            return Ok(false);
        }
        let obj = self.object(key);
        let body = format!(
            "<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
            l.mode.header(),
            core_format::timefmt::rfc3339_utc(self.lock_until())
        );
        let h = vec![("content-md5", md5_b64(body.as_bytes()))];
        let r = self.request("PUT", &obj, &[("retention", "")], &h, body.as_bytes())?;
        match r.status {
            200 | 204 => Ok(true),
            404 => Err(Error::NotFound(key.to_string())),
            _ => Err(self.fail("extend the lock of", &obj, &r)),
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("s3://backups/office/nas"),
            Some(("backups".into(), "office/nas".into()))
        );
        assert_eq!(
            parse_url("s3://backups"),
            Some(("backups".into(), "".into()))
        );
        assert_eq!(parse_url("s3://Bad_Bucket/x"), None);
        assert_eq!(parse_url("https://x"), None);
    }

    #[test]
    fn xml_tags() {
        let x = "<R><IsTruncated>true</IsTruncated><Contents><Key>a&amp;b</Key></Contents></R>";
        assert_eq!(tag(x, "IsTruncated").as_deref(), Some("true"));
        assert_eq!(tag(x, "Key").as_deref(), Some("a&b"));
        assert_eq!(tag(x, "Nope"), None);
    }

    #[test]
    fn secrets_are_not_printed() {
        let c = S3Config {
            endpoint: "https://s3.example".into(),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: String::new(),
            path_style: true,
            access_key: "AKID".into(),
            secret_key: "very-secret".into(),
            lock: None,
            storage_class: None,
        };
        assert!(!format!("{c:?}").contains("very-secret"));
    }
}
