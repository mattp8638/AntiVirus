//! QuickBooks Online with the customer's own Intuit app (OAuth 2.0
//! authorization-code grant, done once by the customer; the backup holds
//! the refresh token). Each entity of the company is an item (its JSON);
//! changes since the previous backup come from `MetaData.LastUpdatedTime`
//! queries, deletions from the change data capture API (30 days). Restore
//! re-creates deleted entities (new IDs) or updates existing ones.
//!
//! Intuit rotates refresh tokens: each refresh may return a new one, after
//! which the old one stops working. The newest is kept in a file on the
//! machine that runs the backups (`token_cache`), tied to the token that
//! was sealed for it, so a token the administrator enters again wins.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::http::{enc, Body, Http};
use crate::store::{Index, Item, Writer};
use crate::{err, Result};

pub const TOKEN_URL: &str = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
pub const API_BASE: &str = "https://quickbooks.api.intuit.com";
pub const MINOR_VERSION: &str = "75";
/// Change data capture looks back at most 30 days.
const CDC_DAYS: i64 = 30;
const PAGE: usize = 1000;

/// Entities backed up when none are named: lists first, then transactions.
pub const DEFAULT_ENTITIES: &[&str] = &[
    "Account",
    "Class",
    "Department",
    "Term",
    "PaymentMethod",
    "TaxCode",
    "TaxRate",
    "Customer",
    "Vendor",
    "Employee",
    "Item",
    "Estimate",
    "Invoice",
    "SalesReceipt",
    "Payment",
    "CreditMemo",
    "RefundReceipt",
    "Bill",
    "BillPayment",
    "VendorCredit",
    "Purchase",
    "PurchaseOrder",
    "JournalEntry",
    "Deposit",
    "Transfer",
    "TimeActivity",
];

/// Read-only in QuickBooks: kept in backups, not written back.
const READ_ONLY: &[&str] = &["TaxCode", "TaxRate"];

#[derive(Debug, Clone)]
pub struct Config {
    /// The company (realm) ID.
    pub realm: String,
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    /// https://quickbooks.api.intuit.com, or the sandbox.
    pub api_base: String,
    pub token_url: String,
    /// Where the newest refresh token is kept (None: not kept).
    pub token_cache: Option<PathBuf>,
}

impl Config {
    /// The sealed secret: `{"client_secret": "...", "refresh_token": "..."}`.
    pub fn from_secret(
        realm: &str,
        client_id: &str,
        secret: &str,
        api_base: &str,
    ) -> Result<Config> {
        let v: Value = serde_json::from_str(secret).map_err(|_| {
            err("the QuickBooks secret is the app's client secret and a refresh token, as JSON")
        })?;
        let field = |k: &str| {
            v[k].as_str()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .ok_or_else(|| err(format!("the QuickBooks secret has no {k}")))
        };
        let base = if api_base.trim().is_empty() {
            API_BASE
        } else {
            api_base.trim()
        };
        if !base.starts_with("https://") {
            return Err(err("the QuickBooks API address must start with https://"));
        }
        Ok(Config {
            realm: realm.to_string(),
            client_id: client_id.to_string(),
            client_secret: field("client_secret")?,
            refresh_token: field("refresh_token")?,
            api_base: base.trim_end_matches('/').to_string(),
            token_url: TOKEN_URL.to_string(),
            token_cache: None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Entity names (empty: DEFAULT_ENTITIES).
    pub entities: Vec<String>,
}

pub struct QuickBooks {
    cfg: Config,
    http: Http,
    token: RefCell<Option<String>>,
}

fn fingerprint(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex()[..32].to_string()
}

impl QuickBooks {
    pub fn new(cfg: Config) -> QuickBooks {
        QuickBooks {
            cfg,
            http: Http::default(),
            token: RefCell::new(None),
        }
    }

    /// The refresh token to use: the newest kept on this machine when it
    /// descends from the sealed one, else the sealed one.
    fn current_refresh(&self) -> String {
        let origin = fingerprint(&self.cfg.refresh_token);
        self.cfg
            .token_cache
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(|v| v["origin"] == origin.as_str())
            .and_then(|v| v["refresh_token"].as_str().map(str::to_string))
            .unwrap_or_else(|| self.cfg.refresh_token.clone())
    }

    fn keep_refresh(&self, token: &str) -> Result<()> {
        let Some(p) = &self.cfg.token_cache else {
            return Ok(());
        };
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| err(e.to_string()))?;
        }
        let tmp = p.with_extension("tmp");
        let body =
            json!({ "origin": fingerprint(&self.cfg.refresh_token), "refresh_token": token });
        std::fs::write(&tmp, body.to_string()).map_err(|e| err(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, p).map_err(|e| err(e.to_string()))
    }

    fn access_token(&self) -> Result<String> {
        if let Some(t) = &*self.token.borrow() {
            return Ok(t.clone());
        }
        use base64::Engine as _;
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.cfg.client_id, self.cfg.client_secret));
        let refresh = self.current_refresh();
        let (s, b) = self.http.send(
            "POST",
            &self.cfg.token_url,
            None,
            &[
                ("Authorization", &format!("Basic {basic}")),
                ("Accept", "application/json"),
            ],
            Body::Form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)]),
        )?;
        let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        if !(200..300).contains(&s) {
            return Err(err(format!(
                "signing in to QuickBooks: {s} {} (the refresh token may have expired after 100 days unused, or been replaced: connect the company again)",
                v["error"].as_str().unwrap_or("")
            )));
        }
        let t = v["access_token"]
            .as_str()
            .ok_or_else(|| err("QuickBooks sign-in returned no token"))?
            .to_string();
        if let Some(r) = v["refresh_token"].as_str() {
            if r != refresh {
                self.keep_refresh(r)?;
            }
        }
        *self.token.borrow_mut() = Some(t.clone());
        Ok(t)
    }

    fn url(&self, path: &str) -> String {
        let sep = if path.contains('?') { '&' } else { '?' };
        format!(
            "{}/v3/company/{}{path}{sep}minorversion={MINOR_VERSION}",
            self.cfg.api_base,
            enc(&self.cfg.realm)
        )
    }

    fn call(&self, method: &str, path: &str, body: Body) -> Result<Value> {
        let t = self.access_token()?;
        let (s, b) = self.http.send(
            method,
            &self.url(path),
            Some(&t),
            &[("Accept", "application/json")],
            body,
        )?;
        let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
        if !(200..300).contains(&s) || v.get("Fault").is_some() {
            let f = &v["Fault"]["Error"][0];
            return Err(err(format!(
                "{method} {}: {s} {} {}",
                path.split('?').next().unwrap_or(path),
                f["Message"].as_str().unwrap_or(""),
                f["Detail"].as_str().unwrap_or("")
            )));
        }
        Ok(v)
    }

    /// Every entity matching `filter` (a WHERE clause or empty), page by page.
    fn query(&self, entity: &str, filter: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut start = 1usize;
        loop {
            let q =
                format!("SELECT * FROM {entity}{filter} STARTPOSITION {start} MAXRESULTS {PAGE}");
            let v = self.call("GET", &format!("/query?query={}", enc(&q)), Body::None)?;
            let page = v["QueryResponse"][entity]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let n = page.len();
            out.extend(page);
            if n < PAGE {
                return Ok(out);
            }
            start += n;
        }
    }

    /// IDs deleted since `since` (change data capture).
    fn deleted(
        &self,
        entities: &[String],
        since: &str,
    ) -> Result<BTreeMap<String, HashSet<String>>> {
        let mut out: BTreeMap<String, HashSet<String>> = BTreeMap::new();
        for chunk in entities.chunks(10) {
            let v = self.call(
                "GET",
                &format!(
                    "/cdc?entities={}&changedSince={}",
                    enc(&chunk.join(",")),
                    enc(since)
                ),
                Body::None,
            )?;
            for resp in v["CDCResponse"].as_array().into_iter().flatten() {
                for qr in resp["QueryResponse"].as_array().into_iter().flatten() {
                    for e in chunk {
                        for r in qr[e.as_str()].as_array().into_iter().flatten() {
                            if r["status"] == "Deleted" {
                                if let Some(id) = r["Id"].as_str() {
                                    out.entry(e.clone()).or_default().insert(id.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn backup(
        &self,
        w: &mut Writer,
        prev: Option<&Index>,
        o: &Options,
        progress: &dyn Fn(&str),
    ) -> Result<()> {
        let entities: Vec<String> = if o.entities.is_empty() {
            DEFAULT_ENTITIES.iter().map(|s| s.to_string()).collect()
        } else {
            o.entities.clone()
        };
        let company = w.index.tenant.clone();
        let started = core_format::timefmt::now_unix();
        let started_iso = core_format::timefmt::rfc3339_utc(started);
        let cursors = prev.map(|p| p.cursors.clone()).unwrap_or_default();
        // An incremental backup needs a cursor within the change data capture window.
        let recent =
            |c: &String| parse_utc(c).is_some_and(|t| started - t < CDC_DAYS * 86_400 - 3600);
        let incremental: Vec<String> = entities
            .iter()
            .filter(|e| {
                cursors
                    .get(&format!("{company}|record|{e}"))
                    .is_some_and(recent)
            })
            .cloned()
            .collect();
        let oldest = incremental
            .iter()
            .filter_map(|e| cursors.get(&format!("{company}|record|{e}")))
            .min()
            .cloned();
        let deleted = match &oldest {
            Some(since) => match self.deleted(&incremental, since) {
                Ok(d) => Some(d),
                Err(e) => {
                    w.index.warnings.push(format!(
                        "deleted entities not checked, so listed in full ({e})"
                    ));
                    None
                }
            },
            None => None,
        };
        for entity in &entities {
            progress(entity);
            let key = format!("{company}|record|{entity}");
            let prev_items: BTreeMap<String, Item> = prev
                .map(|p| {
                    p.items
                        .iter()
                        .filter(|i| i.kind == "record" && i.meta["entity"] == entity.as_str())
                        .map(|i| (i.id.clone(), i.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let since = cursors
                .get(&key)
                .filter(|_| deleted.is_some() && incremental.contains(entity));
            let r = (|| -> Result<()> {
                let filter = since
                    .map(|s| format!(" WHERE MetaData.LastUpdatedTime >= '{s}'"))
                    .unwrap_or_default();
                let mut changed: BTreeMap<String, Value> = BTreeMap::new();
                for rec in self.query(entity, &filter)? {
                    if let Some(id) = rec["Id"].as_str() {
                        changed.insert(id.to_string(), rec.clone());
                    }
                }
                if since.is_some() {
                    let gone = deleted.as_ref().and_then(|d| d.get(entity));
                    for (id, it) in &prev_items {
                        if !changed.contains_key(id)
                            && !gone.is_some_and(|g| g.contains(id))
                            && it.chunks.first().is_some_and(|c| w.has_chunk(c))
                        {
                            w.keep(it.clone());
                        }
                    }
                }
                for (id, rec) in changed {
                    let data = serde_json::to_vec(&rec).map_err(|e| err(e.to_string()))?;
                    let name = rec["DisplayName"]
                        .as_str()
                        .or(rec["Name"].as_str())
                        .or(rec["DocNumber"].as_str())
                        .unwrap_or("")
                        .to_string();
                    w.add(
                        Item {
                            account: company.clone(),
                            kind: "record".into(),
                            id: id.clone(),
                            path: format!("{entity}/{id}"),
                            modified: rec["MetaData"]["LastUpdatedTime"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            size: 0,
                            hash: String::new(),
                            meta: json!({ "entity": entity, "name": name, "object": entity }),
                            chunks: vec![],
                        },
                        &data,
                    )
                    .map_err(|e| err(e.to_string()))?;
                }
                w.index.cursors.insert(key.clone(), started_iso.clone());
                Ok(())
            })();
            if let Err(e) = r {
                w.index.warnings.push(format!("{entity}: {e}"));
                for it in prev_items.into_values() {
                    w.keep(it);
                }
                if let Some(c) = cursors.get(&key) {
                    w.index.cursors.insert(key, c.clone());
                }
            }
        }
        Ok(())
    }

    /// Put an entity back: update it if it still exists (`overwrite`), else
    /// create it again (a new ID). Returns its ID.
    pub fn restore_record(&self, entity: &str, record: &[u8], overwrite: bool) -> Result<String> {
        if READ_ONLY.contains(&entity) {
            return Err(err(format!(
                "{entity} cannot be written through the QuickBooks API"
            )));
        }
        let rec: Value = serde_json::from_slice(record).map_err(|e| err(e.to_string()))?;
        let path = format!("/{}", entity.to_lowercase());
        let id = rec["Id"].as_str().unwrap_or_default().to_string();
        let current = if id.is_empty() {
            None
        } else {
            self.call("GET", &format!("{path}/{}", enc(&id)), Body::None)
                .ok()
                .map(|v| v[entity].clone())
                .filter(|v| v.is_object() && v["status"] != "Deleted")
        };
        let mut body = rec.clone();
        let m = body.as_object_mut().ok_or_else(|| err("not an entity"))?;
        for k in ["MetaData", "domain", "sparse", "status", "time"] {
            m.remove(k);
        }
        if let Some(cur) = current {
            if !overwrite {
                return Ok(id);
            }
            // A full update needs the entity's current SyncToken.
            m.insert("SyncToken".into(), cur["SyncToken"].clone());
            m.insert("sparse".into(), json!(false));
            self.call("POST", &path, Body::Json(&body))?;
            return Ok(id);
        }
        m.remove("Id");
        m.remove("SyncToken");
        let v = self.call("POST", &path, Body::Json(&body))?;
        v[entity]["Id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| err(format!("{entity}: no ID for the re-created entity")))
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` (as the cursors are written) to Unix seconds.
fn parse_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let days = core_format::timefmt::days_from_civil(n(0..4)?, n(5..7)? as u32, n(8..10)? as u32);
    Some(days * 86_400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn cursor_times_round_trip() {
        let t = 1_795_600_000;
        assert_eq!(
            super::parse_utc(&core_format::timefmt::rfc3339_utc(t)),
            Some(t)
        );
        assert_eq!(super::parse_utc("yesterday"), None);
    }
}
