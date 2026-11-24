//! Salesforce with the customer's own connected app (OAuth client
//! credentials flow, a run-as user with "View All Data"). Each record of the
//! chosen objects is an item (its JSON); changes since the previous backup
//! come from `SystemModstamp` and the getDeleted API. Restore re-creates
//! deleted records (createable fields) or updates existing ones.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};

use serde_json::{json, Map, Value};

use crate::http::{enc, Body, Http};
use crate::store::{Index, Item, Writer};
use crate::{err, Result};

pub const API: &str = "v61.0";
/// Objects backed up when none are named.
pub const DEFAULT_OBJECTS: &[&str] = &[
    "Account",
    "Contact",
    "Lead",
    "Opportunity",
    "Case",
    "Campaign",
    "Contract",
    "Product2",
    "Pricebook2",
    "Task",
    "Event",
    "Note",
];

#[derive(Debug, Clone)]
pub struct Config {
    /// https://<my-domain>.my.salesforce.com
    pub domain_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Object API names (empty: DEFAULT_OBJECTS and every custom object).
    pub objects: Vec<String>,
}

pub struct Salesforce {
    cfg: Config,
    http: Http,
    session: RefCell<Option<(String, String)>>,
}

impl Salesforce {
    pub fn new(cfg: Config) -> Salesforce {
        Salesforce {
            cfg,
            http: Http::default(),
            session: RefCell::new(None),
        }
    }

    /// (access token, instance URL)
    fn session(&self) -> Result<(String, String)> {
        if let Some(s) = &*self.session.borrow() {
            return Ok(s.clone());
        }
        let v = self
            .http
            .json(
                "POST",
                &format!(
                    "{}/services/oauth2/token",
                    self.cfg.domain_url.trim_end_matches('/')
                ),
                None,
                Body::Form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &self.cfg.client_id),
                    ("client_secret", &self.cfg.client_secret),
                ]),
            )
            .map_err(|e| {
                err(format!(
                    "signing in to Salesforce with the connected app: {e}"
                ))
            })?;
        let t = v["access_token"]
            .as_str()
            .ok_or_else(|| err("Salesforce sign-in returned no token"))?
            .to_string();
        let i = v["instance_url"]
            .as_str()
            .unwrap_or(&self.cfg.domain_url)
            .trim_end_matches('/')
            .to_string();
        *self.session.borrow_mut() = Some((t.clone(), i.clone()));
        Ok((t, i))
    }

    fn call(&self, method: &str, path: &str, body: Body) -> Result<Value> {
        let (t, i) = self.session()?;
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{i}{path}")
        };
        self.http.json(method, &url, Some(&t), body)
    }

    pub fn objects(&self, only: &[String]) -> Result<Vec<String>> {
        if !only.is_empty() {
            return Ok(only.to_vec());
        }
        let g = self.call("GET", &format!("/services/data/{API}/sobjects"), Body::None)?;
        let mut out: Vec<String> = DEFAULT_OBJECTS.iter().map(|s| s.to_string()).collect();
        for o in g["sobjects"].as_array().into_iter().flatten() {
            let name = o["name"].as_str().unwrap_or_default();
            if o["custom"] == true
                && o["queryable"] == true
                && o["retrieveable"] == true
                && name.ends_with("__c")
            {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }

    fn describe(&self, object: &str) -> Result<Value> {
        self.call(
            "GET",
            &format!("/services/data/{API}/sobjects/{object}/describe"),
            Body::None,
        )
    }

    /// Fields that a SOQL query can select one by one (no compound address/location).
    fn fields(desc: &Value) -> Vec<String> {
        desc["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| !matches!(f["type"].as_str(), Some("address") | Some("location")))
            .filter_map(|f| f["name"].as_str().map(str::to_string))
            .collect()
    }

    pub fn backup(
        &self,
        w: &mut Writer,
        prev: Option<&Index>,
        o: &Options,
        progress: &dyn Fn(&str),
    ) -> Result<()> {
        let cursors = prev.map(|p| p.cursors.clone()).unwrap_or_default();
        let org = w.index.tenant.clone();
        let started = now_iso();
        for object in self.objects(&o.objects)? {
            progress(&object);
            let key = format!("{org}|record|{object}");
            let prev_items: BTreeMap<String, Item> = prev
                .map(|p| {
                    p.items
                        .iter()
                        .filter(|i| i.kind == "record" && i.meta["object"] == object.as_str())
                        .map(|i| (i.id.clone(), i.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let r = (|| -> Result<()> {
                let desc = self.describe(&object)?;
                if desc["queryable"] == false {
                    return Ok(());
                }
                let fields = Self::fields(&desc);
                if !fields.iter().any(|f| f == "SystemModstamp") {
                    w.index.warnings.push(format!(
                        "{object}: no SystemModstamp, backed up in full each time"
                    ));
                }
                let since = cursors
                    .get(&key)
                    .filter(|_| fields.iter().any(|f| f == "SystemModstamp"));
                let mut q = format!("SELECT {} FROM {object}", fields.join(","));
                if let Some(s) = since {
                    q += &format!(" WHERE SystemModstamp >= {s}");
                }
                let mut changed: BTreeMap<String, Value> = BTreeMap::new();
                let mut next = Some(format!("/services/data/{API}/queryAll?q={}", enc(&q)));
                while let Some(u) = next.take() {
                    let v = self.call("GET", &u, Body::None)?;
                    for rec in v["records"].as_array().into_iter().flatten() {
                        if rec["IsDeleted"] == true {
                            continue;
                        }
                        let mut r = rec.clone();
                        if let Some(m) = r.as_object_mut() {
                            m.remove("attributes");
                        }
                        if let Some(id) = r["Id"].as_str() {
                            changed.insert(id.to_string(), r);
                        }
                    }
                    next = v["nextRecordsUrl"].as_str().map(str::to_string);
                }
                let mut deleted: HashSet<String> = HashSet::new();
                if let Some(s) = since {
                    // getDeleted covers about 15 days; older cursors get a full listing next time.
                    let path = format!(
                        "/services/data/{API}/sobjects/{object}/deleted/?start={}&end={}",
                        enc(s),
                        enc(&started)
                    );
                    match self.call("GET", &path, Body::None) {
                        Ok(v) => deleted.extend(
                            v["deletedRecords"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|d| d["id"].as_str().map(str::to_string)),
                        ),
                        Err(e) => w
                            .index
                            .warnings
                            .push(format!("{object}: deleted records not checked ({e})")),
                    }
                }
                if since.is_some() {
                    for (id, it) in &prev_items {
                        if !changed.contains_key(id)
                            && !deleted.contains(id)
                            && it.chunks.first().is_some_and(|c| w.has_chunk(c))
                        {
                            w.keep(it.clone());
                        }
                    }
                }
                for (id, rec) in changed {
                    let data = serde_json::to_vec(&rec).map_err(|e| err(e.to_string()))?;
                    let name = rec["Name"]
                        .as_str()
                        .or(rec["Subject"].as_str())
                        .or(rec["LastName"].as_str())
                        .unwrap_or("")
                        .to_string();
                    w.add(
                        Item {
                            account: org.clone(),
                            kind: "record".into(),
                            id: id.clone(),
                            path: format!("{object}/{id}"),
                            modified: rec["SystemModstamp"].as_str().unwrap_or("").to_string(),
                            size: 0,
                            hash: String::new(),
                            meta: json!({ "object": object, "name": name }),
                            chunks: vec![],
                        },
                        &data,
                    )
                    .map_err(|e| err(e.to_string()))?;
                }
                w.index.cursors.insert(key.clone(), started.clone());
                Ok(())
            })();
            if let Err(e) = r {
                w.index.warnings.push(format!("{object}: {e}"));
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

    /// Put a record back: update it if it still exists (`overwrite`), else
    /// create it again (a new ID). Returns the record's ID.
    pub fn restore_record(&self, object: &str, record: &[u8], overwrite: bool) -> Result<String> {
        let rec: Value = serde_json::from_slice(record).map_err(|e| err(e.to_string()))?;
        let desc = self.describe(object)?;
        let id = rec["Id"].as_str().unwrap_or_default().to_string();
        let exists = !id.is_empty()
            && self
                .call(
                    "GET",
                    &format!("/services/data/{API}/sobjects/{object}/{id}?fields=Id"),
                    Body::None,
                )
                .is_ok();
        let pick = |flag: &str| -> Map<String, Value> {
            let ok: HashSet<&str> = desc["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|f| f[flag] == true)
                .filter_map(|f| f["name"].as_str())
                .collect();
            rec.as_object()
                .into_iter()
                .flatten()
                .filter(|(k, v)| ok.contains(k.as_str()) && !v.is_null())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        if exists {
            if !overwrite {
                return Ok(id);
            }
            let (t, i) = self.session()?;
            let (s, b) = self.http.send(
                "PATCH",
                &format!("{i}/services/data/{API}/sobjects/{object}/{id}"),
                Some(&t),
                &[],
                Body::Bytes(
                    Value::Object(pick("updateable")).to_string().as_bytes(),
                    "application/json",
                ),
            )?;
            if !(200..300).contains(&s) {
                return Err(err(format!(
                    "{object} {id}: {s} {}",
                    String::from_utf8_lossy(&b)
                )));
            }
            return Ok(id);
        }
        let v = self.call(
            "POST",
            &format!("/services/data/{API}/sobjects/{object}"),
            Body::Json(&Value::Object(pick("createable"))),
        )?;
        v["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| err(format!("{object}: no ID for the re-created record")))
    }
}

fn now_iso() -> String {
    // SOQL datetime literal, e.g. 2026-11-24T10:00:00Z
    core_format::timefmt::rfc3339_utc(core_format::timefmt::now_unix())
}
