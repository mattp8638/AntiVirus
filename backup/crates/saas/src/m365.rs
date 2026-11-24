//! Microsoft 365 through Microsoft Graph, with the customer's own app
//! registration (client credentials; application permissions User.Read.All,
//! Mail.ReadWrite, Files.ReadWrite.All). Mail: every folder's messages as
//! MIME (.eml); OneDrive: every file. Changes since the previous backup come
//! from Graph delta queries.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};

use crate::http::{enc, Body, Http};
use crate::store::{Index, Item, Writer};
use crate::{err, Result};

#[derive(Debug, Clone)]
pub struct Config {
    /// Directory (tenant) ID or domain.
    pub tenant: String,
    pub client_id: String,
    pub client_secret: String,
    /// Overridable for tests (default login.microsoftonline.com / graph.microsoft.com).
    pub login_base: String,
    pub graph_base: String,
}

impl Config {
    pub fn new(tenant: &str, client_id: &str, client_secret: &str) -> Config {
        Config {
            tenant: tenant.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            login_base: "https://login.microsoftonline.com".into(),
            graph_base: "https://graph.microsoft.com".into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// User principal names to back up (empty: every user).
    pub users: Vec<String>,
    pub mail: bool,
    pub files: bool,
}

pub struct M365 {
    cfg: Config,
    http: Http,
    token: RefCell<Option<(String, Instant)>>,
}

impl M365 {
    pub fn new(cfg: Config) -> M365 {
        M365 {
            cfg,
            http: Http::default(),
            token: RefCell::new(None),
        }
    }

    fn token(&self) -> Result<String> {
        if let Some((t, until)) = &*self.token.borrow() {
            if Instant::now() < *until {
                return Ok(t.clone());
            }
        }
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.cfg.login_base,
            enc(&self.cfg.tenant)
        );
        let scope = format!("{}/.default", self.cfg.graph_base);
        let v = self
            .http
            .json(
                "POST",
                &url,
                None,
                Body::Form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &self.cfg.client_id),
                    ("client_secret", &self.cfg.client_secret),
                    ("scope", &scope),
                ]),
            )
            .map_err(|e| {
                err(format!(
                    "signing in to Microsoft 365 with the app registration: {e}"
                ))
            })?;
        let t = v["access_token"]
            .as_str()
            .ok_or_else(|| err("Microsoft 365 sign-in returned no token"))?
            .to_string();
        let life = v["expires_in"]
            .as_u64()
            .unwrap_or(3600)
            .saturating_sub(300)
            .max(60);
        *self.token.borrow_mut() = Some((t.clone(), Instant::now() + Duration::from_secs(life)));
        Ok(t)
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}/v1.0{path}", self.cfg.graph_base)
        }
    }

    fn get(&self, path: &str) -> Result<Value> {
        self.http
            .json("GET", &self.url(path), Some(&self.token()?), Body::None)
    }

    /// Every page of a list; returns the items and the final deltaLink, if any.
    fn pages(&self, path: &str) -> Result<(Vec<Value>, Option<String>)> {
        let mut next = Some(self.url(path));
        let mut out = Vec::new();
        let mut delta = None;
        while let Some(u) = next.take() {
            let v = self.get(&u)?;
            out.extend(v["value"].as_array().cloned().unwrap_or_default());
            next = v["@odata.nextLink"].as_str().map(str::to_string);
            if let Some(d) = v["@odata.deltaLink"].as_str() {
                delta = Some(d.to_string());
            }
        }
        Ok((out, delta))
    }

    pub fn users(&self, only: &[String]) -> Result<Vec<(String, String)>> {
        let (all, _) = self.pages("/users?$select=id,userPrincipalName&$top=999")?;
        let want: HashSet<String> = only.iter().map(|u| u.to_lowercase()).collect();
        Ok(all
            .iter()
            .filter_map(|u| {
                let upn = u["userPrincipalName"].as_str()?.to_string();
                (want.is_empty() || want.contains(&upn.to_lowercase()))
                    .then(|| (u["id"].as_str().unwrap_or_default().to_string(), upn))
            })
            .collect())
    }

    /// Back up into `w`, using the previous backup's index for what did not change.
    pub fn backup(
        &self,
        w: &mut Writer,
        prev: Option<&Index>,
        o: &Options,
        progress: &dyn Fn(&str),
    ) -> Result<()> {
        let prev_items: BTreeMap<(String, String, String), Item> = prev
            .map(|p| {
                p.items
                    .iter()
                    .map(|i| ((i.account.clone(), i.kind.clone(), i.id.clone()), i.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let cursors = prev.map(|p| p.cursors.clone()).unwrap_or_default();
        for (uid, upn) in self.users(&o.users)? {
            progress(&upn);
            let r = (|| -> Result<()> {
                if o.mail {
                    self.mail(w, &uid, &upn, &prev_items, &cursors)?;
                }
                if o.files {
                    self.files(w, &uid, &upn, &prev_items, &cursors)?;
                }
                Ok(())
            })();
            if let Err(e) = r {
                w.index.warnings.push(format!("{upn}: {e}"));
                // Keep what the previous backup had for this user, rather than lose it.
                for ((acc, _, _), it) in
                    prev_items.range((upn.clone(), String::new(), String::new())..)
                {
                    if acc != &upn {
                        break;
                    }
                    if !w
                        .index
                        .items
                        .iter()
                        .any(|x| x.account == it.account && x.id == it.id && x.kind == it.kind)
                    {
                        w.keep(it.clone());
                    }
                }
                for (k, v) in cursors.range(format!("{upn}|")..) {
                    if !k.starts_with(&format!("{upn}|")) {
                        break;
                    }
                    w.index
                        .cursors
                        .entry(k.clone())
                        .or_insert_with(|| v.clone());
                }
            }
        }
        Ok(())
    }

    /// Apply a delta listing to the previous items of one collection.
    #[allow(clippy::too_many_arguments)]
    fn apply_delta(
        &self,
        w: &mut Writer,
        account: &str,
        kind: &str,
        prev_items: &BTreeMap<(String, String, String), Item>,
        in_collection: &dyn Fn(&Item) -> bool,
        changes: Vec<Value>,
        incremental: bool,
        to_item: &dyn Fn(&Value) -> Option<(Item, String)>,
    ) -> Result<()> {
        let mut removed = HashSet::new();
        let mut changed: Vec<(Item, String)> = Vec::new();
        for c in &changes {
            let id = c["id"].as_str().unwrap_or_default().to_string();
            if c.get("@removed").is_some() || c.get("deleted").is_some() {
                removed.insert(id);
            } else if let Some(x) = to_item(c) {
                removed.insert(id); // replaced by the new version
                changed.push(x);
            }
        }
        if incremental {
            for ((acc, k, id), it) in
                prev_items.range((account.to_string(), kind.to_string(), String::new())..)
            {
                if acc != account || k != kind {
                    break;
                }
                if in_collection(it) && !removed.contains(id) {
                    if it.chunks.first().is_some_and(|c| w_has(w, c)) {
                        w.keep(it.clone());
                    } else if let Some(url) = it.meta["content"].as_str() {
                        changed.push((it.clone(), url.to_string()));
                    }
                }
            }
        }
        for (it, url) in changed {
            let data = self.http.bytes(&self.url(&url), Some(&self.token()?))?;
            w.add(it, &data).map_err(|e| err(e.to_string()))?;
        }
        Ok(())
    }

    fn mail(
        &self,
        w: &mut Writer,
        uid: &str,
        upn: &str,
        prev: &BTreeMap<(String, String, String), Item>,
        cursors: &BTreeMap<String, String>,
    ) -> Result<()> {
        let (folders, _) = match self.pages(&format!(
            "/users/{uid}/mailFolders/delta?$select=id,displayName,parentFolderId"
        )) {
            Ok(f) => f,
            Err(e) if e.0.contains(" 404 ") || e.0.contains("MailboxNotEnabled") => return Ok(()),
            Err(e) => return Err(e),
        };
        let names: BTreeMap<String, String> = folders
            .iter()
            .map(|f| {
                (
                    f["id"].as_str().unwrap_or_default().to_string(),
                    f["displayName"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        for f in &folders {
            let fid = f["id"].as_str().unwrap_or_default().to_string();
            let fname = names.get(&fid).cloned().unwrap_or_default();
            let key = format!("{upn}|mail|{fid}");
            let (start, incremental) = match cursors.get(&key) {
                Some(d) => (d.clone(), true),
                None => (format!("/users/{uid}/mailFolders/{fid}/messages/delta?$select=id,subject,receivedDateTime,lastModifiedDateTime"), false),
            };
            let (changes, delta) = self.pages(&start)?;
            let to_item = |m: &Value| -> Option<(Item, String)> {
                let id = m["id"].as_str()?.to_string();
                let subject = m["subject"].as_str().unwrap_or("").to_string();
                let content = format!("/users/{uid}/messages/{id}/$value");
                Some((
                    Item {
                        account: upn.to_string(),
                        kind: "mail".into(),
                        id,
                        path: format!("{fname}/{subject}"),
                        modified: m["lastModifiedDateTime"].as_str().unwrap_or("").to_string(),
                        size: 0,
                        hash: String::new(),
                        meta: json!({ "folder_id": fid, "folder": fname, "subject": subject, "received": m["receivedDateTime"], "content": content }),
                        chunks: vec![],
                    },
                    content,
                ))
            };
            let fid2 = fid.clone();
            self.apply_delta(
                w,
                upn,
                "mail",
                prev,
                &|it: &Item| it.meta["folder_id"].as_str() == Some(fid2.as_str()),
                changes,
                incremental,
                &to_item,
            )?;
            if let Some(d) = delta {
                w.index.cursors.insert(key, d);
            }
        }
        Ok(())
    }

    fn files(
        &self,
        w: &mut Writer,
        uid: &str,
        upn: &str,
        prev: &BTreeMap<(String, String, String), Item>,
        cursors: &BTreeMap<String, String>,
    ) -> Result<()> {
        let key = format!("{upn}|file|drive");
        let (start, incremental) = match cursors.get(&key) {
            Some(d) => (d.clone(), true),
            None => (format!("/users/{uid}/drive/root/delta"), false),
        };
        let (changes, delta) = match self.pages(&start) {
            Ok(x) => x,
            // No OneDrive for this user (unlicensed): nothing to back up.
            Err(e) if e.0.contains(" 404 ") => return Ok(()),
            Err(e) => return Err(e),
        };
        let to_item = |d: &Value| -> Option<(Item, String)> {
            d.get("file")?;
            let id = d["id"].as_str()?.to_string();
            let parent = d["parentReference"]["path"]
                .as_str()
                .unwrap_or("")
                .split_once(':')
                .map(|(_, p)| p.to_string())
                .unwrap_or_default();
            let path = format!(
                "{}/{}",
                parent.trim_end_matches('/'),
                d["name"].as_str().unwrap_or(&id)
            );
            let content = format!("/users/{uid}/drive/items/{id}/content");
            Some((
                Item {
                    account: upn.to_string(),
                    kind: "file".into(),
                    id,
                    path: path.trim_start_matches('/').to_string(),
                    modified: d["lastModifiedDateTime"].as_str().unwrap_or("").to_string(),
                    size: 0,
                    hash: String::new(),
                    meta: json!({ "mime": d["file"]["mimeType"], "content": content }),
                    chunks: vec![],
                },
                content,
            ))
        };
        self.apply_delta(
            w,
            upn,
            "file",
            prev,
            &|_| true,
            changes,
            incremental,
            &to_item,
        )?;
        if let Some(d) = delta {
            w.index.cursors.insert(key, d);
        }
        Ok(())
    }

    // ---------------------------------------------------------------- restore

    fn user_id(&self, upn: &str) -> Result<String> {
        let u = self.get(&format!("/users/{}?$select=id", enc(upn)))?;
        u["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| err(format!("no user {upn}")))
    }

    /// Put a file back into `upn`'s OneDrive under `folder`.
    pub fn restore_file(&self, upn: &str, folder: &str, item: &Item, data: &[u8]) -> Result<()> {
        let uid = self.user_id(upn)?;
        let path = format!("{}/{}", folder.trim_matches('/'), item.path)
            .split('/')
            .filter(|s| !s.is_empty())
            .map(enc)
            .collect::<Vec<_>>()
            .join("/");
        let tok = self.token()?;
        if data.len() <= 4 << 20 {
            let (s, b) = self.http.send(
                "PUT",
                &self.url(&format!("/users/{uid}/drive/root:/{path}:/content")),
                Some(&tok),
                &[],
                Body::Bytes(data, "application/octet-stream"),
            )?;
            if !(200..300).contains(&s) {
                return Err(err(format!(
                    "{}: {s} {}",
                    item.path,
                    String::from_utf8_lossy(&b)
                )));
            }
            return Ok(());
        }
        let s = self.http.json(
            "POST",
            &self.url(&format!(
                "/users/{uid}/drive/root:/{path}:/createUploadSession"
            )),
            Some(&tok),
            Body::Json(&json!({ "item": { "@microsoft.graph.conflictBehavior": "rename" } })),
        )?;
        let up = s["uploadUrl"]
            .as_str()
            .ok_or_else(|| err("no upload session"))?;
        // Pieces must be multiples of 320 KiB.
        let piece = 320 * 1024 * 16;
        let total = data.len();
        for (i, p) in data.chunks(piece).enumerate() {
            let from = i * piece;
            let range = format!("bytes {from}-{}/{total}", from + p.len() - 1);
            let (st, b) = self.http.send(
                "PUT",
                up,
                None,
                &[("Content-Range", &range)],
                Body::Bytes(p, "application/octet-stream"),
            )?;
            if !(200..300).contains(&st) {
                return Err(err(format!(
                    "{}: {st} {}",
                    item.path,
                    String::from_utf8_lossy(&b)
                )));
            }
        }
        Ok(())
    }

    /// A mail folder for restored messages (created under `parent`, or the mailbox root).
    pub fn mail_folder(&self, upn: &str, name: &str, parent: Option<&str>) -> Result<String> {
        let uid = self.user_id(upn)?;
        let path = match parent {
            Some(p) => format!("/users/{uid}/mailFolders/{p}/childFolders"),
            None => format!("/users/{uid}/mailFolders"),
        };
        let v = self.http.json(
            "POST",
            &self.url(&path),
            Some(&self.token()?),
            Body::Json(&json!({ "displayName": name })),
        )?;
        v["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| err("no folder ID"))
    }

    /// Put a message (MIME) into a folder.
    pub fn restore_mail(&self, upn: &str, folder_id: &str, mime: &[u8]) -> Result<()> {
        let uid = self.user_id(upn)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(mime);
        let (s, b) = self.http.send(
            "POST",
            &self.url(&format!("/users/{uid}/mailFolders/{folder_id}/messages")),
            Some(&self.token()?),
            &[],
            Body::Bytes(b64.as_bytes(), "text/plain"),
        )?;
        if !(200..300).contains(&s) {
            return Err(err(format!("{s} {}", String::from_utf8_lossy(&b))));
        }
        Ok(())
    }
}

fn w_has(w: &Writer, c: &core_format::chunk::ChunkId) -> bool {
    w.has_chunk(c)
}
