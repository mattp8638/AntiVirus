//! Google Workspace with the customer's own service account and domain-wide
//! delegation (scopes in docs/design/saas.md). Gmail: every message as MIME,
//! changes through the history API; Drive: every file (Google Docs, Sheets
//! and Slides exported as Office files), changes through the changes API.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};

use crate::http::{enc, Body, Http};
use crate::store::{Index, Item, Writer};
use crate::{err, Result};

pub const SCOPES_BACKUP: &str =
    "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.readonly";
pub const SCOPES_RESTORE: &str = "https://www.googleapis.com/auth/gmail.insert https://www.googleapis.com/auth/gmail.labels https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive";
pub const SCOPE_DIRECTORY: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";

#[derive(Debug, Clone)]
pub struct Config {
    /// The service account's JSON key file contents.
    pub client_email: String,
    pub private_key_pem: String,
    pub token_uri: String,
    /// A Workspace administrator to list users as.
    pub admin: String,
    /// The Workspace domain (the backup's tenant name).
    pub domain: String,
    pub gmail_base: String,
    pub drive_base: String,
    pub admin_base: String,
}

impl Config {
    pub fn from_key_file(json_key: &str, admin: &str, domain: &str) -> Result<Config> {
        let k: Value =
            serde_json::from_str(json_key).map_err(|e| err(format!("service account key: {e}")))?;
        let s = |f: &str| {
            k[f].as_str()
                .map(str::to_string)
                .ok_or_else(|| err(format!("service account key has no {f}")))
        };
        Ok(Config {
            client_email: s("client_email")?,
            private_key_pem: s("private_key")?,
            token_uri: k["token_uri"]
                .as_str()
                .unwrap_or("https://oauth2.googleapis.com/token")
                .to_string(),
            admin: admin.into(),
            domain: domain.into(),
            gmail_base: "https://gmail.googleapis.com".into(),
            drive_base: "https://www.googleapis.com".into(),
            admin_base: "https://admin.googleapis.com".into(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub users: Vec<String>,
    pub mail: bool,
    pub files: bool,
}

pub struct Google {
    cfg: Config,
    http: Http,
    key: ring::signature::RsaKeyPair,
    tokens: RefCell<HashMap<(String, String), (String, Instant)>>,
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Google Docs formats and what they are exported as.
pub fn export_format(mime: &str) -> Option<(&'static str, &'static str)> {
    match mime {
        "application/vnd.google-apps.document" => Some((
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".docx",
        )),
        "application/vnd.google-apps.spreadsheet" => Some((
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".xlsx",
        )),
        "application/vnd.google-apps.presentation" => Some((
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".pptx",
        )),
        "application/vnd.google-apps.drawing" => Some(("image/png", ".png")),
        _ => None,
    }
}

impl Google {
    pub fn new(cfg: Config) -> Result<Google> {
        let pem = cfg.private_key_pem.replace("\\n", "\n");
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| err(format!("service account private key: {e}")))?;
        let key = ring::signature::RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| err(format!("service account private key: {e}")))?;
        Ok(Google {
            cfg,
            http: Http::default(),
            key,
            tokens: RefCell::new(HashMap::new()),
        })
    }

    /// A token acting as `user` (domain-wide delegation).
    fn token(&self, user: &str, scopes: &str) -> Result<String> {
        let k = (user.to_string(), scopes.to_string());
        if let Some((t, until)) = self.tokens.borrow().get(&k) {
            if Instant::now() < *until {
                return Ok(t.clone());
            }
        }
        let now = core_format::timefmt::now_unix();
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = b64url(json!({ "iss": self.cfg.client_email, "sub": user, "scope": scopes, "aud": self.cfg.token_uri, "iat": now, "exp": now + 3600 }).to_string().as_bytes());
        let msg = format!("{header}.{claims}");
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                msg.as_bytes(),
                &mut sig,
            )
            .map_err(|_| err("signing the service account assertion"))?;
        let jwt = format!("{msg}.{}", b64url(&sig));
        let v = self.http.json("POST", &self.cfg.token_uri, None, Body::Form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", &jwt)]))
            .map_err(|e| err(format!("signing in to Google as {user} (is domain-wide delegation set up for these scopes?): {e}")))?;
        let t = v["access_token"]
            .as_str()
            .ok_or_else(|| err("Google sign-in returned no token"))?
            .to_string();
        self.tokens.borrow_mut().insert(
            k,
            (
                t.clone(),
                Instant::now()
                    + Duration::from_secs(
                        v["expires_in"]
                            .as_u64()
                            .unwrap_or(3600)
                            .saturating_sub(300)
                            .max(60),
                    ),
            ),
        );
        Ok(t)
    }

    fn get(&self, user: &str, scopes: &str, url: &str) -> Result<Value> {
        self.http
            .json("GET", url, Some(&self.token(user, scopes)?), Body::None)
    }

    pub fn users(&self, only: &[String]) -> Result<Vec<String>> {
        if !only.is_empty() {
            return Ok(only.to_vec());
        }
        let mut out = Vec::new();
        let mut page = String::new();
        loop {
            let v = self.get(
                &self.cfg.admin,
                SCOPE_DIRECTORY,
                &format!(
                    "{}/admin/directory/v1/users?customer=my_customer&maxResults=500{page}",
                    self.cfg.admin_base
                ),
            )?;
            for u in v["users"].as_array().into_iter().flatten() {
                if u["suspended"] != true {
                    out.extend(u["primaryEmail"].as_str().map(str::to_string));
                }
            }
            match v["nextPageToken"].as_str() {
                Some(t) => page = format!("&pageToken={}", enc(t)),
                None => break,
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
        let prev_items: BTreeMap<(String, String, String), Item> = prev
            .map(|p| {
                p.items
                    .iter()
                    .map(|i| ((i.account.clone(), i.kind.clone(), i.id.clone()), i.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let cursors = prev.map(|p| p.cursors.clone()).unwrap_or_default();
        for user in self.users(&o.users)? {
            progress(&user);
            let r = (|| -> Result<()> {
                if o.mail {
                    self.gmail(w, &user, &prev_items, &cursors)?;
                }
                if o.files {
                    self.drive(w, &user, &prev_items, &cursors)?;
                }
                Ok(())
            })();
            if let Err(e) = r {
                w.index.warnings.push(format!("{user}: {e}"));
                for it in prev_items.values().filter(|i| i.account == user) {
                    if !w
                        .index
                        .items
                        .iter()
                        .any(|x| x.account == it.account && x.id == it.id && x.kind == it.kind)
                    {
                        w.keep(it.clone());
                    }
                }
                for (k, v) in cursors
                    .iter()
                    .filter(|(k, _)| k.starts_with(&format!("{user}|")))
                {
                    w.index
                        .cursors
                        .entry(k.clone())
                        .or_insert_with(|| v.clone());
                }
            }
        }
        Ok(())
    }

    fn gmail(
        &self,
        w: &mut Writer,
        user: &str,
        prev: &BTreeMap<(String, String, String), Item>,
        cursors: &BTreeMap<String, String>,
    ) -> Result<()> {
        let base = format!("{}/gmail/v1/users/{}", self.cfg.gmail_base, enc(user));
        let profile = self.get(user, SCOPES_BACKUP, &format!("{base}/profile"))?;
        let history_now = profile["historyId"]
            .as_str()
            .map(str::to_string)
            .or_else(|| profile["historyId"].as_u64().map(|n| n.to_string()))
            .unwrap_or_default();
        let key = format!("{user}|mail");
        let mine: Vec<&Item> = prev
            .values()
            .filter(|i| i.account == user && i.kind == "mail")
            .collect();
        // Which messages exist now: the history since the last backup, or (first time, or history expired) a listing.
        let mut ids: HashSet<String> = mine.iter().map(|i| i.id.clone()).collect();
        let mut changed: HashSet<String> = HashSet::new();
        let listed = if let Some(start) = cursors.get(&key) {
            let mut page = String::new();
            let ok = loop {
                match self.get(user, SCOPES_BACKUP, &format!("{base}/history?startHistoryId={}&historyTypes=messageAdded&historyTypes=messageDeleted&maxResults=500{page}", enc(start))) {
                    Ok(v) => {
                        for h in v["history"].as_array().into_iter().flatten() {
                            for a in h["messagesAdded"].as_array().into_iter().flatten() {
                                if let Some(id) = a["message"]["id"].as_str() {
                                    ids.insert(id.to_string());
                                    changed.insert(id.to_string());
                                }
                            }
                            for d in h["messagesDeleted"].as_array().into_iter().flatten() {
                                if let Some(id) = d["message"]["id"].as_str() {
                                    ids.remove(id);
                                    changed.remove(id);
                                }
                            }
                        }
                        match v["nextPageToken"].as_str() {
                            Some(t) => page = format!("&pageToken={}", enc(t)),
                            None => break true,
                        }
                    }
                    // History older than Gmail keeps: list everything instead.
                    Err(e) if e.0.contains(" 404 ") => break false,
                    Err(e) => return Err(e),
                }
            };
            !ok
        } else {
            true
        };
        if listed {
            ids.clear();
            let mut page = String::new();
            loop {
                let v = self.get(
                    user,
                    SCOPES_BACKUP,
                    &format!("{base}/messages?maxResults=500&includeSpamTrash=false{page}"),
                )?;
                for m in v["messages"].as_array().into_iter().flatten() {
                    if let Some(id) = m["id"].as_str() {
                        ids.insert(id.to_string());
                    }
                }
                match v["nextPageToken"].as_str() {
                    Some(t) => page = format!("&pageToken={}", enc(t)),
                    None => break,
                }
            }
        }
        let known: HashMap<&str, &Item> = mine.iter().map(|i| (i.id.as_str(), *i)).collect();
        let mut sorted: Vec<&String> = ids.iter().collect();
        sorted.sort();
        for id in sorted {
            match known.get(id.as_str()) {
                Some(it)
                    if !changed.contains(id)
                        && it.chunks.first().is_some_and(|c| w.has_chunk(c)) =>
                {
                    w.keep((*it).clone())
                }
                _ => {
                    let v = self.get(
                        user,
                        SCOPES_BACKUP,
                        &format!("{base}/messages/{}?format=raw", enc(id)),
                    )?;
                    let raw = base64::engine::general_purpose::URL_SAFE
                        .decode(v["raw"].as_str().unwrap_or("").replace('=', "").as_bytes())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
                                v["raw"]
                                    .as_str()
                                    .unwrap_or("")
                                    .trim_end_matches('=')
                                    .as_bytes(),
                            )
                        })
                        .map_err(|e| err(format!("message {id}: {e}")))?;
                    let labels: Vec<Value> = v["labelIds"].as_array().cloned().unwrap_or_default();
                    w.add(
                        Item {
                            account: user.to_string(),
                            kind: "mail".into(),
                            id: id.clone(),
                            path: format!("Gmail/{id}"),
                            modified: v["internalDate"].as_str().unwrap_or("").to_string(),
                            size: 0,
                            hash: String::new(),
                            meta: json!({ "labels": labels, "thread": v["threadId"] }),
                            chunks: vec![],
                        },
                        &raw,
                    )
                    .map_err(|e| err(e.to_string()))?;
                }
            }
        }
        if !history_now.is_empty() {
            w.index.cursors.insert(key, history_now);
        }
        Ok(())
    }

    fn drive(
        &self,
        w: &mut Writer,
        user: &str,
        prev: &BTreeMap<(String, String, String), Item>,
        cursors: &BTreeMap<String, String>,
    ) -> Result<()> {
        let api = format!("{}/drive/v3", self.cfg.drive_base);
        let key = format!("{user}|file");
        let start = self.get(
            user,
            SCOPES_BACKUP,
            &format!("{api}/changes/startPageToken"),
        )?["startPageToken"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let fields = "id,name,mimeType,modifiedTime,parents,trashed,size";
        let mine: HashMap<String, &Item> = prev
            .values()
            .filter(|i| i.account == user && i.kind == "file")
            .map(|i| (i.id.clone(), i))
            .collect();
        let mut files: BTreeMap<String, Value> = BTreeMap::new();
        let mut changed: HashSet<String> = HashSet::new();
        let mut folders: HashMap<String, (String, Option<String>)> = HashMap::new();
        if let Some(tok) = cursors.get(&key) {
            for (id, it) in &mine {
                files.insert(id.clone(), it.meta["file"].clone());
            }
            let mut page = tok.clone();
            loop {
                let v = self.get(user, SCOPES_BACKUP, &format!("{api}/changes?pageToken={}&pageSize=1000&fields=nextPageToken,newStartPageToken,changes(fileId,removed,file({fields}))", enc(&page)))?;
                for c in v["changes"].as_array().into_iter().flatten() {
                    let id = c["fileId"].as_str().unwrap_or_default().to_string();
                    if c["removed"] == true || c["file"]["trashed"] == true {
                        files.remove(&id);
                    } else if c["file"]["mimeType"] == "application/vnd.google-apps.folder" {
                        folders.insert(
                            id,
                            (
                                c["file"]["name"].as_str().unwrap_or("").to_string(),
                                c["file"]["parents"][0].as_str().map(str::to_string),
                            ),
                        );
                    } else {
                        files.insert(id.clone(), c["file"].clone());
                        changed.insert(id);
                    }
                }
                match v["nextPageToken"].as_str() {
                    Some(t) => page = t.to_string(),
                    None => break,
                }
            }
        } else {
            let mut page = String::new();
            loop {
                let v = self.get(user, SCOPES_BACKUP, &format!("{api}/files?q=trashed%3Dfalse&pageSize=1000&fields=nextPageToken,files({fields})&corpora=user{page}"))?;
                for f in v["files"].as_array().into_iter().flatten() {
                    let id = f["id"].as_str().unwrap_or_default().to_string();
                    if f["mimeType"] == "application/vnd.google-apps.folder" {
                        folders.insert(
                            id,
                            (
                                f["name"].as_str().unwrap_or("").to_string(),
                                f["parents"][0].as_str().map(str::to_string),
                            ),
                        );
                    } else {
                        changed.insert(id.clone());
                        files.insert(id, f.clone());
                    }
                }
                match v["nextPageToken"].as_str() {
                    Some(t) => page = format!("&pageToken={}", enc(t)),
                    None => break,
                }
            }
        }
        // Folder paths (looked up once each when not listed).
        let mut path_of = |mut parent: Option<String>| -> String {
            let mut parts = Vec::new();
            for _ in 0..64 {
                let Some(p) = parent.take() else { break };
                let entry = match folders.get(&p) {
                    Some(e) => Some(e.clone()),
                    None => self
                        .get(
                            user,
                            SCOPES_BACKUP,
                            &format!("{api}/files/{}?fields=name,parents", enc(&p)),
                        )
                        .ok()
                        .map(|v| {
                            let e = (
                                v["name"].as_str().unwrap_or("").to_string(),
                                v["parents"][0].as_str().map(str::to_string),
                            );
                            folders.insert(p.clone(), e.clone());
                            e
                        }),
                };
                let Some((name, next)) = entry else { break };
                if next.is_some() {
                    parts.push(name);
                }
                parent = next;
            }
            parts.reverse();
            parts.join("/")
        };
        for (id, f) in &files {
            let kept = mine.get(id).filter(|it| {
                !changed.contains(id) && it.chunks.first().is_some_and(|c| w.has_chunk(c))
            });
            if let Some(it) = kept {
                w.keep((*it).clone());
                continue;
            }
            let mime = f["mimeType"].as_str().unwrap_or("");
            let (url, ext) = match export_format(mime) {
                Some((to, ext)) => (
                    format!("{api}/files/{}/export?mimeType={}", enc(id), enc(to)),
                    ext,
                ),
                None if mime.starts_with("application/vnd.google-apps.") => {
                    w.index.warnings.push(format!(
                        "{user}: {} ({mime}) cannot be exported and was skipped",
                        f["name"].as_str().unwrap_or(id)
                    ));
                    continue;
                }
                None => (format!("{api}/files/{}?alt=media", enc(id)), ""),
            };
            let data = self
                .http
                .bytes(&url, Some(&self.token(user, SCOPES_BACKUP)?))?;
            let dir = path_of(f["parents"][0].as_str().map(str::to_string));
            let name = format!("{}{ext}", f["name"].as_str().unwrap_or(id));
            w.add(
                Item {
                    account: user.to_string(),
                    kind: "file".into(),
                    id: id.clone(),
                    path: if dir.is_empty() {
                        name
                    } else {
                        format!("{dir}/{name}")
                    },
                    modified: f["modifiedTime"].as_str().unwrap_or("").to_string(),
                    size: 0,
                    hash: String::new(),
                    meta: json!({ "file": f, "exported": !ext.is_empty() }),
                    chunks: vec![],
                },
                &data,
            )
            .map_err(|e| err(e.to_string()))?;
        }
        if !start.is_empty() {
            w.index.cursors.insert(key, start);
        }
        Ok(())
    }

    // ---------------------------------------------------------------- restore

    /// Put a message back into `user`'s mailbox with a label.
    pub fn restore_mail(&self, user: &str, label: &str, mime: &[u8]) -> Result<()> {
        let base = format!("{}/gmail/v1/users/{}", self.cfg.gmail_base, enc(user));
        let t = self.token(user, SCOPES_RESTORE)?;
        let labels = self
            .http
            .json("GET", &format!("{base}/labels"), Some(&t), Body::None)?;
        let lid = match labels["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|l| l["name"] == label)
            .and_then(|l| l["id"].as_str())
        {
            Some(id) => id.to_string(),
            None => self.http.json(
                "POST",
                &format!("{base}/labels"),
                Some(&t),
                Body::Json(&json!({ "name": label })),
            )?["id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        };
        let up = format!("{}/upload/gmail/v1/users/{}/messages/import?uploadType=media&internalDateSource=dateHeader", self.cfg.gmail_base, enc(user));
        let (s, b) = self.http.send(
            "POST",
            &up,
            Some(&t),
            &[],
            Body::Bytes(mime, "message/rfc822"),
        )?;
        if !(200..300).contains(&s) {
            return Err(err(format!("{s} {}", String::from_utf8_lossy(&b))));
        }
        let id = serde_json::from_slice::<Value>(&b)
            .ok()
            .and_then(|v| v["id"].as_str().map(str::to_string))
            .unwrap_or_default();
        self.http.json(
            "POST",
            &format!("{base}/messages/{}/modify", enc(&id)),
            Some(&t),
            Body::Json(&json!({ "addLabelIds": [lid, "INBOX"] })),
        )?;
        Ok(())
    }

    /// A Drive folder (in the root) for restored files.
    pub fn drive_folder(&self, user: &str, name: &str) -> Result<String> {
        let t = self.token(user, SCOPES_RESTORE)?;
        let v = self.http.json(
            "POST",
            &format!("{}/drive/v3/files", self.cfg.drive_base),
            Some(&t),
            Body::Json(&json!({ "name": name, "mimeType": "application/vnd.google-apps.folder" })),
        )?;
        v["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| err("no folder ID"))
    }

    /// Upload a file into `folder` (its path flattened into the name).
    pub fn restore_file(&self, user: &str, folder: &str, item: &Item, data: &[u8]) -> Result<()> {
        let t = self.token(user, SCOPES_RESTORE)?;
        let boundary = "fenrir-restore-boundary-7d1c";
        let meta = json!({ "name": item.path.replace('/', " - "), "parents": [folder] });
        let mut body = format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
        body.extend_from_slice(data);
        body.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
        let ct = format!("multipart/related; boundary={boundary}");
        let (s, b) = self.http.send(
            "POST",
            &format!(
                "{}/upload/drive/v3/files?uploadType=multipart",
                self.cfg.drive_base
            ),
            Some(&t),
            &[],
            Body::Bytes(&body, &ct),
        )?;
        if !(200..300).contains(&s) {
            return Err(err(format!(
                "{}: {s} {}",
                item.path,
                String::from_utf8_lossy(&b)
            )));
        }
        Ok(())
    }
}
