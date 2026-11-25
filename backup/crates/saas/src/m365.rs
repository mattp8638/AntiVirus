//! Microsoft 365 through Microsoft Graph, with the customer's own app
//! registration (client credentials; application permissions User.Read.All,
//! Mail.ReadWrite, Files.ReadWrite.All, and for the optional workloads
//! Sites.ReadWrite.All, ChannelMessage.Read.All, Directory.Read.All and
//! Policy.Read.All). Mail: every folder's messages as MIME (.eml); OneDrive
//! and SharePoint document libraries: every file; Teams: channel messages
//! and replies (JSON); Entra ID: users, groups and their members,
//! applications, service principals, directory roles and Conditional Access
//! policies (JSON). Changes since the previous backup come from Graph delta
//! queries; the directory is read in full each time (it is small).

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
    /// SharePoint sites' document libraries.
    pub sites: bool,
    /// Teams channel messages and replies.
    pub teams: bool,
    /// Entra ID objects and Conditional Access policies.
    pub directory: bool,
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
        if o.sites {
            progress("SharePoint sites");
            if let Err(e) = self.sites(w, &prev_items, &cursors) {
                w.index.warnings.push(format!("SharePoint: {e}"));
                self.keep_kind(w, prev, "site-file", &cursors, "site:");
            }
        }
        if o.teams {
            progress("Teams");
            if let Err(e) = self.teams(w, &prev_items, &cursors) {
                w.index.warnings.push(format!("Teams: {e}"));
                self.keep_kind(w, prev, "teams-message", &cursors, "team:");
            }
        }
        if o.directory {
            progress("Entra ID");
            if let Err(e) = self.directory(w) {
                w.index.warnings.push(format!("Entra ID: {e}"));
                self.keep_kind(w, prev, "directory", &cursors, "\u{0}");
            }
        }
        if !o.mail && !o.files {
            return Ok(());
        }
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

    /// After a failed workload: keep what the previous backup had of it,
    /// and its cursors, rather than lose it.
    fn keep_kind(
        &self,
        w: &mut Writer,
        prev: Option<&Index>,
        kind: &str,
        cursors: &BTreeMap<String, String>,
        cursor_prefix: &str,
    ) {
        for it in prev
            .into_iter()
            .flat_map(|p| p.items.iter())
            .filter(|i| i.kind == kind)
        {
            if !w
                .index
                .items
                .iter()
                .any(|x| x.kind == kind && x.id == it.id && x.account == it.account)
            {
                w.keep(it.clone());
            }
        }
        for (k, v) in cursors.iter().filter(|(k, _)| k.starts_with(cursor_prefix)) {
            w.index
                .cursors
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
    }

    /// Every SharePoint site's document libraries (drives), through delta queries.
    fn sites(
        &self,
        w: &mut Writer,
        prev: &BTreeMap<(String, String, String), Item>,
        cursors: &BTreeMap<String, String>,
    ) -> Result<()> {
        let (sites, _) = self.pages("/sites?search=*&$select=id,displayName,webUrl")?;
        for site in &sites {
            let Some(sid) = site["id"].as_str() else {
                continue;
            };
            let account = site["webUrl"].as_str().unwrap_or(sid).to_string();
            let (drives, _) = match self.pages(&format!("/sites/{sid}/drives?$select=id,name")) {
                Ok(d) => d,
                Err(e) => {
                    w.index.warnings.push(format!("{account}: {e}"));
                    continue;
                }
            };
            for d in &drives {
                let Some(did) = d["id"].as_str() else {
                    continue;
                };
                let dname = d["name"].as_str().unwrap_or("Documents").to_string();
                let key = format!("site:{account}|site-file|{did}");
                let (start, incremental) = match cursors.get(&key) {
                    Some(c) => (c.clone(), true),
                    None => (format!("/drives/{did}/root/delta"), false),
                };
                let (changes, delta) = self.pages(&start)?;
                let to_item = |x: &Value| -> Option<(Item, String)> {
                    x.get("file")?;
                    let id = x["id"].as_str()?.to_string();
                    let parent = x["parentReference"]["path"]
                        .as_str()
                        .unwrap_or("")
                        .split_once(':')
                        .map(|(_, p)| p.to_string())
                        .unwrap_or_default();
                    let path = format!(
                        "{dname}/{}/{}",
                        parent.trim_matches('/'),
                        x["name"].as_str().unwrap_or(&id)
                    );
                    let content = format!("/drives/{did}/items/{id}/content");
                    Some((
                        Item {
                            account: account.clone(),
                            kind: "site-file".into(),
                            id,
                            path: path.replace("//", "/"),
                            modified: x["lastModifiedDateTime"].as_str().unwrap_or("").to_string(),
                            size: 0,
                            hash: String::new(),
                            meta: json!({ "site_id": sid, "site": site["displayName"], "drive_id": did, "drive": dname,
                                          "mime": x["file"]["mimeType"], "content": content }),
                            chunks: vec![],
                        },
                        content,
                    ))
                };
                let did2 = did.to_string();
                self.apply_delta(
                    w,
                    &account,
                    "site-file",
                    prev,
                    &|it: &Item| it.meta["drive_id"].as_str() == Some(did2.as_str()),
                    changes,
                    incremental,
                    &to_item,
                )?;
                if let Some(c) = delta {
                    w.index.cursors.insert(key, c);
                }
            }
        }
        Ok(())
    }

    /// Store JSON objects as items, applying a delta listing to the
    /// previous ones of the same collection. A kept item whose data a prune
    /// removed cannot be fetched alone: its cursor is dropped, so the next
    /// backup lists that collection in full.
    #[allow(clippy::too_many_arguments)]
    fn apply_json(
        &self,
        w: &mut Writer,
        account: &str,
        kind: &str,
        key: &str,
        prev: &BTreeMap<(String, String, String), Item>,
        in_collection: &dyn Fn(&Item) -> bool,
        changes: &[Value],
        incremental: bool,
        to_item: &dyn Fn(&Value) -> Option<Item>,
    ) -> Result<bool> {
        let mut seen = HashSet::new();
        let mut whole = true;
        for c in changes {
            let id = c["id"].as_str().unwrap_or_default().to_string();
            seen.insert(id);
            if c.get("@removed").is_some() || c.get("deletedDateTime").is_some_and(|d| !d.is_null())
            {
                continue;
            }
            if let Some(it) = to_item(c) {
                let data = serde_json::to_vec(c).map_err(|e| err(e.to_string()))?;
                w.add(it, &data).map_err(|e| err(e.to_string()))?;
            }
        }
        if incremental {
            for ((acc, k, id), it) in
                prev.range((account.to_string(), kind.to_string(), String::new())..)
            {
                if acc != account || k != kind {
                    break;
                }
                if in_collection(it) && !seen.contains(id) {
                    if it.chunks.first().is_some_and(|c| w_has(w, c)) {
                        w.keep(it.clone());
                    } else {
                        whole = false;
                    }
                }
            }
        }
        if !whole {
            w.index.warnings.push(format!(
                "{account} {key}: some earlier items were pruned; listed in full next time"
            ));
        }
        Ok(whole)
    }

    /// Channel messages and their replies of every team (JSON).
    fn teams(
        &self,
        w: &mut Writer,
        prev: &BTreeMap<(String, String, String), Item>,
        cursors: &BTreeMap<String, String>,
    ) -> Result<()> {
        let (teams, _) = self.pages(
            "/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName",
        )?;
        for t in &teams {
            let Some(tid) = t["id"].as_str() else {
                continue;
            };
            let tname = t["displayName"].as_str().unwrap_or(tid).to_string();
            let account = format!("team:{tname}");
            let (channels, _) =
                self.pages(&format!("/teams/{tid}/channels?$select=id,displayName"))?;
            for ch in &channels {
                let Some(cid) = ch["id"].as_str() else {
                    continue;
                };
                let cname = ch["displayName"].as_str().unwrap_or(cid).to_string();
                let key = format!("team:{tname}|teams-message|{cid}");
                let (start, incremental) = match cursors.get(&key) {
                    Some(c) => (c.clone(), true),
                    None => (format!("/teams/{tid}/channels/{cid}/messages/delta"), false),
                };
                let (mut changes, delta) = self.pages(&start)?;
                // Replies are not in the channel's delta: each changed thread's replies.
                let threads: Vec<String> = changes
                    .iter()
                    .filter(|m| m.get("@removed").is_none())
                    .filter_map(|m| m["id"].as_str().map(str::to_string))
                    .collect();
                for mid in threads {
                    if let Ok((replies, _)) = self.pages(&format!(
                        "/teams/{tid}/channels/{cid}/messages/{mid}/replies"
                    )) {
                        changes.extend(replies);
                    }
                }
                let to_item = |m: &Value| -> Option<Item> {
                    let id = m["id"].as_str()?.to_string();
                    let from = m["from"]["user"]["displayName"].as_str().unwrap_or("");
                    let thread = m["replyToId"].as_str().unwrap_or(&id).to_string();
                    Some(Item {
                        account: account.clone(),
                        kind: "teams-message".into(),
                        id: id.clone(),
                        path: format!("{cname}/{thread}/{id}"),
                        modified: m["lastModifiedDateTime"]
                            .as_str()
                            .or(m["createdDateTime"].as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: 0,
                        hash: String::new(),
                        meta: json!({ "team_id": tid, "channel_id": cid, "channel": cname, "from": from,
                                      "created": m["createdDateTime"], "thread": thread }),
                        chunks: vec![],
                    })
                };
                let cid2 = cid.to_string();
                let whole = self.apply_json(
                    w,
                    &account,
                    "teams-message",
                    &key,
                    prev,
                    &|it: &Item| it.meta["channel_id"].as_str() == Some(cid2.as_str()),
                    &changes,
                    incremental,
                    &to_item,
                )?;
                if let (Some(c), true) = (delta, whole) {
                    w.index.cursors.insert(key, c);
                }
            }
        }
        Ok(())
    }

    /// Entra ID objects (JSON), read in full: users, groups with their
    /// members, applications, service principals, directory roles with
    /// their members, and Conditional Access policies.
    fn directory(&self, w: &mut Writer) -> Result<()> {
        let account = format!("directory:{}", self.cfg.tenant);
        let lists: &[(&str, &str, bool)] = &[
            ("user", "/users?$select=id,displayName,userPrincipalName,mail,givenName,surname,jobTitle,department,officeLocation,mobilePhone,businessPhones,accountEnabled,usageLocation,proxyAddresses,otherMails,createdDateTime&$top=999", false),
            ("group", "/groups?$select=id,displayName,description,mailNickname,mailEnabled,securityEnabled,groupTypes,visibility,membershipRule,membershipRuleProcessingState,createdDateTime&$top=999", true),
            ("application", "/applications?$top=999", false),
            ("servicePrincipal", "/servicePrincipals?$top=999", false),
            ("directoryRole", "/directoryRoles", true),
            ("conditionalAccessPolicy", "/identity/conditionalAccess/policies", false),
        ];
        for (kind, path, members) in lists {
            let (objs, _) = match self.pages(path) {
                Ok(x) => x,
                // Not licensed or not granted (Conditional Access needs Policy.Read.All and Entra ID P1).
                Err(e) if e.0.contains(" 403 ") || e.0.contains(" 404 ") => {
                    w.index
                        .warnings
                        .push(format!("Entra ID {kind}: not readable ({e})"));
                    continue;
                }
                Err(e) => return Err(e),
            };
            for mut o in objs {
                let Some(id) = o["id"].as_str().map(str::to_string) else {
                    continue;
                };
                if *members {
                    let base = if *kind == "group" {
                        "groups"
                    } else {
                        "directoryRoles"
                    };
                    if let Ok((m, _)) = self.pages(&format!("/{base}/{id}/members?$select=id")) {
                        o["fenrir_members"] = json!(m
                            .iter()
                            .filter_map(|x| x["id"].as_str())
                            .collect::<Vec<_>>());
                    }
                }
                let name = o["displayName"]
                    .as_str()
                    .or(o["userPrincipalName"].as_str())
                    .unwrap_or(&id)
                    .to_string();
                let data = serde_json::to_vec(&o).map_err(|e| err(e.to_string()))?;
                w.add(
                    Item {
                        account: account.clone(),
                        kind: "directory".into(),
                        id: id.clone(),
                        path: format!("{kind}/{name}"),
                        modified: o["modifiedDateTime"]
                            .as_str()
                            .or(o["createdDateTime"].as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: 0,
                        hash: String::new(),
                        meta: json!({ "type": kind, "name": name }),
                        chunks: vec![],
                    },
                    &data,
                )
                .map_err(|e| err(e.to_string()))?;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- restore

    /// Put a SharePoint file back into its document library under `folder`.
    pub fn restore_site_file(&self, folder: &str, item: &Item, data: &[u8]) -> Result<()> {
        let did = item.meta["drive_id"]
            .as_str()
            .ok_or_else(|| err("no document library recorded"))?;
        // The path starts with the library's name; inside the library it is the rest.
        let inner = item
            .path
            .split_once('/')
            .map(|(_, p)| p)
            .unwrap_or(&item.path);
        self.upload(&format!("/drives/{did}"), folder, inner, &item.path, data)
    }

    /// Restore an Entra ID object: from the recycle bin (deleted users and
    /// groups, 30 days), else a group or a Conditional Access policy is
    /// created again (the policy disabled, for review). Returns what was done.
    pub fn restore_directory(&self, item: &Item, data: &[u8]) -> Result<String> {
        let o: Value = serde_json::from_slice(data).map_err(|e| err(e.to_string()))?;
        let kind = item.meta["type"].as_str().unwrap_or("");
        let tok = self.token()?;
        if matches!(kind, "user" | "group" | "application" | "servicePrincipal") {
            let (s, _) = self.http.send(
                "POST",
                &self.url(&format!("/directory/deletedItems/{}/restore", item.id)),
                Some(&tok),
                &[],
                Body::Bytes(b"", "application/json"),
            )?;
            if (200..300).contains(&s) {
                return Ok(format!("{} restored from the recycle bin", item.path));
            }
        }
        match kind {
            "group" => {
                let mut g = json!({});
                for k in ["displayName", "description", "mailNickname", "mailEnabled", "securityEnabled", "groupTypes", "visibility", "membershipRule", "membershipRuleProcessingState"] {
                    if !o[k].is_null() {
                        g[k] = o[k].clone();
                    }
                }
                let created = self.http.json("POST", &self.url("/groups"), Some(&tok), Body::Json(&g))?;
                let gid = created["id"].as_str().ok_or_else(|| err("no ID for the new group"))?.to_string();
                let mut missing = 0;
                for m in o["fenrir_members"].as_array().into_iter().flatten().filter_map(|m| m.as_str()) {
                    let r = self.http.send(
                        "POST",
                        &self.url(&format!("/groups/{gid}/members/$ref")),
                        Some(&tok),
                        &[],
                        Body::Bytes(json!({ "@odata.id": format!("{}/v1.0/directoryObjects/{m}", self.cfg.graph_base) }).to_string().as_bytes(), "application/json"),
                    )?;
                    if !(200..300).contains(&r.0) {
                        missing += 1;
                    }
                }
                Ok(format!("group {} created again{}", item.path, if missing > 0 { format!(" ({missing} members no longer exist)") } else { String::new() }))
            }
            "conditionalAccessPolicy" => {
                let mut p = o.clone();
                if let Some(m) = p.as_object_mut() {
                    for k in ["id", "createdDateTime", "modifiedDateTime", "templateId", "@odata.context"] {
                        m.remove(k);
                    }
                    m.insert("state".into(), json!("disabled"));
                }
                self.http.json("POST", &self.url("/identity/conditionalAccess/policies"), Some(&tok), Body::Json(&p))?;
                Ok(format!("policy {} created again, disabled: review it and turn it on", item.path))
            }
            "user" => Err(err(format!("{}: users can be restored from the recycle bin within 30 days; after that create the user again (passwords are not backed up)", item.path))),
            _ => Err(err(format!("{}: {kind} objects are kept for reference and export; Microsoft Graph cannot create them again as they were", item.path))),
        }
    }

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
        self.upload(
            &format!("/users/{uid}/drive"),
            folder,
            &item.path,
            &item.path,
            data,
        )
    }

    /// Upload into a drive (`/users/{id}/drive` or `/drives/{id}`) at `folder/path`.
    fn upload(&self, drive: &str, folder: &str, path: &str, what: &str, data: &[u8]) -> Result<()> {
        let path = format!("{}/{}", folder.trim_matches('/'), path)
            .split('/')
            .filter(|s| !s.is_empty())
            .map(enc)
            .collect::<Vec<_>>()
            .join("/");
        let tok = self.token()?;
        if data.len() <= 4 << 20 {
            let (s, b) = self.http.send(
                "PUT",
                &self.url(&format!("{drive}/root:/{path}:/content")),
                Some(&tok),
                &[],
                Body::Bytes(data, "application/octet-stream"),
            )?;
            if !(200..300).contains(&s) {
                return Err(err(format!(
                    "{}: {s} {}",
                    what,
                    String::from_utf8_lossy(&b)
                )));
            }
            return Ok(());
        }
        let s = self.http.json(
            "POST",
            &self.url(&format!("{drive}/root:/{path}:/createUploadSession")),
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
                    what,
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
