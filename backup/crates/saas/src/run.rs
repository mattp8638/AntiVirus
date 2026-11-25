//! SaaS backups and restores against a repository (docs/design/saas.md),
//! shared by the command line and the agent.

use std::collections::HashMap;

use core_format::{ManifestBody, Repository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::{self, Item};
use crate::{err, google, m365, quickbooks, salesforce, Error, Result};

/// Which service and tenant, and the non-secret parts of the customer's
/// app registration, service account or connected app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// "m365", "google", "salesforce" or "quickbooks".
    pub service: String,
    /// Directory (tenant) ID or domain; Google domain; Salesforce org name;
    /// QuickBooks company (realm) ID.
    pub tenant: String,
    #[serde(default)]
    pub client_id: String,
    /// Salesforce: https://<my-domain>.my.salesforce.com. QuickBooks: the
    /// API address (empty: production; the sandbox for development).
    #[serde(default)]
    pub domain_url: String,
    /// Google: an administrator to list users as.
    #[serde(default)]
    pub admin: String,
}

/// What to back up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Users (empty: every user). Not used for Salesforce.
    #[serde(default)]
    pub users: Vec<String>,
    /// Salesforce objects (empty: the standard ones and every custom
    /// object); QuickBooks entities (empty: lists and transactions).
    #[serde(default)]
    pub objects: Vec<String>,
    #[serde(default = "yes")]
    pub mail: bool,
    #[serde(default = "yes")]
    pub files: bool,
    /// Microsoft 365: SharePoint document libraries, Teams channel
    /// messages, Entra ID objects (each needs its own permission).
    #[serde(default)]
    pub sites: bool,
    #[serde(default)]
    pub teams: bool,
    #[serde(default)]
    pub directory: bool,
}

impl Default for Scope {
    fn default() -> Self {
        Scope {
            users: vec![],
            objects: vec![],
            mail: true,
            files: true,
            sites: false,
            teams: false,
            directory: false,
        }
    }
}

fn yes() -> bool {
    true
}

pub enum Conn {
    M365(m365::M365),
    Google(Box<google::Google>),
    Salesforce(salesforce::Salesforce),
    QuickBooks(quickbooks::QuickBooks),
}

/// Sign-in details. `secret` is the client secret (Microsoft 365,
/// Salesforce), the service account's JSON key (Google), or the client
/// secret and refresh token as JSON (QuickBooks).
pub fn connect(s: &Settings, secret: &str) -> Result<Conn> {
    connect_in(s, secret, None)
}

/// As `connect`; `state` is a folder of this machine where rotating
/// refresh tokens (QuickBooks) are kept between runs.
pub fn connect_in(s: &Settings, secret: &str, state: Option<&std::path::Path>) -> Result<Conn> {
    let need = |v: &str, what: &str| {
        if v.trim().is_empty() {
            Err(err(format!("{what} is needed for {}", s.service)))
        } else {
            Ok(v.trim().to_string())
        }
    };
    let secret = need(secret, "the secret")?;
    Ok(match s.service.as_str() {
        "m365" => Conn::M365(m365::M365::new(m365::Config::new(
            &need(&s.tenant, "the tenant")?,
            &need(&s.client_id, "the client ID")?,
            &secret,
        ))),
        "google" => Conn::Google(Box::new(google::Google::new(
            google::Config::from_key_file(
                &secret,
                &need(&s.admin, "an administrator")?,
                &need(&s.tenant, "the domain")?,
            )?,
        )?)),
        "salesforce" => Conn::Salesforce(salesforce::Salesforce::new(salesforce::Config {
            domain_url: need(&s.domain_url, "the My Domain URL")?,
            client_id: need(&s.client_id, "the consumer key")?,
            client_secret: secret,
        })),
        "quickbooks" => {
            let realm = need(&s.tenant, "the company (realm) ID")?;
            let client = need(&s.client_id, "the client ID")?;
            let mut cfg = quickbooks::Config::from_secret(&realm, &client, &secret, &s.domain_url)?;
            cfg.token_cache = state.map(|d| {
                d.join(format!(
                    "quickbooks-{}.json",
                    blake3::hash(format!("{client}|{realm}").as_bytes())
                        .to_hex()
                        .get(..16)
                        .unwrap_or("")
                ))
            });
            Conn::QuickBooks(quickbooks::QuickBooks::new(cfg))
        }
        other => {
            return Err(err(format!(
                "unknown service {other}: m365, google, salesforce or quickbooks"
            )))
        }
    })
}

fn fe(e: core_format::Error) -> Error {
    err(e.to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupSummary {
    pub image_id: Uuid,
    pub items: usize,
    pub chunks_new: u64,
    pub warnings: Vec<String>,
}

pub fn backup(
    repo: &Repository,
    conn: &Conn,
    s: &Settings,
    scope: &Scope,
    label: Option<String>,
    progress: &dyn Fn(&str),
) -> Result<BackupSummary> {
    let started = std::time::Instant::now();
    let prev = store::previous(repo, &s.service, &s.tenant).map_err(fe)?;
    let mut w = store::Writer::new(repo, &s.service, &s.tenant);
    let pi = prev.as_ref().map(|p| &p.1);
    match conn {
        Conn::M365(m) => m.backup(
            &mut w,
            pi,
            &m365::Options {
                users: scope.users.clone(),
                mail: scope.mail,
                files: scope.files,
                sites: scope.sites,
                teams: scope.teams,
                directory: scope.directory,
            },
            progress,
        ),
        Conn::Google(g) => g.backup(
            &mut w,
            pi,
            &google::Options {
                users: scope.users.clone(),
                mail: scope.mail,
                files: scope.files,
            },
            progress,
        ),
        Conn::Salesforce(f) => f.backup(
            &mut w,
            pi,
            &salesforce::Options {
                objects: scope.objects.clone(),
            },
            progress,
        ),
        Conn::QuickBooks(q) => q.backup(
            &mut w,
            pi,
            &quickbooks::Options {
                entities: scope.objects.clone(),
            },
            progress,
        ),
    }?;
    let items = w.index.items.len();
    let warnings = w.index.warnings.clone();
    let chunks_new = w.stats.chunks_new;
    let image_id = w.finish(label, started).map_err(fe)?;
    Ok(BackupSummary {
        image_id,
        items,
        chunks_new,
        warnings,
    })
}

/// Which items to put back, and where.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub account: String,
    /// Restore into another account (default: the same).
    #[serde(default)]
    pub to_account: Option<String>,
    /// "mail", "file" or "record" (default: all).
    #[serde(default)]
    pub kind: Option<String>,
    /// Only items whose path starts with this.
    #[serde(default)]
    pub path: Option<String>,
    /// Salesforce: update records that still exist.
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreSummary {
    pub restored: usize,
    pub failed: Vec<String>,
    pub to: String,
    pub folder: String,
}

pub fn restore(
    repo: &Repository,
    conn: &Conn,
    m: &ManifestBody,
    sel: &Selection,
) -> Result<RestoreSummary> {
    let idx = store::read_index(repo, m).map_err(fe)?;
    let service = match conn {
        Conn::M365(_) => "m365",
        Conn::Google(_) => "google",
        Conn::Salesforce(_) => "salesforce",
        Conn::QuickBooks(_) => "quickbooks",
    };
    if idx.service != service {
        return Err(err(format!("that is a {} backup", idx.service)));
    }
    let target = sel
        .to_account
        .clone()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| sel.account.clone());
    let folder = format!("Restored {}", m.created.get(..10).unwrap_or(""));
    let items: Vec<&Item> = idx
        .items
        .iter()
        .filter(|i| {
            i.account == sel.account
                && sel.kind.as_ref().is_none_or(|k| &i.kind == k)
                && sel
                    .path
                    .as_ref()
                    .is_none_or(|p| i.path.starts_with(p.as_str()))
        })
        .collect();
    if items.is_empty() {
        return Err(err(format!(
            "the backup has nothing of {} that matches",
            sel.account
        )));
    }
    let (mut done, mut failed) = (0usize, Vec::new());
    let mut m365_folders: HashMap<String, String> = HashMap::new();
    let mut drive_folder: Option<String> = None;
    for it in items {
        let data = store::read_item(repo, it).map_err(fe)?;
        let r = match (conn, it.kind.as_str()) {
            (Conn::M365(c), "file") => c.restore_file(&target, &folder, it, &data),
            (Conn::M365(c), "site-file") => c.restore_site_file(&folder, it, &data),
            (Conn::M365(c), "directory") => c.restore_directory(it, &data).map(|_| ()),
            (Conn::M365(_), "teams-message") => Err(err(
                "Teams messages are kept for export: Microsoft Graph cannot post them again as their authors",
            )),
            (Conn::M365(c), "mail") => {
                let orig = it.meta["folder"].as_str().unwrap_or("Mail").to_string();
                let fid = match m365_folders.get(&orig) {
                    Some(f) => Ok(f.clone()),
                    None => {
                        let top = match m365_folders.get("") {
                            Some(t) => t.clone(),
                            None => {
                                let t = c.mail_folder(&target, &folder, None)?;
                                m365_folders.insert(String::new(), t.clone());
                                t
                            }
                        };
                        c.mail_folder(&target, &orig, Some(&top)).inspect(|f| {
                            m365_folders.insert(orig.clone(), f.clone());
                        })
                    }
                };
                fid.and_then(|f| c.restore_mail(&target, &f, &data))
            }
            (Conn::Google(g), "mail") => g.restore_mail(&target, &folder, &data),
            (Conn::Google(g), "file") => {
                let f = match &drive_folder {
                    Some(f) => f.clone(),
                    None => {
                        let f = g.drive_folder(&target, &folder)?;
                        drive_folder = Some(f.clone());
                        f
                    }
                };
                g.restore_file(&target, &f, it, &data)
            }
            (Conn::QuickBooks(q), "record") => q
                .restore_record(
                    it.meta["entity"].as_str().unwrap_or(""),
                    &data,
                    sel.overwrite,
                )
                .map(|_| ()),
            (Conn::Salesforce(s), "record") => s
                .restore_record(
                    it.meta["object"].as_str().unwrap_or(""),
                    &data,
                    sel.overwrite,
                )
                .map(|_| ()),
            _ => Err(err(format!(
                "{} items cannot be restored to {service}",
                it.kind
            ))),
        };
        match r {
            Ok(()) => done += 1,
            Err(e) => failed.push(format!("{}: {e}", it.path)),
        }
    }
    Ok(RestoreSummary {
        restored: done,
        failed,
        to: target,
        folder,
    })
}
