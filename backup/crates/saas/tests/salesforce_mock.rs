//! Salesforce backup against a mock of the REST API: a full backup (paged
//! query), an incremental one (changed records by SystemModstamp, deleted ones
//! from getDeleted), and re-creating a deleted record.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::{InitOptions, Repository};
use saas::salesforce::{Config, Options, Salesforce};
use saas::store;
use serde_json::json;

#[derive(Default)]
struct State {
    downloads: Vec<String>,
    uploads: Vec<(String, Vec<u8>)>,
}

fn serve(state: Arc<Mutex<State>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let b2 = base.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let mut it = line.split_whitespace();
            let (method, path) = (
                it.next().unwrap().to_string(),
                it.next().unwrap().to_string(),
            );
            let p = path.split('?').next().unwrap().to_string();
            let j = |v: serde_json::Value| ("application/json", v.to_string().into_bytes());
            let q = path
                .split_once("?q=")
                .map(|(_, q)| q.to_string())
                .unwrap_or_default();
            let acct = |id: &str, name: &str| json!({ "attributes": { "type": "Account" }, "Id": id, "Name": name, "Industry": "Retail", "SystemModstamp": "2026-11-01T10:00:00.000+0000", "IsDeleted": false });
            let (ct, out): (&str, Vec<u8>) = match (method.as_str(), p.as_str()) {
                ("POST", "/services/oauth2/token") => {
                    j(json!({ "access_token": "tok", "instance_url": b2 }))
                }
                ("GET", "/services/data/v61.0/sobjects/Account/describe") => {
                    j(json!({ "queryable": true, "fields": [
                    { "name": "Id", "type": "id", "createable": false, "updateable": false },
                    { "name": "Name", "type": "string", "createable": true, "updateable": true },
                    { "name": "Industry", "type": "picklist", "createable": true, "updateable": true },
                    { "name": "BillingAddress", "type": "address", "createable": false, "updateable": false },
                    { "name": "SystemModstamp", "type": "datetime", "createable": false, "updateable": false },
                    { "name": "IsDeleted", "type": "boolean", "createable": false, "updateable": false }] }))
                }
                ("GET", "/services/data/v61.0/queryAll") => {
                    state.lock().unwrap().downloads.push(q.clone());
                    assert!(
                        !q.contains("BillingAddress"),
                        "compound fields are not selected: {q}"
                    );
                    if q.contains("WHERE") {
                        j(json!({ "records": [acct("001C", "Gamma Ltd")], "done": true }))
                    } else {
                        j(
                            json!({ "records": [acct("001A", "Alpha Ltd")], "done": false, "nextRecordsUrl": "/services/data/v61.0/query/01gNEXT-2000" }),
                        )
                    }
                }
                ("GET", "/services/data/v61.0/query/01gNEXT-2000") => {
                    j(json!({ "records": [acct("001B", "Beta Ltd")], "done": true }))
                }
                ("GET", "/services/data/v61.0/sobjects/Account/deleted/") => {
                    j(json!({ "deletedRecords": [{ "id": "001B" }] }))
                }
                ("GET", "/services/data/v61.0/sobjects/Account/001A") => j(json!({ "Id": "001A" })),
                ("POST", "/services/data/v61.0/sobjects/Account") => {
                    state
                        .lock()
                        .unwrap()
                        .uploads
                        .push((p.clone(), body.clone()));
                    j(json!({ "id": "001NEW", "success": true }))
                }
                _ => {
                    let b = format!("no mock for {method} {p}");
                    s.write_all(format!("HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).as_bytes()).unwrap();
                    continue;
                }
            };
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", out.len()).as_bytes()).unwrap();
            s.write_all(&out).unwrap();
        }
    });
    base
}

#[test]
fn salesforce_full_incremental_and_restore() {
    for v in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        std::env::remove_var(v);
    }
    let state = Arc::new(Mutex::new(State::default()));
    let base = serve(state.clone());
    let sf = Salesforce::new(Config {
        domain_url: base.clone(),
        client_id: "app".into(),
        client_secret: "secret".into(),
    });
    let dir = tempfile::tempdir().unwrap();
    let b: Arc<dyn Backend> = Arc::new(LocalBackend::create(dir.path().join("r")).unwrap());
    let (repo, _) = Repository::init(
        b,
        b"pw",
        InitOptions {
            kdf: KdfParams::INSECURE_FAST,
            ..Default::default()
        },
    )
    .unwrap();
    let opts = Options {
        objects: vec!["Account".into()],
    };

    let mut w = store::Writer::new(&repo, "salesforce", "acme");
    sf.backup(&mut w, None, &opts, &|_| {}).unwrap();
    assert!(w.index.warnings.is_empty(), "{:?}", w.index.warnings);
    w.finish(None, std::time::Instant::now()).unwrap();

    let (_, prev) = store::previous(&repo, "salesforce", "acme")
        .unwrap()
        .unwrap();
    assert_eq!(prev.items.len(), 2, "both pages");
    let mut w = store::Writer::new(&repo, "salesforce", "acme");
    sf.backup(&mut w, Some(&prev), &opts, &|_| {}).unwrap();
    let second = w.finish(None, std::time::Instant::now()).unwrap();
    let qs = state.lock().unwrap().downloads.clone();
    assert!(
        qs[1].contains("WHERE") && qs[1].contains("SystemModstamp"),
        "{qs:?}"
    );
    let idx = store::read_index(&repo, &repo.load_manifest(&second).unwrap()).unwrap();
    let mut ids: Vec<&str> = idx.items.iter().map(|i| i.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, vec!["001A", "001C"], "B was deleted, C is new, A kept");

    // B was deleted in Salesforce: from the first backup, re-create it.
    let first = store::read_index(
        &repo,
        &repo.load_manifest(&prev_id(&repo, &second)).unwrap(),
    )
    .unwrap();
    let beta = first.items.iter().find(|i| i.id == "001B").unwrap();
    let new_id = sf
        .restore_record("Account", &store::read_item(&repo, beta).unwrap(), false)
        .unwrap();
    assert_eq!(new_id, "001NEW");
    let up = state.lock().unwrap().uploads.clone();
    let sent: serde_json::Value = serde_json::from_slice(&up[0].1).unwrap();
    assert_eq!(
        sent,
        json!({ "Name": "Beta Ltd", "Industry": "Retail" }),
        "createable fields only"
    );
    // A still exists: left alone without overwrite.
    let alpha = idx.items.iter().find(|i| i.id == "001A").unwrap();
    assert_eq!(
        sf.restore_record("Account", &store::read_item(&repo, alpha).unwrap(), false)
            .unwrap(),
        "001A"
    );
}

fn prev_id(repo: &Repository, second: &uuid::Uuid) -> uuid::Uuid {
    repo.load_manifest(second).unwrap().parent.unwrap()
}
