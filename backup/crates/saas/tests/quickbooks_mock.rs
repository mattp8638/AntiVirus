//! QuickBooks Online against a local mock of the Intuit API: full and
//! incremental backups (deletions from change data capture), rotating
//! refresh tokens kept on the machine, and restores (re-create, update).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::{InitOptions, Repository};
use saas::quickbooks::{Config, Options, QuickBooks};
use saas::store;
use serde_json::json;

#[derive(Default)]
struct State {
    refreshes: Vec<String>,
    queries: Vec<String>,
    cdc: usize,
    posts: Vec<serde_json::Value>,
}

fn decode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn serve(state: Arc<Mutex<State>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let mut len = 0usize;
            let mut auth = String::new();
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if lower.starts_with("authorization:") {
                    auth = h.trim().to_string();
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let mut it = line.split_whitespace();
            let (method, path) = (
                it.next().unwrap().to_string(),
                it.next().unwrap().to_string(),
            );
            let (p, q) = path.split_once('?').unwrap_or((&path, ""));
            assert!(
                q.contains("minorversion=75") || p.starts_with("/oauth2"),
                "{path}"
            );
            let cust = |id: &str, name: &str| json!({ "Id": id, "DisplayName": name, "SyncToken": "0", "MetaData": { "LastUpdatedTime": "2026-11-01T10:00:00-08:00" }, "domain": "QBO", "sparse": false });
            let mut status = "200 OK";
            let out = match (method.as_str(), p) {
                ("POST", "/oauth2/v1/tokens/bearer") => {
                    assert!(auth.starts_with("Authorization: Basic "), "client credentials in Basic auth");
                    let form = String::from_utf8(body.clone()).unwrap();
                    let used = decode(form.split("refresh_token=").nth(1).unwrap());
                    state.lock().unwrap().refreshes.push(used.clone());
                    // Each refresh rotates the token; an old one is refused.
                    let next = match used.as_str() {
                        "rt-1" => "rt-2",
                        "rt-2" => "rt-3",
                        "rt-new" => "rt-new-2",
                        _ => {
                            status = "400 Bad Request";
                            ""
                        }
                    };
                    if next.is_empty() {
                        json!({ "error": "invalid_grant" })
                    } else {
                        json!({ "access_token": "at", "refresh_token": next, "expires_in": 3600 })
                    }
                }
                ("GET", "/v3/company/123/query") => {
                    let qq = decode(q.split("query=").nth(1).unwrap().split('&').next().unwrap());
                    state.lock().unwrap().queries.push(qq.clone());
                    if qq.contains("WHERE") {
                        json!({ "QueryResponse": { "Customer": [cust("3", "Gamma Ltd")] } })
                    } else {
                        json!({ "QueryResponse": { "Customer": [cust("1", "Alpha Ltd"), cust("2", "Beta Ltd")] } })
                    }
                }
                ("GET", "/v3/company/123/cdc") => {
                    state.lock().unwrap().cdc += 1;
                    json!({ "CDCResponse": [{ "QueryResponse": [{ "Customer": [{ "Id": "2", "status": "Deleted" }] }] }] })
                }
                ("GET", "/v3/company/123/customer/1") => json!({ "Customer": { "Id": "1", "SyncToken": "5" } }),
                ("GET", "/v3/company/123/customer/2") => {
                    status = "400 Bad Request";
                    json!({ "Fault": { "Error": [{ "Message": "Object Not Found" }] } })
                }
                ("POST", "/v3/company/123/customer") => {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    state.lock().unwrap().posts.push(v.clone());
                    json!({ "Customer": { "Id": v["Id"].as_str().unwrap_or("99") } })
                }
                _ => {
                    status = "404 Not Found";
                    json!({ "error": format!("no mock for {method} {p}") })
                }
            }
            .to_string();
            s.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len()).as_bytes()).unwrap();
        }
    });
    base
}

#[test]
fn quickbooks_full_incremental_rotating_tokens_and_restore() {
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
    let dir = tempfile::tempdir().unwrap();
    let cfg = |refresh: &str| {
        let mut c = Config::from_secret(
            "123",
            "app",
            &json!({ "client_secret": "s", "refresh_token": refresh }).to_string(),
            "https://example.invalid",
        )
        .unwrap();
        c.api_base = base.clone();
        c.token_url = format!("{base}/oauth2/v1/tokens/bearer");
        c.token_cache = Some(dir.path().join("tokens").join("qb.json"));
        c
    };
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
        entities: vec!["Customer".into()],
    };

    let qb = QuickBooks::new(cfg("rt-1"));
    let mut w = store::Writer::new(&repo, "quickbooks", "123");
    qb.backup(&mut w, None, &opts, &|_| {}).unwrap();
    assert!(w.index.warnings.is_empty(), "{:?}", w.index.warnings);
    let first = w.finish(None, std::time::Instant::now()).unwrap();

    // A new run (a new process) uses the rotated token kept on the machine, not the sealed one.
    let (_, prev) = store::previous(&repo, "quickbooks", "123")
        .unwrap()
        .unwrap();
    let qb = QuickBooks::new(cfg("rt-1"));
    let mut w = store::Writer::new(&repo, "quickbooks", "123");
    qb.backup(&mut w, Some(&prev), &opts, &|_| {}).unwrap();
    assert!(w.index.warnings.is_empty(), "{:?}", w.index.warnings);
    let second = w.finish(None, std::time::Instant::now()).unwrap();
    {
        let s = state.lock().unwrap();
        assert_eq!(s.refreshes, vec!["rt-1", "rt-2"]);
        assert!(
            s.queries[1].contains("WHERE MetaData.LastUpdatedTime >= '"),
            "{:?}",
            s.queries
        );
        assert_eq!(s.cdc, 1);
    }
    let idx = store::read_index(&repo, &repo.load_manifest(&second).unwrap()).unwrap();
    let mut ids: Vec<&str> = idx.items.iter().map(|i| i.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, vec!["1", "3"], "2 was deleted, 3 is new, 1 kept");

    // Restore: 2 is re-created without its ID; 1 is updated with its current SyncToken.
    let idx1 = store::read_index(&repo, &repo.load_manifest(&first).unwrap()).unwrap();
    let get = |id: &str| {
        store::read_item(&repo, idx1.items.iter().find(|i| i.id == id).unwrap()).unwrap()
    };
    assert_eq!(
        qb.restore_record("Customer", &get("2"), false).unwrap(),
        "99"
    );
    assert_eq!(
        qb.restore_record("Customer", &get("1"), false).unwrap(),
        "1",
        "exists: left alone"
    );
    qb.restore_record("Customer", &get("1"), true).unwrap();
    assert!(
        qb.restore_record("TaxCode", &get("1"), true).is_err(),
        "read-only entities are not written"
    );
    {
        let s = state.lock().unwrap();
        assert_eq!(s.posts.len(), 2);
        assert!(
            s.posts[0].get("Id").is_none()
                && s.posts[0].get("SyncToken").is_none()
                && s.posts[0].get("MetaData").is_none()
        );
        assert_eq!(s.posts[0]["DisplayName"], "Beta Ltd");
        assert_eq!(
            (
                s.posts[1]["Id"].as_str(),
                s.posts[1]["SyncToken"].as_str(),
                s.posts[1]["sparse"].as_bool()
            ),
            (Some("1"), Some("5"), Some(false))
        );
    }

    // A token the administrator entered again wins over the one kept from the old chain.
    let qb = QuickBooks::new(cfg("rt-new"));
    let mut w = store::Writer::new(&repo, "quickbooks", "123");
    qb.backup(&mut w, None, &opts, &|_| {}).unwrap();
    assert_eq!(state.lock().unwrap().refreshes.last().unwrap(), "rt-new");
    let kept = std::fs::read_to_string(dir.path().join("tokens/qb.json")).unwrap();
    assert!(kept.contains("rt-new-2"));
}
