//! Microsoft 365 backup against a mock of Microsoft Graph: a full backup, an
//! incremental one through delta links (one message removed, one added, the
//! rest not downloaded again), and restoring a file and a message.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::{InitOptions, Repository};
use saas::m365::{Config, Options, M365};
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
            let msg = |id: &str| json!({ "id": id, "subject": format!("Subject {id}"), "lastModifiedDateTime": "2026-11-01T10:00:00Z" });
            let (ct, out): (&str, Vec<u8>) = match (method.as_str(), p.as_str()) {
                ("POST", "/contoso/oauth2/v2.0/token") => {
                    j(json!({ "access_token": "tok", "expires_in": 3600 }))
                }
                ("GET", "/v1.0/users") => {
                    j(json!({ "value": [{ "id": "u1", "userPrincipalName": "ann@contoso.com" }] }))
                }
                ("GET", "/v1.0/users/ann%40contoso.com") => j(json!({ "id": "u1" })),
                ("GET", "/v1.0/users/u1/mailFolders/delta") => {
                    j(json!({ "value": [{ "id": "inbox", "displayName": "Inbox" }] }))
                }
                ("GET", "/v1.0/users/u1/mailFolders/inbox/messages/delta") => j(json!({
                    "value": [msg("m1"), msg("m2")], "@odata.deltaLink": format!("{b2}/v1.0/mail-delta-2") })),
                ("GET", "/v1.0/mail-delta-2") => j(json!({
                    "value": [{ "id": "m2", "@removed": { "reason": "deleted" } }, msg("m3")], "@odata.deltaLink": format!("{b2}/v1.0/mail-delta-3") })),
                ("GET", "/v1.0/users/u1/drive/root/delta") => j(json!({
                    "value": [{ "id": "root", "name": "root", "folder": {} },
                              { "id": "f1", "name": "plan.txt", "file": { "mimeType": "text/plain" }, "parentReference": { "path": "/drive/root:/Docs" } }],
                    "@odata.deltaLink": format!("{b2}/v1.0/drive-delta-2") })),
                ("GET", "/v1.0/drive-delta-2") => j(
                    json!({ "value": [], "@odata.deltaLink": format!("{b2}/v1.0/drive-delta-3") }),
                ),
                ("GET", q) if q.ends_with("/$value") || q.ends_with("/content") => {
                    state.lock().unwrap().downloads.push(q.to_string());
                    let id = q.split('/').nth(5).unwrap_or("");
                    (
                        "application/octet-stream",
                        if q.ends_with("/content") {
                            b"the plan, version 1".to_vec()
                        } else {
                            format!("Subject: Subject {id}\r\n\r\nBody of {id}\r\n").into_bytes()
                        },
                    )
                }
                ("POST", "/v1.0/users/u1/mailFolders") => j(json!({ "id": "restored" })),
                ("POST", q) | ("PUT", q) => {
                    state
                        .lock()
                        .unwrap()
                        .uploads
                        .push((q.to_string(), body.clone()));
                    j(json!({ "id": "new" }))
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
fn m365_full_incremental_and_restore() {
    // The mock is local: no proxy in between.
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
    let mut cfg = Config::new("contoso", "app", "secret");
    cfg.login_base = base.clone();
    cfg.graph_base = base.clone();
    let m = M365::new(cfg);
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
        users: vec![],
        mail: true,
        files: true,
    };

    // Full backup.
    let mut w = store::Writer::new(&repo, "m365", "contoso");
    m.backup(&mut w, None, &opts, &|_| {}).unwrap();
    let first = w.finish(None, std::time::Instant::now()).unwrap();
    assert_eq!(
        state.lock().unwrap().downloads.len(),
        3,
        "two messages and one file"
    );

    // Incremental: only the new message is downloaded; the removed one is gone.
    state.lock().unwrap().downloads.clear();
    let (prev_m, prev) = store::previous(&repo, "m365", "contoso").unwrap().unwrap();
    assert_eq!(prev_m.image_id, first);
    let mut w = store::Writer::new(&repo, "m365", "contoso");
    m.backup(&mut w, Some(&prev), &opts, &|_| {}).unwrap();
    assert!(w.index.warnings.is_empty(), "{:?}", w.index.warnings);
    let second = w.finish(None, std::time::Instant::now()).unwrap();
    assert_eq!(
        state.lock().unwrap().downloads,
        vec!["/v1.0/users/u1/messages/m3/$value".to_string()]
    );
    let m2 = repo.load_manifest(&second).unwrap();
    let idx = store::read_index(&repo, &m2).unwrap();
    let ids: Vec<&str> = idx.items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids.len(), 3);
    assert!(
        ids.contains(&"m1") && ids.contains(&"m3") && ids.contains(&"f1") && !ids.contains(&"m2")
    );
    let file = idx.items.iter().find(|i| i.id == "f1").unwrap();
    assert_eq!(file.path, "Docs/plan.txt");
    assert_eq!(
        store::read_item(&repo, file).unwrap(),
        b"the plan, version 1"
    );
    assert_eq!(idx.cursors.len(), 2, "mail folder and drive delta links");
    // The unchanged items are the same chunks: nothing stored twice.
    let m1 = repo.load_manifest(&first).unwrap();
    let old = store::read_index(&repo, &m1).unwrap();
    assert_eq!(
        old.items.iter().find(|i| i.id == "f1").unwrap().chunks,
        file.chunks
    );

    // Restore a file and a message.
    let mail = idx.items.iter().find(|i| i.id == "m1").unwrap();
    m.restore_file(
        "ann@contoso.com",
        "Restored",
        file,
        &store::read_item(&repo, file).unwrap(),
    )
    .unwrap();
    let folder = m.mail_folder("ann@contoso.com", "Restored", None).unwrap();
    m.restore_mail(
        "ann@contoso.com",
        &folder,
        &store::read_item(&repo, mail).unwrap(),
    )
    .unwrap();
    let up = state.lock().unwrap().uploads.clone();
    assert_eq!(
        up[0].0,
        "/v1.0/users/u1/drive/root:/Restored/Docs/plan.txt:/content"
    );
    assert_eq!(up[0].1, b"the plan, version 1");
    assert_eq!(up[1].0, "/v1.0/users/u1/mailFolders/restored/messages");
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&up[1].1)
            .unwrap(),
        b"Subject: Subject m1\r\n\r\nBody of m1\r\n"
    );
}
