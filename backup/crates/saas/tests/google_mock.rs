//! Google Workspace backup against a mock of the Google APIs: a full backup
//! (Gmail messages, Drive files with folder paths, a Google Doc exported), an
//! incremental one through Gmail history and Drive changes, and a restore.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use core_format::backend::{Backend, LocalBackend};
use core_format::crypto::KdfParams;
use core_format::{InitOptions, Repository};
use saas::google::{Config, Google, Options};
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
            let raw = |id: &str| {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(format!("Subject: {id}\r\n\r\nBody {id}\r\n"))
            };
            let u = "/gmail/v1/users/ann%40example.com";
            let (ct, out): (&str, Vec<u8>) = match (method.as_str(), p.as_str()) {
                ("POST", "/token") => {
                    let b = String::from_utf8_lossy(&body).to_string();
                    assert!(
                        b.contains(
                            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
                        ) && b.matches('.').count() >= 2,
                        "{b}"
                    );
                    j(json!({ "access_token": "tok", "expires_in": 3600 }))
                }
                ("GET", q) if q == format!("{u}/profile") => j(json!({ "historyId": "100" })),
                ("GET", q) if q == format!("{u}/messages") => {
                    j(json!({ "messages": [{ "id": "g1" }, { "id": "g2" }] }))
                }
                ("GET", q) if q == format!("{u}/history") => j(json!({ "history": [
                    { "messagesAdded": [{ "message": { "id": "g3" } }] },
                    { "messagesDeleted": [{ "message": { "id": "g2" } }] }] })),
                ("GET", q) if q.starts_with(&format!("{u}/messages/")) => {
                    let id = q.rsplit('/').next().unwrap().to_string();
                    state.lock().unwrap().downloads.push(id.clone());
                    j(json!({ "id": id, "raw": raw(&id), "labelIds": ["INBOX"], "threadId": "t" }))
                }
                ("GET", "/drive/v3/changes/startPageToken") => j(json!({ "startPageToken": "5" })),
                ("GET", "/drive/v3/files") => j(json!({ "files": [
                    { "id": "F1", "name": "Projects", "mimeType": "application/vnd.google-apps.folder", "parents": ["root"] },
                    { "id": "d1", "name": "Plan", "mimeType": "application/vnd.google-apps.document", "parents": ["F1"], "modifiedTime": "2026-11-01T00:00:00Z" },
                    { "id": "b1", "name": "notes.txt", "mimeType": "text/plain", "parents": ["root"], "modifiedTime": "2026-11-01T00:00:00Z" }] })),
                ("GET", "/drive/v3/files/root") => j(json!({ "name": "My Drive" })),
                ("GET", "/drive/v3/changes") => {
                    j(json!({ "changes": [], "newStartPageToken": "6" }))
                }
                ("GET", "/drive/v3/files/d1/export") => {
                    state.lock().unwrap().downloads.push("d1".into());
                    ("application/octet-stream", b"DOCX BYTES".to_vec())
                }
                ("GET", "/drive/v3/files/b1") => {
                    state.lock().unwrap().downloads.push("b1".into());
                    ("application/octet-stream", b"my notes".to_vec())
                }
                ("GET", q) if q == format!("{u}/labels") => j(json!({ "labels": [] })),
                ("POST", q) if q == format!("{u}/labels") => j(json!({ "id": "L1" })),
                ("POST", "/drive/v3/files") => j(json!({ "id": "RF" })),
                ("POST", q) => {
                    state
                        .lock()
                        .unwrap()
                        .uploads
                        .push((q.to_string(), body.clone()));
                    j(json!({ "id": "new1" }))
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
fn google_full_incremental_and_restore() {
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
    let pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test-service-account.pem"
    ))
    .unwrap();
    let key = json!({ "client_email": "fenrir@example.iam.gserviceaccount.com", "private_key": pem, "token_uri": format!("{base}/token") });
    let mut cfg =
        Config::from_key_file(&key.to_string(), "admin@example.com", "example.com").unwrap();
    cfg.gmail_base = base.clone();
    cfg.drive_base = base.clone();
    cfg.admin_base = base.clone();
    let g = Google::new(cfg).unwrap();
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
        users: vec!["ann@example.com".into()],
        mail: true,
        files: true,
    };

    let mut w = store::Writer::new(&repo, "google", "example.com");
    g.backup(&mut w, None, &opts, &|_| {}).unwrap();
    assert!(w.index.warnings.is_empty(), "{:?}", w.index.warnings);
    w.finish(None, std::time::Instant::now()).unwrap();
    let mut d = state.lock().unwrap().downloads.clone();
    d.sort();
    assert_eq!(d, vec!["b1", "d1", "g1", "g2"]);

    state.lock().unwrap().downloads.clear();
    let (_, prev) = store::previous(&repo, "google", "example.com")
        .unwrap()
        .unwrap();
    let mut w = store::Writer::new(&repo, "google", "example.com");
    g.backup(&mut w, Some(&prev), &opts, &|_| {}).unwrap();
    let second = w.finish(None, std::time::Instant::now()).unwrap();
    assert_eq!(
        state.lock().unwrap().downloads,
        vec!["g3"],
        "only the new message"
    );
    let idx = store::read_index(&repo, &repo.load_manifest(&second).unwrap()).unwrap();
    let mut paths: Vec<String> = idx
        .items
        .iter()
        .map(|i| format!("{}:{}", i.kind, i.path))
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "file:Projects/Plan.docx",
            "file:notes.txt",
            "mail:Gmail/g1",
            "mail:Gmail/g3"
        ]
    );
    assert_eq!(
        idx.cursors.get("ann@example.com|mail").map(String::as_str),
        Some("100")
    );
    assert_eq!(
        idx.cursors.get("ann@example.com|file").map(String::as_str),
        Some("5")
    );

    let mail = idx.items.iter().find(|i| i.id == "g1").unwrap();
    g.restore_mail(
        "ann@example.com",
        "Restored",
        &store::read_item(&repo, mail).unwrap(),
    )
    .unwrap();
    let doc = idx.items.iter().find(|i| i.id == "d1").unwrap();
    let folder = g.drive_folder("ann@example.com", "Restored").unwrap();
    g.restore_file(
        "ann@example.com",
        &folder,
        doc,
        &store::read_item(&repo, doc).unwrap(),
    )
    .unwrap();
    let up = state.lock().unwrap().uploads.clone();
    assert!(up[0]
        .0
        .starts_with("/upload/gmail/v1/users/ann%40example.com/messages/import"));
    assert_eq!(up[0].1, b"Subject: g1\r\n\r\nBody g1\r\n");
    assert_eq!(
        up[1].0,
        "/gmail/v1/users/ann%40example.com/messages/new1/modify"
    );
    assert!(String::from_utf8_lossy(&up[1].1).contains("L1"));
    assert!(up[2].0.starts_with("/upload/drive/v3/files"));
    let body = String::from_utf8_lossy(&up[2].1);
    assert!(
        body.contains("Projects - Plan.docx")
            && body.contains("\"RF\"")
            && body.contains("DOCX BYTES"),
        "{body}"
    );
}
