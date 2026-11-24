//! The S3 backend against an S3 emulator. Set FENRIR_TEST_S3 to a command
//! that starts one on a port given as its last argument (CI: moto_server or
//! MinIO); skipped otherwise.

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use core_format::backend::{Backend, PutOutcome};
use core_format::error::Error;
use s3store::{Lock, LockMode, S3Backend, S3Config};

struct Emu(Child, u16);
impl Drop for Emu {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start() -> Option<Emu> {
    let cmd = std::env::var("FENRIR_TEST_S3").ok()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut parts = cmd.split_whitespace();
    let child = Command::new(parts.next()?)
        .args(parts)
        .arg(port.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Emu(child, port));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn backend(port: u16, bucket: &str, prefix: &str, lock: Option<Lock>) -> S3Backend {
    S3Backend::new(S3Config {
        endpoint: format!("http://127.0.0.1:{port}"),
        region: "us-east-1".into(),
        bucket: bucket.into(),
        prefix: prefix.into(),
        path_style: true,
        access_key: std::env::var("FENRIR_TEST_S3_KEY").unwrap_or_else(|_| "testing".into()),
        secret_key: std::env::var("FENRIR_TEST_S3_SECRET").unwrap_or_else(|_| "testing".into()),
        lock,
    })
    .unwrap()
}

#[test]
fn s3_backend_against_an_emulator() {
    let Some(emu) = start() else {
        eprintln!("FENRIR_TEST_S3 not set: skipped");
        return;
    };
    let port = emu.1;

    // Without a lock.
    let b = backend(port, "plain", "office/nas", None);
    // A new repository creates its bucket; an existing one is left alone.
    assert!(b.ensure_bucket().unwrap(), "created");
    assert!(!b.ensure_bucket().unwrap(), "already there");
    assert!(b.is_empty().unwrap());
    assert_eq!(b.put("config.json", b"{}").unwrap(), PutOutcome::Created);
    assert_eq!(
        b.put("config.json", b"other").unwrap(),
        PutOutcome::AlreadyExists,
        "create-only"
    );
    assert_eq!(b.get("config.json").unwrap(), b"{}");
    assert!(b.exists("config.json").unwrap());
    assert!(!b.exists("nope").unwrap());
    assert!(matches!(b.get("nope"), Err(Error::NotFound(_))));
    assert_eq!(b.size("config.json").unwrap(), 2);
    assert!(!b.is_empty().unwrap());
    // More than one page of listing.
    for i in 0..1005 {
        b.put(&format!("chunks/{:02x}/{i:064x}", i % 256), b"x")
            .unwrap();
    }
    let mut keys = b.list("chunks/").unwrap();
    keys.sort();
    assert_eq!(keys.len(), 1005);
    assert!(
        keys.iter().all(|k| k.starts_with("chunks/")),
        "keys are relative to the prefix"
    );
    // Another prefix in the same bucket is separate.
    let other = backend(port, "plain", "elsewhere", None);
    assert!(other.is_empty().unwrap());
    b.delete("config.json").unwrap();
    assert!(!b.exists("config.json").unwrap());
    assert_eq!(b.lock_days(), None);
    assert!(!b.extend_lock("chunks/00/0").unwrap_or(false));

    // With a compliance lock: deleting is refused, extending works,
    // repository locks are never locked.
    let lock = Some(Lock {
        mode: LockMode::Compliance,
        days: 1,
    });
    let l = backend(port, "immutable", "", lock);
    // Created with Object Lock on, because the repository uses it.
    assert!(l.ensure_bucket().unwrap());
    assert_eq!(
        l.put("manifests/m1", b"manifest").unwrap(),
        PutOutcome::Created
    );
    match l.delete("manifests/m1") {
        Err(Error::Retained(m)) => assert!(m.contains("manifests/m1"), "{m}"),
        other => panic!("expected the lock to refuse the delete, got {other:?}"),
    }
    assert_eq!(l.get("manifests/m1").unwrap(), b"manifest", "still there");
    assert!(l.extend_lock("manifests/m1").unwrap());
    assert_eq!(l.lock_days(), Some(1));
    l.put("locks/abc.1.json", b"{}").unwrap();
    l.delete("locks/abc.1.json").unwrap();
    assert!(!l.exists("locks/abc.1.json").unwrap());
    let note = l.check().unwrap();
    assert!(note.contains("Object Lock is enforced"), "{note}");

    // A lock asked of a bucket without Object Lock is caught by the check.
    let fake = backend(port, "plain", "check", lock);
    assert!(fake.check().is_err());

    // A whole repository on it.
    let repo_backend: Arc<dyn Backend> = Arc::new(backend(port, "immutable", "repo1", lock));
    let (repo, _rk) =
        core_format::Repository::init(repo_backend.clone(), b"s3 passphrase", Default::default())
            .unwrap();
    drop(repo);
    let repo =
        core_format::Repository::unlock_with_passphrase(repo_backend, b"s3 passphrase").unwrap();
    let data = vec![7u8; 100_000];
    let id = repo.chunk_id(&data);
    repo.put_chunk(&id, &data).unwrap();
    assert_eq!(repo.get_chunk(&id).unwrap(), data);
}
