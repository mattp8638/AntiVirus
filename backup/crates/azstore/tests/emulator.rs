//! The Azure Blob backend against the Azurite emulator. Set
//! FENRIR_TEST_AZURE to a command that starts it with the blob service on a
//! port given as its last argument (ci/azurite-start.sh); skipped otherwise.
//!
//! Azurite checks Shared Key signatures like Azure does, so this also checks
//! the signing. It does not implement immutability policies: those are
//! checked against the request format in the unit tests.

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use azstore::{AzureBackend, AzureConfig, Credential};
use core_format::backend::{Backend, PutOutcome};
use core_format::error::Error;

/// Azurite's documented development account.
const ACCOUNT: &str = "devstoreaccount1";
const KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

struct Emu(Child, u16);
impl Drop for Emu {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start() -> Option<Emu> {
    let cmd = std::env::var("FENRIR_TEST_AZURE").ok()?;
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
    for _ in 0..300 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Emu(child, port));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn backend(port: u16, container: &str, prefix: &str, key: &str) -> AzureBackend {
    AzureBackend::new(AzureConfig {
        endpoint: format!("http://127.0.0.1:{port}/{ACCOUNT}"),
        account: ACCOUNT.into(),
        container: container.into(),
        prefix: prefix.into(),
        credential: Credential::AccountKey(key.into()),
        lock: None,
        access_tier: None,
    })
    .unwrap()
}

#[test]
fn azure_backend_against_azurite() {
    let Some(emu) = start() else {
        eprintln!("FENRIR_TEST_AZURE not set: skipped");
        return;
    };
    let port = emu.1;
    let b = backend(port, "fenrir-test", "office/nas", KEY);
    assert!(
        b.ensure_container().unwrap(),
        "created for a new repository"
    );
    assert!(!b.ensure_container().unwrap(), "already there: left alone");
    b.create_container(false).unwrap(); // already there: fine
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
    // More than one page of listing (Azure pages at 5000; Azurite too).
    for i in 0..5010 {
        b.put(&format!("chunks/{:02x}/{i:064x}", i % 256), b"x")
            .unwrap();
    }
    let keys = b.list("chunks/").unwrap();
    assert_eq!(keys.len(), 5010);
    assert!(keys.iter().all(|k| k.starts_with("chunks/")));
    let other = backend(port, "fenrir-test", "elsewhere", KEY);
    assert!(other.is_empty().unwrap());
    b.delete("config.json").unwrap();
    assert!(!b.exists("config.json").unwrap());
    b.delete("config.json").unwrap(); // gone already: fine
    assert!(b.check().unwrap().contains("write, read and list work"));

    // A wrong key is refused, with a hint.
    let bad = backend(port, "fenrir-test", "", "d3Jvbmcta2V5");
    let e = bad.get("x").unwrap_err().to_string();
    assert!(e.contains("403"), "{e}");

    // A whole repository on it.
    let rb: Arc<dyn Backend> = Arc::new(backend(port, "fenrir-test", "repo1", KEY));
    let (repo, _rk) =
        core_format::Repository::init(rb.clone(), b"azure passphrase", Default::default()).unwrap();
    drop(repo);
    let repo = core_format::Repository::unlock_with_passphrase(rb, b"azure passphrase").unwrap();
    let data = vec![9u8; 200_000];
    let id = repo.chunk_id(&data);
    repo.put_chunk(&id, &data).unwrap();
    assert_eq!(repo.get_chunk(&id).unwrap(), data);
}

#[test]
fn disk_restored_as_a_fixed_vhd_page_blob() {
    use engine::WriteTarget;
    let Some(emu) = start() else {
        eprintln!("FENRIR_TEST_AZURE not set: skipped");
        return;
    };
    let b = backend(emu.1, "restores", "pm-acer", KEY);
    b.ensure_container().unwrap();
    let size = (3u64 << 20) + 4096; // not a whole MiB: rounded up for Azure
    let t = azstore::pageblob::PageBlobTarget::create(
        backend(emu.1, "restores", "pm-acer", KEY),
        "disk0.vhd",
        size,
    )
    .unwrap();
    assert_eq!(t.disk_size(), 4 << 20);
    let mut data = vec![0u8; 1 << 20];
    data[512..1024].fill(0xAB); // one page set
    data[(1 << 20) - 512..].fill(0xCD); // and the last
    t.write_at(1 << 20, &data).unwrap();
    t.write_at(size - 4096, &[0xEE; 4096]).unwrap();
    assert!(t.write_at(3, &[1; 512]).is_err(), "unaligned");
    assert!(
        azstore::pageblob::PageBlobTarget::create(
            backend(emu.1, "restores", "pm-acer", KEY),
            "disk0.vhd",
            size
        )
        .is_err(),
        "an existing blob is never overwritten"
    );
    let url = t.finish([9; 16]).unwrap();
    assert!(url.ends_with("/restores/pm-acer/disk0.vhd"), "{url}");

    let blob = b.get("disk0.vhd").unwrap();
    assert_eq!(blob.len() as u64, (4 << 20) + 512);
    assert!(blob[..1 << 20].iter().all(|&x| x == 0));
    assert!(blob[(1 << 20) + 512..(1 << 20) + 1024]
        .iter()
        .all(|&x| x == 0xAB));
    assert!(
        blob[(1 << 20) + 1024..(2 << 20) - 512]
            .iter()
            .all(|&x| x == 0),
        "zero pages stay unwritten"
    );
    assert!(blob[(2 << 20) - 512..2 << 20].iter().all(|&x| x == 0xCD));
    assert!(blob[(size - 4096) as usize..size as usize]
        .iter()
        .all(|&x| x == 0xEE));
    assert_eq!(&blob[4 << 20..(4 << 20) + 8], b"conectix");
}
