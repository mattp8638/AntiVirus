//! fenrir-reader: read-only reference reader for Fenrir-Backup repositories.
//!
//! Deliberately small and dependency-light so third parties can read it
//! next to docs/FORMAT.md. It never modifies a repository, and `export`
//! only ever creates a new file.
//!
//! ```text
//! fenrir-reader <repo> list
//! fenrir-reader <repo> show <image-id>
//! fenrir-reader <repo> export <image-id> <disk-index> <new-file>
//! fenrir-reader <repo> check <image-id>
//! ```
//! Passphrase from FENRIR_PASSPHRASE, or FENRIR_RECOVERY_KEY=<file>.

use std::io::Write;
use std::process::exit;
use std::sync::Arc;

use core_format::backend::{Backend, LocalBackend};
use core_format::{RecoveryKey, Repository};

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("fenrir-reader: {msg}");
    exit(1)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: fenrir-reader <repo> list | show <id> | check <id> | export <id> <disk> <new-file>");
        exit(2);
    }
    let backend: Arc<dyn Backend> =
        Arc::new(LocalBackend::open(&args[0]).unwrap_or_else(|e| fail(e)));
    let repo = if let Ok(p) = std::env::var("FENRIR_RECOVERY_KEY") {
        let rk = RecoveryKey::from_file_contents(
            &std::fs::read_to_string(p).unwrap_or_else(|e| fail(e)),
        )
        .unwrap_or_else(|e| fail(e));
        Repository::unlock_with_recovery_key(backend, &rk)
    } else {
        let p = std::env::var("FENRIR_PASSPHRASE")
            .unwrap_or_else(|_| fail("set FENRIR_PASSPHRASE or FENRIR_RECOVERY_KEY"));
        Repository::unlock_with_passphrase(backend, p.as_bytes())
    }
    .unwrap_or_else(|e| fail(e));

    match (args[1].as_str(), &args[2..]) {
        ("list", []) => {
            let (ok, bad) = repo.load_all_manifests().unwrap_or_else(|e| fail(e));
            for m in ok {
                println!(
                    "{}  {}  {}  {} disk(s)",
                    m.image_id,
                    m.created,
                    m.machine.hostname,
                    m.disks.len()
                );
            }
            for (id, e) in bad {
                println!("{id}  UNREADABLE: {e}");
            }
        }
        ("show", [id]) => {
            let m = load(&repo, id);
            println!("{}", serde_json::to_string_pretty(&m).unwrap());
        }
        ("check", [id]) => {
            let m = load(&repo, id);
            let mut bad = 0;
            for c in m.chunk_ids() {
                if let Err(e) = repo.get_chunk(&c) {
                    println!("{c}: {e}");
                    bad += 1;
                }
            }
            if bad > 0 {
                fail(format!("{bad} bad chunk(s)"));
            }
            println!("ok");
        }
        ("export", [id, disk, out]) => {
            let m = load(&repo, id);
            let di: u32 = disk
                .parse()
                .unwrap_or_else(|_| fail("disk index must be a number"));
            let d = m
                .disks
                .iter()
                .find(|d| d.index == di)
                .unwrap_or_else(|| fail("no such disk"));
            // create_new: never overwrite anything, never open a device.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)
                .unwrap_or_else(|e| fail(format!("{out}: {e}")));
            let cs = m.chunk_size as u64;
            let mut next = 0u64; // next byte offset to write
            let zeros = vec![0u8; cs as usize];
            for r in &d.chunks {
                let off = r.0 * cs;
                while next < off {
                    let n = (off - next).min(cs);
                    f.write_all(&zeros[..n as usize])
                        .unwrap_or_else(|e| fail(e));
                    next += n;
                }
                let data = repo.get_chunk(&r.1).unwrap_or_else(|e| fail(e));
                f.write_all(&data).unwrap_or_else(|e| fail(e));
                next += data.len() as u64;
            }
            f.set_len(d.size).unwrap_or_else(|e| fail(e));
            f.sync_all().unwrap_or_else(|e| fail(e));
            println!("wrote {} bytes to {out}", d.size);
        }
        _ => fail("unknown command"),
    }
}

fn load(repo: &Repository, id: &str) -> core_format::ManifestBody {
    let id = repo.resolve_image_id(id).unwrap_or_else(|e| fail(e));
    repo.load_manifest(&id).unwrap_or_else(|e| fail(e))
}
