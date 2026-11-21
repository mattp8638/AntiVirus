use std::path::Path;
use std::process::{Command, Output};

use core_format::partition::gpt_types;
use core_format::partition::testutil::{write_gpt, GptPart};
use serde_json::Value;

const MIB: usize = 1024 * 1024;

fn fenrir(repo: &Path, pass: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fenrir-backup"))
        .arg("--json")
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env("FENRIR_PASSPHRASE", pass)
        .env_remove("FENRIR_REPO")
        .output()
        .unwrap()
}

fn json(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "bad JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn make_image(path: &Path) -> Vec<u8> {
    let mut d: Vec<u8> = (0..16 * MIB).map(|i| (i * 31 % 251) as u8).collect();
    write_gpt(
        &mut d,
        512,
        uuid::Uuid::from_u128(99),
        &[
            GptPart {
                type_guid: gpt_types::ESP,
                first_lba: 2048,
                last_lba: 4095,
                name: "EFI",
            },
            GptPart {
                type_guid: gpt_types::LINUX_FS,
                first_lba: 4096,
                last_lba: 30000,
                name: "root",
            },
        ],
    );
    std::fs::write(path, &d).unwrap();
    d
}

#[test]
fn end_to_end_backup_verify_restore() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let rk = dir.path().join("recovery.json");
    let pass = "correct horse battery";

    // init
    let o = fenrir(
        &repo,
        pass,
        &[
            "repo",
            "init",
            "--recovery-key-out",
            rk.to_str().unwrap(),
            "--chunk-size-kib",
            "1024",
        ],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(json(&o)["ok"], true);
    assert!(rk.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&rk).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Refuses to init over an existing repository / recovery key.
    let o = fenrir(
        &repo,
        pass,
        &["repo", "init", "--recovery-key-out", rk.to_str().unwrap()],
    );
    assert_eq!(code(&o), 2);

    // backup
    let img = dir.path().join("disk.img");
    let original = make_image(&img);
    let o = fenrir(
        &repo,
        pass,
        &[
            "backup",
            "disk",
            img.to_str().unwrap(),
            "--machine-id",
            "test-box",
            "--label",
            "first",
        ],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let id = json(&o)["result"]["image_id"].as_str().unwrap().to_string();

    // dry run: needs no repository, reports the plan
    let o = fenrir(
        &dir.path().join("no-repo-here"),
        pass,
        &["backup", "disk", img.to_str().unwrap(), "--dry-run"],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let v = json(&o);
    assert_eq!(v["result"]["dry_run"], true);
    assert_eq!(v["result"]["disks"][0]["partitions"][0]["role"], "esp");
    assert!(
        v["result"]["disks"][0]["probe_bytes_read"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(!dir.path().join("no-repo-here").exists());

    // list
    let o = fenrir(&repo, pass, &["image", "list"]);
    let v = json(&o);
    assert_eq!(v["result"][0]["image_id"], id.as_str());
    assert_eq!(v["result"][0]["label"], "first");
    assert_eq!(v["result"][0]["consistency"], "offline");

    // show by prefix
    let o = fenrir(&repo, pass, &["image", "show", &id[..8]]);
    assert_eq!(
        json(&o)["result"]["disks"][0]["partition_table"]["scheme"],
        "gpt"
    );

    // verify
    let o = fenrir(&repo, pass, &["verify", "--full"]);
    assert_eq!(code(&o), 0);
    assert_eq!(json(&o)["result"]["ok"], true);

    // restore without --yes: refused, nothing created
    let out = dir.path().join("restored.img");
    let o = fenrir(
        &repo,
        pass,
        &[
            "restore",
            "disk",
            "--image",
            &id,
            "--target",
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&o), 6);
    assert_eq!(json(&o)["error"]["kind"], "confirmation_required");
    assert!(!out.exists());

    // restore with --yes
    let o = fenrir(
        &repo,
        pass,
        &[
            "restore",
            "disk",
            "--image",
            &id,
            "--target",
            out.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let restored = std::fs::read(&out).unwrap();
    // Partitioned area (to end of partition 2) and GPT backup are exact.
    let end = 30001 * 512;
    assert_eq!(&restored[..end], &original[..end]);
    assert_eq!(
        &restored[restored.len() - 33 * 512..],
        &original[original.len() - 33 * 512..]
    );

    // wrong passphrase
    let o = fenrir(&repo, "nope", &["image", "list"]);
    assert_eq!(code(&o), 4);
    assert_eq!(json(&o)["error"]["kind"], "key_error");

    // recovery key works without the passphrase
    let o = Command::new(env!("CARGO_BIN_EXE_fenrir-backup"))
        .args([
            "--json",
            "--repo",
            repo.to_str().unwrap(),
            "--recovery-key",
            rk.to_str().unwrap(),
            "image",
            "list",
        ])
        .env_remove("FENRIR_PASSPHRASE")
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));

    // corrupt one chunk: full verify fails with exit 3 and names it
    let chunks_dir = repo.join("chunks");
    let sub = std::fs::read_dir(&chunks_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let victim = std::fs::read_dir(&sub)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut raw = std::fs::read(&victim).unwrap();
    let n = raw.len();
    raw[n - 1] ^= 0xFF;
    std::fs::write(&victim, raw).unwrap();
    let o = fenrir(&repo, pass, &["verify", "--full"]);
    assert_eq!(code(&o), 3);
    let v = json(&o);
    assert_eq!(v["result"]["ok"], false);
    assert_eq!(v["result"]["corrupt_chunks"].as_array().unwrap().len(), 1);
}

#[test]
fn missing_repo_and_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let o = fenrir(&dir.path().join("nope"), "x", &["image", "list"]);
    assert_eq!(code(&o), 5);
    let o = Command::new(env!("CARGO_BIN_EXE_fenrir-backup"))
        .args(["--json", "image", "list"])
        .env_remove("FENRIR_REPO")
        .output()
        .unwrap();
    assert_eq!(code(&o), 2);
    #[cfg(not(windows))]
    {
        let o = fenrir(dir.path(), "x", &["backup", "system"]);
        // Repository missing is reported before platform support; either
        // way the exit code is non-zero and output is JSON.
        assert_ne!(code(&o), 0);
        json(&o);
    }
}
