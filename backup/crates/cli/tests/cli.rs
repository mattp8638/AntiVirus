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

/// Bare-metal restore onto a bigger disk of a machine whose ESP has only
/// the Windows loader: the GPT moves to the new end and the fallback loader
/// is added for the new hardware's firmware.
#[test]
fn bare_metal_restore_to_a_larger_disk_adds_the_fallback_loader() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let pass = "correct horse battery";
    let rk = dir.path().join("rk.json");
    let o = fenrir(
        &repo,
        pass,
        &["repo", "init", "--recovery-key-out", rk.to_str().unwrap()],
    );
    assert_eq!(code(&o), 0);

    // 64 MiB disk: 33 MiB FAT32 ESP at 1 MiB, data after it.
    let mut d = vec![0u8; 64 * MIB];
    let esp = (2048u64, 2048 + 33 * 2048 - 1);
    write_gpt(
        &mut d,
        512,
        uuid::Uuid::from_u128(5),
        &[
            GptPart {
                type_guid: gpt_types::ESP,
                first_lba: esp.0,
                last_lba: esp.1,
                name: "EFI",
            },
            GptPart {
                type_guid: gpt_types::BASIC_DATA,
                first_lba: esp.1 + 1,
                last_lba: 120_000,
                name: "C",
            },
        ],
    );
    {
        let part = &mut d[esp.0 as usize * 512..(esp.1 as usize + 1) * 512];
        let mut c = std::io::Cursor::new(part);
        fatfs::format_volume(
            &mut c,
            fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32),
        )
        .unwrap();
        let fs = fatfs::FileSystem::new(&mut c, fatfs::FsOptions::new()).unwrap();
        let b = fs
            .root_dir()
            .create_dir("EFI")
            .unwrap()
            .create_dir("Microsoft")
            .unwrap()
            .create_dir("Boot")
            .unwrap();
        b.create_file("bootmgfw.efi")
            .unwrap()
            .write_all(b"MZ windows boot manager")
            .unwrap();
    }
    d[100_000 * 512..100_001 * 512].fill(0xC5);
    let img = dir.path().join("disk.img");
    std::fs::write(&img, &d).unwrap();
    let o = fenrir(
        &repo,
        pass,
        &[
            "backup",
            "disk",
            img.to_str().unwrap(),
            "--machine-id",
            "pc",
        ],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let id = json(&o)["result"]["image_id"].as_str().unwrap().to_string();

    // The new disk is bigger.
    let args = |t: &Path| {
        vec![
            "restore".to_string(),
            "disk".into(),
            "--image".into(),
            id.clone(),
            "--target".into(),
            t.to_str().unwrap().into(),
            "--yes".into(),
        ]
    };
    let big = dir.path().join("big.img");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(96 * MIB as u64)
        .unwrap();
    let mut a = args(&big);
    a.extend(["--fit".into(), "--boot-fixup".into()]);
    let o = fenrir(
        &repo,
        pass,
        &a.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let v = json(&o);
    assert_eq!(v["result"]["boot"]["added"][0], "\\EFI\\BOOT\\BOOTX64.EFI");
    assert_eq!(
        v["result"]["boot"]["loader"]["label"],
        "Windows Boot Manager"
    );

    let out = std::fs::read(&big).unwrap();
    assert_eq!(out.len(), 96 * MIB);
    struct B<'a>(&'a [u8]);
    impl core_format::io::ReadAt for B<'_> {
        fn read_at(&self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
            b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
            Ok(())
        }
    }
    let t = core_format::partition::read_table(&B(&out), out.len() as u64, 512).unwrap();
    assert!(t.backup_table_valid);
    assert_eq!(t.partitions.len(), 2);
    assert!(out[100_000 * 512..100_001 * 512].iter().all(|&b| b == 0xC5));
    let part = &out[esp.0 as usize * 512..(esp.1 as usize + 1) * 512];
    let fs = fatfs::FileSystem::new(std::io::Cursor::new(part.to_vec()), fatfs::FsOptions::new())
        .unwrap();
    let mut data = Vec::new();
    fs.root_dir()
        .open_file("EFI/BOOT/BOOTX64.EFI")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"MZ windows boot manager");
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

/// `--repo s3://...` end to end against an S3 emulator (FENRIR_TEST_S3: a
/// command starting one on the port given as its last argument), with a
/// compliance Object Lock: create, back up, full verify, restore.
#[test]
fn s3_repository_with_object_lock() {
    use std::process::Stdio;
    let Ok(cmd) = std::env::var("FENRIR_TEST_S3") else {
        eprintln!("FENRIR_TEST_S3 not set: skipped");
        return;
    };
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut parts = cmd.split_whitespace();
    let mut emu = Command::new(parts.next().unwrap())
        .args(parts)
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct Kill<'a>(&'a mut std::process::Child);
    impl Drop for Kill<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _guard = Kill(&mut emu);
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let endpoint = format!("http://127.0.0.1:{port}");
    let key = std::env::var("FENRIR_TEST_S3_KEY").unwrap_or_else(|_| "testing".into());
    let secret = std::env::var("FENRIR_TEST_S3_SECRET").unwrap_or_else(|_| "testing".into());
    s3store::S3Backend::new(s3store::S3Config {
        endpoint: endpoint.clone(),
        region: "us-east-1".into(),
        bucket: "cli-backups".into(),
        prefix: String::new(),
        path_style: true,
        access_key: key.clone(),
        secret_key: secret.clone(),
        lock: None,
    })
    .unwrap()
    .create_bucket(true)
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_fenrir-backup"))
            .arg("--json")
            .args(["--repo", "s3://cli-backups/office"])
            .args(args)
            .env("FENRIR_PASSPHRASE", "s3 passphrase")
            .env("FENRIR_S3_ENDPOINT", &endpoint)
            .env("FENRIR_S3_PATH_STYLE", "1")
            .env("FENRIR_S3_LOCK", "compliance:1")
            .env("AWS_ACCESS_KEY_ID", &key)
            .env("AWS_SECRET_ACCESS_KEY", &secret)
            .env_remove("FENRIR_REPO")
            .output()
            .unwrap()
    };
    let rk = dir.path().join("rk.json");
    let o = run(&[
        "repo",
        "init",
        "--recovery-key-out",
        rk.to_str().unwrap(),
        "--chunk-size-kib",
        "1024",
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let o = run(&[
        "repo",
        "init",
        "--recovery-key-out",
        dir.path().join("rk2.json").to_str().unwrap(),
    ]);
    assert_ne!(
        code(&o),
        0,
        "a second repository in the same place is refused"
    );

    let img = dir.path().join("disk.img");
    let original = make_image(&img);
    let o = run(&[
        "backup",
        "disk",
        img.to_str().unwrap(),
        "--machine-id",
        "s3-box",
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let id = json(&o)["result"]["image_id"].as_str().unwrap().to_string();
    let o = run(&["verify", "--full"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    assert_eq!(json(&o)["result"]["ok"], true);
    let out = dir.path().join("restored.img");
    let o = run(&[
        "restore",
        "disk",
        "--image",
        &id,
        "--target",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let restored = std::fs::read(&out).unwrap();
    let end = 30001 * 512;
    assert_eq!(&restored[..end], &original[..end]);
}

#[test]
fn copy_to_another_repository() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let img = dir.path().join("disk.img");
    let orig = make_image(&img);
    for (repo, pass) in [(&a, "passphrase-one"), (&b, "passphrase-two")] {
        let o = fenrir(
            repo,
            pass,
            &[
                "repo",
                "init",
                "--recovery-key-out",
                &dir.path().join(format!("{pass}.key")).display().to_string(),
            ],
        );
        assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    }
    let o = fenrir(
        &a,
        "passphrase-one",
        &["backup", "disk", img.to_str().unwrap(), "--machine-id", "m"],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    // The destination needs its own passphrase.
    let o = fenrir(&a, "passphrase-one", &["copy", "--to", b.to_str().unwrap()]);
    assert_ne!(code(&o), 0, "no destination passphrase");
    let o = Command::new(env!("CARGO_BIN_EXE_fenrir-backup"))
        .args([
            "--json",
            "--repo",
            a.to_str().unwrap(),
            "copy",
            "--to",
            b.to_str().unwrap(),
            "--full-verify",
        ])
        .env("FENRIR_PASSPHRASE", "passphrase-one")
        .env("FENRIR_TO_PASSPHRASE", "passphrase-two")
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let r = json(&o);
    assert_eq!(r["result"]["copied"].as_array().unwrap().len(), 1);
    assert_eq!(r["result"]["verified"], true);
    // The copy restores to the same bytes, from the destination with its key.
    let copied = r["result"]["copied"][0].as_str().unwrap().to_string();
    let out = dir.path().join("restored.img");
    let o = fenrir(
        &b,
        "passphrase-two",
        &[
            "restore",
            "disk",
            "--image",
            &copied,
            "--target",
            out.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let restored = std::fs::read(&out).unwrap();
    assert_eq!(restored.len(), orig.len());
    assert_eq!(&restored[..4096], &orig[..4096], "partition table");
}
