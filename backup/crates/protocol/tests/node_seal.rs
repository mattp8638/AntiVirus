//! ci/seal.mjs (the web UI's sealing, run by Node in CI) produces blobs the
//! agent opens. Skipped when Node is not installed.

use protocol::seal::{AgentKey, Sealed};

#[test]
fn node_sealed_blob_opens() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ci/seal.mjs");
    let key = AgentKey::generate();
    let secret = r#"{"domain":"CORP","username":"backup-svc","password":"päss w0rd"}"#;
    let out = match std::process::Command::new("node")
        .args([script, &key.public_b64(), secret])
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            eprintln!("skipped: node not installed");
            return;
        }
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sealed: Sealed = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(&key.open(&sealed).unwrap()[..], secret.as_bytes());
    assert!(AgentKey::generate().open(&sealed).is_err());
}
