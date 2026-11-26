//! Restore evidence (BDR-03): what a restore wrote, its SHA-256 as read back
//! from where it was written, and whether the restored data was checked
//! against the backup. The server adds the recovery point, the times and the
//! RPO and RTO from its own records and keeps the whole record with a hash.

use std::io::Read;
use std::path::Path;

use protocol::{JobState, JobUpdate};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// SHA-256 and size of a file, read back from disk.
pub fn sha256_file(path: &Path) -> std::io::Result<(u64, String)> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        let r = f.read(&mut buf)?;
        if r == 0 {
            break;
        }
        h.update(&buf[..r]);
        n += r as u64;
    }
    Ok((n, h.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

/// `[{path, bytes, sha256} | {path, error}]` for each written file.
pub fn outputs<P: AsRef<Path>>(paths: &[P]) -> Value {
    Value::Array(
        paths
            .iter()
            .map(|p| {
                let p = p.as_ref();
                match sha256_file(p) {
                    Ok((bytes, sha)) => {
                        json!({ "path": p.display().to_string(), "bytes": bytes, "sha256": sha })
                    }
                    Err(e) => json!({ "path": p.display().to_string(), "error": e.to_string() }),
                }
            })
            .collect(),
    )
}

/// The verification summary of a set of engine disk restores.
pub fn disk_verification(reports: &[&engine::RestoreReport]) -> Value {
    Value::Array(
        reports
            .iter()
            .map(|r| match &r.verification {
                Some(v) => json!({ "disk": r.disk, "target": r.target, "method": "read-back", "supported": v.supported,
                                   "chunksChecked": v.chunks_checked, "bytesChecked": v.bytes_checked,
                                   "zeroRangesChecked": v.zero_ranges_checked, "mismatches": v.mismatches,
                                   "firstMismatches": v.first_mismatches, "outsideTarget": v.outside_target,
                                   "contentSha256": v.content_sha256 }),
                None => json!({ "disk": r.disk, "target": r.target, "method": "none", "supported": false }),
            })
            .collect(),
    )
}

/// Put `evidence` into the job's result. A read-back mismatch makes the job a
/// warning that says so: the target does not hold exactly the backup's data.
pub fn attach(u: &mut JobUpdate, outputs: Value, verification: Value, checks: Value) {
    let mismatches: u64 = verification
        .as_array()
        .map(|a| a.iter().filter_map(|v| v["mismatches"].as_u64()).sum())
        .unwrap_or(0);
    let failed_outputs = outputs
        .as_array()
        .map(|a| a.iter().filter(|o| o.get("error").is_some()).count())
        .unwrap_or(0);
    let ev = json!({
        "outputs": outputs,
        "verification": verification,
        "checks": checks,
        "verified": mismatches == 0 && failed_outputs == 0,
        "hashedAt": chrono_now(),
    });
    if mismatches > 0 {
        u.warnings.push(format!(
            "{mismatches} restored chunk(s) did not read back as written: the target does not hold exactly the backup's data. Do not rely on it; check the disk and restore again."
        ));
        if u.state == JobState::Succeeded {
            u.state = JobState::Warning;
        }
    }
    match u.result.as_mut() {
        Some(Value::Object(m)) => {
            m.insert("evidence".into(), ev);
        }
        _ => u.result = Some(json!({ "evidence": ev })),
    }
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    core_format::timefmt::rfc3339_utc(secs as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_hash_what_is_on_disk_and_mismatches_turn_the_job_into_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"abc").unwrap();
        let out = outputs(&[f.as_path(), dir.path().join("gone").as_path()]);
        assert_eq!(
            out[0]["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(out[0]["bytes"], 3);
        assert!(out[1]["error"].is_string());

        let mut u = crate::jobs::finished(JobState::Succeeded);
        attach(
            &mut u,
            json!([{ "path": "x", "bytes": 1, "sha256": "00" }]),
            json!([{ "mismatches": 2 }]),
            json!([]),
        );
        assert_eq!(u.state, JobState::Warning);
        assert_eq!(u.result.as_ref().unwrap()["evidence"]["verified"], false);
        let mut ok = crate::jobs::finished(JobState::Succeeded);
        attach(
            &mut ok,
            json!([{ "path": "x", "bytes": 1, "sha256": "00" }]),
            json!([{ "mismatches": 0 }]),
            json!([]),
        );
        assert_eq!(ok.state, JobState::Succeeded);
        assert_eq!(ok.result.as_ref().unwrap()["evidence"]["verified"], true);
    }
}
